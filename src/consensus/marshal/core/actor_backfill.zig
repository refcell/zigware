//! The marshal actor's resolver traffic (commonware `core/actor.rs`
//! `handle_resolver_message`, `handle_produce`, `handle_deliver`, and `verify_delivered`).
//! Every function takes the actor (`*actor.Actor(P)`) as `self`.
//!
//! A batch takes up to `max_repair` handler messages. Block deliveries are handled at once;
//! certificate-bearing deliveries are parsed, then verified together per epoch; produce
//! requests are served after repair has had a chance to fill gaps from the batch.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const codec = @import("codec");
const cryptography = @import("cryptography");
const resolver_api = @import("resolver");
const utils = @import("utils");
const types = @import("../../types.zig");
const context = @import("../../simplex/actors/context.zig");
const handler = @import("../resolver/handler.zig");
const delivery = @import("delivery.zig");
const variant = @import("variant.zig");
const finalize = @import("actor_finalize.zig");

const oneshot = utils.channel.oneshot;
const Height = types.Height;
const Round = types.Round;
const Outcome = resolver_api.Outcome;
const Produced = resolver_api.p2p.Produced;
const Annotation = handler.Annotation;

fn Pending(comptime Actor: type) type {
    return delivery.PendingVerification(Actor.S, Actor.V);
}

fn Produce(comptime Actor: type) type {
    return struct { key: Actor.Key, response: oneshot.Sender(Produced) };
}

/// Handles `first` and up to `max_repair - 1` more ready handler messages, then repairs,
/// syncs once, and serves the batch's produce requests.
pub fn handle(self: anytype, first: anytype) !void {
    const Actor = @TypeOf(self.*);
    const gpa = self.gpa;
    var produces: std.ArrayList(Produce(Actor)) = .empty;
    defer {
        for (produces.items) |*item| item.response.deinit();
        produces.deinit(gpa);
    }
    var delivers: std.ArrayList(Pending(Actor)) = .empty;
    defer {
        for (delivers.items) |*item| item.deinit(gpa, false);
        delivers.deinit(gpa);
    }
    var handled = false;
    var next: ?Actor.HandlerMessage = first;
    var taken: u32 = 0;
    while (next) |message| : (taken += 1) {
        const more = taken + 1 < self.max_repair;
        next = if (more) self.resolver_receiver.try_recv() catch null else null;
        if (message.response_closed()) {
            Actor.HandlerMessage.discard(message);
            continue;
        }
        handled = true;
        switch (message.body) {
            .produce => |body| {
                produces.append(gpa, .{ .key = body.key, .response = body.response }) catch |err| {
                    Actor.HandlerMessage.discard(message);
                    return err;
                };
            },
            .deliver => |body| try handle_deliver(self, message.gpa, body, &delivers),
        }
    }
    if (!handled) return;
    try verify_delivered(self, &delivers);
    // Fill gaps before serving, so requests can be served with data from this batch.
    if (try finalize.try_repair_gaps(self)) {}
    try finalize.start_finalized_sync(self);
    // Each request leaves the list before it is answered, so the cleanup above only closes
    // the ones an error left behind.
    while (produces.pop()) |entry| {
        var item = entry;
        const closed = item.response.is_closed();
        const bytes = if (closed) null else handle_produce(self, item.key) catch |err| {
            item.response.deinit();
            return err;
        };
        const value = bytes orelse {
            item.response.deinit();
            continue;
        };
        const produced: Produced = .{ .bytes = value, .gpa = gpa };
        item.response.send(produced) catch produced.deinit();
    }
    assert(self.stream.is_synced());
}

/// The encoded answer to a peer's request for `key` (owned), or null when the data is
/// missing locally.
fn handle_produce(self: anytype, key: anytype) !?[]u8 {
    const V = @TypeOf(self.*).V;
    const gpa = self.gpa;
    return switch (key) {
        .block => |commitment| bytes: {
            var block = try finalize.find_block_by_commitment(self, commitment) orelse
                return null;
            defer V.deinit_block(gpa, &block);
            break :bytes try encode_values(gpa, .{block});
        },
        .finalized => |height| bytes: {
            var finalization = try finalize.get_finalization_by_height(self, height) orelse
                return null;
            defer finalization.deinit(gpa);
            const stored = try finalize.get_finalized_block(self, height) orelse return null;
            // The block at a height is stored under the digest its finalization commits to.
            const digest = V.commitment_to_inner(finalization.proposal.payload);
            var shared = V.into_shared(try finalize.restore(self, stored, digest));
            defer shared.deinit();
            break :bytes try encode_values(gpa, .{ finalization, shared });
        },
        .notarized => |round| bytes: {
            var notarization = try self.cache.get_notarization(round) orelse return null;
            defer notarization.deinit(gpa);
            const commitment = notarization.proposal.payload;
            var block = try finalize.find_block_by_commitment(self, commitment) orelse
                return null;
            defer V.deinit_block(gpa, &block);
            break :bytes try encode_values(gpa, .{ notarization, block });
        },
    };
}

/// The encodings of `values` in order (a Rust tuple's encoding), through each type's own
/// `write` and `encode_size` (blocks need not be decodable as written).
fn encode_values(gpa: Allocator, values: anytype) Allocator.Error![]u8 {
    var size: usize = 0;
    inline for (values) |value| size += value.encode_size();
    const bytes = try gpa.alloc(u8, size);
    var writer = codec.Writer.init(bytes);
    inline for (values) |value| value.write(&writer);
    assert(writer.unused_capacity() == 0);
    assert(writer.written().len == size);
    return bytes;
}

/// Handles one delivery (owned, freed with `message_gpa`). Block deliveries are processed
/// now; certificate deliveries are parsed and queued in `delivers`.
fn handle_deliver(self: anytype, message_gpa: Allocator, body: anytype, delivers: anytype) !void {
    var response = body.response;
    var value_owned = true;
    defer if (value_owned) message_gpa.free(body.value);
    defer message_gpa.free(body.delivery.subscribers);
    switch (body.delivery.key) {
        .block => |commitment| {
            try deliver_block(self, commitment, body.delivery.subscribers, body.value, &response);
        },
        .finalized => |height| {
            try deliver_finalized(self, height, body.value, response, delivers);
        },
        .notarized => |round| {
            value_owned = false;
            const value = try self.gpa.dupe(u8, body.value);
            value_owned = true;
            errdefer self.gpa.free(value);
            try deliver_notarized(self, round, value, response, delivers);
        },
    }
}

fn respond(response: anytype, outcome: Outcome) void {
    response.send(outcome) catch {};
}

fn any_annotation(
    annotations: []const Annotation,
    comptime tags: []const std.meta.Tag(Annotation),
) bool {
    for (annotations) |annotation| {
        inline for (tags) |tag| if (annotation == tag) return true;
    }
    return false;
}

fn deliver_block(
    self: anytype,
    commitment: anytype,
    annotations: []const Annotation,
    value: []const u8,
    response: anytype,
) !void {
    const V = @TypeOf(self.*).V;
    // Any `certified` or `finalized` subscriber authenticates the shared commitment.
    const expected: variant.ExpectedCommitment(V.Commitment) =
        if (any_annotation(annotations, &.{ .certified, .finalized }))
            .{ .trusted = commitment }
        else
            .{ .untrusted = commitment };
    const config = self.block_codec_config;
    var block = V.decode_block(self.gpa, value, config, expected, self.strategy) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return respond(response, .invalid),
        };
    defer V.deinit_block(self.gpa, &block);
    respond(response, .{ .resolved = .complete });
    // A block matching the pending floor installs (or is rejected) as the anchor only.
    if (try finalize.ingest(self, &block)) return;
    const height = block.inner().height();
    const digest = block.digest();
    // A certified block's parent link was checked by the validators that certified it.
    if (any_annotation(annotations, &.{.certified})) {
        if (height.previous()) |parent| {
            try self.certified.insert(self.gpa, parent, V.parent_commitment(&block));
        }
    }
    // Here `finalized` means the block belongs in the finalized chain.
    const finalization = try self.cache.get_finalization_for(digest);
    if (finalization) |*found| {
        try finalize.witness_round(self, height, found.round());
        try self.stream.sync();
    }
    if (finalization != null or any_annotation(annotations, &.{.finalized})) {
        _ = try finalize.store_finalization(self, height, &block, finalization);
        return;
    }
    if (!bounded_above(annotations, height)) return;
    if (height.get() <= self.floor.processed_height().get()) return;
    const info = self.epocher.containing(height) orelse return;
    try self.cache.put_certified(info.epoch, height, digest, &block);
}

/// Whether a `certified` or `untrusted` subscriber retains `height`.
fn bounded_above(annotations: []const Annotation, height: Height) bool {
    for (annotations) |annotation| switch (annotation) {
        .certified, .untrusted => |bound| if (height.get() <= bound.get()) return true,
        else => {},
    };
    return false;
}

fn deliver_finalized(
    self: anytype,
    height: Height,
    value: []const u8,
    response: anytype,
    delivers: anytype,
) !void {
    const Actor = @TypeOf(self.*);
    const V = Actor.V;
    const gpa = self.gpa;
    var answer = response;
    // Without an epoch or a scope for the height the response cannot be validated: the key
    // is retired without crediting or blaming its source.
    const info = self.epocher.containing(height) orelse return respond(&answer, .ignored);
    const scoped = self.provider.scoped(info.epoch) orelse return respond(&answer, .ignored);
    var reader = codec.Reader.init(value);
    const cfg = scoped.certificate_codec_config();
    var finalization = Actor.Finalization.read(gpa, &reader, cfg) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return respond(&answer, .invalid),
    };
    var finalization_owned = true;
    defer if (finalization_owned) finalization.deinit(gpa);
    // The certificate was bounded by this epoch's participants, so it must claim the epoch.
    if (finalization.epoch().get() != info.epoch.get()) return respond(&answer, .invalid);
    const block_config = self.block_codec_config;
    const block = codec.decode_reader(V.ApplicationBlock, gpa, &reader, block_config) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return respond(&answer, .invalid),
        };
    var digested = broadcast.Digested(V.ApplicationBlock).compute(gpa, block) catch |err| {
        codec.free(V.ApplicationBlock, gpa, block);
        return err;
    };
    var digested_owned = true;
    defer if (digested_owned) digested.deinit();
    // Once the certificate verifies it authenticates the block: check height and digest.
    if (digested.inner().height().get() != height.get()) return respond(&answer, .invalid);
    if (!digested.digest().eql(V.commitment_to_inner(finalization.proposal.payload))) {
        return respond(&answer, .invalid);
    }
    try delivers.ensureUnusedCapacity(gpa, 1);
    finalization_owned = false;
    digested_owned = false;
    delivers.appendAssumeCapacity(.{ .finalized = .{
        .scoped = scoped,
        .finalization = finalization,
        .block = digested,
        .response = answer,
    } });
}

/// Parses a notarized delivery; `value` (owned) holds the certificate and the block.
fn deliver_notarized(
    self: anytype,
    round: Round,
    value: []u8,
    response: anytype,
    delivers: anytype,
) !void {
    const Actor = @TypeOf(self.*);
    const gpa = self.gpa;
    var answer = response;
    var value_owned = true;
    defer if (value_owned) gpa.free(value);
    // The payload check needs the epoch's participant set; without it the key is retired.
    const scheme = self.provider.scheme(round.epoch) orelse return respond(&answer, .ignored);
    var reader = codec.Reader.init(value);
    const cfg = scheme.certificate_codec_config();
    var notarization = Actor.Notarization.read(gpa, &reader, cfg) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return respond(&answer, .invalid),
    };
    var notarization_owned = true;
    defer if (notarization_owned) notarization.deinit(gpa);
    // The key binds the response to `round`.
    if (notarization.round().order(round) != .eq) return respond(&answer, .invalid);
    if (!Actor.V.check_payload(scheme, notarization.proposal.payload)) {
        return respond(&answer, .invalid);
    }
    try delivers.ensureUnusedCapacity(gpa, 1);
    notarization_owned = false;
    value_owned = false;
    delivers.appendAssumeCapacity(.{ .notarized = .{
        .scoped = .scheme(scheme),
        .notarization = notarization,
        .value = value,
        .block_offset = value.len - reader.remaining(),
        .response = answer,
    } });
}

/// Verifies the queued certificates per epoch (under the scope each was admitted with) and
/// processes the valid ones; invalid ones are answered `invalid`. Empties `delivers`.
fn verify_delivered(self: anytype, delivers: anytype) !void {
    const gpa = self.gpa;
    // Drop deliveries whose requester stopped waiting.
    var kept: usize = 0;
    for (delivers.items) |*item| {
        if (item.response_closed()) {
            item.deinit(gpa, false);
            continue;
        }
        delivers.items[kept] = item.*;
        kept += 1;
    }
    delivers.shrinkRetainingCapacity(kept);
    if (delivers.items.len == 0) return;
    const verified = try gpa.alloc(bool, delivers.items.len);
    defer gpa.free(verified);
    try verify_by_epoch(self, delivers.items, verified);
    // Take every item out first, so an error leaves nothing for the caller to free twice.
    const items = try delivers.toOwnedSlice(gpa);
    defer gpa.free(items);
    var index: usize = 0;
    errdefer for (items[index..]) |*item| item.deinit(gpa, false);
    while (index < items.len) : (index += 1) {
        var item = items[index];
        if (!verified[index]) {
            item.respond(.invalid);
            item.deinit(gpa, true);
            continue;
        }
        switch (item) {
            .finalized => |finalized| try process_finalized(self, finalized),
            .notarized => |notarized| try process_notarized(self, notarized),
        }
    }
}

/// Fills `verified` with each item's verdict, verifying each epoch's group in one batch.
fn verify_by_epoch(self: anytype, items: anytype, verified: []bool) !void {
    const Actor = @TypeOf(self.*);
    const gpa = self.gpa;
    const CertificateItem = cryptography.certificate.CertificateItem(Actor.S);
    const indices = try gpa.alloc(usize, items.len);
    defer gpa.free(indices);
    for (indices, 0..) |*slot, position| slot.* = position;
    const ByEpoch = struct {
        fn less(all: @TypeOf(items), a: usize, b: usize) bool {
            const left = all[a].epoch().get();
            const right = all[b].epoch().get();
            return left < right or (left == right and a < b);
        }
    };
    std.sort.pdq(usize, indices, items, ByEpoch.less);
    const group = try gpa.alloc(CertificateItem, items.len);
    defer gpa.free(group);
    const results = try gpa.alloc(bool, items.len);
    defer gpa.free(results);
    var rng: context.IoRng = .{ .io = self.io };
    var start: usize = 0;
    while (start < indices.len) {
        const epoch = items[indices[start]].epoch();
        var end = start;
        while (end < indices.len and
            items[indices[end]].epoch().get() == epoch.get()) : (end += 1)
        {
            group[end - start] = items[indices[end]].certificate_item();
        }
        const scoped = items[indices[start]].scoped();
        const count = end - start;
        try cryptography.certificate.verify_certificates_bisect(
            &scoped,
            gpa,
            &rng,
            group[0..count],
            results[0..count],
            self.strategy,
        );
        for (indices[start..end], results[0..count]) |position, ok| verified[position] = ok;
        start = end;
    }
}

fn process_finalized(self: anytype, item: anytype) !void {
    const V = @TypeOf(self.*).V;
    var response = item.response;
    var finalization = item.finalization;
    respond(&response, .{ .resolved = .complete });
    var block = V.from_application_block(item.block, finalization.proposal.payload);
    defer V.deinit_block(self.gpa, &block);
    const round = finalization.round();
    const height = block.inner().height();
    // The floor-anchor path fully handles this finalization.
    if (try finalize.ingest(self, &block)) return finalization.deinit(self.gpa);
    finalize.witness_round(self, height, round) catch |err| {
        finalization.deinit(self.gpa);
        return err;
    };
    self.stream.sync() catch |err| {
        finalization.deinit(self.gpa);
        return err;
    };
    _ = try finalize.store_finalization(self, height, &block, @as(
        ?@TypeOf(finalization),
        finalization,
    ));
}

fn process_notarized(self: anytype, item: anytype) !void {
    const V = @TypeOf(self.*).V;
    const gpa = self.gpa;
    var response = item.response;
    var notarization = item.notarization;
    defer notarization.deinit(gpa);
    defer gpa.free(item.value);
    // A notarization does not prove the commitment encodes the block: recompute it.
    const commitment = notarization.proposal.payload;
    const bytes = item.value[item.block_offset..];
    const expected: variant.ExpectedCommitment(V.Commitment) = .{ .untrusted = commitment };
    const config = self.block_codec_config;
    var block = V.decode_block(gpa, bytes, config, expected, self.strategy) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return respond(&response, .invalid),
        };
    defer V.deinit_block(gpa, &block);
    respond(&response, .{ .resolved = .complete });
    const round = notarization.round();
    const digest = V.commitment_to_inner(commitment);
    const height = block.inner().height();
    // Both writes are durable when they return, before the repair bookkeeping below.
    try self.cache.put_notarized(round, digest, &block);
    try self.cache.put_notarization(round, digest, &notarization);
    // A notarized delivery can carry the pending floor block.
    if (try finalize.ingest(self, &block)) return;
    // A cached finalization for this block finalizes it now.
    var finalization = try self.cache.get_finalization_for(digest) orelse return;
    finalize.witness_round(self, height, finalization.round()) catch |err| {
        finalization.deinit(gpa);
        return err;
    };
    self.stream.sync() catch |err| {
        finalization.deinit(gpa);
        return err;
    };
    _ = try finalize.store_finalization(self, height, &block, @as(
        ?@TypeOf(finalization),
        finalization,
    ));
}
