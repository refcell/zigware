//! The marshal actor's mailbox messages (commonware `core/actor.rs`
//! `handle_mailbox_message`, `handle_subscribe`, `install_floor`, and `persist_verified`).
//! Every function takes the actor (`*actor.Actor(P)`) as `self` and takes ownership of the
//! message it handles.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const types = @import("../../types.zig");
const context = @import("../../simplex/actors/context.zig");
const finalize = @import("actor_finalize.zig");

const Height = types.Height;
const Round = types.Round;

/// Handles one mailbox message (owned).
pub fn handle(self: anytype, message: anytype) !void {
    const Actor = @TypeOf(self.*);
    if (message.response_closed()) return Actor.Message.discard(message);
    switch (message.body) {
        .get_info => |body| reply(self.gpa, body.response, try get_info(self, body.identifier)),
        .get_verified => |body| reply(self.gpa, body.response, try get_verified(self, body.round)),
        .get_block => |body| reply(self.gpa, body.response, try get_block(self, body.identifier)),
        .get_finalization => |body| {
            const found = try finalize.get_finalization_by_height(self, body.height);
            reply(self.gpa, body.response, found);
        },
        .get_processed => |body| reply(self.gpa, body.response, self.floor.processed),
        .get_anchor => |body| reply(self.gpa, body.response, try get_anchor(self)),
        .forward => |body| try forward(self, message.gpa, body),
        .proposed => |body| try proposed(self, message.gpa, body),
        .prepared => |body| {
            var recipients = body.recipients;
            defer recipients.deinit(message.gpa);
            try self.buffer.send(body.round, body.block, recipients);
        },
        .verified => |body| try persist_verified(self, body.round, body.block, body.ack),
        .certified => |body| try certified(self, body.round, body.block, body.ack),
        .certification => |notarization| try certification(self, notarization),
        .notarization => |notarization| try on_notarization(self, notarization),
        .finalization => |finalization| try on_finalization(self, finalization),
        .hint_finalized => |body| try hint_finalized(self, message.gpa, body),
        .subscribe_by_digest => |body| try subscribe(
            self,
            Actor.SubscriptionKey{ .digest = body.digest },
            body.fallback.commitment_fallback(),
            body.response,
        ),
        .subscribe_by_commitment => |body| try subscribe(
            self,
            Actor.SubscriptionKey{ .commitment = body.commitment },
            body.fallback,
            body.response,
        ),
        .hint_notarized => |body| try hint_notarized(self, body.round, body.commitment),
        .set_floor => |finalization| try install_floor(self, finalization),
        .prune => |height| {
            // Only pruning at or below the processed floor is allowed.
            if (height.get() > self.floor.processed_height().get()) return;
            try finalize.prune_finalized_archives(self, height);
        },
    }
}

/// Sends `value` (owned) to `response`; a caller that stopped waiting drops it.
fn reply(gpa: std.mem.Allocator, response: anytype, value: anytype) void {
    var sender = response;
    sender.send(value) catch {
        var dropped = value;
        release(gpa, &dropped);
    };
}

/// Frees a reply nobody received.
fn release(gpa: std.mem.Allocator, value: anytype) void {
    const T = @TypeOf(value.*);
    switch (@typeInfo(T)) {
        .optional => if (value.*) |*inner| release(gpa, inner),
        .@"struct" => {
            if (comptime std.meta.hasMethod(T, "deinit")) {
                const params = @typeInfo(@TypeOf(T.deinit)).@"fn".param_types.len;
                if (params == 2) value.deinit(gpa) else value.deinit();
            } else if (comptime @hasField(T, "block")) {
                release(gpa, &value.block);
            }
        },
        else => {},
    }
}

fn get_info(self: anytype, identifier: anytype) !?@TypeOf(self.*).Message.Info {
    const V = @TypeOf(self.*).V;
    switch (identifier) {
        // The archive maps a digest to its height only through the stored block.
        .digest => |digest| {
            const stored = try self.finalized_blocks.get(.{ .key = digest }) orelse return null;
            defer codec.free(V.StoredBlock, self.gpa, stored);
            return .{ .height = stored.height(), .digest = digest };
        },
        .height => |height| return get_info_by_height(self, height),
        .latest => {
            const latest = try finalize.get_latest(self) orelse return null;
            return .{ .height = latest.height, .digest = latest.digest };
        },
    }
}

fn get_info_by_height(self: anytype, height: Height) !?@TypeOf(self.*).Message.Info {
    const V = @TypeOf(self.*).V;
    if (try finalize.get_finalization_by_height(self, height)) |found| {
        var finalization = found;
        defer finalization.deinit(self.gpa);
        const digest = V.commitment_to_inner(finalization.proposal.payload);
        return .{ .height = height, .digest = digest };
    }
    const stored = try finalize.get_finalized_block(self, height) orelse return null;
    var block = try finalize.restore_across(self, stored);
    defer V.deinit_block(self.gpa, &block);
    return .{ .height = block.inner().height(), .digest = block.digest() };
}

fn get_verified(self: anytype, round: Round) !?@TypeOf(self.*).Block {
    const stored = try self.cache.get_verified(round) orelse return null;
    return try finalize.restore_across(self, stored);
}

fn get_block(self: anytype, identifier: anytype) !?@TypeOf(self.*).Block {
    switch (identifier) {
        .digest => |digest| return finalize.find_block_by_digest(self, digest),
        .height => |height| {
            const stored = try finalize.get_finalized_block(self, height) orelse return null;
            return try finalize.restore_across(self, stored);
        },
        .latest => {
            const latest = try finalize.get_latest(self) orelse return null;
            return finalize.find_block_by_digest(self, latest.digest);
        },
    }
}

fn get_anchor(self: anytype) !?@TypeOf(self.*).Message.Anchor {
    const processed = self.floor.processed orelse return null;
    const stored = try finalize.get_finalized_block(self, processed.anchor()) orelse
        @panic("processed position must be backed by a stored block");
    const block = try finalize.restore_across(self, stored);
    return .{ .processed = processed, .block = block };
}

fn forward(self: anytype, gpa: std.mem.Allocator, body: anytype) !void {
    var recipients = body.recipients;
    defer recipients.deinit(gpa);
    if (recipients == .some and recipients.some.len == 0) return;
    const block = try finalize.find_block_by_commitment(self, body.commitment) orelse return;
    try self.buffer.send(body.round, block, recipients);
}

/// Broadcasts a proposed block before persisting it: durability is not needed until
/// certify, and a block no journaled vote names cannot be notarized.
fn proposed(self: anytype, gpa: std.mem.Allocator, body: anytype) !void {
    const V = @TypeOf(self.*).V;
    var recipients = body.recipients;
    defer recipients.deinit(gpa);
    var block = body.block;
    var ack = body.ack;
    self.buffer.send(body.round, V.clone_block(&block), recipients) catch |err| {
        V.deinit_block(self.gpa, &block);
        ack.deinit();
        return err;
    };
    try persist_verified(self, body.round, block, ack);
}

/// Ingests `block` (owned) and stores it as the round's verify-stage candidate; `ack` fires
/// once it is durable. A pruned round or a duplicate is a no-op that still acknowledges.
fn persist_verified(self: anytype, round: Round, block: anytype, ack: anytype) !void {
    const V = @TypeOf(self.*).V;
    var owned = block;
    defer V.deinit_block(self.gpa, &owned);
    var sender = ack;
    errdefer sender.deinit();
    _ = try finalize.ingest(self, &owned);
    try self.cache.put_verified(round, owned.digest(), &owned);
    sender.send({}) catch {};
}

/// Stores a certified block unless the verified archive holds it, and acknowledges once the
/// block and the round's notarization are durable.
fn certified(self: anytype, round: Round, block: anytype, ack: anytype) !void {
    const V = @TypeOf(self.*).V;
    var owned = block;
    defer V.deinit_block(self.gpa, &owned);
    var sender = ack;
    errdefer sender.deinit();
    _ = try finalize.ingest(self, &owned);
    const digest = owned.digest();
    // At most one notarization exists per round, so the notarized slot cannot belong to
    // another payload: a held verified copy already vouches for the block.
    if (try self.cache.has_verified(round, digest)) {
        try self.cache.start_sync_verified(round);
    } else {
        try self.cache.put_notarized(round, digest, &owned);
    }
    try self.cache.start_sync_notarizations(round);
    sender.send({}) catch {};
}

/// Certification authenticates the block's commitment and its parent's.
fn certification(self: anytype, notarization: anytype) !void {
    const V = @TypeOf(self.*).V;
    var owned = notarization;
    defer owned.deinit(self.gpa);
    const commitment = owned.proposal.payload;
    var block = try finalize.find_block_by_commitment(self, commitment) orelse return;
    defer V.deinit_block(self.gpa, &block);
    const height = block.inner().height();
    try self.certified.insert(self.gpa, height, commitment);
    if (height.previous()) |parent| {
        try self.certified.insert(self.gpa, parent, V.parent_commitment(&block));
    }
}

/// Persists a notarization and, if the block is local, the notarized block. A notarization
/// alone does not fetch missing proposal data.
fn on_notarization(self: anytype, notarization: anytype) !void {
    const V = @TypeOf(self.*).V;
    var owned = notarization;
    defer owned.deinit(self.gpa);
    const round = owned.round();
    const commitment = owned.proposal.payload;
    const digest = V.commitment_to_inner(commitment);
    try self.cache.put_notarization(round, digest, &owned);
    var block = try finalize.find_block_by_commitment(self, commitment) orelse return;
    defer V.deinit_block(self.gpa, &block);
    _ = try finalize.ingest(self, &block);
    if (try self.cache.has_verified(round, digest)) return;
    try self.cache.put_notarized(round, digest, &block);
}

/// Caches a finalization and stores its block when local, or fetches the block by round.
fn on_finalization(self: anytype, finalization: anytype) !void {
    const Actor = @TypeOf(self.*);
    const V = Actor.V;
    var owned: ?Actor.Finalization = finalization;
    defer if (owned) |*value| value.deinit(self.gpa);
    const round = owned.?.round();
    const commitment = owned.?.proposal.payload;
    const digest = V.commitment_to_inner(commitment);
    try self.cache.put_finalization(round, digest, &owned.?);
    var block = try finalize.find_block_by_commitment(self, commitment) orelse {
        // A finalization names the commitment but not the height: fetch by round.
        _ = try self.floor.fetch_if_permitted(&self.resolver, .{ .finalized_by_round = .{
            .commitment = commitment,
            .bound = round,
        } });
        return;
    };
    defer V.deinit_block(self.gpa, &block);
    // The anchor path stores the floor block and finalization and resumes dispatch.
    if (try finalize.ingest(self, &block)) return;
    const height = block.inner().height();
    try finalize.witness_round(self, height, round);
    try self.stream.sync();
    const value = owned;
    owned = null;
    if (!try finalize.store_finalization(self, height, &block, value)) return;
    self.staged.insert(self.gpa, height, V.clone_block(&block));
    // With a pending floor anchor, repair and dispatch wait for it.
    _ = try finalize.try_repair_gaps(self);
    try finalize.start_finalized_sync(self);
}

fn hint_finalized(self: anytype, gpa: std.mem.Allocator, body: anytype) !void {
    defer gpa.free(body.targets);
    if (try self.finalizations_by_height.has(body.height)) return;
    _ = try self.floor.fetch_targeted_if_permitted(
        &self.resolver,
        .{ .finalized = body.height },
        body.targets,
    );
}

fn hint_notarized(self: anytype, round: Round, commitment: anytype) !void {
    const V = @TypeOf(self.*).V;
    if (try finalize.find_block_by_commitment(self, commitment)) |found| {
        var block = found;
        V.deinit_block(self.gpa, &block);
        return;
    }
    _ = try self.floor.fetch_if_permitted(&self.resolver, .{ .notarized = round });
}

/// Answers a subscription from local storage, or fetches per `fallback` and registers the
/// caller for later availability.
fn subscribe(self: anytype, key: anytype, fallback: anytype, response: anytype) !void {
    const V = @TypeOf(self.*).V;
    var sender = response;
    const found = switch (key) {
        .digest => |digest| finalize.find_block_by_digest(self, digest),
        .commitment => |commitment| finalize.find_block_by_commitment(self, commitment),
    } catch |err| {
        sender.deinit();
        return err;
    };
    if (found) |local| {
        var block = local;
        // An ancestor may be certified through a descendant without its own notification:
        // its digest binds the parent commitment, so extend the evidence here.
        extend_certified(self, key, &block) catch |err| {
            V.deinit_block(self.gpa, &block);
            sender.deinit();
            return err;
        };
        sender.send(block) catch V.deinit_block(self.gpa, &block);
        return;
    }
    fetch_fallback(self, key, fallback) catch |err| {
        sender.deinit();
        return err;
    };
    try self.block_subscriptions.insert(self.gpa, key, sender, &self.waiters, &self.buffer);
}

fn extend_certified(self: anytype, key: anytype, block: anytype) !void {
    const V = @TypeOf(self.*).V;
    const height = block.inner().height();
    const parent = height.previous() orelse return;
    const known = switch (key) {
        .commitment => |commitment| self.certified.contains(height, commitment),
        .digest => |digest| known: {
            for (self.certified.at(height)) |entry| {
                if (V.commitment_to_inner(entry.commitment).eql(digest)) break :known true;
            }
            break :known false;
        },
    };
    if (known) try self.certified.insert(self.gpa, parent, V.parent_commitment(block));
}

fn fetch_fallback(self: anytype, key: anytype, fallback: anytype) !void {
    switch (fallback) {
        .wait => {},
        // The notarized proposal's height is not known soon enough to key the request.
        .fetch_by_round => |round| {
            _ = try self.floor.fetch_if_permitted(&self.resolver, .{ .notarized = round });
        },
        .fetch_by_commitment => |bound| {
            const height = bound.height;
            const commitment = switch (key) {
                .commitment => |value| value,
                .digest => unreachable, // Proof: digest fallbacks never fetch by commitment.
            };
            // Ancestry may be only notarized: reuse commitment material only when certified.
            // Certification also fixes the block's height, so only an untrusted request needs
            // the round as a bound.
            const Request = @TypeOf(self.*).Request;
            const request: Request = if (self.certified.contains(height, commitment))
                .{ .certified = .{ .commitment = commitment, .bound = height } }
            else
                .{ .untrusted = .{
                    .commitment = commitment,
                    .bound = .{ .height = height, .round = bound.round },
                } };
            _ = try self.floor.fetch_if_permitted(&self.resolver, request);
        },
    }
}

/// Verifies and installs a floor (owned), awaiting its anchor block from the buffer or
/// peers if it is not local.
pub fn install_floor(self: anytype, finalization: anytype) !void {
    const V = @TypeOf(self.*).V;
    const gpa = self.gpa;
    var owned = finalization;
    var finalization_owned = true;
    defer if (finalization_owned) owned.deinit(gpa);
    const round = owned.round();
    if (self.floor.cutoff.covers(round)) return;
    const scoped = self.provider.scoped(owned.epoch()) orelse
        @panic("floor finalization epoch unavailable");
    var rng: context.IoRng = .{ .io = self.io };
    if (!try owned.verify(gpa, &rng, scoped, self.strategy)) {
        @panic("floor finalization must verify");
    }
    const commitment = owned.proposal.payload;
    const digest = V.commitment_to_inner(commitment);
    try self.cache.put_finalization(round, digest, &owned);
    // A pending floor at the same or a newer round keeps blocking progress.
    if (self.floor.pending_finalization()) |pending| {
        if (pending.round().order(round) != .lt) return;
    }
    if (try finalize.find_block_by_commitment(self, commitment)) |found| {
        var block = found;
        defer V.deinit_block(gpa, &block);
        finalization_owned = false;
        self.floor.set_pending(gpa, owned, null);
        const anchored = try finalize.ingest(self, &block);
        assert(anchored);
        return;
    }
    // The pending floor owns the next application sync point.
    self.clear_acks();
    // A closed buffer subscription keeps the floor pending; the fetch below runs anyway.
    const aborter = if (try self.buffer.subscribe_by_commitment(commitment)) |receiver|
        try self.waiters.push_floor(receiver)
    else
        null;
    finalization_owned = false;
    self.floor.set_pending(gpa, owned, aborter);
    _ = try self.floor.fetch_if_permitted(&self.resolver, .{ .finalized_by_round = .{
        .commitment = commitment,
        .bound = round,
    } });
}
