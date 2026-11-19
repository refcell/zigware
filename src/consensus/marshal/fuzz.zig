//! Fuzzing of marshal's decoders and state machines outside the coding variant (commonware's
//! consensus/fuzz has no marshal target; AGENTS.md asks for one per decoder and state
//! machine). Each body runs on seeded inputs in `zig build test` and under `std.testing.fuzz`
//! (`codec.fuzz.run`), drawing every value through `codec.fuzz.Draws`.
//!
//! - The resolver `Key` codec: an encoded key decodes to itself, and any decoded input
//!   re-encodes to exactly the bytes it read.
//! - `Annotation.order`: Rust's derived `Ord`, a total order consistent with `eql`.
//! - The standard variant's `decode_block`: a block decodes under its own digest and under no
//!   other, and a mutated encoding decodes only when it is still the block's encoding.
//! - `DispatchGate`, `PendingAcks`, and `Staged`, each against a simple model.
//!
//! The mailbox overflow policy's fuzz lives in `core/mailbox_test.zig` and the ancestor
//! stream's in `ancestry.zig`, next to the helpers they use.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const parallel = @import("parallel");
const cryptography = @import("cryptography");
const types = @import("../types.zig");
const handler = @import("resolver/handler.zig");
const standard = @import("standard/root.zig");
const durability = @import("core/durability.zig");
const acks = @import("core/acks.zig");
const staged = @import("core/staged.zig");

const Draws = codec.fuzz.Draws;
const Smith = testing.Smith;
const Height = types.Height;
const Round = types.Round;
const D = cryptography.Sha256.Digest;
const Key = handler.Key(D);
const Annotation = handler.Annotation;
const gpa = testing.allocator;

fn draw_digest(draws: Draws) D {
    return .{ .bytes = draws.value([32]u8) };
}

fn draw_round(draws: Draws) Round {
    return .new(.new(draws.value(u64)), .new(draws.value(u64)));
}

fn draw_key(draws: Draws) Key {
    return switch (draws.range_at_most(u8, 0, 2)) {
        0 => .{ .block = draw_digest(draws) },
        1 => .{ .finalized = .new(draws.value(u64)) },
        else => .{ .notarized = draw_round(draws) },
    };
}

fn fuzz_key(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const key = draw_key(draws);
    const encoded = try codec.encode(Key, gpa, key);
    defer gpa.free(encoded);
    try testing.expectEqual(key.encode_size(), encoded.len);
    try testing.expect(encoded.len <= Key.max_encode_size);
    try testing.expect((try codec.decode(Key, gpa, encoded)).eql(key));
    // Arbitrary bytes either fail to decode or are exactly a key's canonical encoding.
    var raw: [Key.max_encode_size + 4]u8 = undefined;
    const len = draws.range_at_most(usize, 0, raw.len);
    smith.bytes(raw[0..len]);
    if (draws.value(bool) and len > 0) raw[0] = draws.range_at_most(u8, 0, 3);
    const decoded = codec.decode(Key, gpa, raw[0..len]) catch return;
    const again = try codec.encode(Key, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, raw[0..len], again);
}

test "fuzz resolver key codec" {
    try codec.fuzz.run({}, fuzz_key, 0x4B45, 512);
}

fn draw_annotation(draws: Draws) Annotation {
    // Narrow values so equal and adjacent annotations are common.
    const height: Height = .new(draws.range_at_most(u64, 0, 3));
    const epoch = draws.range_at_most(u64, 0, 1);
    const round: Round = .new(.new(epoch), .new(draws.range_at_most(u64, 0, 2)));
    return switch (draws.range_at_most(u8, 0, 4)) {
        0 => .{ .notarization = round },
        1 => .{ .untrusted = .{
            .height = height,
            .round = if (draws.range_at_most(u8, 0, 1) == 0) null else round,
        } },
        2 => .{ .certified = height },
        3 => .{ .finalized = .{ .by_height = height } },
        else => .{ .finalized = .{ .by_round = round } },
    };
}

/// Rust's derived `Ord` for `Annotation`, written out: by variant in declaration order
/// (`finalized` by height before by round), then by value, rounds by epoch then view, and an
/// untrusted request's optional round after its height with no round first.
fn model_order(a: Annotation, b: Annotation) std.math.Order {
    const rank = struct {
        fn rank(value: Annotation) u8 {
            return switch (value) {
                .notarization => 0,
                .untrusted => 1,
                .certified => 2,
                .finalized => |finalized| if (finalized == .by_height) 3 else 4,
            };
        }
        fn key(value: Annotation) [4]u64 {
            return switch (value) {
                .notarization => |round| .{ round.epoch.get(), round.view.get(), 0, 0 },
                .untrusted => |untrusted| if (untrusted.round) |round|
                    .{ untrusted.height.get(), 1, round.epoch.get(), round.view.get() }
                else
                    .{ untrusted.height.get(), 0, 0, 0 },
                .certified => |height| .{ height.get(), 0, 0, 0 },
                .finalized => |finalized| switch (finalized) {
                    .by_height => |height| .{ height.get(), 0, 0, 0 },
                    .by_round => |round| .{ round.epoch.get(), round.view.get(), 0, 0 },
                },
            };
        }
    };
    const by_rank = std.math.order(rank.rank(a), rank.rank(b));
    if (by_rank != .eq) return by_rank;
    const left = rank.key(a);
    const right = rank.key(b);
    for (left, right) |l, r| {
        const order = std.math.order(l, r);
        if (order != .eq) return order;
    }
    return .eq;
}

fn fuzz_annotation_order(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const a = draw_annotation(draws);
    const b = draw_annotation(draws);
    const c = draw_annotation(draws);
    try testing.expectEqual(model_order(a, b), Annotation.order(a, b));
    try testing.expectEqual(Annotation.order(a, a), .eq);
    try testing.expectEqual(Annotation.order(a, b), Annotation.order(b, a).invert());
    try testing.expectEqual(Annotation.order(a, b) == .eq, a.eql(b));
    const ab = Annotation.order(a, b);
    if (ab != .gt and Annotation.order(b, c) != .gt) {
        try testing.expect(Annotation.order(a, c) != .gt);
        if (ab == .lt or Annotation.order(b, c) == .lt) try testing.expect(a.order(c) == .lt);
    }
}

test "fuzz resolver annotation order" {
    try codec.fuzz.run({}, fuzz_annotation_order, 0xA2207, 1024);
}

/// `EmptyBlock` digests every field it encodes, so a changed encoding changes its digest (the
/// mock `Block` carries its digest in its encoding, as commonware's does).
const B = @import("mocks/block.zig").EmptyBlock(cryptography.Sha256);
const V = standard.Standard(B);

fn fuzz_decode_block(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const raw = B.init(draw_digest(draws), .new(draws.value(u64)), draws.value(u64));
    const digest = raw.digest();
    const encoded = try codec.encode(B, gpa, raw);
    defer gpa.free(encoded);
    const trusted: V.Expected = if (draws.value(bool))
        .{ .trusted = digest }
    else
        .{ .untrusted = digest };
    // The block decodes under its own digest, and to the same digest.
    var block = try V.decode_block(gpa, encoded, {}, trusted, parallel.sequential);
    try testing.expect(block.digest().eql(digest));
    V.deinit_block(gpa, &block);
    // Under any other digest it is rejected.
    const other = draw_digest(draws);
    if (!other.eql(digest)) {
        const wrong: V.Expected = .{ .untrusted = other };
        const result = V.decode_block(gpa, encoded, {}, wrong, parallel.sequential);
        try testing.expectError(error.Invalid, result);
    }
    try check_mutated(draws, encoded, trusted, digest);
}

/// A mutated encoding (a flipped byte, a truncation, or trailing bytes) decodes only when it
/// is still the block's exact encoding.
fn check_mutated(draws: Draws, encoded: []const u8, expected: V.Expected, digest: D) !void {
    var buffer: [512]u8 = undefined;
    if (encoded.len + 4 > buffer.len) return;
    @memcpy(buffer[0..encoded.len], encoded);
    var len = encoded.len;
    switch (draws.range_at_most(u8, 0, 2)) {
        0 => buffer[draws.index(len)] ^= draws.range_at_most(u8, 1, 255),
        1 => len = draws.range_less_than(usize, 0, len),
        else => {
            const extra = draws.range_at_most(usize, 1, 4);
            for (buffer[len..][0..extra]) |*byte| byte.* = draws.value(u8);
            len += extra;
        },
    }
    var block = V.decode_block(gpa, buffer[0..len], {}, expected, parallel.sequential) catch
        return;
    defer V.deinit_block(gpa, &block);
    try testing.expect(block.digest().eql(digest));
    try testing.expectEqualSlices(u8, encoded, buffer[0..len]);
}

test "fuzz standard decode block" {
    try codec.fuzz.run({}, fuzz_decode_block, 0xDEC0, 256);
}

const steps_max = 64;
const heights_max = 32;

/// The gate's per-write model: each deferred write is open (no sync), adopted by a batch, or
/// released; the barrier is the lowest write not yet released.
const GateModel = struct {
    const Write = struct { height: u64, batch: ?u64, released: bool };

    writes: [steps_max]Write = undefined,
    len: usize = 0,
    next_seq: u64 = 0,

    fn barrier(self: *const GateModel) ?u64 {
        var lowest: ?u64 = null;
        for (self.writes[0..self.len]) |write| {
            if (write.released) continue;
            if (lowest == null or write.height < lowest.?) lowest = write.height;
        }
        return lowest;
    }

    fn adopt(self: *GateModel) ?u64 {
        var any = false;
        for (self.writes[0..self.len]) |*write| {
            if (write.released or write.batch != null) continue;
            write.batch = self.next_seq;
            any = true;
        }
        if (!any) return null;
        self.next_seq += 1;
        return self.next_seq - 1;
    }

    fn release(self: *GateModel, seq: u64) void {
        for (self.writes[0..self.len]) |*write| {
            if (write.batch) |batch| if (batch <= seq) {
                write.released = true;
            };
        }
    }

    fn clear(self: *GateModel) void {
        for (self.writes[0..self.len]) |*write| write.released = true;
    }
};

fn fuzz_dispatch_gate(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    var gate: durability.DispatchGate = .{};
    defer gate.deinit(gpa);
    var model: GateModel = .{};
    const steps = draws.range_at_most(usize, 0, steps_max);
    for (0..steps) |_| {
        switch (draws.range_at_most(u8, 0, 5)) {
            0, 1, 2 => {
                const height = draws.range_less_than(u64, 0, heights_max);
                gate.defer_write(.new(height));
                model.writes[model.len] = .{ .height = height, .batch = null, .released = false };
                model.len += 1;
            },
            3 => {
                const seq = try gate.adopt(gpa);
                try testing.expectEqual(model.adopt(), seq);
            },
            4 => if (model.next_seq > 0) {
                // Pooled syncs may complete in any order, and stale completions repeat.
                const seq = draws.range_less_than(u64, 0, model.next_seq);
                gate.release(seq);
                model.release(seq);
            },
            else => {
                gate.clear();
                model.clear();
            },
        }
        const barrier: ?u64 = if (gate.barrier()) |height| height.get() else null;
        try testing.expectEqual(model.barrier(), barrier);
    }
}

test "fuzz dispatch gate against a per-write model" {
    try codec.fuzz.run({}, fuzz_dispatch_gate, 0x6A7E, 512);
}

const Exact = utils.acknowledgement.Exact;
const Pending = acks.PendingAcks(Exact);

/// The acks model: queued heights, oldest first, each open, acknowledged, or canceled.
const AckModel = struct {
    const State = enum { open, acknowledged, canceled };
    const Entry = struct { height: u64, state: State, ack: Exact };

    entries: [8]Entry = undefined,
    head: usize = 0,
    len: usize = 0,

    fn at(self: *AckModel, offset: usize) *Entry {
        assert(offset < self.len);
        return &self.entries[(self.head + offset) % self.entries.len];
    }

    fn push(self: *AckModel, entry: Entry) void {
        assert(self.len < self.entries.len);
        self.len += 1;
        self.at(self.len - 1).* = entry;
    }

    fn pop(self: *AckModel) Entry {
        const entry = self.at(0).*;
        self.head = (self.head + 1) % self.entries.len;
        self.len -= 1;
        return entry;
    }

    /// Releases every acknowledgement the test still holds.
    fn release_all(self: *AckModel) void {
        while (self.len > 0) {
            var entry = self.pop();
            if (entry.state == .open) entry.ack.deinit();
        }
    }
};

fn fuzz_pending_acks(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const max = draws.range_at_most(u32, 1, 8);
    var pending: Pending = try .init(gpa, max);
    defer pending.deinit(gpa);
    var model: AckModel = .{};
    defer model.release_all();
    var cursor = draws.range_at_most(u64, 0, 1000);
    const steps = draws.range_at_most(usize, 0, steps_max);
    for (0..steps) |_| {
        try step_pending_acks(draws, &pending, &model, &cursor, max);
        try testing.expectEqual(model.len < max, pending.has_capacity());
        const next = if (model.len == 0) cursor else model.at(model.len - 1).height + 1;
        try testing.expectEqual(next, pending.next_dispatch_height(.new(cursor)).get());
        const current: ?u64 = if (pending.current()) |ack| ack.height.get() else null;
        try testing.expectEqual(if (model.len == 0) null else model.at(0).height, current);
    }
}

fn step_pending_acks(
    draws: Draws,
    pending: *Pending,
    model: *AckModel,
    cursor: *u64,
    max: u32,
) !void {
    switch (draws.range_at_most(u8, 0, 4)) {
        0 => if (model.len < max) {
            const height = pending.next_dispatch_height(.new(cursor.*));
            const handle = try Exact.handle(gpa, testing.io);
            pending.enqueue(.{ .height = height, .waiter = handle.waiter });
            model.push(.{ .height = height.get(), .state = .open, .ack = handle.acknowledgement });
        },
        1, 2 => if (model.len > 0) {
            // Acknowledge or drop any queued ack, out of order.
            const entry = model.at(draws.index(model.len));
            if (entry.state != .open) return;
            if (draws.value(bool)) {
                entry.ack.acknowledge();
                entry.state = .acknowledged;
            } else {
                entry.ack.deinit();
                entry.state = .canceled;
            }
        },
        3 => {
            const ready = pending.pop_ready();
            if (model.len == 0 or model.at(0).state == .open) {
                return testing.expect(ready == null);
            }
            const expected = model.pop();
            const height, const result = ready orelse return error.TestAckNotReady;
            try testing.expectEqual(expected.height, height.get());
            if (expected.state == .canceled) {
                try testing.expectError(error.AcknowledgementCanceled, result);
            } else {
                try result;
            }
            cursor.* = height.get() + 1;
        },
        else => {
            pending.clear();
            model.release_all();
        },
    }
}

test "fuzz pending acks against a fifo model" {
    try codec.fuzz.run({}, fuzz_pending_acks, 0xAC45, 512);
}

/// A variant whose blocks are tokens counted while live, so the fuzz sees every release.
const Counted = struct {
    pub const Block = struct { id: u32, live: *u32 };

    pub fn deinit_block(_: Allocator, block: *Block) void {
        assert(block.live.* > 0);
        block.live.* -= 1;
    }
};

fn fuzz_staged(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const max = draws.range_at_most(u32, 1, 8);
    var live: u32 = 0;
    var store: staged.Staged(Counted) = try .init(gpa, max);
    defer store.deinit(gpa);
    // The model: the block id staged at each height, and the retention minimum.
    var model: [heights_max]?u32 = @splat(null);
    var min: u64 = 0;
    var next_id: u32 = 0;
    const steps = draws.range_at_most(usize, 0, steps_max);
    for (0..steps) |_| {
        const height = draws.range_less_than(u64, 0, heights_max);
        var count: u32 = 0;
        for (model) |entry| count += @intFromBool(entry != null);
        switch (draws.range_at_most(u8, 0, 3)) {
            0, 1 => {
                live += 1;
                store.insert(gpa, .new(height), .{ .id = next_id, .live = &live });
                const accepted = height >= min and count < max and model[height] == null;
                if (accepted) model[height] = next_id;
                next_id += 1;
            },
            2 => {
                var removed = store.remove(.new(height));
                const id: ?u32 = if (removed) |block| block.id else null;
                try testing.expectEqual(model[height], id);
                if (removed) |*block| Counted.deinit_block(gpa, block);
                model[height] = null;
            },
            else => if (height > min) {
                store.retain(gpa, .new(height));
                for (model[0..height]) |*entry| entry.* = null;
                min = height;
            } else store.retain(gpa, .new(height)),
        }
        count = 0;
        for (model) |entry| count += @intFromBool(entry != null);
        try testing.expectEqual(count, store.len());
        // Only staged blocks are live: every rejected or dropped block was released once.
        try testing.expectEqual(count, live);
    }
}

test "fuzz staged blocks against a height map model" {
    try codec.fuzz.run({}, fuzz_staged, 0x57A6, 512);
}
