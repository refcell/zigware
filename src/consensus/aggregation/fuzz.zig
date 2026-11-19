//! Fuzzing of aggregation's decoders and state machines (commonware's consensus/fuzz has no
//! aggregation target; AGENTS.md asks for one per decoder and state machine). Each body runs
//! on seeded inputs in `zig build test` and under `std.testing.fuzz` (`codec.fuzz.run`),
//! drawing every value through `codec.fuzz.Draws`.
//!
//! - `SafeTip` against a model that sorts every tip: updates, set reconciles, and the safe
//!   tip (the `f + 1`th highest tip) after each step.
//! - `HeightMap` against a per-height model.
//! - The `Item`, `TipAck`, and `Activity` codecs over ed25519: valid encodings, mutated, and
//!   raw bytes either fail to decode or decode to a value that re-encodes to the same bytes.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const Height = @import("../types.zig").Height;
const types = @import("types.zig");
const scheme = @import("scheme.zig");
const SafeTipOf = @import("safe_tip.zig").SafeTip;
const HeightMap = @import("height_map.zig").HeightMap;

const Draws = codec.fuzz.Draws;
const Smith = testing.Smith;
const PublicKey = cryptography.ed25519.PublicKey;
const SafeTip = SafeTipOf(PublicKey);
const Set = utils.ordered.Set(PublicKey);
const D = cryptography.Sha256.Digest;
const gpa = testing.allocator;

const pool_size = 10;
const validators_max = 7;
const steps_max = 48;

const Pool = [pool_size]PublicKey;

fn pool_init() Pool {
    var pool: Pool = undefined;
    for (&pool, 0..) |*slot, seed| {
        slot.* = cryptography.ed25519.PrivateKey.from_seed(seed + 1).public_key();
    }
    return pool;
}

/// Draws `n` distinct pool indexes into `chosen` (a partial Fisher-Yates shuffle).
fn draw_members(draws: Draws, n: usize, members: *[pool_size]bool) void {
    assert(n > 0 and n <= validators_max);
    var order: [pool_size]u8 = undefined;
    for (&order, 0..) |*slot, index| slot.* = @intCast(index);
    for (0..n) |cursor| {
        const pick = draws.range_at_most(usize, cursor, pool_size - 1);
        std.mem.swap(u8, &order[cursor], &order[pick]);
    }
    @memset(members, false);
    for (order[0..n]) |index| members[index] = true;
}

fn set_of(pool: *const Pool, members: *const [pool_size]bool) !Set {
    var keys: [pool_size]PublicKey = undefined;
    var n: usize = 0;
    for (pool, members) |key, member| {
        if (!member) continue;
        keys[n] = key;
        n += 1;
    }
    return Set.init(gpa, keys[0..n]);
}

/// The model's safe tip: the `f + 1`th highest tip among members.
fn model_safe_tip(tips: *const [pool_size]u64, members: *const [pool_size]bool, f: u32) u64 {
    var sorted: [pool_size]u64 = undefined;
    var n: usize = 0;
    for (tips, members) |tip, member| {
        if (!member) continue;
        sorted[n] = tip;
        n += 1;
    }
    std.mem.sort(u64, sorted[0..n], {}, std.sort.desc(u64));
    assert(f < n);
    return sorted[f];
}

fn fuzz_safe_tip(pool: *const Pool, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const n = draws.range_at_most(usize, 1, validators_max);
    var members: [pool_size]bool = undefined;
    draw_members(draws, n, &members);
    var tips: [pool_size]u64 = @splat(0);
    var set = try set_of(pool, &members);
    defer set.deinit(gpa);
    const f = set.max_faults(utils.N3f1);
    var tracker: SafeTip = .empty;
    try tracker.init(gpa, &set);
    defer tracker.deinit(gpa);
    const steps = draws.range_at_most(usize, 0, steps_max);
    for (0..steps) |_| {
        const index = draws.range_at_most(usize, 0, pool_size - 1);
        if (draws.range_at_most(u8, 0, 7) == 0) {
            draw_members(draws, n, &members);
            for (&tips, members) |*tip, member| {
                if (!member) tip.* = 0;
            }
            var next = try set_of(pool, &members);
            defer next.deinit(gpa);
            tracker.reconcile(&next);
        } else {
            const new = draws.range_at_most(u64, 0, 12);
            const old = tracker.update(pool[index], .new(new));
            const accepted = members[index] and new > tips[index];
            try testing.expectEqual(accepted, old != null);
            if (old) |value| try testing.expectEqual(tips[index], value.get());
            if (accepted) tips[index] = new;
        }
        try testing.expectEqual(model_safe_tip(&tips, &members, f), tracker.get().get());
        for (pool, members, tips) |key, member, tip| {
            const expected: ?Height = if (member) .new(tip) else null;
            try testing.expectEqual(expected, tracker.tip(key));
        }
    }
}

test "fuzz safe tip against a sorted model" {
    const pool = pool_init();
    try codec.fuzz.run(&pool, fuzz_safe_tip, 0x5AFE, 512);
}

const heights_max = 24;

fn fuzz_height_map(_: void, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    var map: HeightMap(u32) = .empty;
    defer map.deinit(gpa);
    var model: [heights_max]?u32 = @splat(null);
    const steps = draws.range_at_most(usize, 0, steps_max);
    for (0..steps) |step| {
        const height = draws.range_at_most(u64, 0, heights_max - 1);
        if (draws.range_at_most(u8, 0, 3) == 0) {
            var below: usize = 0;
            for (model[0..height]) |slot| below += @intFromBool(slot != null);
            try testing.expectEqual(below, map.below(.new(height)).len);
            map.remove_below(.new(height));
            @memset(model[0..height], null);
        } else if (model[height] == null) {
            try map.put_new(gpa, .new(height), @intCast(step));
            model[height] = @intCast(step);
        }
        var count: usize = 0;
        var last: ?Height = null;
        for (model, 0..) |slot, at| {
            const found = map.get(.new(at));
            try testing.expectEqual(slot, if (found) |value| value.* else null);
            if (slot == null) continue;
            try testing.expectEqual(Height.new(at), map.items()[count].height);
            count += 1;
            last = .new(at);
        }
        try testing.expectEqual(count, map.len());
        try testing.expectEqual(last, map.last());
    }
}

test "fuzz height map against a per-height model" {
    try codec.fuzz.run({}, fuzz_height_map, 0x4E16, 512);
}

const S = scheme.ed25519.Scheme(D);
const Item = types.Item(D);
const TipAck = types.TipAck(S, D);
const Activity = types.Activity(S, D);

/// Valid encodings to mutate, and the certificate codec bound.
const Encodings = struct {
    item: []u8,
    tip_ack: []u8,
    ack: []u8,
    certified: []u8,
    tip: []u8,
    cfg: codec.Cfg(Activity),

    fn deinit(self: *Encodings) void {
        inline for (.{ "item", "tip_ack", "ack", "certified", "tip" }) |name| {
            gpa.free(@field(self, name));
        }
        self.* = undefined;
    }
};

fn encodings_init() !Encodings {
    var rng = utils.rng.test_rng();
    var built = try scheme.ed25519.fixture(S, gpa, &rng, "fuzz", 4);
    defer built.deinit(gpa);
    const signers = built.schemes;
    const item: Item = .{ .height = .new(300), .digest = cryptography.Sha256.hash(&.{"fuzz"}) };
    const Ack = types.Ack(S, D);
    var acks: [3]Ack = undefined;
    for (&acks, signers[0..3]) |*slot, *signer| {
        slot.* = (try Ack.sign(gpa, signer, .new(2), item)).?;
    }
    const Certificate = types.Certificate(S, D);
    var certificate = try Certificate.from_acks(gpa, &signers[0], &acks, parallel.sequential);
    defer certificate.deinit(gpa);
    const certified: Activity = .{ .certified = certificate };
    return .{
        .item = try codec.encode(Item, gpa, item),
        .tip_ack = try codec.encode(TipAck, gpa, .{ .tip = .new(301), .ack = acks[0] }),
        .ack = try codec.encode(Activity, gpa, .{ .ack = acks[1] }),
        .certified = try codec.encode(Activity, gpa, certified),
        .tip = try codec.encode(Activity, gpa, .{ .tip = .new(7) }),
        .cfg = signers[0].certificate_codec_config(),
    };
}

/// Decodes `bytes` as `T`; a decoded value must re-encode to exactly `bytes`.
fn expect_canonical(comptime T: type, bytes: []const u8, cfg: codec.Cfg(T)) !void {
    const decoded = codec.decode_cfg(T, gpa, bytes, cfg) catch return;
    defer codec.free(T, gpa, decoded);
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
}

fn fuzz_codec(encodings: *const Encodings, smith: *Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const kind = draws.range_at_most(u8, 0, 5);
    const source = switch (kind) {
        0 => encodings.item,
        1 => encodings.tip_ack,
        2 => encodings.ack,
        3 => encodings.certified,
        4 => encodings.tip,
        else => &.{},
    };
    var buffer: [512]u8 = undefined;
    assert(source.len <= buffer.len);
    var len = source.len;
    @memcpy(buffer[0..len], source);
    if (kind == 5) {
        len = draws.range_at_most(usize, 0, 96);
        smith.bytes(buffer[0..len]);
    }
    const mutations = draws.range_at_most(u8, 0, 3);
    for (0..mutations) |_| {
        if (len == 0) break;
        switch (draws.range_at_most(u8, 0, 2)) {
            0 => buffer[draws.range_at_most(usize, 0, len - 1)] ^= draws.value(u8) | 1,
            1 => buffer[draws.range_at_most(usize, 0, len - 1)] = draws.value(u8),
            else => len = draws.range_at_most(usize, 0, len - 1),
        }
    }
    const bytes = buffer[0..len];
    // An unmutated valid encoding decodes.
    if (kind < 5 and mutations == 0) {
        if (kind == 0) _ = try codec.decode(Item, gpa, bytes);
        if (kind == 1) _ = try codec.decode(TipAck, gpa, bytes);
    }
    try expect_canonical(Item, bytes, {});
    try expect_canonical(TipAck, bytes, {});
    try expect_canonical(Activity, bytes, encodings.cfg);
}

test "fuzz item, tip ack, and activity codecs" {
    var encodings = try encodings_init();
    defer encodings.deinit();
    try codec.fuzz.run(&encodings, fuzz_codec, 0xA66C, 1024);
}
