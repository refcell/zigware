//! Tests of `SafeTip` (commonware `aggregation/safe_tip.rs` tests). The `should_panic` cases
//! (empty set, size mismatch, decrementing a missing height) have no counterpart: Zig tests
//! cannot catch a panic.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const utils = @import("utils");
const Height = @import("../types.zig").Height;
const safe_tip_mod = @import("safe_tip.zig");

const PublicKey = cryptography.ed25519.PublicKey;
const SafeTip = safe_tip_mod.SafeTip(PublicKey);
const Counts = safe_tip_mod.Counts;
const Set = utils.ordered.Set(PublicKey);
const gpa = testing.allocator;

fn key(seed: u64) PublicKey {
    return cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
}

fn h(value: u64) Height {
    return .new(value);
}

fn set_of(seeds: []const u64) !Set {
    var keys: [16]PublicKey = undefined;
    for (seeds, keys[0..seeds.len]) |seed, *slot| slot.* = key(seed);
    return Set.init(gpa, keys[0..seeds.len]);
}

/// A safe tip over the validators `key(1)..key(n)`, and that set.
fn setup(n: u64) !struct { SafeTip, Set } {
    var seeds: [16]u64 = undefined;
    for (seeds[0..n], 1..) |*seed, i| seed.* = i;
    var validators = try set_of(seeds[0..n]);
    errdefer validators.deinit(gpa);
    var safe_tip: SafeTip = .empty;
    try safe_tip.init(gpa, &validators);
    return .{ safe_tip, validators };
}

/// `setup(n)`, then validator `i` (in set order) reports `tips[i]` when it is non-zero.
fn setup_with_tips(n: u64, tips: []const u64) !struct { SafeTip, Set } {
    var safe_tip, const validators = try setup(n);
    for (tips, 0..) |value, i| {
        if (i < validators.len() and value > 0) _ = safe_tip.update(validators.items[i], h(value));
    }
    return .{ safe_tip, validators };
}

fn release(safe_tip: *SafeTip, validators: *Set) void {
    safe_tip.deinit(gpa);
    validators.deinit(gpa);
}

fn reconcile(safe_tip: *SafeTip, keys: []const PublicKey) !void {
    var validators = try Set.init(gpa, keys);
    defer validators.deinit(gpa);
    safe_tip.reconcile(&validators);
}

test "init" {
    var safe_tip, var validators = try setup(4);
    defer release(&safe_tip, &validators);
    try testing.expectEqual(4, safe_tip.keys.len);
    try testing.expectEqual(h(0), safe_tip.get());
}

test "update and get" {
    var safe_tip, var validators = try setup(4);
    defer release(&safe_tip, &validators);
    const v = validators.items;
    try testing.expectEqual(h(0), safe_tip.update(v[0], h(10)).?);
    try testing.expectEqual(h(0), safe_tip.get());
    // Lower and equal tips are no-ops.
    try testing.expectEqual(null, safe_tip.update(v[0], h(5)));
    try testing.expectEqual(null, safe_tip.update(v[0], h(10)));
    try testing.expectEqual(h(0), safe_tip.get());
    try testing.expectEqual(h(0), safe_tip.update(v[1], h(20)).?);
    try testing.expectEqual(h(10), safe_tip.get());
    try testing.expectEqual(h(0), safe_tip.update(v[2], h(30)).?);
    try testing.expectEqual(h(20), safe_tip.get());
    try testing.expectEqual(h(0), safe_tip.update(v[3], h(40)).?);
    try testing.expectEqual(h(30), safe_tip.get());
}

test "reconcile" {
    var validators = try set_of(&.{ 1, 2, 3, 4 });
    defer validators.deinit(gpa);
    var safe_tip: SafeTip = .empty;
    defer safe_tip.deinit(gpa);
    try safe_tip.init(gpa, &validators);
    for ([_]u64{ 1, 2, 3, 4 }) |i| _ = safe_tip.update(key(i), h(i * 10));
    try testing.expectEqual(h(30), safe_tip.get());
    try reconcile(&safe_tip, &.{ key(3), key(4), key(5), key(6) });
    try testing.expectEqual(4, safe_tip.keys.len);
    try testing.expectEqual(null, safe_tip.tip(key(1)));
    try testing.expectEqual(h(30), safe_tip.tip(key(3)).?);
    try testing.expectEqual(h(40), safe_tip.tip(key(4)).?);
    try testing.expectEqual(h(0), safe_tip.tip(key(5)).?);
    try testing.expectEqual(h(0), safe_tip.tip(key(6)).?);
    try testing.expectEqual(h(30), safe_tip.get());
}

test "reconcile with an identical set is a no-op" {
    var validators = try set_of(&.{ 1, 2, 3, 4 });
    defer validators.deinit(gpa);
    var safe_tip: SafeTip = .empty;
    defer safe_tip.deinit(gpa);
    try safe_tip.init(gpa, &validators);
    for ([_]u64{ 1, 2, 3 }) |i| _ = safe_tip.update(key(i), h(i * 10));
    const before = safe_tip.get();
    var tips: [4]Height = undefined;
    @memcpy(&tips, safe_tip.tips);
    const hi = safe_tip.hi.entries[0..safe_tip.hi.len];
    const lo = safe_tip.lo.entries[0..safe_tip.lo.len];
    var hi_before: [4]Counts.Entry = undefined;
    var lo_before: [4]Counts.Entry = undefined;
    @memcpy(hi_before[0..hi.len], hi);
    @memcpy(lo_before[0..lo.len], lo);
    safe_tip.reconcile(&validators);
    try testing.expectEqual(before, safe_tip.get());
    try testing.expectEqualSlices(Height, &tips, safe_tip.tips);
    try testing.expectEqualDeep(hi_before[0..hi.len], safe_tip.hi.entries[0..safe_tip.hi.len]);
    try testing.expectEqualDeep(lo_before[0..lo.len], safe_tip.lo.entries[0..safe_tip.lo.len]);
}

test "update of a non-validator is ignored" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 10, 20, 0, 0 });
    defer release(&safe_tip, &validators);
    const before = safe_tip.get();
    for ([_]u64{ 100, 200, 300 }) |seed| {
        try testing.expectEqual(null, safe_tip.update(key(seed), h(50)));
    }
    try testing.expectEqual(before, safe_tip.get());
    try testing.expectEqual(null, safe_tip.tip(key(100)));
}

test "edge cases for f" {
    const cases = [_]struct { n: u64, f: u32 }{
        .{ .n = 1, .f = 0 }, .{ .n = 2, .f = 0 }, .{ .n = 3, .f = 0 },
        .{ .n = 4, .f = 1 }, .{ .n = 7, .f = 2 },
    };
    for (cases) |case| {
        var safe_tip, var validators = try setup(case.n);
        defer release(&safe_tip, &validators);
        try testing.expectEqual(h(0), safe_tip.get());
        if (case.f == 0) {
            try testing.expectEqual(0, safe_tip.hi.count());
            try testing.expectEqual(1, safe_tip.lo.count());
            // With no faults possible, an update moves the safe tip at once.
            _ = safe_tip.update(validators.items[0], h(10));
            try testing.expectEqual(h(10), safe_tip.get());
        } else {
            try testing.expectEqual(1, safe_tip.hi.count());
            try testing.expectEqual(1, safe_tip.lo.count());
            try testing.expectEqual(case.f, safe_tip.hi.get(h(0)).?);
            try testing.expectEqual(case.n - case.f, safe_tip.lo.get(h(0)).?);
        }
    }
}

test "counts inc and dec" {
    var counts = try Counts.init(gpa, 4);
    defer counts.deinit(gpa);
    counts.inc(h(10));
    try testing.expectEqual(1, counts.get(h(10)).?);
    counts.inc(h(10));
    try testing.expectEqual(2, counts.get(h(10)).?);
    counts.inc(h(30));
    counts.inc(h(20));
    try testing.expectEqual(1, counts.get(h(20)).?);
    try testing.expectEqual(3, counts.count());
    try testing.expectEqual(h(10), counts.min().?);
    try testing.expectEqual(h(30), counts.max().?);
    counts.dec(h(10));
    try testing.expectEqual(1, counts.get(h(10)).?);
    counts.dec(h(10));
    try testing.expectEqual(null, counts.get(h(10)));
    try testing.expectEqual(2, counts.count());
    counts.dec(h(20));
    counts.dec(h(30));
    try testing.expectEqual(0, counts.count());
    try testing.expectEqual(null, counts.max());
}

test "reconcile removing a validator in lo" {
    var safe_tip, var validators = try setup_with_tips(7, &.{ 5, 10, 15, 20, 25, 30, 35 });
    defer release(&safe_tip, &validators);
    try testing.expectEqual(h(25), safe_tip.get());
    const v = validators.items;
    // Replace the validator with tip 10 (in lo).
    try reconcile(&safe_tip, &.{ v[0], key(8), v[2], v[3], v[4], v[5], v[6] });
    try testing.expectEqual(h(25), safe_tip.get());
    try testing.expectEqual(h(0), safe_tip.tip(key(8)).?);
}

test "reconcile removing a validator in hi" {
    var safe_tip, var validators = try setup_with_tips(7, &.{ 5, 10, 15, 20, 25, 30, 35 });
    defer release(&safe_tip, &validators);
    const v = validators.items;
    // Replace the validator with tip 30 (in hi): the largest lo value drops from 25 to 20.
    try reconcile(&safe_tip, &.{ v[0], v[1], v[2], v[3], v[4], key(8), v[6] });
    try testing.expectEqual(h(20), safe_tip.get());
    try testing.expectEqual(h(0), safe_tip.tip(key(8)).?);
}

test "reconcile rebalances the heaps" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 10, 20, 30, 0 });
    defer release(&safe_tip, &validators);
    try testing.expectEqual(h(20), safe_tip.get());
    const v = validators.items;
    try reconcile(&safe_tip, &.{ v[0], v[1], key(8), v[3] });
    try testing.expectEqual(h(0), safe_tip.tip(key(8)).?);
    // Tips [10, 20, 0, 0]: lo holds [0, 0, 10].
    try testing.expectEqual(h(10), safe_tip.get());
}

test "reconcile case 1: a zero tip leaves the heaps unchanged" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 0, 10, 20, 30 });
    defer release(&safe_tip, &validators);
    var hi = try Counts.init(gpa, 4);
    defer hi.deinit(gpa);
    var lo = try Counts.init(gpa, 4);
    defer lo.deinit(gpa);
    @memcpy(hi.entries[0..safe_tip.hi.len], safe_tip.hi.entries[0..safe_tip.hi.len]);
    hi.len = safe_tip.hi.len;
    @memcpy(lo.entries[0..safe_tip.lo.len], safe_tip.lo.entries[0..safe_tip.lo.len]);
    lo.len = safe_tip.lo.len;
    const v = validators.items;
    try reconcile(&safe_tip, &.{ key(8), v[1], v[2], v[3] });
    try testing.expect(hi.eql(&safe_tip.hi));
    try testing.expect(lo.eql(&safe_tip.lo));
    try testing.expectEqual(h(20), safe_tip.get());
}

test "reconcile case 2: the value stays in lo" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 5, 15, 25, 30 });
    defer release(&safe_tip, &validators);
    try testing.expectEqual(h(25), safe_tip.get());
    for ([_]u64{ 5, 15, 25 }) |value| try testing.expect(safe_tip.lo.contains(h(value)));
    try testing.expect(safe_tip.hi.contains(h(30)));
    const v = validators.items;
    try reconcile(&safe_tip, &.{ key(8), v[1], v[2], v[3] });
    try testing.expect(safe_tip.lo.contains(h(0)));
    try testing.expect(!safe_tip.lo.contains(h(5)));
    try testing.expectEqual(h(25), safe_tip.get());
}

test "reconcile case 3: the value stays in hi" {
    var safe_tip, var validators = try setup_with_tips(7, &.{ 0, 0, 0, 0, 0, 10, 20 });
    defer release(&safe_tip, &validators);
    try testing.expectEqual(h(0), safe_tip.get());
    const v = validators.items;
    // Remove the validator with tip 10 (in hi): the largest lo value is 0, so 0 stays in hi.
    try reconcile(&safe_tip, &.{ v[0], v[1], v[2], v[3], v[4], key(8), v[6] });
    try testing.expect(safe_tip.hi.contains(h(0)));
    try testing.expectEqual(h(0), safe_tip.get());
}

test "reconcile case 4: the value moves from hi to lo" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 10, 20, 30, 40 });
    defer release(&safe_tip, &validators);
    try testing.expectEqual(h(30), safe_tip.get());
    const v = validators.items;
    try reconcile(&safe_tip, &.{ v[0], v[1], v[2], key(8) });
    // The 0 goes to lo, and the largest lo value (30) moves to hi.
    try testing.expect(safe_tip.hi.contains(h(30)));
    try testing.expect(safe_tip.lo.contains(h(0)));
    try testing.expectEqual(h(20), safe_tip.get());
}

test "update case 2: the value stays in lo" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 5, 15, 25, 35 });
    defer release(&safe_tip, &validators);
    try testing.expect(safe_tip.lo.contains(h(5)));
    _ = safe_tip.update(validators.items[0], h(10));
    try testing.expect(safe_tip.lo.contains(h(10)));
    try testing.expect(!safe_tip.lo.contains(h(5)));
    try testing.expectEqual(h(25), safe_tip.get());
}

test "update case 3: the value moves from lo to hi" {
    var safe_tip, var validators = try setup_with_tips(4, &.{ 5, 15, 25, 35 });
    defer release(&safe_tip, &validators);
    _ = safe_tip.update(validators.items[0], h(40));
    try testing.expect(safe_tip.hi.contains(h(40)));
    try testing.expect(safe_tip.lo.contains(h(35)));
    try testing.expectEqual(h(35), safe_tip.get());
}

test "update edge cases" {
    var safe_tip, var validators = try setup_with_tips(7, &.{ 0, 0, 0, 0, 0, 10, 20 });
    defer release(&safe_tip, &validators);
    _ = safe_tip.update(validators.items[0], h(100));
    try testing.expect(safe_tip.hi.contains(h(100)));
    try testing.expectEqual(h(10), safe_tip.get());
}

/// The safe tip of `tips` computed by sorting: the `n - f`th lowest.
fn reference(tips: []const u64, f: usize) u64 {
    var sorted: [16]u64 = undefined;
    @memcpy(sorted[0..tips.len], tips);
    std.mem.sort(u64, sorted[0..tips.len], {}, std.sort.asc(u64));
    return sorted[tips.len - f - 1];
}

test "seeded fuzz against a sorting reference" {
    var prng = std.Random.DefaultPrng.init(0x5afe_71b);
    const random = prng.random();
    for (0..64) |_| {
        const n = random.intRangeAtMost(u64, 1, 10);
        var safe_tip, var validators = try setup(n);
        defer release(&safe_tip, &validators);
        const f = validators.max_faults(utils.N3f1);
        var tips: [16]u64 = @splat(0);
        for (0..200) |_| {
            const index = random.uintLessThan(usize, n);
            const value = random.uintLessThan(u64, 50);
            const old = safe_tip.update(validators.items[index], h(value));
            try testing.expectEqual(value > tips[index], old != null);
            tips[index] = @max(tips[index], value);
            try testing.expectEqual(reference(tips[0..n], f), safe_tip.get().get());
        }
    }
}
