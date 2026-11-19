//! Concurrent reads of `any` and `current` databases (commonware shares one behind an
//! `AsyncRwLock`): reader tasks on `std.Io.Threaded` hold read guards and `get`/`get_many`
//! seeded keys through `*const Db`, while the test applies and commits batches of other keys
//! under the write guard (each commit's floor walk moves seeded updates to the tip). A page
//! cache of a few pages makes most reads miss, so readers fetch pages of one blob at once.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const any_support = @import("test_support.zig");
const current_support = @import("../current/test_support.zig");

const gpa = testing.allocator;
const io = testing.io;
const Digest = any_support.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

const seeded_keys = 200;
const readers = 3;
const read_rounds = 300;
const write_rounds = 30;

fn Shared(comptime D: type) type {
    return utils.sync.UpgradableRwLock(D);
}

/// Reads `read_rounds` random seeded keys (and a `get_many` of 8 every round), counting
/// every value that differs from its seed's.
fn reader(comptime D: type) fn (*Shared(D), u64) u32 {
    return struct {
        fn read(lock: *Shared(D), seed: u64) u32 {
            var prng: std.Random.DefaultPrng = .init(seed);
            var failures: u32 = 0;
            var keys: [8]Digest = undefined;
            var out: [8]?D.Value = undefined;
            for (0..read_rounds) |_| {
                var guard = lock.read() catch return failures + 1;
                defer guard.deinit();
                const db: *const D = guard.get();
                const i = prng.random().uintLessThan(u64, seeded_keys);
                const got = db.get(&any_support.to_digest(i)) catch null;
                if (got == null or !got.?.eql(any_support.to_val(i, 0))) failures += 1;
                for (&keys, 0..) |*key, k| key.* = any_support.to_digest((i + k * 7) % seeded_keys);
                db.get_many(&keys, &out) catch {
                    failures += 1;
                    continue;
                };
                for (out, 0..) |value, k| {
                    const want = any_support.to_val((i + k * 7) % seeded_keys, 0);
                    if (value == null or !value.?.eql(want)) failures += 1;
                }
            }
            return failures;
        }
    }.read;
}

fn write_round(comptime D: type, lock: *Shared(D), round: u64) !void {
    var guard = try lock.write();
    defer guard.deinit();
    var writes: [4]any_support.Write = undefined;
    for (&writes, 0..) |*w, k| w.* = .{
        .key = any_support.to_digest(seeded_keys + round * writes.len + k),
        .value = any_support.to_val(round, k),
    };
    try any_support.apply_writes(D, guard.get(), &writes);
    try guard.get().commit();
}

fn seed_db(comptime D: type, db: *D) !void {
    var writes: [seeded_keys]any_support.Write = undefined;
    for (&writes, 0..) |*w, i| w.* = .{
        .key = any_support.to_digest(i),
        .value = any_support.to_val(i, 0),
    };
    try any_support.apply_writes(D, db, &writes);
    try db.commit();
}

fn run(comptime D: type, db_owned: D) !void {
    var lock: Shared(D) = .init(io, db_owned);
    defer {
        var db = lock.into_inner();
        db.deinit();
    }
    try seed_db(D, &lock.value);
    var futures: [readers]std.Io.Future(u32) = undefined;
    var started: usize = 0;
    defer for (futures[0..started]) |*future| {
        _ = future.cancel(io);
    };
    for (&futures, 0..) |*future, index| {
        future.* = try io.concurrent(reader(D), .{ &lock, index + 1 });
        started += 1;
    }
    for (0..write_rounds) |round| try write_round(D, &lock, round);
    var failures: u32 = 0;
    for (futures[0..started]) |*future| failures += future.await(io);
    started = 0;
    try testing.expectEqual(@as(u32, 0), failures);
}

test "any concurrent readers under a read lock see every seeded value" {
    inline for (.{
        any_support.UnorderedFixed(Mmr),
        any_support.OrderedFixed(Mmb),
        any_support.UnorderedVariable(Mmb),
        any_support.OrderedVariable(Mmr),
    }) |D| {
        var harness = try any_support.Harness.init(gpa);
        defer harness.deinit();
        try run(D, try harness.open(D, null));
    }
}

test "current concurrent readers under a read lock see every seeded value" {
    inline for (.{
        current_support.UnorderedFixed(Mmr),
        current_support.OrderedVariable(Mmb),
    }) |D| {
        var harness = try current_support.Harness.init(gpa);
        defer harness.deinit();
        try run(D, try harness.open(D, null));
    }
}
