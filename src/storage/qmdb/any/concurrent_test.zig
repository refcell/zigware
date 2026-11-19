//! Concurrent reads of `any` and `current` databases (commonware shares one behind an
//! `AsyncRwLock`): reader tasks on `std.Io.Threaded` hold read guards and `get`/`get_many`
//! seeded keys through `*const Db`, while the test applies and commits batches of other keys
//! under the write guard (each commit's floor walk moves seeded updates to the tip). A batcher
//! task merkleizes batches against the database under read guards beside them, and prover
//! tasks serve sync proofs from it through a `JournalSource`, verifying each. A page
//! cache of a few pages makes most reads miss, so readers fetch pages of one blob at once.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const any_support = @import("test_support.zig");
const current_support = @import("../current/test_support.zig");
const sync = @import("../sync/mod.zig");
const verify = @import("../verify.zig");

const gpa = testing.allocator;
const io = testing.io;
const Digest = any_support.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

const seeded_keys = 200;
const readers = 3;
const read_rounds = 300;
const write_rounds = 30;
const batch_rounds = 40;
const prove_rounds = 60;
const provers = 2;

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

/// Builds `batch_rounds` batches beside the readers, each under a read guard: overwrites a
/// seeded key, merkleizes against the shared database, and reads the new value and another
/// seeded key back through the batch, counting every mismatch.
fn batcher(comptime D: type) fn (*Shared(D), u64) u32 {
    return struct {
        fn run(lock: *Shared(D), seed: u64) u32 {
            var prng: std.Random.DefaultPrng = .init(seed);
            var failures: u32 = 0;
            for (0..batch_rounds) |_| {
                const i = prng.random().uintLessThan(u64, seeded_keys);
                const other = (i + 1) % seeded_keys;
                var guard = lock.read() catch return failures + 1;
                defer guard.deinit();
                failures += batch_round(D, guard.get(), i, other) catch 1;
            }
            return failures;
        }
    }.run;
}

fn batch_round(comptime D: type, db: *const D, i: u64, other: u64) !u32 {
    assert(i != other);
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try batch.write(any_support.to_digest(i), any_support.to_val(i, 1));
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    var failures: u32 = 0;
    const got = try merkleized.get(&any_support.to_digest(i), db);
    if (got == null or !got.?.eql(any_support.to_val(i, 1))) failures += 1;
    const kept = try merkleized.get(&any_support.to_digest(other), db);
    if (kept == null or !kept.?.eql(any_support.to_val(other, 0))) failures += 1;
    return failures;
}

/// `D`'s `any` database: `D` itself, or the one a `current` database wraps.
fn AnyOf(comptime D: type) type {
    return if (@hasDecl(D, "Any")) D.Any else D;
}

/// Serves `prove_rounds` sync requests through a `JournalSource` under read guards, as glue's
/// `SharedSource` does for peers, checking every proof against the root read under the guard.
fn prover(comptime D: type) fn (*Shared(D), u64) u32 {
    return struct {
        fn run(lock: *Shared(D), seed: u64) u32 {
            var prng: std.Random.DefaultPrng = .init(seed);
            var failures: u32 = 0;
            for (0..prove_rounds) |_| {
                var guard = lock.read() catch return failures + 1;
                defer guard.deinit();
                const db = guard.get();
                const any_db: *const AnyOf(D) = if (comptime @hasDecl(D, "Any")) &db.any else db;
                failures += prove_round(AnyOf(D), any_db, prng.random().int(u64)) catch 1;
            }
            return failures;
        }
    }.run;
}

fn prove_round(comptime A: type, db: *const A, pick: u64) !u32 {
    const source: sync.JournalSource(A.Family, A.Log) = .{ .journal = &db.log };
    const size = db.log.size();
    assert(size > seeded_keys);
    const start = pick % size;
    const request: sync.Request(A.Family) = .{
        .operations = .{ .size = size, .start = start, .max_ops = 16 },
    };
    var served = try source.serve(gpa, request);
    defer served.response.deinit(gpa);
    assert(served.feedback == null);
    const ops = &served.response.operations;
    const root = db.root();
    const Sha256 = any_support.Sha256;
    const proved = ops.operations;
    const Op = A.Operation;
    const valid = try verify.verify(A.Family, Sha256, Op, gpa, &ops.proof, start, proved, &root);
    return @intFromBool(!valid);
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
    // The readers, then one batcher, then the provers.
    var futures: [readers + 1 + provers]std.Io.Future(u32) = undefined;
    var started: usize = 0;
    defer for (futures[0..started]) |*future| {
        _ = future.cancel(io);
    };
    for (&futures, 0..) |*future, index| {
        future.* = if (index < readers)
            try io.concurrent(reader(D), .{ &lock, index + 1 })
        else if (index == readers)
            try io.concurrent(batcher(D), .{ &lock, index + 1 })
        else
            try io.concurrent(prover(D), .{ &lock, index + 1 });
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
