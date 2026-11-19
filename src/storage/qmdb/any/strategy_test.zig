//! `any` on a parallel strategy (commonware's Merkle `strategy`, which `Db::strategy` returns):
//! merkleized batches and batched reads give the same roots and values on Rayon pools of
//! several sizes as on `parallel.sequential`, live and after a reopen with a cold page cache.

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const metrics = @import("runtime").telemetry.metrics;
const merkle = @import("../../merkle/mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const key = support.to_digest;
const val = support.to_val;

const keys = 300;
/// Keys read back: every 5th written key, absent keys past the end, and repeats.
const reads = 72;

/// What a run observed: the root after each commit and the values read back.
const Observed = struct {
    roots: [3]Digest = undefined,
    live: [reads]?Digest = undefined,
    reopened: [reads]?Digest = undefined,
};

fn read_keys() [reads]Digest {
    var out: [reads]Digest = undefined;
    for (&out, 0..) |*k, i| {
        k.* = if (i < 60) key(i * 5) else if (i < 66) key(keys + i) else key(i - 66);
    }
    return out;
}

fn commit_writes(comptime D: type, db: *D, writes: []const support.Write) !void {
    try support.apply_writes(D, db, writes);
    try db.commit();
}

/// Writes every key, then updates a third and deletes a seventh.
fn populate(comptime D: type, db: *D, observed: *Observed) !void {
    var writes: [keys]support.Write = undefined;
    for (&writes, 0..) |*w, i| w.* = .{ .key = key(i), .value = val(i, 1) };
    try commit_writes(D, db, &writes);
    observed.roots[1] = db.root();
    var count: usize = 0;
    var i: usize = 0;
    while (i < keys) : (i += 3) {
        writes[count] = .{ .key = key(i), .value = val(i, 2) };
        count += 1;
    }
    i = 1;
    while (i < keys) : (i += 7) {
        writes[count] = .{ .key = key(i), .value = null };
        count += 1;
    }
    try commit_writes(D, db, writes[0..count]);
    observed.roots[2] = db.root();
}

/// Opens `D` on `harness` with `strategy`, registering its metrics afresh.
fn open(comptime D: type, harness: *support.Harness, strategy: ?parallel.Rayon) !D {
    var cfg = harness.cfg(D);
    cfg.strategy = strategy;
    harness.registry.deinit();
    harness.registry = metrics.Registry.init(gpa);
    const scope = metrics.Scope.init(&harness.registry).child("db");
    return D.init(gpa, harness.storage.interface(), scope, cfg, null);
}

fn run(comptime D: type, strategy: ?parallel.Rayon) !Observed {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var observed: Observed = .{};
    const k = read_keys();
    {
        var db = try open(D, &harness, strategy);
        defer db.deinit();
        observed.roots[0] = db.root();
        try populate(D, &db, &observed);
        try db.get_many(&k, &observed.live);
        try db.sync();
    }
    var reopened = try open(D, &harness, strategy);
    defer reopened.deinit();
    try testing.expect(reopened.root().eql(observed.roots[2]));
    try reopened.get_many(&k, &observed.reopened);
    return observed;
}

fn expect_same(want: *const Observed, got: *const Observed) !void {
    for (want.roots, got.roots) |w, g| try testing.expect(w.eql(g));
    for (want.live, got.live, want.reopened, got.reopened) |wl, gl, wr, gr| {
        for ([_]?Digest{ wl, wr }, [_]?Digest{ gl, gr }) |w, g| {
            try testing.expectEqual(w == null, g == null);
            if (w) |value| try testing.expect(value.eql(g.?));
        }
    }
}

fn check(comptime D: type) !void {
    const want = try run(D, null);
    // The serial run read back the written, updated, and deleted keys as expected.
    try testing.expect(want.live[0].?.eql(val(0, 2))); // Key 0 was updated.
    try testing.expect(want.live[1].?.eql(val(5, 1))); // Key 5 was not touched.
    try testing.expect(want.live[60] == null); // Past the written keys.
    try testing.expect(want.live[67] == null); // Key 1 was deleted.
    for ([_]u32{ 1, 3, 4 }) |threads| {
        const pool = try parallel.ThreadPool.create(gpa, testing.io, .{ .threads = threads });
        defer pool.destroy();
        const strategy = parallel.Rayon.init(pool).with_parallelism(threads + 1);
        const got = try run(D, strategy);
        try expect_same(&want, &got);
    }
}

test "any on a strategy: unordered variable values match sequential on every pool" {
    try check(support.UnorderedVariable(merkle.mmr.Family));
}

test "any on a strategy: ordered fixed values match sequential on every pool" {
    try check(support.OrderedFixed(merkle.mmb.Family));
}
