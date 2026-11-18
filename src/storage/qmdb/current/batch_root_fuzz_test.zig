//! The `qmdb_current_unordered_batch_root` and `qmdb_current_ordered_batch_root` fuzz targets
//! (commonware `storage/fuzz`): a collision-heavy key space, a committed seed batch, then one
//! of three chain schedules whose pending tip must give the same canonical and ops roots as
//! the same writes rebuilt on the committed database. Every batch walks its floor under a
//! drawn `fuzz_floor.Plan`, checked by the floor oracle against a model of the live state,
//! and rebuilt batches must make the same floor decisions. The run ends by committing,
//! reopening, and comparing the roots, floor, and every key with the model.
//!
//! Ordered databases also check strict, non-wrapping neighbors of every key in the space
//! (and one above it) against the model, on every batch as it is merkleized, on the pending
//! and rebuilt child once its parent is committed, and on the database.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const fuzz_floor = @import("../fuzz_floor.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;

const collision_groups = 4;
const key_space = 32;
const max_initial_writes = 16;
const max_mutations = 16;
/// More decisions than the key space holds live keys.
const record_capacity = collision_groups * key_space;
const Recorder = fuzz_floor.Recorder(Digest, Digest, record_capacity);
const Model = Recorder.Model;

/// A scripted `replace(seed)` writes `[seed] ** 32`, as commonware's targets do.
fn replacement(seed: u8) Digest {
    return .{ .bytes = @splat(seed) };
}

const Schedule = enum { pending_parent, pending_chain, dropped_prefix_chain };

/// A write, or a delete when `value` is null.
const Mutation = struct { key: [32]u8, value: ?[32]u8 };

const Input = struct {
    schedule: Schedule,
    plans: [4]fuzz_floor.Plan,
    initial: []const Mutation,
    parent: []const Mutation,
    child: []const Mutation,
    grandchild: []const Mutation,
};

fn key_bytes(prefix: u8, suffix: u64) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[0] = prefix % collision_groups;
    std.mem.writeInt(u64, bytes[24..32], suffix % key_space, .big);
    assert(bytes[0] < collision_groups);
    return bytes;
}

fn decode_mutations(
    reader: *fuzz_bytes.Reader,
    out: []Mutation,
    min: usize,
    writes_only: bool,
) []const Mutation {
    assert(min <= out.len);
    const len = min + @as(usize, @intCast(reader.below(out.len - min + 1)));
    assert(len <= out.len);
    for (out[0..len]) |*m| {
        const write = writes_only or reader.boolean();
        const prefix = reader.int(u8);
        m.key = key_bytes(prefix, reader.int(u64));
        m.value = null;
        if (write) {
            var value: [32]u8 = undefined;
            for (&value) |*b| b.* = reader.int(u8);
            m.value = value;
        }
    }
    return out[0..len];
}

const Buffers = struct {
    initial: [max_initial_writes]Mutation = undefined,
    parent: [max_mutations]Mutation = undefined,
    child: [max_mutations]Mutation = undefined,
    grandchild: [max_mutations]Mutation = undefined,
};

fn decode(reader: *fuzz_bytes.Reader, buffers: *Buffers) Input {
    const schedule: Schedule = @fromBackingInt(@intCast(reader.below(3)));
    var plans: [4]fuzz_floor.Plan = undefined;
    for (&plans) |*plan| plan.* = .decode(reader);
    const input: Input = .{
        .schedule = schedule,
        .plans = plans,
        .initial = decode_mutations(reader, &buffers.initial, 0, true),
        .parent = decode_mutations(reader, &buffers.parent, 1, false),
        .child = decode_mutations(reader, &buffers.child, 1, false),
        .grandchild = decode_mutations(reader, &buffers.grandchild, 1, false),
    };
    assert(input.parent.len > 0 and input.grandchild.len > 0);
    return input;
}

fn apply_to_model(model: *Model, mutations: []const Mutation) !void {
    for (mutations) |m| {
        if (m.value) |bytes| {
            try model.put(gpa, .{ .bytes = m.key }, .{ .bytes = bytes });
        } else {
            _ = model.remove(.{ .bytes = m.key });
        }
    }
}

fn Driver(comptime D: type) type {
    return struct {
        const Batch = D.MerkleizedBatch;

        /// A new batch on `parent` (or the database) with `mutations` written.
        fn written(db: *D, parent: ?*Batch, mutations: []const Mutation) !D.UnmerkleizedBatch {
            comptime assert(D.Key == Digest and D.Value == Digest);
            var batch = if (parent) |p| p.new_batch() else try db.new_batch();
            errdefer batch.deinit();
            for (mutations) |m| {
                const value: ?D.Value = if (m.value) |v| .{ .bytes = v } else null;
                try batch.write(.{ .bytes = m.key }, value);
            }
            assert(batch.inner != null);
            return batch;
        }

        /// Merkleizes `mutations` on `parent` under `plan`, advances `model` by the writes,
        /// checks the floor walk against it, and replays the walk's decisions into it.
        fn merkleize(
            db: *D,
            parent: ?*Batch,
            mutations: []const Mutation,
            plan: fuzz_floor.Plan,
            model: *Model,
            recorder: *Recorder,
        ) !*Batch {
            const inherited =
                if (parent) |p| p.bounds().inactivity_floor else db.inactivity_floor();
            var batch = try written(db, parent, mutations);
            try apply_to_model(model, mutations);
            recorder.* = .init(plan, &replacement);
            const merkleized = batch.merkleize_with(db, recorder) catch |err| {
                batch.deinit();
                return err;
            };
            errdefer merkleized.release();
            const bounds = merkleized.bounds();
            assert(bounds.tip.size > 0);
            try recorder.check(gpa, model, inherited, bounds.inactivity_floor, bounds.tip.size - 1);
            try expect_neighbors(db, merkleized, model);
            return merkleized;
        }

        /// Merkleizes `mutations` on `parent`, rebuilding a batch `original` walked along
        /// another path, and checks the walk makes the same decisions.
        fn rebuild(
            db: *D,
            parent: ?*Batch,
            mutations: []const Mutation,
            plan: fuzz_floor.Plan,
            original: *const Recorder,
        ) !*Batch {
            var batch = try written(db, parent, mutations);
            var recorder: Recorder = .init(plan, &replacement);
            const merkleized = batch.merkleize_with(db, &recorder) catch |err| {
                batch.deinit();
                return err;
            };
            errdefer merkleized.release();
            try recorder.expect_same_walk(original);
            assert(merkleized.bounds().tip.size > 0);
            return merkleized;
        }

        /// The pending and rebuilt tips agree, and applying the pending one gives the
        /// rebuilt roots.
        fn expect_same_tip(db: *D, pending: *Batch, rebuilt: *Batch) !void {
            try testing.expect(pending.root().eql(rebuilt.root()));
            try testing.expect(pending.ops_root().eql(rebuilt.ops_root()));
            try db.apply_batch(pending);
            try testing.expect(db.root().eql(rebuilt.root()));
            try testing.expect(db.ops_root().eql(rebuilt.ops_root()));
        }

        /// Builds the child while the parent is pending, then rebuilds it on the committed
        /// parent.
        fn pending_parent(db: *D, input: *const Input, model: *Model) !void {
            var walk: Recorder = undefined;
            const parent = try merkleize(db, null, input.parent, input.plans[1], model, &walk);
            defer parent.release();
            const child = try merkleize(db, parent, input.child, input.plans[2], model, &walk);
            defer child.release();
            try db.apply_batch(parent);
            try db.commit();
            const rebuilt = try rebuild(db, null, input.child, input.plans[2], &walk);
            defer rebuilt.release();
            try expect_neighbors(db, rebuilt, model);
            try expect_neighbors(db, child, model);
            try expect_same_tip(db, child, rebuilt);
        }

        /// Builds parent, child, and grandchild with two ancestors pending, then rebuilds the
        /// grandchild on the committed prefix.
        fn pending_chain(db: *D, input: *const Input, model: *Model) !void {
            var walk: Recorder = undefined;
            const parent = try merkleize(db, null, input.parent, input.plans[1], model, &walk);
            defer parent.release();
            const child = try merkleize(db, parent, input.child, input.plans[2], model, &walk);
            defer child.release();
            const grandchild =
                try merkleize(db, child, input.grandchild, input.plans[3], model, &walk);
            defer grandchild.release();
            try db.apply_batch(parent);
            try db.commit();
            try db.apply_batch(child);
            try db.commit();
            const rebuilt = try rebuild(db, null, input.grandchild, input.plans[3], &walk);
            defer rebuilt.release();
            try expect_same_tip(db, grandchild, rebuilt);
        }

        /// Builds A, B, and C (C repeats A's mutations), commits and drops A, merkleizes D on
        /// C, then rebuilds B, C, and D on the committed A.
        fn dropped_prefix_chain(db: *D, input: *const Input, model: *Model) !void {
            var a_walk: Recorder = undefined;
            var walks: [3]Recorder = undefined;
            const a = try merkleize(db, null, input.parent, input.plans[1], model, &a_walk);
            const b = b: {
                errdefer a.release();
                break :b try merkleize(db, a, input.child, input.plans[2], model, &walks[0]);
            };
            defer b.release();
            const c = c: {
                errdefer a.release();
                break :c try merkleize(db, b, input.parent, input.plans[1], model, &walks[1]);
            };
            defer c.release();
            // Applying A releases its last reference; B keeps only a weak parent.
            db.apply_batch(a) catch |err| {
                a.release();
                return err;
            };
            a.release();
            try db.commit();
            const d = try merkleize(db, c, input.grandchild, input.plans[3], model, &walks[2]);
            defer d.release();
            const rebuilt_b = try rebuild(db, null, input.child, input.plans[2], &walks[0]);
            defer rebuilt_b.release();
            const rebuilt_c = try rebuild(db, rebuilt_b, input.parent, input.plans[1], &walks[1]);
            defer rebuilt_c.release();
            const rebuilt_d =
                try rebuild(db, rebuilt_c, input.grandchild, input.plans[3], &walks[2]);
            defer rebuilt_d.release();
            try expect_same_tip(db, d, rebuilt_d);
        }

        fn expect_matches_model(db: *D, model: *const Model) !void {
            try testing.expectEqual(model.count() == 0, db.is_empty());
            for (0..collision_groups) |prefix| for (0..key_space) |suffix| {
                const k = key_bytes(@intCast(prefix), suffix);
                const got = try db.get(&.{ .bytes = k });
                const expected = model.get(.{ .bytes = k });
                try testing.expectEqual(expected == null, got == null);
                if (got) |v| try testing.expectEqualSlices(u8, &expected.?.bytes, &v.bytes);
            };
        }

        fn neighbor(
            comptime side: enum { prev, next },
            db: *D,
            batch: ?*const Batch,
            query: *const D.Key,
        ) !?D.Key {
            if (batch) |b| {
                return if (side == .prev) b.get_prev_key(query, db) else b.get_next_key(query, db);
            }
            return if (side == .prev) db.get_prev_key(query) else db.get_next_key(query);
        }

        /// The strict, non-wrapping neighbors after `batch` (or of the database) match the
        /// model's, for every key of the space and one above it. Unordered databases have none.
        fn expect_neighbors(db: *D, batch: ?*const Batch, model: *const Model) !void {
            if (comptime !D.Any.Update.siblings) return;
            var queries: [record_capacity + 1][32]u8 = undefined;
            for (0..collision_groups) |prefix| for (0..key_space) |suffix| {
                queries[prefix * key_space + suffix] = key_bytes(@intCast(prefix), suffix);
            };
            queries[record_capacity] = @splat(0xff);
            for (&queries) |*q| {
                var prev: ?[32]u8 = null;
                var next: ?[32]u8 = null;
                var keys = model.keyIterator();
                while (keys.next()) |entry| {
                    const k = entry.bytes;
                    const order = std.mem.order(u8, &k, q);
                    if (order == .lt and (prev == null or std.mem.order(u8, &k, &prev.?) == .gt))
                        prev = k;
                    if (order == .gt and (next == null or std.mem.order(u8, &k, &next.?) == .lt))
                        next = k;
                }
                const query: D.Key = .{ .bytes = q.* };
                const got_prev = try neighbor(.prev, db, batch, &query);
                const got_next = try neighbor(.next, db, batch, &query);
                try testing.expectEqual(prev == null, got_prev == null);
                try testing.expectEqual(next == null, got_next == null);
                if (prev) |p| try testing.expectEqualSlices(u8, &p, &got_prev.?.bytes);
                if (next) |n| try testing.expectEqualSlices(u8, &n, &got_next.?.bytes);
            }
        }

        /// Commits, reopens, and checks that recovery rebuilds the same roots, floor, and live
        /// state, including the floor walks' rewrites and evictions.
        fn expect_recovers(harness: *support.Harness, db: *D, model: *const Model) !void {
            try db.commit();
            try expect_matches_model(db, model);
            const root = db.root();
            const ops_root = db.ops_root();
            const floor = db.inactivity_floor();
            db.deinit();
            db.* = try harness.open(D, null);
            try testing.expect(db.root().eql(root));
            try testing.expect(db.ops_root().eql(ops_root));
            try testing.expectEqual(floor, db.inactivity_floor());
            try expect_matches_model(db, model);
            try expect_neighbors(db, null, model);
        }

        fn run(input: *const Input) !void {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open(D, null);
            defer db.deinit();
            var model: Model = .empty;
            defer model.deinit(gpa);
            var walk: Recorder = undefined;
            const initial = try merkleize(&db, null, input.initial, input.plans[0], &model, &walk);
            defer initial.release();
            try db.apply_batch(initial);
            try db.commit();
            try expect_neighbors(&db, null, &model);
            switch (input.schedule) {
                .pending_parent => try pending_parent(&db, input, &model),
                .pending_chain => try pending_chain(&db, input, &model),
                .dropped_prefix_chain => try dropped_prefix_chain(&db, input, &model),
            }
            try expect_neighbors(&db, null, &model);
            try expect_recovers(&harness, &db, &model);
        }
    };
}

fn run_unordered(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var buffers: Buffers = .{};
    const input = decode(&reader, &buffers);
    try Driver(support.UnorderedFixed(merkle.mmr.Family)).run(&input);
    try Driver(support.UnorderedFixed(merkle.mmb.Family)).run(&input);
}

fn run_ordered(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var buffers: Buffers = .{};
    const input = decode(&reader, &buffers);
    try Driver(support.OrderedFixed(merkle.mmr.Family)).run(&input);
    try Driver(support.OrderedFixed(merkle.mmb.Family)).run(&input);
}

const input_max = 2048;

test "fuzz qmdb_current_unordered_batch_root (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x63756272, 24, run_unordered);
}

test "fuzz qmdb_current_unordered_batch_root" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run_unordered), .{});
}

test "fuzz qmdb_current_ordered_batch_root (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x636f6272, 24, run_ordered);
}

test "fuzz qmdb_current_ordered_batch_root" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run_ordered), .{});
}
