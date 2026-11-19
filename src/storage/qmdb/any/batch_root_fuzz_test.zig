//! The `qmdb_any_unordered_batch_root` and `qmdb_any_ordered_batch_root` fuzz targets
//! (commonware `storage/fuzz`): chains of merkleized batches built while their ancestors are
//! pending, or after an applied ancestor was dropped, must have the same roots and floor walks
//! as the same batches rebuilt from the committed state. Every walk is checked by the floor
//! oracle, and the final state must survive a reopen with the same root, floor, and keys.
//!
//! Differences from commonware's targets: values are 32 copies of a drawn byte, and the
//! ordered variant also checks each pending batch's neighbor lookups against the model.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const fuzz_floor = @import("../fuzz_floor.zig");
const diff_mod = @import("diff.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const Recorder = fuzz_floor.Recorder(Digest, Digest, 256);
const Plan = fuzz_floor.Plan;
const Muts = []const Mutation;
const Model = Recorder.Model;

const collision_groups = 4;
const key_space = 32;
const max_initial_writes = 16;
const max_mutations = 16;

const Schedule = enum { pending_parent, dropped_committed_prefix, pending_chain, dropped_chain };

/// A write of a key (a collision group and a suffix), or a delete when `value` is null.
const Mutation = struct { prefix: u8, suffix: u8, value: ?u8 };

const Input = struct {
    schedule: Schedule,
    plans: [4]fuzz_floor.Plan,
    initial: []const Mutation,
    parent: []const Mutation,
    child: []const Mutation,
    grandchild: []const Mutation,
};

fn key_of(prefix: u8, suffix: u8) Digest {
    return support.colliding_digest(prefix % collision_groups, suffix % key_space);
}

fn value_of(byte: u8) Digest {
    return .{ .bytes = @splat(byte) };
}

fn replacement(seed: u8) Digest {
    var bytes: [32]u8 = @splat(seed);
    bytes[0] = 0xff;
    bytes[1] = 0x00; // Distinct from every `value_of`.
    return .{ .bytes = bytes };
}

fn decode_mutations(
    reader: *fuzz_bytes.Reader,
    out: []Mutation,
    min: usize,
    writes: bool,
) []Mutation {
    const len = min + reader.below(out.len - min + 1);
    for (out[0..len]) |*m| {
        const prefix = reader.int(u8);
        const suffix = reader.int(u8);
        const is_write = writes or reader.boolean();
        const v: ?u8 = if (is_write) reader.int(u8) else null;
        m.* = .{ .prefix = prefix, .suffix = suffix, .value = v };
    }
    return out[0..len];
}

fn apply_to_model(model: *Model, mutations: []const Mutation) !void {
    for (mutations) |m| {
        const k = key_of(m.prefix, m.suffix);
        if (m.value) |v| try model.put(gpa, k, value_of(v)) else _ = model.remove(k);
    }
}

fn Driver(comptime D: type) type {
    return struct {
        const Self = @This();
        const M = D.MerkleizedBatch;
        const U = D.UnmerkleizedBatch;

        harness: support.Harness,
        db: D,
        model: Model = .empty,

        /// `batch` with `mutations` written; consumes `batch`, also on error.
        fn with(batch: U, mutations: []const Mutation) !U {
            var b = batch;
            errdefer b.deinit();
            for (mutations) |m| {
                const v: ?Digest = if (m.value) |byte| value_of(byte) else null;
                try b.write(key_of(m.prefix, m.suffix), v);
            }
            return b;
        }

        /// Merkleizes `batch` (consumed) under `plan` from `inherited`, checks its walk against
        /// the model advanced by `mutations`, and replays the walk's decisions into it.
        fn merkleize(
            self: *Self,
            batch: U,
            mutations: []const Mutation,
            inherited: u64,
            plan: fuzz_floor.Plan,
            walk: ?*Recorder,
        ) !*M {
            var b = try with(batch, mutations);
            try apply_to_model(&self.model, mutations);
            var policy = Recorder.init(plan, &replacement);
            const m = b.merkleize_with(&self.db, &policy) catch |err| {
                b.deinit();
                return err;
            };
            errdefer m.release();
            const bounds = m.bounds;
            const commit = bounds.tip.size - 1;
            try policy.check(gpa, &self.model, inherited, bounds.inactivity_floor, commit);
            if (comptime D.Update.siblings) try self.expect_neighbors(m);
            if (walk) |w| w.* = policy;
            return m;
        }

        /// Merkleizes `batch` (consumed), the batch `original` walked along another path, and
        /// checks that it makes the same decisions.
        fn rebuild(
            self: *Self,
            batch: U,
            mutations: []const Mutation,
            plan: fuzz_floor.Plan,
            original: *const Recorder,
        ) !*M {
            var b = try with(batch, mutations);
            var policy = Recorder.init(plan, &replacement);
            const m = b.merkleize_with(&self.db, &policy) catch |err| {
                b.deinit();
                return err;
            };
            errdefer m.release();
            try policy.expect_same_walk(original);
            return m;
        }

        /// `merkleize` of `mutations` on the database.
        fn on_db(self: *Self, mutations: Muts, plan: Plan, walk: ?*Recorder) !*M {
            const floor = self.db.inactivity_floor();
            return self.merkleize(try self.db.new_batch(), mutations, floor, plan, walk);
        }

        /// `merkleize` of `mutations` on `parent`.
        fn on(self: *Self, parent: *M, mutations: Muts, plan: Plan, walk: ?*Recorder) !*M {
            const floor = parent.bounds.inactivity_floor;
            return self.merkleize(parent.new_batch(), mutations, floor, plan, walk);
        }

        /// `rebuild` of `mutations` on the database, or on `parent`.
        fn re(self: *Self, parent: ?*M, mutations: Muts, plan: Plan, walk: *const Recorder) !*M {
            const batch = if (parent) |p| p.new_batch() else try self.db.new_batch();
            return self.rebuild(batch, mutations, plan, walk);
        }

        /// The ordered batch's neighbor lookups match the model, which is its view.
        fn expect_neighbors(self: *Self, batch: *M) !void {
            for (0..collision_groups) |prefix| {
                for (0..key_space + 1) |suffix| {
                    const probe = key_of(@intCast(prefix), @intCast(suffix));
                    var prev: ?Digest = null;
                    var next: ?Digest = null;
                    var it = self.model.keyIterator();
                    while (it.next()) |k| switch (diff_mod.order(Digest, k, &probe)) {
                        .lt => if (prev == null or diff_mod.order(Digest, k, &prev.?) == .gt) {
                            prev = k.*;
                        },
                        .gt => if (next == null or diff_mod.order(Digest, k, &next.?) == .lt) {
                            next = k.*;
                        },
                        .eq => {},
                    };
                    try expect_key(next, try batch.get_next_key(&probe, &self.db));
                    try expect_key(prev, try batch.get_prev_key(&probe, &self.db));
                }
            }
        }

        fn expect_key(want: ?Digest, got: ?Digest) !void {
            try testing.expectEqual(want == null, got == null);
            if (want) |w| try testing.expect(w.eql(got.?));
        }

        fn apply(self: *Self, batch: *M) !void {
            try self.db.apply_batch(batch);
            try self.db.commit();
        }

        /// Every key of the mutation space reads as the model says.
        fn expect_model(self: *Self) !void {
            try testing.expectEqual(self.model.count() == 0, self.db.is_empty());
            for (0..collision_groups) |prefix| {
                for (0..key_space) |suffix| {
                    const k = key_of(@intCast(prefix), @intCast(suffix));
                    const got = try self.db.get(&k);
                    const want = self.model.get(k);
                    try testing.expectEqual(want == null, got == null);
                    if (want) |w| try testing.expect(w.eql(got.?));
                }
            }
        }

        /// Commits, reopens, and checks that recovery rebuilds the root, floor, and keys.
        fn expect_recovers(self: *Self) !void {
            try self.db.commit();
            try self.expect_model();
            const root = self.db.root();
            const floor = self.db.inactivity_floor();
            self.db.deinit();
            self.db = try self.harness.open(D, null);
            try testing.expect(self.db.root().eql(root));
            try testing.expectEqual(floor, self.db.inactivity_floor());
            try self.expect_model();
        }

        /// Builds the parent, then the child while the parent is pending; the child rebuilt
        /// from the committed parent must have the same root.
        fn pending_parent(self: *Self, in: *const Input) !void {
            const parent = try self.on_db(in.parent, in.plans[1], null);
            defer parent.release();
            var child_walk: Recorder = undefined;
            const pending = try self.on(parent, in.child, in.plans[2], &child_walk);
            defer pending.release();
            try self.apply(parent);
            const committed = try self.re(null, in.child, in.plans[2], &child_walk);
            defer committed.release();
            try testing.expect(pending.root().eql(committed.root()));
            try self.db.apply_batch(pending);
            try testing.expect(self.db.root().eql(committed.root()));
        }

        /// Builds A -> B, applies and drops A, then merkleizes C on B; the chain rebuilt from
        /// the committed A must have the same root.
        fn dropped_committed_prefix(self: *Self, in: *const Input) !void {
            const a = try self.on_db(in.parent, in.plans[1], null);
            var b_walk: Recorder = undefined;
            const b = b: {
                defer a.release();
                const b = try self.on(a, in.child, in.plans[2], &b_walk);
                errdefer b.release();
                try self.apply(a);
                break :b b;
            };
            defer b.release();
            var c_walk: Recorder = undefined;
            const c = try self.on(b, in.grandchild, in.plans[3], &c_walk);
            defer c.release();
            const rebuilt_b = try self.re(null, in.child, in.plans[2], &b_walk);
            defer rebuilt_b.release();
            const rebuilt_c = try self.re(rebuilt_b, in.grandchild, in.plans[3], &c_walk);
            defer rebuilt_c.release();
            try testing.expect(c.root().eql(rebuilt_c.root()));
            try self.db.apply_batch(c);
            try testing.expect(self.db.root().eql(rebuilt_c.root()));
        }

        /// Builds parent -> child -> grandchild with both ancestors pending; the grandchild
        /// rebuilt from the committed chain must have the same root.
        fn pending_chain(self: *Self, in: *const Input) !void {
            const parent = try self.on_db(in.parent, in.plans[1], null);
            defer parent.release();
            const child = try self.on(parent, in.child, in.plans[2], null);
            defer child.release();
            var walk: Recorder = undefined;
            const pending = try self.on(child, in.grandchild, in.plans[3], &walk);
            defer pending.release();
            try self.apply(parent);
            try self.apply(child);
            const committed = try self.re(null, in.grandchild, in.plans[3], &walk);
            defer committed.release();
            try testing.expect(pending.root().eql(committed.root()));
            try self.db.apply_batch(pending);
            try testing.expect(self.db.root().eql(committed.root()));
        }

        /// Builds A -> B -> C (C reusing the parent mutations), applies and drops A, then
        /// merkleizes D on C; the chain rebuilt from the committed A must have the same root.
        fn dropped_chain(self: *Self, in: *const Input) !void {
            const a = try self.on_db(in.parent, in.plans[1], null);
            var b_walk: Recorder = undefined;
            var c_walk: Recorder = undefined;
            const b, const c = chain: {
                defer a.release();
                const b = try self.on(a, in.child, in.plans[2], &b_walk);
                errdefer b.release();
                const c = try self.on(b, in.parent, in.plans[1], &c_walk);
                errdefer c.release();
                try self.apply(a);
                break :chain .{ b, c };
            };
            defer b.release();
            defer c.release();
            var d_walk: Recorder = undefined;
            const d = try self.on(c, in.grandchild, in.plans[3], &d_walk);
            defer d.release();
            const rebuilt_b = try self.re(null, in.child, in.plans[2], &b_walk);
            defer rebuilt_b.release();
            const rebuilt_c = try self.re(rebuilt_b, in.parent, in.plans[1], &c_walk);
            defer rebuilt_c.release();
            const rebuilt_d = try self.re(rebuilt_c, in.grandchild, in.plans[3], &d_walk);
            defer rebuilt_d.release();
            try testing.expect(d.root().eql(rebuilt_d.root()));
            try self.db.apply_batch(d);
            try testing.expect(self.db.root().eql(rebuilt_d.root()));
        }

        fn run(in: *const Input) !void {
            var self: Self = .{ .harness = try .init(gpa), .db = undefined };
            defer self.harness.deinit();
            self.db = try self.harness.open(D, null);
            defer self.db.deinit();
            defer self.model.deinit(gpa);
            // The committed base state, with collisions under `OneCap`.
            const initial = try self.on_db(in.initial, in.plans[0], null);
            defer initial.release();
            try self.apply(initial);
            switch (in.schedule) {
                .pending_parent => try self.pending_parent(in),
                .dropped_committed_prefix => try self.dropped_committed_prefix(in),
                .pending_chain => try self.pending_chain(in),
                .dropped_chain => try self.dropped_chain(in),
            }
            try self.expect_recovers();
        }
    };
}

fn run_with(comptime Db: fn (type) type, bytes: []const u8) !void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var storage: [4][max_mutations]Mutation = undefined;
    var in: Input = undefined;
    in.schedule = @fromBackingInt(@intCast(reader.int(u8) % 4));
    for (&in.plans) |*p| p.* = .decode(&reader);
    in.initial = decode_mutations(&reader, storage[0][0..max_initial_writes], 0, true);
    in.parent = decode_mutations(&reader, &storage[1], 1, false);
    in.child = decode_mutations(&reader, &storage[2], 1, false);
    in.grandchild = decode_mutations(&reader, &storage[3], 1, false);
    try Driver(Db(merkle.mmr.Family)).run(&in);
    try Driver(Db(merkle.mmb.Family)).run(&in);
}

fn Unordered(comptime F: type) type {
    return support.UnorderedFixedChunks(F, 64);
}

fn run_unordered(bytes: []const u8) anyerror!void {
    return run_with(Unordered, bytes);
}

fn run_ordered(bytes: []const u8) anyerror!void {
    return run_with(support.OrderedFixed, bytes);
}

test "fuzz qmdb_any_unordered_batch_root (seeded)" {
    try fuzz_bytes.seeded(512, 0x62726f55, 32, run_unordered);
}

test "fuzz qmdb_any_unordered_batch_root" {
    try testing.fuzz({}, fuzz_bytes.smith(512, run_unordered), .{});
}

test "fuzz qmdb_any_ordered_batch_root (seeded)" {
    try fuzz_bytes.seeded(512, 0x62726f4f, 32, run_ordered);
}

test "fuzz qmdb_any_ordered_batch_root" {
    try testing.fuzz({}, fuzz_bytes.smith(512, run_ordered), .{});
}

comptime {
    assert(max_initial_writes <= max_mutations);
}
