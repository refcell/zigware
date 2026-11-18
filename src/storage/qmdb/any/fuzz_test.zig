//! The `qmdb_any_unordered_operations` and `qmdb_any_ordered_operations` fuzz targets
//! (commonware `storage/fuzz`): an any database driven by updates, deletes, commits under a
//! fuzzed floor plan, roots, proofs, reads, and (ordered) spans, neighbors, and arbitrary proofs,
//! under both families. Every commit's floor walk is checked by the floor oracle
//! (`qmdb/fuzz_floor.zig`) against a model of the live keys, which reads must match.
//!
//! Differences from commonware's targets: keys come from a byte seed whose high nibble picks one
//! of 16 `OneCap` buckets (commonware draws raw 32-byte keys under `EightCap`, which rarely
//! collide), values are digests, and a reopen operation checks that the replayed state and
//! root match the model.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const fuzz_floor = @import("../fuzz_floor.zig");
const verify = @import("../verify.zig");
const diff_mod = @import("diff.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Sha256 = support.Sha256;
const Digest = support.Digest;
const Recorder = fuzz_floor.Recorder(Digest, Digest, 256);
const Model = Recorder.Model;

const max_proof_ops = 100;
const max_proof_digests = 8;

const Operation = union(enum) {
    update: struct { key: u8, value: u8 },
    delete: u8,
    commit: fuzz_floor.Plan,
    op_count,
    root,
    proof: struct { start: u64, max_ops: u16 },
    arbitrary_proof: struct {
        start: u64,
        max_ops: u16,
        leaves: u64,
        count: u8,
        digests: [max_proof_digests]u8,
    },
    get: u8,
    get_span: u8,
    get_neighbors: u8,
    reopen,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        return switch (reader.int(u8) % 11) {
            0, 1 => .{ .update = .{ .key = reader.int(u8), .value = reader.int(u8) } },
            2 => .{ .delete = reader.int(u8) },
            3 => .{ .commit = .decode(reader) },
            4 => if (reader.boolean()) .op_count else .root,
            5 => .{ .proof = .{ .start = reader.int(u64), .max_ops = reader.int(u16) } },
            6 => arbitrary: {
                var digests: [max_proof_digests]u8 = undefined;
                for (&digests) |*d| d.* = reader.int(u8);
                break :arbitrary .{ .arbitrary_proof = .{
                    .start = reader.int(u64),
                    .max_ops = reader.int(u16),
                    .leaves = reader.int(u16),
                    .count = reader.int(u8) % (max_proof_digests + 1),
                    .digests = digests,
                } };
            },
            7 => .{ .get = reader.int(u8) },
            8 => .{ .get_span = reader.int(u8) },
            9 => .{ .get_neighbors = reader.int(u8) },
            10 => .reopen,
            else => unreachable, // Proof: `% 11` is in 0..11.
        };
    }
};

/// The key of a seed: its high nibble picks the `OneCap` bucket.
fn key_of(seed: u8) Digest {
    return support.colliding_digest(seed >> 4, seed);
}

fn value_of(seed: u8) Digest {
    return .{ .bytes = @splat(seed) };
}

/// Commonware's replacement value for a scripted `Replace(seed)`.
fn replacement(seed: u8) Digest {
    var bytes: [32]u8 = @splat(seed);
    bytes[0] = 0xff; // Distinct from every `value_of`.
    return .{ .bytes = bytes };
}

fn Driver(comptime D: type) type {
    return struct {
        const Self = @This();
        const ordered = D.Update.siblings;

        harness: support.Harness,
        db: D,
        plan: fuzz_floor.Plan = .proportional,
        writes: std.ArrayList(support.Write) = .empty,
        /// The pending writes' effect: a key's new value, or null for a delete.
        pending: std.AutoHashMapUnmanaged(Digest, ?Digest) = .empty,
        /// The live keys after the last commit.
        committed: Model = .empty,

        fn init(self: *Self) !void {
            self.harness = try .init(gpa);
            errdefer self.harness.deinit();
            self.plan = .proportional;
            self.writes = .empty;
            self.pending = .empty;
            self.committed = .empty;
            self.db = try self.harness.open(D, null);
            assert(self.db.is_empty());
        }

        fn deinit(self: *Self) void {
            self.db.deinit();
            self.writes.deinit(gpa);
            self.pending.deinit(gpa);
            self.committed.deinit(gpa);
            self.harness.deinit();
        }

        fn write(self: *Self, key: Digest, value: ?Digest) !void {
            try self.writes.append(gpa, .{ .key = key, .value = value });
            try self.pending.put(gpa, key, value);
        }

        fn delete(self: *Self, seed: u8) !void {
            const key = key_of(seed);
            if (!ordered) {
                // As commonware's unordered target does, delete only a live key.
                const got = try self.db.get(&key);
                const pending_live = if (self.pending.get(key)) |v| v != null else false;
                if (got == null and !pending_live) return;
            }
            try self.write(key, null);
        }

        /// Merkleizes the pending writes under the current plan, applies and commits them, then
        /// checks the floor walk and replays its decisions into the model.
        fn commit_pending(self: *Self) !void {
            const inherited = self.db.inactivity_floor();
            var policy = Recorder.init(self.plan, &replacement);
            var batch = try self.db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (self.writes.items) |w| try batch.write(w.key, w.value);
                break :merkleized try batch.merkleize_with(&self.db, &policy);
            };
            defer merkleized.release();
            try self.db.apply_batch(merkleized);
            try self.db.commit();
            self.writes.clearRetainingCapacity();
            var it = self.pending.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.*) |v| {
                    try self.committed.put(gpa, entry.key_ptr.*, v);
                } else {
                    _ = self.committed.remove(entry.key_ptr.*);
                }
            }
            self.pending.clearRetainingCapacity();
            const commit = self.db.bounds().end - 1;
            const floor = self.db.inactivity_floor();
            try policy.check(gpa, &self.committed, inherited, floor, commit);
            try testing.expectEqual(self.committed.count() == 0, self.db.is_empty());
        }

        fn get(self: *Self, key: *const Digest) !void {
            const got = try self.db.get(key);
            const want = self.committed.get(key.*);
            try testing.expectEqual(want == null, got == null);
            if (want) |w| try testing.expect(w.eql(got.?));
        }

        fn proof(self: *Self, raw_start: u64, raw_max: u16) !void {
            try self.commit_pending();
            const end = self.db.bounds().end;
            const start = raw_start % end;
            const max_ops = raw_max % max_proof_ops + 1;
            const root = self.db.root();
            var proved = try self.db.proof(start, max_ops);
            defer proved.deinit(gpa);
            const Op = D.Operation;
            try testing.expectEqual(@min(max_ops, end - start), proved.items.len);
            const items = proved.items;
            const p = &proved.proof;
            const ok = try verify.verify(D.Family, Sha256, Op, gpa, p, start, items, &root);
            try testing.expect(ok);
        }

        /// Verifies the database's operations against a proof of arbitrary digests, which must
        /// not misbehave (and is all but certain to fail).
        fn arbitrary_proof(self: *Self, p: @FieldType(Operation, "arbitrary_proof")) !void {
            try self.commit_pending();
            const end = self.db.bounds().end;
            const start = p.start % end;
            var proved = try self.db.proof(start, p.max_ops % max_proof_ops + 1);
            defer proved.deinit(gpa);
            var digests: [max_proof_digests]Digest = undefined;
            for (&digests, p.digests) |*d, seed| d.* = value_of(seed);
            const forged: verify.Proof(D.Family, Sha256) = .{
                .leaves = p.leaves,
                .inactive_peaks = 0,
                .digests = digests[0..p.count],
            };
            const root = self.db.root();
            const Op = D.Operation;
            _ = try verify.verify(D.Family, Sha256, Op, gpa, &forged, start, proved.items, &root);
        }

        /// The span holding `key` is a live key's update linking to its successor (cyclic).
        fn get_span(self: *Self, seed: u8) !void {
            const key = key_of(seed);
            const got = try self.db.get_span(&key);
            try testing.expectEqual(self.db.is_empty(), got == null);
            var span = got orelse return;
            defer span.update.deinit(gpa);
            const live = self.committed.get(span.update.key) orelse
                return error.TestUnexpectedResult; // The span's key is live.
            try testing.expect(live.eql(span.update.value));
            _, const next = self.neighbors(&span.update.key);
            const expected_next = next orelse self.extreme(.lt);
            try testing.expect(expected_next.eql(span.update.next_key));
            // `key` lies in `[span key, next)`, cyclically.
            const at_or_after = diff_mod.order(Digest, &span.update.key, &key) != .gt;
            const before_next = diff_mod.order(Digest, &key, &span.update.next_key) == .lt;
            const wraps = diff_mod.order(Digest, &span.update.next_key, &span.update.key) != .gt;
            const inside = if (wraps) at_or_after or before_next else at_or_after and before_next;
            try testing.expect(inside);
        }

        /// The smallest (`.lt`) or largest (`.gt`) live key; the model is not empty.
        fn extreme(self: *const Self, comptime direction: std.math.Order) Digest {
            var it = self.committed.keyIterator();
            var best = it.next().?.*;
            while (it.next()) |k| {
                if (diff_mod.order(Digest, k, &best) == direction) best = k.*;
            }
            return best;
        }

        /// The model's strict, non-wrapping predecessor and successor of `query`.
        fn neighbors(self: *const Self, query: *const Digest) struct { ?Digest, ?Digest } {
            var prev: ?Digest = null;
            var next: ?Digest = null;
            var it = self.committed.keyIterator();
            while (it.next()) |k| {
                switch (diff_mod.order(Digest, k, query)) {
                    .lt => if (prev == null or diff_mod.order(Digest, k, &prev.?) == .gt) {
                        prev = k.*;
                    },
                    .gt => if (next == null or diff_mod.order(Digest, k, &next.?) == .lt) {
                        next = k.*;
                    },
                    .eq => {},
                }
            }
            return .{ prev, next };
        }

        fn expect_neighbors(self: *Self, query: *const Digest) !void {
            const want_prev, const want_next = self.neighbors(query);
            const prev = try self.db.get_prev_key(query);
            const next = try self.db.get_next_key(query);
            try testing.expectEqual(want_prev == null, prev == null);
            if (want_prev) |w| try testing.expect(w.eql(prev.?));
            try testing.expectEqual(want_next == null, next == null);
            if (want_next) |w| try testing.expect(w.eql(next.?));
        }

        /// Closes and reopens: pending writes are lost, and the replayed state must match.
        fn reopen(self: *Self) !void {
            const root = self.db.root();
            self.writes.clearRetainingCapacity();
            self.pending.clearRetainingCapacity();
            self.db.deinit();
            self.db = try self.harness.open(D, null);
            try testing.expect(self.db.root().eql(root));
            try self.check_all();
        }

        /// Every key of the seed space reads as the model says.
        fn check_all(self: *Self) !void {
            for (0..256) |seed| try self.get(&key_of(@intCast(seed)));
            if (!ordered) return;
            for (0..256) |seed| try self.expect_neighbors(&key_of(@intCast(seed)));
            try self.expect_neighbors(&.{ .bytes = @splat(0) });
            try self.expect_neighbors(&.{ .bytes = @splat(0xff) });
        }

        fn step(self: *Self, op: Operation) !void {
            switch (op) {
                .update => |u| try self.write(key_of(u.key), value_of(u.value)),
                .delete => |seed| try self.delete(seed),
                .commit => |plan| {
                    self.plan = plan;
                    try self.commit_pending();
                },
                .op_count => try testing.expect(self.db.bounds().end > self.db.inactivity_floor()),
                .root => {
                    try self.commit_pending();
                    const head = try self.db.to_batch();
                    defer head.release();
                    try testing.expect(head.root().eql(self.db.root()));
                },
                .proof => |p| try self.proof(p.start, p.max_ops),
                .arbitrary_proof => |p| if (ordered) try self.arbitrary_proof(p),
                .get => |seed| try self.get(&key_of(seed)),
                .get_span => |seed| if (ordered) try self.get_span(seed),
                .get_neighbors => |seed| if (ordered) try self.expect_neighbors(&key_of(seed)),
                .reopen => try self.reopen(),
            }
        }
    };
}

fn run_family(comptime D: type, ops: []const Operation) !void {
    var driver: Driver(D) = undefined;
    try driver.init();
    defer driver.deinit();
    for (ops) |op| try driver.step(op);
    try driver.commit_pending();
    try driver.check_all();
}

fn run_with(comptime Db: fn (type) type, comptime max_operations: usize, bytes: []const u8) !void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var ops: [max_operations]Operation = undefined;
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        ops[count] = Operation.decode(&reader);
    }
    try run_family(Db(merkle.mmr.Family), ops[0..count]);
    try run_family(Db(merkle.mmb.Family), ops[0..count]);
}

fn Unordered(comptime F: type) type {
    return support.UnorderedFixedChunks(F, 64);
}

fn run_unordered(bytes: []const u8) anyerror!void {
    return run_with(Unordered, 50, bytes);
}

/// Commonware's ordered target takes at most 25 operations.
fn run_ordered(bytes: []const u8) anyerror!void {
    return run_with(support.OrderedFixed, 25, bytes);
}

test "fuzz qmdb_any_unordered_operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x616e7955, 32, run_unordered);
}

test "fuzz qmdb_any_unordered_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run_unordered), .{});
}

test "fuzz qmdb_any_ordered_operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x616e794f, 32, run_ordered);
}

test "fuzz qmdb_any_ordered_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run_ordered), .{});
}
