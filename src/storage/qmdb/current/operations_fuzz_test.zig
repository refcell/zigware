//! The `qmdb_current_unordered_operations` and `qmdb_current_ordered_operations` fuzz targets
//! (commonware `storage/fuzz`): up to 320 seeded writes, then updates, deletes, reads,
//! commits under drawn floor plans, prunes, size and root checks, range proofs, tampered range
//! proofs, and key-value proofs; ordered databases add spans, exclusion proofs, and
//! neighbors. Every commit's floor walk is checked by `fuzz_floor`'s oracle and replayed into
//! the committed model, and reads, proofs, and the final state must match it.
//!
//! Commonware draws arbitrary 32-byte keys; this port draws them from a 128-key space or the
//! seeded keys, so deletes, rewrites, and proofs hit live keys.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const fuzz_floor = @import("../fuzz_floor.zig");
const proof_mod = @import("proof.zig");
const verification = @import("verification.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Recorder = fuzz_floor.Recorder(Digest, Digest, 512);
const Model = Recorder.Model;
const Pending = std.AutoHashMapUnmanaged(Digest, ?Digest);

const max_operations = 100;
/// Enough seeded writes for at least one pending bitmap chunk.
const max_initial_writes = 320;
const collision_groups = 4;
const key_space = 32;
const max_bad_digests = 4;

fn replacement(seed: u8) Digest {
    return .{ .bytes = @splat(seed) };
}

/// A key of the 128-key space, or (half the time) one of the seeded keys, so reads and
/// proofs hit live keys.
fn draw_key(reader: *fuzz_bytes.Reader) Digest {
    if (reader.boolean()) return seed_write(reader.below(max_initial_writes))[0];
    var bytes: [32]u8 = @splat(0);
    bytes[0] = reader.int(u8) % collision_groups;
    std.mem.writeInt(u64, bytes[24..32], reader.below(key_space), .big);
    assert(bytes[0] < collision_groups);
    return .{ .bytes = bytes };
}

fn draw_digest(reader: *fuzz_bytes.Reader) Digest {
    var bytes: [32]u8 = undefined;
    for (&bytes) |*b| b.* = reader.int(u8);
    return .{ .bytes = bytes };
}

/// Commonware's `generate_seed_kv`.
fn seed_write(i: u64) struct { Digest, Digest } {
    var k: [32]u8 = @splat(0);
    std.mem.writeInt(u64, k[0..8], i, .big);
    var v: [32]u8 = @splat(0);
    std.mem.writeInt(u64, v[24..32], i, .big);
    return .{ .{ .bytes = k }, .{ .bytes = v } };
}

const Tamper = struct {
    start: u64,
    max_ops: u64,
    bad_digests: [max_bad_digests]Digest,
    bad_digest_count: usize,
    bad_pending: ?Digest,
    bad_partial: ?Digest,
    chunk_xor: [32]u8,
};

const Operation = union(enum) {
    update: struct { key: Digest, value: Digest },
    delete: Digest,
    get: Digest,
    commit: fuzz_floor.Plan,
    prune,
    op_count,
    root,
    range_proof: struct { start: u64, max_ops: u64 },
    key_value_proof: Digest,
    arbitrary_proof: Tamper,
    get_span: Digest,
    exclusion_proof: Digest,
    get_neighbors: Digest,

    fn decode(reader: *fuzz_bytes.Reader, ordered: bool) Operation {
        const tag = reader.below(if (ordered) 13 else 10);
        return switch (tag) {
            0 => .{ .update = .{ .key = draw_key(reader), .value = draw_digest(reader) } },
            1 => .{ .delete = draw_key(reader) },
            2 => .{ .get = draw_key(reader) },
            3 => .{ .commit = .decode(reader) },
            4 => .prune,
            5 => .op_count,
            6 => .root,
            7 => .{ .range_proof = .{
                .start = reader.int(u64),
                .max_ops = 1 + reader.below(16),
            } },
            8 => .{ .key_value_proof = draw_key(reader) },
            9 => .{ .arbitrary_proof = decode_tamper(reader) },
            10 => .{ .get_span = draw_key(reader) },
            11 => .{ .exclusion_proof = draw_key(reader) },
            12 => .{ .get_neighbors = draw_key(reader) },
            else => unreachable, // Proof: `below(13)` is in 0..13.
        };
    }

    fn decode_tamper(reader: *fuzz_bytes.Reader) Tamper {
        var tamper: Tamper = .{
            .start = reader.int(u64),
            .max_ops = 1 + reader.below(16),
            .bad_digests = undefined,
            .bad_digest_count = @intCast(reader.below(max_bad_digests + 1)),
            .bad_pending = if (reader.boolean()) draw_digest(reader) else null,
            .bad_partial = if (reader.boolean()) draw_digest(reader) else null,
            .chunk_xor = draw_digest(reader).bytes,
        };
        for (tamper.bad_digests[0..tamper.bad_digest_count]) |*d| d.* = draw_digest(reader);
        assert(tamper.bad_digest_count <= max_bad_digests);
        return tamper;
    }
};

fn Driver(comptime D: type) type {
    return struct {
        const Self = @This();
        const F = D.Family;
        const ordered = D.Any.Update.siblings;

        db: D,
        plan: fuzz_floor.Plan = .proportional,
        committed: Model = .empty,
        pending: Pending = .empty,
        writes: std.ArrayList(struct { key: Digest, value: ?Digest }) = .empty,
        committed_op_count: u64 = 1,

        fn deinit(self: *Self) void {
            self.writes.deinit(gpa);
            self.pending.deinit(gpa);
            self.committed.deinit(gpa);
        }

        fn queue(self: *Self, key: Digest, value: ?Digest) !void {
            try self.writes.append(gpa, .{ .key = key, .value = value });
            try self.pending.put(gpa, key, value);
            assert(self.pending.count() <= self.writes.items.len);
        }

        /// Commits the queued writes under the current plan, checks the floor walk against
        /// the post-write state, and replays its decisions into the committed model.
        fn commit_pending(self: *Self) !void {
            const inherited = self.db.inactivity_floor();
            var batch = try self.db.new_batch();
            var recorder: Recorder = .init(self.plan, &replacement);
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (self.writes.items) |w| try batch.write(w.key, w.value);
                break :merkleized try batch.merkleize_with(&self.db, &recorder);
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
            const end = self.db.bounds().end;
            const floor = self.db.inactivity_floor();
            try recorder.check(gpa, &self.committed, inherited, floor, end - 1);
            self.committed_op_count = end;
        }

        fn expect_get(self: *Self, key: Digest) !void {
            const got = try self.db.get(&key);
            const expected = self.committed.get(key);
            try testing.expectEqual(expected == null, got == null);
            if (got) |g| try testing.expect(g.eql(expected.?));
        }

        fn encode_ops(ranged: *const D.Ranged, out: [][]const u8) ![]const []const u8 {
            assert(ranged.operations.len <= out.len);
            var done: usize = 0;
            errdefer for (out[0..done]) |bytes| gpa.free(bytes);
            for (ranged.operations, 0..) |op, i| {
                out[i] = try codec.encode(D.Operation, gpa, op);
                done += 1;
            }
            return out[0..done];
        }

        fn verify(
            proof: *const @FieldType(D.Ranged, "proof"),
            start: u64,
            ops: []const []const u8,
            chunks: []const [32]u8,
            root: *const Digest,
        ) bool {
            var slices: [16][]const u8 = undefined;
            assert(chunks.len <= slices.len);
            for (chunks, 0..) |*chunk, i| slices[i] = chunk;
            const used = slices[0..chunks.len];
            return verification.verify_range(F, Sha256, proof, start, ops, used, 32, root);
        }

        fn range_proof(self: *Self, start_draw: u64, max_ops: u64) !void {
            try self.commit_pending();
            const root = self.db.root();
            const start = start_draw % self.db.bounds().end;
            if (start < self.db.sync_boundary()) return;
            var ranged = try self.db.range_proof(start, max_ops);
            defer ranged.deinit(gpa);
            var buffer: [16][]const u8 = undefined;
            const ops = try encode_ops(&ranged, &buffer);
            defer for (ops) |bytes| gpa.free(bytes);
            try testing.expect(verify(&ranged.proof, start, ops, ranged.chunks, &root));
        }

        /// A range proof stays unverifiable with its digests, pending or partial chunk digest,
        /// or chunks replaced.
        fn arbitrary_proof(self: *Self, tamper: *const Tamper) !void {
            try self.commit_pending();
            const root = self.db.root();
            const start = tamper.start % self.db.bounds().end;
            var ranged = self.db.range_proof(start, tamper.max_ops) catch |err| switch (err) {
                error.OperationPruned => return,
                else => return err,
            };
            defer ranged.deinit(gpa);
            var buffer: [16][]const u8 = undefined;
            const ops = try encode_ops(&ranged, &buffer);
            defer for (ops) |bytes| gpa.free(bytes);
            const bad = tamper.bad_digests[0..tamper.bad_digest_count];
            const digests = ranged.proof.proof.digests;
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(digests), std.mem.sliceAsBytes(bad))) {
                var copy = ranged.proof;
                copy.proof.digests = @constCast(bad);
                try testing.expect(!verify(&copy, start, ops, ranged.chunks, &root));
            }
            if (proof_mod.pending_from(F, Digest, tamper.bad_pending)) |pending| {
                const slot = ranged.proof.pending_chunk_digest;
                const original = proof_mod.pending_digest(F, Digest, slot);
                if (!optional_eql(original, tamper.bad_pending)) {
                    var copy = ranged.proof;
                    copy.pending_chunk_digest = pending;
                    try testing.expect(!verify(&copy, start, ops, ranged.chunks, &root));
                }
            } else |_| {}
            if (!optional_eql(ranged.proof.partial_chunk_digest, tamper.bad_partial)) {
                var copy = ranged.proof;
                copy.partial_chunk_digest = tamper.bad_partial;
                try testing.expect(!verify(&copy, start, ops, ranged.chunks, &root));
            }
            try self.tampered_chunks(&ranged, start, ops, &tamper.chunk_xor, &root);
        }

        fn tampered_chunks(
            _: *Self,
            ranged: *const D.Ranged,
            start: u64,
            ops: []const []const u8,
            xor: *const [32]u8,
            root: *const Digest,
        ) !void {
            if (std.mem.allEqual(u8, xor, 0)) return;
            var chunks: [16][32]u8 = undefined;
            assert(ranged.chunks.len <= chunks.len);
            for (ranged.chunks, 0..) |chunk, i| {
                for (&chunks[i], chunk, xor) |*b, c, x| b.* = c ^ x;
            }
            const bad = chunks[0..ranged.chunks.len];
            try testing.expect(!verify(&ranged.proof, start, ops, bad, root));
        }

        fn optional_eql(a: ?Digest, b: ?Digest) bool {
            if (a == null or b == null) return a == null and b == null;
            return a.?.eql(b.?);
        }

        fn key_value_proof(self: *Self, key: Digest) !void {
            try self.commit_pending();
            const root = self.db.root();
            var proved = self.db.key_value_proof(&key) catch |err| switch (err) {
                error.KeyNotFound => {
                    try testing.expect(self.committed.get(key) == null);
                    return;
                },
                else => return err,
            };
            defer proved.deinit(gpa);
            try testing.expect(proved.value.eql(self.committed.get(key).?));
            try testing.expect(D.verify_key_value_proof(&proved.proof, key, proved.value, &root));
        }

        fn exclusion_proof(self: *Self, key: Digest) !void {
            try self.commit_pending();
            const root = self.db.root();
            var proof = self.db.exclusion_proof(&key) catch |err| switch (err) {
                error.KeyExists => {
                    try testing.expect(self.committed.contains(key));
                    return;
                },
                else => return err,
            };
            defer if (@hasDecl(@TypeOf(proof), "deinit")) proof.deinit(gpa);
            try testing.expect(!self.committed.contains(key));
            try testing.expect(D.verify_exclusion_proof(&proof, key, &root));
        }

        /// Strict, non-wrapping neighbors against the committed model.
        fn expect_neighbors(self: *Self, query: Digest) !void {
            var prev: ?Digest = null;
            var next: ?Digest = null;
            var keys = self.committed.keyIterator();
            while (keys.next()) |k| {
                const order = std.mem.order(u8, &k.bytes, &query.bytes);
                const below = prev == null or std.mem.order(u8, &k.bytes, &prev.?.bytes) == .gt;
                const above = next == null or std.mem.order(u8, &k.bytes, &next.?.bytes) == .lt;
                if (order == .lt and below) prev = k.*;
                if (order == .gt and above) next = k.*;
            }
            try testing.expect(optional_eql(prev, try self.db.get_prev_key(&query)));
            try testing.expect(optional_eql(next, try self.db.get_next_key(&query)));
        }

        fn step(self: *Self, operation: Operation) !void {
            switch (operation) {
                .update => |u| try self.queue(u.key, u.value),
                .delete => |k| {
                    const queued = self.pending.get(k);
                    const live = if (queued) |v| v != null else self.committed.contains(k);
                    if (live) try self.queue(k, null);
                },
                .get => |k| try self.expect_get(k),
                .commit => |plan| {
                    self.plan = plan;
                    try self.commit_pending();
                },
                .prune => {
                    try self.commit_pending();
                    try self.db.prune(self.db.sync_boundary());
                },
                .op_count => try testing.expectEqual(self.committed_op_count, self.db.bounds().end),
                .root => try self.commit_pending(),
                .range_proof => |r| try self.range_proof(r.start, r.max_ops),
                .key_value_proof => |k| try self.key_value_proof(k),
                .arbitrary_proof => |*t| try self.arbitrary_proof(t),
                .get_span => |k| if (comptime ordered) {
                    var span = try self.db.get_span(&k);
                    defer if (span) |*s| s.update.deinit(gpa);
                    try testing.expectEqual(!self.db.is_empty(), span != null);
                } else unreachable, // Proof: unordered decoding draws no ordered operation.
                .exclusion_proof => |k| if (comptime ordered) {
                    try self.exclusion_proof(k);
                } else unreachable, // Proof: as above.
                .get_neighbors => |k| if (comptime ordered) {
                    try self.expect_neighbors(k);
                } else unreachable, // Proof: as above.
            }
        }

        fn expect_final(self: *Self) !void {
            if (self.writes.items.len > 0) try self.commit_pending();
            for (0..collision_groups) |prefix| for (0..key_space) |suffix| {
                var bytes: [32]u8 = @splat(0);
                bytes[0] = @intCast(prefix);
                std.mem.writeInt(u64, bytes[24..32], suffix, .big);
                try self.expect_get(.{ .bytes = bytes });
                if (comptime ordered) try self.expect_neighbors(.{ .bytes = bytes });
            };
            var it = self.committed.iterator();
            while (it.next()) |entry| try self.expect_get(entry.key_ptr.*);
            if (comptime ordered) {
                try self.expect_neighbors(.{ .bytes = @splat(0) });
                try self.expect_neighbors(.{ .bytes = @splat(0xff) });
            }
        }

        fn run(bytes: []const u8) !void {
            var reader = fuzz_bytes.Reader.init(bytes);
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var self: Self = .{ .db = try harness.open(D, null) };
            defer self.db.deinit();
            defer self.deinit();
            const initial = reader.below(max_initial_writes + 1);
            for (0..initial) |i| {
                const k, const v = seed_write(i);
                try self.queue(k, v);
            }
            if (initial > 0) try self.commit_pending();
            const count = 1 + reader.below(max_operations);
            for (0..count) |_| try self.step(Operation.decode(&reader, ordered));
            try self.expect_final();
        }
    };
}

fn run_unordered(bytes: []const u8) anyerror!void {
    try Driver(support.UnorderedFixed(merkle.mmr.Family)).run(bytes);
    try Driver(support.UnorderedFixed(merkle.mmb.Family)).run(bytes);
}

fn run_ordered(bytes: []const u8) anyerror!void {
    try Driver(support.OrderedFixed(merkle.mmr.Family)).run(bytes);
    try Driver(support.OrderedFixed(merkle.mmb.Family)).run(bytes);
}

const input_max = 2048;

test "fuzz qmdb_current_unordered_operations (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x63756f70, 8, run_unordered);
}

test "fuzz qmdb_current_unordered_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run_unordered), .{});
}

test "fuzz qmdb_current_ordered_operations (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x636f6f70, 8, run_ordered);
}

test "fuzz qmdb_current_ordered_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run_ordered), .{});
}
