//! The `qmdb_immutable_operations` fuzz target (commonware `storage/fuzz`): an immutable
//! database over variable byte values driven by sets of unique keys, reads, commits with
//! metadata and floor advances, prunes, proofs, historical proofs, and roots, under both
//! families.
//!
//! Beyond commonware's checks, this port keeps a model of every applied set, so reads must
//! return exactly the value set (or nothing for a key never applied, pruned, or below the floor
//! after a reopen), metadata must match the last commit, and proofs must verify. It also crashes
//! and reopens the database, which commonware's target does not.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Sha256 = support.Sha256;
const Digest = support.Digest;
const Bytes = []const u8;

const max_operations = 50;
const max_proof_ops = 100;
/// Values are short so seeded runs stay fast; commonware draws up to 256 bytes.
const max_value_len = 48;

const Operation = union(enum) {
    set: struct { key_seed: u8, len: u8 },
    get: u8,
    commit: struct { metadata_len: ?u8, advance_floor: bool },
    prune: u32,
    proof: struct { start: u32, max_ops: u16 },
    historical_proof: struct { size: u32, start: u32, max_ops: u16 },
    get_metadata,
    op_count,
    oldest_retained_loc,
    root,
    simulate_failure,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        return switch (reader.int(u8) % 11) {
            0 => .{ .set = .{ .key_seed = reader.int(u8), .len = reader.int(u8) } },
            1 => .{ .get = reader.int(u8) },
            2 => .{ .commit = .{
                .metadata_len = if (reader.boolean()) reader.int(u8) else null,
                .advance_floor = reader.boolean(),
            } },
            3 => .{ .prune = reader.int(u32) },
            4 => .{ .proof = .{ .start = reader.int(u32), .max_ops = reader.int(u16) } },
            5 => .{ .historical_proof = .{
                .size = reader.int(u32),
                .start = reader.int(u32),
                .max_ops = reader.int(u16),
            } },
            6 => .get_metadata,
            7 => .op_count,
            8 => .oldest_retained_loc,
            9 => .root,
            10 => .simulate_failure,
            else => unreachable, // Proof: `% 11` is in 0..11.
        };
    }
};

/// Commonware's `generate_key`: the key is the hash of its seed.
fn generate_key(seed: u64) Digest {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, seed, .big);
    return Sha256.hash(&.{&be});
}

/// Commonware's `generate_value`: the seed's big-endian bytes cycled to `len` (at least 1).
fn generate_value(seed: u64, len: usize) ![]u8 {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, seed, .big);
    const bytes = try gpa.alloc(u8, std.math.clamp(len, 1, max_value_len));
    for (bytes, 0..) |*byte, i| byte.* = be[i % be.len];
    return bytes;
}

/// An applied set: where it is and what it holds. `indexed` turns false when a reopen rebuilds
/// the index from a floor above it.
const Entry = struct { key: Digest, value: []u8, loc: u64, indexed: bool };

/// A commit the database passed through: its log size and root.
fn Commit(comptime F: type) type {
    return struct { end: u64, root: support.Bytes(F).Digest };
}

fn Driver(comptime F: type) type {
    return struct {
        const Self = @This();
        const D = support.Bytes(F);

        harness: support.Harness,
        db: D,
        /// Seeds of every key set so far (pending or applied); keys are set once.
        used: std.AutoHashMapUnmanaged(u8, void) = .empty,
        pending: std.ArrayList(Entry) = .empty,
        applied: std.ArrayList(Entry) = .empty,
        metadata: ?[]u8 = null,
        commits: std.ArrayList(Commit(F)) = .empty,

        fn init(self: *Self) !void {
            self.harness = try .init(gpa);
            errdefer self.harness.deinit();
            self.used = .empty;
            self.pending = .empty;
            self.applied = .empty;
            self.metadata = null;
            self.commits = .empty;
            self.db = try self.harness.open_db(D, null);
            assert(self.db.bounds().end == 1);
            try self.record_commit();
        }

        fn deinit(self: *Self) void {
            self.db.deinit();
            self.drop_pending();
            self.pending.deinit(gpa);
            for (self.applied.items) |entry| gpa.free(entry.value);
            self.applied.deinit(gpa);
            if (self.metadata) |m| gpa.free(m);
            self.used.deinit(gpa);
            self.commits.deinit(gpa);
            self.harness.deinit();
        }

        fn record_commit(self: *Self) !void {
            const end = self.db.bounds().end;
            const last = self.commits.items;
            if (last.len > 0 and last[last.len - 1].end == end) return;
            try self.commits.append(gpa, .{ .end = end, .root = self.db.root() });
        }

        fn drop_pending(self: *Self) void {
            for (self.pending.items) |entry| gpa.free(entry.value);
            self.pending.clearRetainingCapacity();
        }

        /// Applies and commits the pending sets with `floor` (null inherits) and `metadata`
        /// (owned by the driver; the batch gets a copy).
        fn flush(self: *Self, floor: ?u64, metadata: ?[]u8) !void {
            errdefer if (metadata) |m| gpa.free(m);
            var batch = try self.db.new_batch();
            errdefer batch.deinit();
            for (self.pending.items) |entry| {
                const copy = try gpa.dupe(u8, entry.value);
                errdefer gpa.free(copy);
                try batch.set(entry.key, copy);
            }
            if (floor) |f| batch.with_inactivity_floor(f);
            if (metadata) |m| batch.with_metadata(try gpa.dupe(u8, m));
            const merkleized = try batch.merkleize(&self.db);
            defer merkleized.release();
            const start = self.db.bounds().end;
            try self.db.apply_batch(merkleized);
            try self.db.commit();
            try self.move_pending(start);
            try self.record_commit();
            if (self.metadata) |m| gpa.free(m);
            self.metadata = metadata;
        }

        /// Moves the pending sets into the model at the locations the batch gave them: its sets
        /// in key order from `start`, then the commit.
        fn move_pending(self: *Self, start: u64) !void {
            const sets = self.pending.items;
            std.mem.sort(Entry, sets, {}, struct {
                fn less(_: void, a: Entry, b: Entry) bool {
                    return std.mem.order(u8, &a.key.bytes, &b.key.bytes) == .lt;
                }
            }.less);
            try self.applied.ensureUnusedCapacity(gpa, sets.len);
            for (sets, 0..) |entry, i| {
                var moved = entry;
                moved.loc = start + i;
                self.applied.appendAssumeCapacity(moved);
            }
            self.pending.clearRetainingCapacity();
            assert(self.db.bounds().end == start + sets.len + 1);
        }

        fn set(self: *Self, key_seed: u8, len: u8) !void {
            const gop = try self.used.getOrPut(gpa, key_seed);
            if (gop.found_existing) return;
            const bytes = try generate_value(key_seed, len);
            errdefer gpa.free(bytes);
            const entry: Entry = .{
                .key = generate_key(key_seed),
                .value = bytes,
                .loc = 0,
                .indexed = true,
            };
            try self.pending.append(gpa, entry);
        }

        /// The value the database must serve for `key`, if any.
        fn expected(self: *const Self, key: *const Digest) ?[]const u8 {
            for (self.applied.items) |entry| {
                if (!entry.key.eql(key.*)) continue;
                if (!entry.indexed or entry.loc < self.db.bounds().start) return null;
                return entry.value;
            }
            return null;
        }

        fn get(self: *Self, key_seed: u8) !void {
            const key = generate_key(key_seed);
            const got = try self.db.get(&key);
            defer codec.free(?Bytes, gpa, got);
            const want = self.expected(&key);
            try testing.expectEqual(want == null, got == null);
            if (want) |w| try testing.expectEqualSlices(u8, w, got.?);
        }

        fn get_metadata(self: *Self) !void {
            const got = try self.db.get_metadata();
            defer codec.free(?Bytes, gpa, got);
            try testing.expectEqual(self.metadata == null, got == null);
            if (self.metadata) |m| try testing.expectEqualSlices(u8, m, got.?);
        }

        fn commit_op(self: *Self, metadata_len: ?u8, advance_floor: bool) !void {
            const metadata = if (metadata_len) |len| try generate_value(len, len) else null;
            // The commit's location is the maximum valid floor.
            const commit_loc = self.db.bounds().end + self.pending.items.len;
            try self.flush(if (advance_floor) commit_loc else null, metadata);
            try testing.expectEqual(commit_loc + 1, self.db.bounds().end);
            if (advance_floor) try testing.expectEqual(commit_loc, self.db.inactivity_floor());
        }

        fn prune(self: *Self, raw: u32) !void {
            const last_commit = self.db.bounds().end - 1;
            const safe_loc = raw % (last_commit + 1);
            // Raise the floor to `safe_loc` so the prune succeeds, never lowering it.
            const floor = @max(safe_loc, self.db.inactivity_floor());
            const start_before = self.db.bounds().start;
            try self.flush(floor, null);
            try self.db.prune(safe_loc);
            // Pruning never moves the start back, and it keeps whole blobs, so the retained
            // start may lie below `safe_loc`.
            const start = self.db.bounds().start;
            try testing.expect(start >= start_before);
            try testing.expect(start <= @max(safe_loc, start_before));
            try testing.expectError(
                error.PruneBeyondMinRequired,
                self.db.prune(self.db.inactivity_floor() + 1),
            );
        }

        /// Proves `[start, start + max_ops)` at `size` and verifies it against `root`.
        fn check_proof(self: *Self, size: u64, start: u64, max_ops: u64, root: Digest) !void {
            var proved = try self.db.historical_proof(size, start, max_ops);
            defer proved.deinit(gpa);
            const items = proved.items;
            try testing.expectEqual(@min(max_ops, size - start), items.len);
            const Op = D.Operation;
            const ok = try verify.verify(F, Sha256, Op, gpa, &proved.proof, start, items, &root);
            try testing.expect(ok);
            if (start > 0) {
                const p = &proved.proof;
                const shifted = try verify.verify(F, Sha256, Op, gpa, p, start - 1, items, &root);
                try testing.expect(!shifted);
            }
        }

        fn proof(self: *Self, raw_start: u32, raw_max: u16) !void {
            try self.flush(null, null);
            const span = self.db.bounds();
            const start = span.start + raw_start % (span.end - span.start);
            try self.check_proof(span.end, start, raw_max % max_proof_ops + 1, self.db.root());
        }

        /// Proves against a past commit, verifying against the root the database had then.
        fn historical_proof(self: *Self, raw_size: u32, raw_start: u32, raw_max: u16) !void {
            if (self.pending.items.len != 0) return; // As commonware's target skips.
            try self.flush(null, null);
            const span = self.db.bounds();
            const max_ops = raw_max % max_proof_ops + 1;
            const size = raw_size % span.end + 1;
            const start = raw_start % size;
            const commit = for (self.commits.items) |c| {
                if (c.end == size) break c;
            } else {
                // Not a commit boundary: commonware only requires the call not to misbehave.
                if (start < span.start) return;
                var proved = self.db.historical_proof(size, start, max_ops) catch return;
                proved.deinit(gpa);
                return;
            };
            // The proof needs the commit at `size - 1` and the operations from `start`.
            if (start < span.start or size - 1 < span.start) return;
            try self.check_proof(size, start, max_ops, commit.root);
        }

        /// Crashes and reopens: pending sets are lost, and the index is rebuilt from the floor.
        fn simulate_failure(self: *Self) !void {
            const root = self.db.root();
            const end = self.db.bounds().end;
            self.drop_pending();
            self.db.deinit();
            self.db = try self.harness.open_db(D, null);
            try testing.expect(self.db.root().eql(root));
            try testing.expectEqual(end, self.db.bounds().end);
            const floor = self.db.inactivity_floor();
            for (self.applied.items) |*entry| {
                if (entry.loc < floor) entry.indexed = false;
            }
        }

        fn step(self: *Self, op: Operation) !void {
            switch (op) {
                .set => |s| try self.set(s.key_seed, s.len),
                .get => |seed| try self.get(seed),
                .commit => |c| try self.commit_op(c.metadata_len, c.advance_floor),
                .prune => |raw| try self.prune(raw),
                .proof => |p| try self.proof(p.start, p.max_ops),
                .historical_proof => |p| try self.historical_proof(p.size, p.start, p.max_ops),
                .get_metadata => try self.get_metadata(),
                .op_count => try testing.expect(self.db.bounds().end >= self.applied.items.len),
                .oldest_retained_loc => {
                    const span = self.db.bounds();
                    try testing.expect(span.start <= self.db.inactivity_floor());
                    try testing.expect(span.start < span.end);
                },
                .root => {
                    try self.flush(null, null);
                    const head = try self.db.to_batch();
                    defer head.release();
                    try testing.expect(head.root().eql(self.db.root()));
                },
                .simulate_failure => try self.simulate_failure(),
            }
        }
    };
}

fn run_family(comptime F: type, ops: []const Operation) !void {
    var driver: Driver(F) = undefined;
    try driver.init();
    defer driver.deinit();
    for (ops) |op| try driver.step(op);
    try driver.flush(null, null);
    for (0..256) |seed| try driver.get(@intCast(seed));
    try driver.get_metadata();
}

fn run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var ops: [max_operations]Operation = undefined;
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        ops[count] = Operation.decode(&reader);
    }
    try run_family(merkle.mmr.Family, ops[0..count]);
    try run_family(merkle.mmb.Family, ops[0..count]);
}

test "fuzz qmdb_immutable_operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x696d6d75, 48, run);
}

test "fuzz qmdb_immutable_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run), .{});
}
