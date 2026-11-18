//! The `qmdb_keyless_operations` fuzz target (commonware `storage/fuzz`): a keyless database
//! over variable byte values driven by appends, commits with valid and invalid floors, chained
//! commits with invalid child floors, reads, proofs, prunes, crashes, and bounded reopens,
//! under both families.
//!
//! Beyond commonware's checks (proofs verify, invalid floors are refused with the right error,
//! bounded reopens select the modeled commit), this port keeps a model of every applied value,
//! so reads of retained locations must return exactly what was appended.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const value = @import("../value.zig");
const verify = @import("../verify.zig");
const keyless = @import("mod.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const metrics = runtime.telemetry.metrics;
const Bytes = []const u8;
const Encoding = value.Variable(Bytes);

const max_operations = 50;
const max_proof_ops = 100;
/// Values are short so seeded runs stay fast; commonware draws up to 10000 bytes.
const max_value_len = 48;

fn Db(comptime F: type) type {
    return keyless.Db(F, Encoding, variable.Journal(keyless.Operation(F, Encoding)), Sha256);
}

const FloorKind = enum { current, advance_to_commit, bad_regression, bad_beyond_commit };

const Operation = union(enum) {
    append: struct { byte: u8, len: u8 },
    commit: struct { metadata: ?u8, floor: FloorKind },
    bad_chained_commit: FloorKind,
    get: u32,
    get_metadata,
    prune,
    sync,
    root,
    proof: struct { start: u32, max_ops: u16 },
    historical_proof: struct { size: u32, start: u32, max_ops: u16 },
    simulate_failure,
    reopen_at_most: u64,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        return switch (reader.int(u8) % 12) {
            0 => .{ .append = .{ .byte = reader.int(u8), .len = reader.int(u8) % max_value_len } },
            1 => .{ .commit = .{
                .metadata = if (reader.boolean()) reader.int(u8) else null,
                .floor = @fromBackingInt(@intCast(reader.int(u8) % 4)),
            } },
            2 => .{
                .bad_chained_commit = if (reader.boolean()) .bad_regression else .bad_beyond_commit,
            },
            3 => .{ .get = reader.int(u32) },
            4 => .get_metadata,
            5 => .prune,
            6 => .sync,
            7 => .root,
            8 => .{ .proof = .{ .start = reader.int(u32), .max_ops = reader.int(u16) } },
            9 => .{ .historical_proof = .{
                .size = reader.int(u32),
                .start = reader.int(u32),
                .max_ops = reader.int(u16),
            } },
            10 => .simulate_failure,
            11 => .{ .reopen_at_most = reader.int(u16) },
            else => unreachable, // Proof: `% 12` is in 0..12.
        };
    }
};

/// What a location of the applied log holds: an appended value, or a commit's metadata.
const Slot = struct { bytes: ?[]u8 };

/// A commit the database passed through: its log size, root, and floor.
fn Commit(comptime F: type) type {
    return struct { end: u64, root: Db(F).Digest, floor: u64 };
}

fn Driver(comptime F: type) type {
    return struct {
        const Self = @This();
        const D = Db(F);

        storage: runtime.buffer.mocks.Storage,
        cache_ref: runtime.buffer.paged.CacheRef,
        registry: metrics.Registry,
        db: D,
        pending: std.ArrayList([]u8) = .empty,
        /// One entry per applied location.
        model: std.ArrayList(Slot) = .empty,
        commits: std.ArrayList(Commit(F)) = .empty,

        fn init(self: *Self) !void {
            self.storage = .init(gpa);
            errdefer self.storage.deinit();
            self.cache_ref = try .init(gpa, 127, 8);
            errdefer self.cache_ref.deinit();
            self.registry = metrics.Registry.init(gpa);
            errdefer self.registry.deinit();
            self.pending = .empty;
            self.model = .empty;
            self.commits = .empty;
            self.db = try self.open(null);
            // The initial commit.
            try self.model.append(gpa, .{ .bytes = null });
            assert(self.db.bounds().end == 1);
        }

        fn deinit(self: *Self) void {
            self.db.deinit();
            for (self.pending.items) |bytes| gpa.free(bytes);
            self.pending.deinit(gpa);
            for (self.model.items) |slot| if (slot.bytes) |b| gpa.free(b);
            self.model.deinit(gpa);
            self.commits.deinit(gpa);
            self.registry.deinit();
            self.cache_ref.deinit();
            self.storage.deinit();
        }

        fn cfg(self: *Self) D.Cfg {
            return .{
                .merkle = .{
                    .journal_partition = "fuzz-journal",
                    .metadata_partition = "fuzz-meta",
                    .items_per_blob = 3,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &self.cache_ref,
                },
                .log = .{
                    .partition = "fuzz-log",
                    .items_per_section = 7,
                    .codec_config = .{ .range = .inclusive(0, 10000) },
                    .cache_ref = &self.cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
            };
        }

        fn open(self: *Self, max_size: ?u64) !D {
            self.registry.deinit();
            self.registry = metrics.Registry.init(gpa);
            const scope = metrics.Scope.init(&self.registry).child("db");
            return D.init(gpa, self.storage.interface(), scope, self.cfg(), max_size);
        }

        fn record_commit(self: *Self) !void {
            const end = self.db.bounds().end;
            const last = self.commits.items;
            if (last.len > 0 and last[last.len - 1].end == end) return;
            const commit: Commit(F) = .{
                .end = end,
                .root = self.db.root(),
                .floor = self.db.inactivity_floor(),
            };
            try self.commits.append(gpa, commit);
        }

        /// Merkleizes the pending appends with `floor` and `metadata`; null floor inherits.
        fn merkleize(self: *Self, floor: ?u64, metadata: ?u8) !*D.MerkleizedBatch {
            var batch = try self.db.new_batch();
            errdefer batch.deinit();
            for (self.pending.items) |bytes| {
                const copy = try gpa.dupe(u8, bytes);
                errdefer gpa.free(copy);
                try batch.append(copy);
            }
            if (floor) |f| batch.with_inactivity_floor(f);
            if (metadata) |byte| batch.with_metadata(try gpa.dupe(u8, &.{byte}));
            return batch.merkleize(&self.db);
        }

        /// Applies a merkleized batch of the pending appends, moving them into the model.
        fn apply(self: *Self, merkleized: *D.MerkleizedBatch, metadata: ?u8) !void {
            defer merkleized.release();
            try self.db.apply_batch(merkleized);
            try self.model.ensureUnusedCapacity(gpa, self.pending.items.len + 1);
            for (self.pending.items) |bytes| self.model.appendAssumeCapacity(.{ .bytes = bytes });
            self.pending.clearRetainingCapacity();
            const meta: ?[]u8 = if (metadata) |byte| try gpa.dupe(u8, &.{byte}) else null;
            self.model.appendAssumeCapacity(.{ .bytes = meta });
            assert(self.model.items.len == self.db.bounds().end);
        }

        /// Commits the pending appends (commonware's flushing ops).
        fn flush(self: *Self, floor: ?u64) !void {
            try self.apply(try self.merkleize(floor, null), null);
            try self.db.commit();
        }

        fn drop_pending(self: *Self) void {
            for (self.pending.items) |bytes| gpa.free(bytes);
            self.pending.clearRetainingCapacity();
        }

        /// Reopens from storage (a crash: only committed operations survive).
        fn reopen(self: *Self) !void {
            self.drop_pending();
            self.db.deinit();
            try self.reopen_closed();
        }

        /// Opens the database again after `self.db` was closed.
        fn reopen_closed(self: *Self) !void {
            self.db = try self.open(null);
            self.truncate_model(self.db.bounds().end);
        }

        fn truncate_model(self: *Self, end: u64) void {
            assert(end <= self.model.items.len);
            for (self.model.items[end..]) |slot| if (slot.bytes) |b| gpa.free(b);
            self.model.shrinkRetainingCapacity(end);
            var keep: usize = 0;
            for (self.commits.items) |c| {
                if (c.end > end) continue;
                self.commits.items[keep] = c;
                keep += 1;
            }
            self.commits.shrinkRetainingCapacity(keep);
        }

        fn commit_op(self: *Self, metadata: ?u8, kind: FloorKind) !void {
            const commit_loc = self.db.bounds().end + self.pending.items.len;
            const current = self.db.inactivity_floor();
            const floor: ?u64, const expected: ?anyerror = switch (kind) {
                .current => .{ null, null },
                .advance_to_commit => .{ commit_loc, null },
                .bad_regression => if (current == 0)
                    .{ null, null }
                else
                    .{ current - 1, error.FloorRegressed },
                .bad_beyond_commit => .{ commit_loc + 1, error.FloorBeyondCommit },
            };
            if (expected) |err| {
                try testing.expectError(err, self.merkleize(floor, metadata));
                return;
            }
            try self.apply(try self.merkleize(floor, metadata), metadata);
            try self.db.commit();
            const got = try self.db.get_metadata();
            defer codec.free(?Bytes, gpa, got);
            try testing.expectEqual(metadata != null, got != null);
        }

        fn bad_chained(self: *Self, kind: FloorKind) !void {
            const parent_commit = self.db.bounds().end + 1;
            const child_commit = parent_commit + 2;
            var parent_batch = try self.db.new_batch();
            try parent_batch.append(try gpa.dupe(u8, &.{0}));
            parent_batch.with_inactivity_floor(parent_commit);
            const parent = try parent_batch.merkleize(&self.db);
            defer parent.release();
            var child = parent.new_batch();
            defer child.deinit();
            try child.append(try gpa.dupe(u8, &.{1}));
            const floor, const err: anyerror = switch (kind) {
                .bad_regression => .{ parent_commit - 1, error.FloorRegressed },
                else => .{ child_commit + 1, error.FloorBeyondCommit },
            };
            child.with_inactivity_floor(floor);
            try testing.expectError(err, child.merkleize(&self.db));
        }

        fn get(self: *Self, offset: u32) !void {
            const span = self.db.bounds();
            const loc = offset % span.end;
            const got = self.db.get(loc) catch |err| {
                try testing.expect(loc < span.start);
                try testing.expectEqual(error.ItemPruned, err);
                return;
            };
            defer codec.free(?Bytes, gpa, got);
            const want = self.model.items[@intCast(loc)].bytes;
            try testing.expectEqual(want == null, got == null);
            if (want) |w| try testing.expectEqualSlices(u8, w, got.?);
        }

        fn proof(self: *Self, size: u64, start: u64, max_ops: u64) !void {
            const root = self.db.root();
            var proved = self.db.historical_proof(size, start, max_ops) catch return;
            defer proved.deinit(gpa);
            const items = proved.items;
            const Op = D.Operation;
            const ok = try verify.verify(F, Sha256, Op, gpa, &proved.proof, start, items, &root);
            try testing.expect(ok);
        }

        fn reopen_at_most(self: *Self, raw_cap: u64) !void {
            self.drop_pending();
            const before = self.db.bounds();
            const before_root = self.db.root();
            const cap = raw_cap % (before.end + 3);
            try self.record_commit();
            var selected: ?Commit(F) = null;
            for (self.commits.items) |c| {
                if (c.end <= cap) selected = c;
            }
            try self.db.sync();
            // One database at a time holds the storage and the metric names.
            self.db.deinit();
            var opened = self.open(cap) catch |err| {
                switch (err) {
                    error.InvalidInitializationBound => try testing.expectEqual(@as(u64, 0), cap),
                    else => {
                        try testing.expect(cap != 0);
                        try testing.expect(selected == null or selected.?.end <= before.start);
                    },
                }
                try self.reopen_closed();
                try testing.expect(self.db.root().eql(before_root));
                return;
            };
            const commit = selected orelse {
                opened.deinit();
                try self.reopen_closed();
                return error.TestUnexpectedResult; // A cap that opens selects a modeled commit.
            };
            try testing.expectEqual(commit.end, opened.bounds().end);
            try testing.expect(opened.root().eql(commit.root));
            const floor = opened.inactivity_floor();
            opened.deinit();
            try self.reopen_closed();
            try testing.expectEqual(commit.floor, floor);
            try testing.expectEqual(commit.end, self.db.bounds().end);
            try testing.expect(self.db.root().eql(commit.root));
        }

        fn step(self: *Self, op: Operation) !void {
            try self.record_commit();
            switch (op) {
                .append => |a| {
                    const bytes = try gpa.alloc(u8, a.len);
                    errdefer gpa.free(bytes);
                    @memset(bytes, a.byte);
                    try self.pending.append(gpa, bytes);
                },
                .commit => |c| try self.commit_op(c.metadata, c.floor),
                .bad_chained_commit => |kind| try self.bad_chained(kind),
                .get => |offset| try self.get(offset),
                .get_metadata => {
                    const got = try self.db.get_metadata();
                    codec.free(?Bytes, gpa, got);
                },
                .prune => {
                    try self.flush(self.db.bounds().end + self.pending.items.len);
                    try self.db.prune(self.db.inactivity_floor());
                    // Pruning keeps whole blobs, so the retained start may lie below the floor.
                    try testing.expect(self.db.bounds().start <= self.db.inactivity_floor());
                },
                .sync => {
                    try self.apply(try self.merkleize(null, null), null);
                    try self.db.sync();
                },
                .root => try self.flush(null),
                .proof => |p| {
                    try self.flush(null);
                    const end = self.db.bounds().end;
                    try self.proof(end, p.start % end, p.max_ops % max_proof_ops + 1);
                },
                .historical_proof => |p| {
                    try self.flush(null);
                    const end = self.db.bounds().end;
                    const size = p.size % end + 1;
                    // As commonware's target does, prove against the current root.
                    try self.proof(end, p.start % size, p.max_ops % max_proof_ops + 1);
                },
                .simulate_failure => try self.reopen(),
                .reopen_at_most => |cap| try self.reopen_at_most(cap),
            }
        }
    };
}

fn run_family(comptime F: type, ops: []const Operation) !void {
    var driver: Driver(F) = undefined;
    try driver.init();
    defer driver.deinit();
    for (ops) |op| try driver.step(op);
    try driver.flush(null);
    for (0..driver.db.bounds().end) |loc| try driver.get(@intCast(loc));
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

test "fuzz qmdb_keyless_operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x6b65796c, 48, run);
}

test "fuzz qmdb_keyless_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run), .{});
}
