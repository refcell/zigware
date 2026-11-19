//! The `qmdb_any_fixed_sync` and `qmdb_any_variable_sync` fuzz targets (commonware
//! `storage/fuzz`), under both families.
//!
//! `qmdb_any_fixed_sync` builds a source database of digest values from updates, deletes,
//! commits (each carrying the commit counter as metadata, which the next commit checks),
//! prunes, and unclean reopens, and syncs it in full: each sync commits the pending writes,
//! targets `[sync boundary, end)` at the source's root, and serves the engine from the source's
//! log, through the same page cache as the target. The synced root must equal the target's.
//!
//! `qmdb_any_variable_sync` drives a database of owned byte values through updates, deletes,
//! commits with optional metadata, prunes, reads, proofs against the current root, historical
//! proofs against the roots recorded at earlier commits, syncs, and unclean reopens.
//!
//! Differences from commonware's targets: keys come from a byte seed whose high nibble picks one
//! of 16 `OneCap` buckets (commonware draws raw 32-byte keys under `TwoCap`); values of the
//! variable target are a drawn byte repeated a drawn length; syncs, proofs, and historical
//! proofs must succeed where commonware ignores their errors (historical proofs are taken only
//! from the sync boundary, below which commonware's may fail); and the variable target checks
//! every read against a model of the applied writes, which a reopen refreshes from the
//! database.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const sync = @import("../sync/mod.zig");
const verify = @import("../verify.zig");
const qmdb_support = @import("../test_support.zig");
const any_sync = @import("sync.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Sha256 = support.Sha256;
const Digest = support.Digest;
const metrics = runtime.telemetry.metrics;

/// The key of a seed: its high nibble picks the `OneCap` bucket.
fn key_of(seed: u8) Digest {
    return support.colliding_digest(seed >> 4, seed);
}

/// Storage, one page cache shared by every database (commonware's single `CacheRef`), and a
/// metrics registry per open database.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    source_registry: metrics.Registry,
    target_registry: metrics.Registry,

    fn init(self: *Harness) !void {
        self.storage = .init(gpa);
        errdefer self.storage.deinit();
        // Commonware's 129-byte pages; a few of them, as the engine reads while it writes.
        self.cache_ref = try .init(gpa, 129, 4);
        self.source_registry = .init(gpa);
        self.target_registry = .init(gpa);
    }

    fn deinit(self: *Harness) void {
        self.target_registry.deinit();
        self.source_registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// Commonware's `test_config`: three items per blob or section, an init cache of three.
    fn cfg(self: *Harness, comptime Cfg: type, comptime prefix: []const u8) Cfg {
        var log = qmdb_support.log_config(@FieldType(Cfg, "log"), &self.cache_ref);
        log.partition = prefix ++ "-log";
        if (comptime @hasField(@TypeOf(log), "items_per_section")) {
            log.items_per_section = 3;
        } else {
            log.items_per_blob = 3;
        }
        return .{
            .merkle = .{
                .journal_partition = prefix ++ "-merkle",
                .metadata_partition = prefix ++ "-meta",
                .items_per_blob = 3,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = log,
            .translator = .{},
            .init_cache = 3,
        };
    }

    /// Opens the source database, registering its metrics afresh.
    fn open(self: *Harness, comptime D: type) !D {
        self.source_registry.deinit();
        self.source_registry = .init(gpa);
        const scope = metrics.Scope.init(&self.source_registry).child("db");
        return D.init(gpa, self.storage.interface(), scope, self.cfg(D.Cfg, "source"), null);
    }

    fn target_scope(self: *Harness) metrics.Scope {
        self.target_registry.deinit();
        self.target_registry = .init(gpa);
        return metrics.Scope.init(&self.target_registry).child("db");
    }
};

const FixedOperation = union(enum) {
    update: struct { key: u8, value: u8 },
    delete: u8,
    commit,
    prune,
    sync_full: u64,
    simulate_failure,

    fn decode(reader: *fuzz_bytes.Reader) FixedOperation {
        return switch (reader.int(u8) % 8) {
            0, 1 => .{ .update = .{ .key = reader.int(u8), .value = reader.int(u8) } },
            2, 7 => .{ .delete = reader.int(u8) },
            3 => .commit,
            4 => .prune,
            5 => .{ .sync_full = reader.int(u64) },
            6 => .simulate_failure,
            else => unreachable, // Proof: `% 8` is in 0..8.
        };
    }
};

/// The metadata of the commit numbered `counter`: its big-endian counter, zero padded.
fn commit_id(counter: u64) Digest {
    var bytes: [32]u8 = @splat(0);
    std.mem.writeInt(u64, bytes[0..8], counter, .big);
    return .{ .bytes = bytes };
}

fn FixedDriver(comptime F: type) type {
    return struct {
        const Self = @This();
        const D = support.UnorderedFixed(F);
        const S = any_sync.Database(D, Sha256);
        const Source = sync.JournalSource(F, D.Log);

        harness: Harness,
        db: D,
        writes: std.ArrayList(support.Write),
        commit_counter: u64,
        open: bool,

        fn init(self: *Self) !void {
            try self.harness.init();
            errdefer self.harness.deinit();
            self.writes = .empty;
            self.commit_counter = 0;
            self.db = try self.harness.open(D);
            self.open = true;
            assert(self.db.bounds().end == 1);
        }

        fn deinit(self: *Self) void {
            if (self.open) self.db.deinit();
            self.writes.deinit(gpa);
            self.harness.deinit();
        }

        /// Commonware's last step: applies the pending writes, then destroys the database.
        fn finish(self: *Self) !void {
            try self.commit_writes(null);
            self.open = false;
            try self.db.destroy(); // Closes it.
        }

        /// Applies and commits the pending writes with `metadata`.
        fn commit_writes(self: *Self, metadata: ?Digest) !void {
            var batch = try self.db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (self.writes.items) |w| try batch.write(w.key, w.value);
                batch.with_metadata(metadata);
                break :merkleized try batch.merkleize(&self.db);
            };
            defer merkleized.release();
            try self.db.apply_batch(merkleized);
            try self.db.commit();
            self.writes.clearRetainingCapacity();
        }

        /// Checks the last commit's metadata, then commits under the next counter.
        fn commit(self: *Self) !void {
            const metadata = try self.db.get_metadata();
            if (self.commit_counter == 0) {
                try testing.expect(metadata == null);
            } else {
                try testing.expect(metadata != null);
                try testing.expect(metadata.?.eql(commit_id(self.commit_counter)));
            }
            self.commit_counter += 1;
            try self.commit_writes(commit_id(self.commit_counter));
        }

        /// Commits, then syncs a fresh database to the source's `[sync boundary, end)`.
        fn sync_full(self: *Self, raw_batch_size: u64) !void {
            self.commit_counter += 1;
            try self.commit_writes(commit_id(self.commit_counter));
            const root = self.db.root();
            const target: S.Target = .init(root, self.db.sync_boundary(), self.db.bounds().end);
            var source: Source = .{ .journal = &self.db.log };
            var synced = try sync.sync(S, Source, gpa, testing.io, .{
                .storage = self.harness.storage.interface(),
                .scope = self.harness.target_scope(),
                .source = &source,
                .target = target,
                .max_outstanding_requests = 10,
                .fetch_batch_size = raw_batch_size % 100 + 1,
                .apply_batch_size = 100,
                .db_config = self.harness.cfg(D.Cfg, "target"),
            });
            errdefer synced.deinit();
            try testing.expect(synced.db.root().eql(root));
            try testing.expect(synced.db.root().eql(self.db.root()));
            try synced.db.destroy(); // Closes it and frees its partitions for the next sync.
        }

        /// Drops the database without committing its pending writes and reopens it.
        fn simulate_failure(self: *Self) !void {
            self.writes.clearRetainingCapacity();
            self.open = false;
            self.db.deinit();
            self.db = try self.harness.open(D);
            self.open = true;
            assert(self.db.bounds().end >= 1);
        }

        fn step(self: *Self, op: FixedOperation) !void {
            switch (op) {
                .update => |u| try self.writes.append(gpa, .{
                    .key = key_of(u.key),
                    .value = .{ .bytes = @splat(u.value) },
                }),
                .delete => |seed| {
                    try self.writes.append(gpa, .{ .key = key_of(seed), .value = null });
                },
                .commit => try self.commit(),
                .prune => try self.db.prune(self.db.sync_boundary()),
                .sync_full => |batch_size| try self.sync_full(batch_size),
                .simulate_failure => try self.simulate_failure(),
            }
        }
    };
}

fn run_fixed_family(comptime F: type, ops: []const FixedOperation) !void {
    var driver: FixedDriver(F) = undefined;
    try driver.init();
    defer driver.deinit();
    for (ops) |op| try driver.step(op);
    try driver.finish();
}

const max_operations = 50;

fn run_fixed(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var ops: [max_operations]FixedOperation = undefined;
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        ops[count] = FixedOperation.decode(&reader);
    }
    try run_fixed_family(merkle.mmr.Family, ops[0..count]);
    try run_fixed_family(merkle.mmb.Family, ops[0..count]);
}

test "fuzz qmdb_any_fixed_sync (seeded)" {
    try fuzz_bytes.seeded(192, 0x616e7953, 8, run_fixed);
}

test "fuzz qmdb_any_fixed_sync" {
    try testing.fuzz({}, fuzz_bytes.smith(192, run_fixed), .{});
}

/// A value of the variable target: `len` copies of `byte`.
const Shape = struct {
    byte: u8,
    len: u16,

    fn make(self: Shape) ![]const u8 {
        assert(self.len > 0);
        const bytes = try gpa.alloc(u8, self.len);
        @memset(bytes, self.byte);
        return bytes;
    }

    /// Checks `got` (owned, freed here) against `expected`.
    fn expect(expected: ?Shape, got: ?[]const u8) !void {
        defer codec.free(?[]const u8, gpa, got);
        try testing.expectEqual(expected == null, got == null);
        const want = expected orelse return;
        try testing.expectEqual(@as(usize, want.len), got.?.len);
        for (got.?) |byte| try testing.expectEqual(want.byte, byte);
    }
};

const VariableOperation = union(enum) {
    update: struct { key: u8, value: Shape },
    delete: u8,
    commit: ?Shape,
    prune,
    get: u8,
    get_metadata,
    proof: struct { start: u64, max_ops: u64 },
    historical_proof: struct { size: u64, start: u64, max_ops: u64 },
    sync,
    inactivity_floor,
    op_count,
    root,
    simulate_failure,

    fn decode(reader: *fuzz_bytes.Reader) VariableOperation {
        return switch (reader.int(u8) % 14) {
            0 => .{ .update = .{ .key = reader.int(u8), .value = shape(reader, 10000) } },
            1 => .{ .delete = reader.int(u8) },
            2 => .{ .commit = if (reader.boolean()) shape(reader, 1000) else null },
            3 => .prune,
            4 => .{ .get = reader.int(u8) },
            5 => .get_metadata,
            6 => .{ .proof = .{ .start = reader.int(u64), .max_ops = max_ops(reader) } },
            7 => .{ .historical_proof = .{
                .size = reader.int(u64),
                .start = reader.int(u64),
                .max_ops = max_ops(reader),
            } },
            8 => .sync,
            9 => .inactivity_floor,
            10 => .op_count,
            11 => .root,
            12, 13 => .simulate_failure,
            else => unreachable, // Proof: `% 14` is in 0..14.
        };
    }

    /// Commonware's lengths: `len % bound + 1`.
    fn shape(reader: *fuzz_bytes.Reader, comptime bound: u16) Shape {
        const byte = reader.int(u8);
        return .{ .byte = byte, .len = @intCast(reader.int(u16) % bound + 1) };
    }

    /// Commonware's `int_in_range(1..=u32::MAX)`.
    fn max_ops(reader: *fuzz_bytes.Reader) u64 {
        return @max(1, reader.int(u32));
    }
};

fn VariableDriver(comptime F: type) type {
    return struct {
        const Self = @This();
        const D = support.UnorderedBytes(F);
        const Pending = struct { key: Digest, value: ?Shape };
        const Commit = struct { end: u64, root: Digest };

        harness: Harness,
        db: D,
        open: bool,
        pending: std.ArrayList(Pending),
        /// The live keys and the metadata as applied to the database.
        model: std.AutoHashMapUnmanaged(Digest, Shape),
        metadata: ?Shape,
        /// The root at each applied commit's end, in increasing end order.
        roots: std.ArrayList(Commit),

        fn init(self: *Self) !void {
            try self.harness.init();
            errdefer self.harness.deinit();
            self.pending = .empty;
            self.model = .empty;
            self.metadata = null;
            self.roots = .empty;
            self.db = try self.harness.open(D);
            self.open = true;
            assert(self.db.bounds().end == 1);
        }

        fn deinit(self: *Self) void {
            if (self.open) self.db.deinit();
            self.roots.deinit(gpa);
            self.model.deinit(gpa);
            self.pending.deinit(gpa);
            self.harness.deinit();
        }

        /// Applies the pending writes in one batch with `metadata`, committing if `durable`,
        /// and records the new root.
        fn apply(self: *Self, metadata: ?Shape, durable: bool) !void {
            var batch = try self.db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (self.pending.items) |p| {
                    const value = if (p.value) |s| try s.make() else null;
                    errdefer codec.free(?[]const u8, gpa, value);
                    try batch.write(p.key, value);
                }
                batch.with_metadata(if (metadata) |s| try s.make() else null);
                break :merkleized try batch.merkleize(&self.db);
            };
            defer merkleized.release();
            try self.db.apply_batch(merkleized);
            if (durable) try self.db.commit();
            for (self.pending.items) |p| {
                if (p.value) |s| {
                    try self.model.put(gpa, p.key, s);
                } else {
                    _ = self.model.remove(p.key);
                }
            }
            self.pending.clearRetainingCapacity();
            self.metadata = metadata;
            const end = self.db.bounds().end;
            if (self.roots.items.len > 0) assert(self.roots.getLast().end < end);
            try self.roots.append(gpa, .{ .end = end, .root = self.db.root() });
        }

        fn proof(self: *Self, raw_start: u64, max_ops: u64) !void {
            try self.apply(null, true);
            const end = self.db.bounds().end;
            const start = raw_start % end;
            if (start < self.db.sync_boundary()) return;
            const root = self.db.root();
            var proved = try self.db.proof(start, max_ops);
            defer proved.deinit(gpa);
            try testing.expectEqual(@min(max_ops, end - start), proved.items.len);
            const p = &proved.proof;
            const Op = D.Operation;
            const items = proved.items;
            try testing.expect(try verify.verify(F, Sha256, Op, gpa, p, start, items, &root));
        }

        /// A proof against the root recorded at one of the commits, as commonware takes it
        /// (only when `max_ops` covers the commit's whole history).
        fn historical_proof(self: *Self, raw_size: u64, raw_start: u64, max_ops: u64) !void {
            try self.apply(null, true);
            const commit = self.roots.items[raw_size % self.roots.items.len];
            const start = raw_start % commit.end;
            if (commit.end > max_ops or start < self.db.sync_boundary()) return;
            var proved = try self.db.historical_proof(commit.end, start, max_ops);
            defer proved.deinit(gpa);
            try testing.expectEqual(commit.end - start, proved.items.len);
            const p = &proved.proof;
            const items = proved.items;
            const root = &commit.root;
            const Op = D.Operation;
            try testing.expect(try verify.verify(F, Sha256, Op, gpa, p, start, items, root));
        }

        /// Drops the database without committing and reopens it; the model becomes what the
        /// database recovered, which must be a state it was in.
        fn simulate_failure(self: *Self) !void {
            self.pending.clearRetainingCapacity();
            self.roots.clearRetainingCapacity();
            self.open = false;
            self.db.deinit();
            self.db = try self.harness.open(D);
            self.open = true;
            self.model.clearRetainingCapacity();
            for (0..256) |seed| {
                const key = key_of(@intCast(seed));
                const got = try self.db.get(&key);
                defer codec.free(?[]const u8, gpa, got);
                const value = got orelse continue;
                assert(value.len > 0 and value.len <= 10000);
                try self.model.put(gpa, key, .{ .byte = value[0], .len = @intCast(value.len) });
            }
            const metadata = try self.db.get_metadata();
            defer codec.free(?[]const u8, gpa, metadata);
            self.metadata = if (metadata) |m| .{ .byte = m[0], .len = @intCast(m.len) } else null;
            try self.check_all();
        }

        fn write(self: *Self, key: Digest, value: ?Shape) !void {
            try self.pending.append(gpa, .{ .key = key, .value = value });
        }

        fn get(self: *Self, key: *const Digest) !void {
            try Shape.expect(self.model.get(key.*), try self.db.get(key));
        }

        /// Every key of the seed space and the metadata read as the model says.
        fn check_all(self: *Self) !void {
            for (0..256) |seed| try self.get(&key_of(@intCast(seed)));
            try Shape.expect(self.metadata, try self.db.get_metadata());
        }

        fn step(self: *Self, op: VariableOperation) !void {
            switch (op) {
                .update => |u| try self.write(key_of(u.key), u.value),
                .delete => |seed| try self.write(key_of(seed), null),
                .commit => |metadata| try self.apply(metadata, true),
                .prune => try self.db.prune(self.db.sync_boundary()),
                .get => |seed| try self.get(&key_of(seed)),
                .get_metadata => try Shape.expect(self.metadata, try self.db.get_metadata()),
                .proof => |p| try self.proof(p.start, p.max_ops),
                .historical_proof => |p| try self.historical_proof(p.size, p.start, p.max_ops),
                .sync => {
                    try self.apply(null, false);
                    try self.db.sync();
                },
                .inactivity_floor => {
                    try testing.expect(self.db.sync_boundary() <= self.db.inactivity_floor());
                },
                .op_count => try testing.expect(self.db.bounds().end > self.db.inactivity_floor()),
                .root => try self.apply(null, true),
                .simulate_failure => try self.simulate_failure(),
            }
        }
    };
}

fn run_variable_family(comptime F: type, ops: []const VariableOperation) !void {
    var driver: VariableDriver(F) = undefined;
    try driver.init();
    defer driver.deinit();
    for (ops) |op| try driver.step(op);
    try driver.apply(null, true);
    try driver.check_all();
    driver.open = false;
    try driver.db.destroy(); // Closes it.
}

fn run_variable(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var ops: [max_operations]VariableOperation = undefined;
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        ops[count] = VariableOperation.decode(&reader);
    }
    try run_variable_family(merkle.mmr.Family, ops[0..count]);
    try run_variable_family(merkle.mmb.Family, ops[0..count]);
}

test "fuzz qmdb_any_variable_sync (seeded)" {
    try fuzz_bytes.seeded(256, 0x616e7956, 8, run_variable);
}

test "fuzz qmdb_any_variable_sync" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run_variable), .{});
}
