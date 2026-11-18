//! The `qmdb_current_recovery` fuzz target (commonware `storage/fuzz`): an unordered variable
//! `current` database over drawn page, blob, and buffer sizes, driven by updates, deletes,
//! commits, and prunes under drawn write, sync, and remove faults until a mutation fails. It
//! then crashes, runs a chain of faulted recoveries, and reopens on reliable storage. The
//! recovered root must be one recorded at a batch boundary the run could have crashed at,
//! with exactly that boundary's key-value state; every recovered key must prove against the
//! root, every range proof from the sync boundary must verify, and the database must accept
//! another batch.
//!
//! Commonware draws arbitrary 32-byte keys; this port draws them from a 128-key space so
//! deletes and rewrites hit live keys, and checks the whole space. Remove faults stay armed
//! for the whole run rather than only around prunes (only prunes remove blobs before the
//! crash).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const index = @import("../../index/mod.zig");
const translator = @import("../../translator.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;
const value = @import("../value.zig");
const any = @import("../any/mod.zig");
const qmdb_support = @import("../test_support.zig");
const verification = @import("verification.zig");
const current = @import("mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const metrics = runtime.telemetry.metrics;
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Model = std.AutoArrayHashMapUnmanaged([32]u8, [32]u8);
const Pending = std.AutoArrayHashMapUnmanaged([32]u8, ?[32]u8);

const collision_groups = 4;
const key_space = 32;
const max_operations = 64;

fn Db(comptime F: type) type {
    const E = value.Variable(Digest);
    const Journal = variable.Journal(any.operation.Unordered(F, Digest, E));
    const U = any.operation.update.Unordered(Digest, E);
    const I = index.unordered.Index(translator.TwoCap, u64);
    return current.Db(F, U, Journal, I, Sha256, 32);
}

const Params = struct {
    page_size: u16,
    page_cache_size: u32,
    merkle_items_per_blob: u64,
    log_items_per_section: u64,
    write_buffer: u32,
    replay_buffer: u32,

    fn decode(reader: *fuzz_bytes.Reader) Params {
        const params: Params = .{
            .page_size = @intCast(1 + reader.below(256)),
            .page_cache_size = @intCast(1 + reader.below(16)),
            .merkle_items_per_blob = 1 + reader.below(64),
            .log_items_per_section = 1 + reader.below(64),
            .write_buffer = @intCast(1 + reader.below(2048)),
            .replay_buffer = @intCast(1 + reader.below(2048)),
        };
        assert(params.page_size >= 1 and params.page_size <= 256);
        assert(params.write_buffer >= 1 and params.replay_buffer >= 1);
        return params;
    }
};

const Operation = union(enum) {
    update: struct { key: [32]u8, value: [32]u8 },
    delete: [32]u8,
    commit,
    prune,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        const tag = reader.below(4);
        const k = key_bytes(reader.int(u8), reader.int(u8));
        return switch (tag) {
            0 => .{ .update = .{ .key = k, .value = @splat(reader.int(u8)) } },
            1 => .{ .delete = k },
            2 => .commit,
            3 => .prune,
            else => unreachable, // Proof: `below(4)` is in 0..4.
        };
    }
};

fn key_bytes(prefix: u8, suffix: u64) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[0] = prefix % collision_groups;
    std.mem.writeInt(u64, bytes[24..32], suffix % key_space, .big);
    assert(bytes[0] < collision_groups);
    return bytes;
}

/// A batch boundary recovery may expose: its live state and canonical root.
const Allowed = struct { state: Model, root: Digest };

fn Harness(comptime F: type) type {
    return struct {
        const Self = @This();
        const D = Db(F);

        /// Pinned: `faults` must stay at one address.
        faults: Faults,
        cache_ref: runtime.buffer.paged.CacheRef,
        registry: metrics.Registry,
        params: Params,

        fn init(self: *Self, params: Params, seed: u64) !void {
            self.params = params;
            self.cache_ref = try .init(gpa, params.page_size, params.page_cache_size);
            errdefer self.cache_ref.deinit();
            self.registry = metrics.Registry.init(gpa);
            self.faults.init(gpa, seed);
            assert(self.faults.layer.inner == &self.faults.inner);
        }

        fn deinit(self: *Self) void {
            self.faults.deinit();
            self.registry.deinit();
            self.cache_ref.deinit();
        }

        fn cfg(self: *Self) D.Cfg {
            var log = qmdb_support.log_config(@FieldType(D.Cfg, "log"), &self.cache_ref);
            log.partition = "crash-log";
            log.items_per_section = self.params.log_items_per_section;
            log.write_buffer = self.params.write_buffer;
            log.replay_buffer = self.params.replay_buffer;
            return .{
                .merkle = .{
                    .journal_partition = "crash-merkle-journal",
                    .metadata_partition = "crash-merkle-metadata",
                    .items_per_blob = self.params.merkle_items_per_blob,
                    .write_buffer = self.params.write_buffer,
                    .replay_buffer = self.params.replay_buffer,
                    .cache_ref = &self.cache_ref,
                },
                .log = log,
                .grafted_metadata_partition = "crash-grafted-merkle-metadata",
                .translator = .{},
                .init_cache = 3,
            };
        }

        fn open(self: *Self) !D {
            self.registry.deinit();
            self.registry = metrics.Registry.init(gpa);
            const scope = metrics.Scope.init(&self.registry).child("db");
            return D.init(gpa, self.faults.interface(), scope, self.cfg(), null);
        }

        fn recover(self: *Self) anyerror!void {
            var db = try self.open();
            db.deinit();
        }
    };
}

/// The run's model: the committed state and root, the uncommitted writes, and once a
/// mutation fails, the boundaries recovery may expose.
const Tracker = struct {
    committed: Model = .empty,
    committed_root: Digest,
    pending: Pending = .empty,
    allowed: std.ArrayList(Allowed) = .empty,

    fn deinit(self: *Tracker) void {
        self.committed.deinit(gpa);
        self.pending.deinit(gpa);
        for (self.allowed.items) |*a| a.state.deinit(gpa);
        self.allowed.deinit(gpa);
    }

    /// The committed state with the pending writes applied.
    fn post(self: *const Tracker) !Model {
        var state = try self.committed.clone(gpa);
        errdefer state.deinit(gpa);
        for (self.pending.keys(), self.pending.values()) |k, v| {
            if (v) |val| try state.put(gpa, k, val) else _ = state.swapRemove(k);
        }
        return state;
    }

    fn allow(self: *Tracker, state: Model, root: Digest) !void {
        var owned = state;
        errdefer owned.deinit(gpa);
        try self.allowed.append(gpa, .{ .state = owned, .root = root });
        assert(self.allowed.items.len <= 2);
    }

    /// An errored batch: recovery may expose the committed boundary or the batch's.
    fn failed(self: *Tracker, post_root: Digest) !void {
        assert(self.allowed.items.len == 0);
        try self.allow(try self.committed.clone(gpa), self.committed_root);
        var state = try self.post();
        const same = post_root.eql(self.committed_root) and models_equal(&state, &self.committed);
        if (same) state.deinit(gpa) else try self.allow(state, post_root);
    }

    fn succeeded(self: *Tracker, post_root: Digest) !void {
        const state = try self.post();
        self.committed.deinit(gpa);
        self.committed = state;
        self.committed_root = post_root;
        self.pending.clearRetainingCapacity();
        assert(self.pending.count() == 0);
    }
};

fn models_equal(a: *const Model, b: *const Model) bool {
    if (a.count() != b.count()) return false;
    for (a.keys(), a.values()) |k, v| {
        const other = b.get(k) orelse return false;
        if (!std.mem.eql(u8, &v, &other)) return false;
    }
    return true;
}

fn Driver(comptime F: type) type {
    return struct {
        const H = Harness(F);
        const D = H.D;

        /// Commits the pending writes; false when applying or committing failed (a crash
        /// trigger), with the allowed boundaries recorded.
        fn commit_pending(db: *D, tracker: *Tracker) !bool {
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (tracker.pending.keys(), tracker.pending.values()) |k, v| {
                    const val: ?Digest = if (v) |bytes| .{ .bytes = bytes } else null;
                    try batch.write(.{ .bytes = k }, val);
                }
                // Merkleize only reads, and reads never fault: an error here is a bug.
                break :merkleized try batch.merkleize(db);
            };
            defer merkleized.release();
            const post_root = merkleized.root();
            db.apply_batch(merkleized) catch |err| {
                if (err == error.OutOfMemory) return err;
                try tracker.failed(post_root);
                return false;
            };
            db.commit() catch |err| {
                if (err == error.OutOfMemory) return err;
                try tracker.failed(post_root);
                return false;
            };
            try tracker.succeeded(post_root);
            assert(db.root().eql(post_root));
            return true;
        }

        /// Runs the operations under faults until one fails; leaves the allowed boundaries.
        fn drive(harness: *H, reader: *fuzz_bytes.Reader, tracker: *Tracker) !void {
            var db = try harness.open();
            defer db.deinit();
            tracker.committed_root = db.root();
            harness.faults.arm(reader);
            const count = reader.below(max_operations + 1);
            for (0..count) |_| switch (Operation.decode(reader)) {
                .update => |u| try tracker.pending.put(gpa, u.key, u.value),
                .delete => |k| try tracker.pending.put(gpa, k, null),
                .commit => if (!try commit_pending(&db, tracker)) return,
                .prune => {
                    if (!try commit_pending(&db, tracker)) return;
                    // A failed prune leaves the live state and root unchanged.
                    db.prune(db.sync_boundary()) catch |err| {
                        if (err == error.OutOfMemory) return err;
                        break;
                    };
                },
            };
            try tracker.allow(try tracker.committed.clone(gpa), tracker.committed_root);
        }

        /// The recovered root and every key of the space match one allowed boundary.
        fn expect_allowed(db: *D, allowed: []const Allowed) !*const Model {
            const root = db.root();
            outer: for (allowed) |*a| {
                if (!a.root.eql(root)) continue;
                for (0..collision_groups) |prefix| for (0..key_space) |suffix| {
                    const k = key_bytes(@intCast(prefix), suffix);
                    const got = try db.get(&.{ .bytes = k });
                    const expected = a.state.get(k);
                    if ((got == null) != (expected == null)) continue :outer;
                    if (got) |g| if (!std.mem.eql(u8, &g.bytes, &expected.?)) continue :outer;
                };
                return &a.state;
            }
            return error.RecoveredStateNotAtBoundary;
        }

        fn expect_proofs(db: *D, state: *const Model) !void {
            const root = db.root();
            for (state.keys(), state.values()) |k, v| {
                var proved = try db.key_value_proof(&.{ .bytes = k });
                defer proved.deinit(gpa);
                try testing.expectEqualSlices(u8, &v, &proved.value.bytes);
                const proof = &proved.proof;
                const ok = D.verify_key_value_proof(proof, .{ .bytes = k }, proved.value, &root);
                try testing.expect(ok);
            }
            var location = db.sync_boundary();
            while (location < db.bounds().end) : (location += 1) {
                var ranged = try db.range_proof(location, 4);
                defer ranged.deinit(gpa);
                try testing.expect(try verify_ranged(&ranged, location, &root));
            }
        }

        fn verify_ranged(ranged: *const D.Ranged, start: u64, root: *const Digest) !bool {
            var encoded: [4][]const u8 = undefined;
            assert(ranged.operations.len <= encoded.len);
            var done: usize = 0;
            defer for (encoded[0..done]) |bytes| gpa.free(bytes);
            for (ranged.operations, 0..) |op, i| {
                encoded[i] = try codec.encode(D.Operation, gpa, op);
                done += 1;
            }
            var chunks: [4][]const u8 = undefined;
            assert(ranged.chunks.len <= chunks.len);
            for (ranged.chunks, 0..) |*chunk, i| chunks[i] = chunk;
            const ops = encoded[0..ranged.operations.len];
            const used = chunks[0..ranged.chunks.len];
            return verification.verify_range(F, Sha256, &ranged.proof, start, ops, used, 32, root);
        }

        fn run(params: Params, seed: u64, reader: *fuzz_bytes.Reader) !void {
            var harness: H = undefined;
            try harness.init(params, seed);
            defer harness.deinit();
            var tracker: Tracker = .{ .committed_root = undefined };
            defer tracker.deinit();
            try drive(&harness, reader, &tracker);
            assert(tracker.allowed.items.len > 0);
            harness.faults.disarm();
            try harness.faults.crash();
            try harness.faults.faulted_recovery(&harness, H.recover);
            var db = try harness.open();
            defer db.deinit();
            const state = try expect_allowed(&db, tracker.allowed.items);
            try expect_proofs(&db, state);
            // The recovered database accepts another batch.
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                try batch.write(.{ .bytes = @splat(0xab) }, .{ .bytes = @splat(0xcd) });
                break :merkleized try batch.merkleize(&db);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
            try db.commit();
        }
    };
}

fn run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    const params = Params.decode(&reader);
    const seed = reader.int(u64);
    // Both families replay the same operations from their own copy of the reader.
    var mmb_reader = reader;
    try Driver(merkle.mmr.Family).run(params, seed, &reader);
    try Driver(merkle.mmb.Family).run(params, seed, &mmb_reader);
}

const input_max = 1024;

test "fuzz qmdb_current_recovery (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x63726563, 16, run);
}

test "fuzz qmdb_current_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run), .{});
}
