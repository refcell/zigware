//! The `qmdb_immutable_recovery` fuzz target, the fault-injected counterpart of
//! `qmdb_immutable_operations`: a variable immutable database over drawn page, blob, and
//! buffer sizes, driven by sets of fresh keys, commits that keep or advance the inactivity
//! floor, and prunes, under drawn write, sync, and remove faults until a mutation fails. It
//! then crashes, runs a chain of faulted recoveries, and reopens on reliable storage. The
//! recovered root must be one recorded at a batch boundary the run could have crashed at, every
//! key ever set must read as that boundary holds it, every operation range from the inactivity
//! floor must prove against the root, and the database must accept another batch.
//!
//! A commit that advances the floor moves it to the batch's first location, so only that
//! batch's sets stay readable: the model follows the floor without tracking log positions.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;
const qmdb_support = @import("../test_support.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const metrics = runtime.telemetry.metrics;
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Model = std.AutoArrayHashMapUnmanaged([32]u8, [32]u8);

const max_operations = 64;

fn Db(comptime F: type) type {
    return support.Variable(F);
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
    set: [32]u8,
    commit: bool,
    prune,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        const tag = reader.below(4);
        const fill = reader.int(u8);
        return switch (tag) {
            0, 1 => .{ .set = @splat(fill) },
            2 => .{ .commit = fill % 2 == 0 },
            3 => .prune,
            else => unreachable, // Proof: `below(4)` is in 0..4.
        };
    }
};

/// The key of the `n`th set: distinct per set, as immutable requires, and spread over the
/// `TwoCap` buckets by its first two bytes.
fn key_bytes(n: u64) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[0] = @intCast(n % 4);
    std.mem.writeInt(u64, bytes[24..32], n, .big);
    assert(std.mem.readInt(u64, bytes[24..32], .big) == n);
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
                .translator = .{},
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

/// The run's model: the readable committed state and root, the uncommitted sets, the keys
/// issued, and once a mutation fails, the boundaries recovery may expose.
const Tracker = struct {
    committed: Model = .empty,
    committed_root: Digest,
    pending: Model = .empty,
    /// Whether the batch being committed advances the floor past every earlier set.
    advance: bool = false,
    issued: u64 = 0,
    allowed: std.ArrayList(Allowed) = .empty,

    fn deinit(self: *Tracker) void {
        self.committed.deinit(gpa);
        self.pending.deinit(gpa);
        for (self.allowed.items) |*a| a.state.deinit(gpa);
        self.allowed.deinit(gpa);
    }

    /// The readable state after the pending batch: its sets, over the committed state unless
    /// the batch advances the floor.
    fn post(self: *const Tracker) !Model {
        var state: Model = if (self.advance) .empty else try self.committed.clone(gpa);
        errdefer state.deinit(gpa);
        for (self.pending.keys(), self.pending.values()) |k, v| {
            assert(!state.contains(k)); // Keys are never reused.
            try state.put(gpa, k, v);
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
        self.advance = false;
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
        fn commit_pending(db: *D, tracker: *Tracker, advance: bool) !bool {
            tracker.advance = advance;
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (tracker.pending.keys(), tracker.pending.values()) |k, v| {
                    try batch.set(.{ .bytes = k }, .{ .bytes = v });
                }
                // The batch's sets start at the current size: only they stay above the floor.
                if (advance) batch.with_inactivity_floor(db.bounds().end);
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
                .set => |v| {
                    try tracker.pending.put(gpa, key_bytes(tracker.issued), v);
                    tracker.issued += 1;
                },
                .commit => |advance| if (!try commit_pending(&db, tracker, advance)) return,
                .prune => {
                    if (!try commit_pending(&db, tracker, false)) return;
                    // A failed prune leaves the readable state and root unchanged.
                    db.prune(db.inactivity_floor()) catch |err| {
                        if (err == error.OutOfMemory) return err;
                        break;
                    };
                },
            };
            try tracker.allow(try tracker.committed.clone(gpa), tracker.committed_root);
        }

        /// The recovered root and every key ever issued match one allowed boundary.
        fn expect_allowed(db: *D, tracker: *const Tracker) !*const Model {
            const root = db.root();
            outer: for (tracker.allowed.items) |*a| {
                if (!a.root.eql(root)) continue;
                for (0..tracker.issued) |n| {
                    const k = key_bytes(n);
                    const got = try db.get(&.{ .bytes = k });
                    const expected = a.state.get(k);
                    if ((got == null) != (expected == null)) continue :outer;
                    if (got) |g| if (!std.mem.eql(u8, &g.bytes, &expected.?)) continue :outer;
                }
                return &a.state;
            }
            return error.RecoveredStateNotAtBoundary;
        }

        /// Every operation from the inactivity floor proves against the recovered root.
        fn expect_proofs(db: *D) !void {
            const root = db.root();
            const end = db.bounds().end;
            var location = db.inactivity_floor();
            assert(location < end);
            while (location < end) : (location += 4) {
                var proved = try db.proof(location, 4);
                defer proved.deinit(gpa);
                try testing.expectEqual(@min(4, end - location), proved.items.len);
                const items = proved.items;
                const p = &proved.proof;
                const Op = D.Operation;
                const ok = try verify.verify(F, Sha256, Op, gpa, p, location, items, &root);
                try testing.expect(ok);
            }
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
            _ = try expect_allowed(&db, &tracker);
            try expect_proofs(&db);
            // The recovered database accepts another batch.
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                const fresh = key_bytes(tracker.issued);
                try batch.set(.{ .bytes = fresh }, .{ .bytes = @splat(0xcd) });
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

test "fuzz qmdb_immutable_recovery (seeded)" {
    try fuzz_bytes.seeded(input_max, 0x69726563, 16, run);
}

test "fuzz qmdb_immutable_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(input_max, run), .{});
}
