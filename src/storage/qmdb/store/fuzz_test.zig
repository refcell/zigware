//! The `qmdb_store_operations` fuzz target (commonware `storage/fuzz`): a store driven by
//! updates, deletes, commits under a fuzzed floor plan, reads, batched reads, syncs, prunes, and
//! crashes. Every commit's floor walk is checked by the floor oracle (`qmdb/fuzz_floor.zig`)
//! against a model of committed state, which reads and every reopen must match.
//!
//! Differences from commonware's target: the oracle needs values that own no memory, so values
//! are digests (the owned-bytes path is covered by db_test.zig), and keys come from a byte seed
//! whose high nibble picks one of 16 `TwoCap` buckets, so collisions are common.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const fuzz_floor = @import("../fuzz_floor.zig");
const test_support = @import("../test_support.zig");
const store = @import("mod.zig");

const gpa = testing.allocator;
const Digest = cryptography.Blake3.Digest;
const Db = store.Db(Digest, value.Variable(Digest), translator.TwoCap);
const Recorder = fuzz_floor.Recorder(Digest, Digest, 256);
const Model = Recorder.Model;

const max_operations = 50;
const max_get_many_keys = 8;

const Operation = union(enum) {
    update: struct { key: u8, value: u8 },
    delete: u8,
    commit: struct { metadata: ?u8, plan: fuzz_floor.Plan },
    get: u8,
    get_many: struct { count: u8, keys: [max_get_many_keys]u8 },
    get_metadata,
    sync,
    prune,
    op_count,
    simulate_failure,

    fn decode(reader: *fuzz_bytes.Reader) Operation {
        return switch (reader.int(u8) % 11) {
            0, 1 => .{ .update = .{ .key = reader.int(u8), .value = reader.int(u8) } },
            2 => .{ .delete = reader.int(u8) },
            3 => .{ .commit = .{
                .metadata = if (reader.boolean()) reader.int(u8) else null,
                .plan = .decode(reader),
            } },
            4 => .{ .get = reader.int(u8) },
            5 => many: {
                var keys: [max_get_many_keys]u8 = undefined;
                for (&keys) |*k| k.* = reader.int(u8);
                const count: u8 = @intCast(reader.int(u8) % (max_get_many_keys + 1));
                break :many .{ .get_many = .{ .count = count, .keys = keys } };
            },
            6 => .get_metadata,
            7 => .sync,
            8 => .prune,
            9 => .op_count,
            10 => .simulate_failure,
            else => unreachable, // Proof: `% 11` is in 0..11.
        };
    }
};

/// The key of a seed: its high nibble picks the `TwoCap` bucket.
fn key_of(seed: u8) Digest {
    var bytes: [32]u8 = @splat(0);
    bytes[0] = seed >> 4;
    bytes[31] = seed;
    return .{ .bytes = bytes };
}

fn value_of(seed: u8) Digest {
    return .{ .bytes = @splat(seed) };
}

/// Commonware's replacement for a scripted `Replace(seed)`, distinct from every `value_of`.
fn replacement(seed: u8) Digest {
    var bytes: [32]u8 = @splat(seed);
    bytes[0] = 0xff;
    bytes[1] = 0x00;
    return .{ .bytes = bytes };
}

const Driver = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    db: Db,
    /// Writes not yet applied: a key's new value, or null to delete it.
    pending: std.AutoArrayHashMapUnmanaged(Digest, ?Digest) = .empty,
    /// The live keys after the last commit; every applied batch commits.
    model: Model = .empty,
    metadata: ?Digest = null,

    fn init(self: *Driver) !void {
        self.storage = .init(gpa);
        errdefer self.storage.deinit();
        self.cache_ref = try .init(gpa, 125, 8);
        errdefer self.cache_ref.deinit();
        self.pending = .empty;
        self.model = .empty;
        self.metadata = null;
        self.db = try self.open();
        assert(self.db.is_empty());
    }

    fn deinit(self: *Driver) void {
        self.db.deinit();
        self.pending.deinit(gpa);
        self.model.deinit(gpa);
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Driver) !Db {
        const CodecCfg = @FieldType(Db.Journal.Cfg, "codec_config");
        const cfg: Db.Cfg = .{
            .log = .{
                .partition = "store-fuzz-test-log",
                .items_per_section = 7,
                .codec_config = test_support.codec_config(CodecCfg),
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 3,
        };
        return Db.init(gpa, self.storage.interface(), cfg, null);
    }

    fn commit(self: *Driver, metadata: ?u8, plan: fuzz_floor.Plan) !void {
        var batch = self.db.new_batch();
        const changeset_result = changeset: {
            errdefer batch.deinit();
            var it = self.pending.iterator();
            while (it.next()) |entry| try batch.write(entry.key_ptr.*, entry.value_ptr.*);
            batch.with_metadata(if (metadata) |m| value_of(m) else null);
            break :changeset batch.finalize();
        };
        var changeset = try changeset_result;
        var it = self.pending.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*) |v| {
                try self.model.put(gpa, entry.key_ptr.*, v);
            } else {
                _ = self.model.remove(entry.key_ptr.*);
            }
        }
        self.pending.clearRetainingCapacity();
        const inherited = self.db.inactivity_floor();
        var policy = Recorder.init(plan, &replacement);
        try self.db.apply_batch_with(&changeset, &policy);
        const commit_loc = self.db.bounds().end - 1;
        try policy.check(gpa, &self.model, inherited, self.db.inactivity_floor(), commit_loc);
        try self.db.commit();
        self.metadata = if (metadata) |m| value_of(m) else null;
        try testing.expectEqual(self.model.count() == 0, self.db.is_empty());
    }

    fn expect_committed(self: *Driver, key: *const Digest, got: ?Digest) !void {
        const want = self.model.get(key.*);
        try testing.expectEqual(want == null, got == null);
        if (want) |w| try testing.expect(w.eql(got.?));
    }

    fn get(self: *Driver, seed: u8) !void {
        const key = key_of(seed);
        if (self.pending.contains(key)) return; // Reads see committed state only.
        try self.expect_committed(&key, try self.db.get(&key));
    }

    /// The store reads committed state; a batch holding the pending writes reads them first.
    fn get_many(self: *Driver, seeds: []const u8) !void {
        var keys: [max_get_many_keys]Digest = undefined;
        var committed: [max_get_many_keys]Digest = undefined;
        var n: usize = 0;
        for (seeds, 0..) |seed, i| {
            keys[i] = key_of(seed);
            if (self.pending.contains(keys[i])) continue;
            committed[n] = keys[i];
            n += 1;
        }
        var out: [max_get_many_keys]?Digest = undefined;
        try self.db.get_many(committed[0..n], out[0..n]);
        for (committed[0..n], out[0..n]) |*k, got| try self.expect_committed(k, got);
        var batch = self.db.new_batch();
        defer batch.deinit();
        var it = self.pending.iterator();
        while (it.next()) |entry| try batch.write(entry.key_ptr.*, entry.value_ptr.*);
        try batch.get_many(keys[0..seeds.len], &self.db, out[0..seeds.len]);
        for (keys[0..seeds.len], out[0..seeds.len]) |*k, got| {
            if (self.pending.get(k.*)) |want| {
                try testing.expectEqual(want == null, got == null);
                if (want) |w| try testing.expect(w.eql(got.?));
            } else {
                try self.expect_committed(k, got);
            }
        }
    }

    fn get_metadata(self: *Driver) !void {
        const got = try self.db.get_metadata();
        try testing.expectEqual(self.metadata == null, got == null);
        if (self.metadata) |m| try testing.expect(m.eql(got.?));
    }

    /// Crashes and reopens: pending writes are lost; the floor and every key survive.
    fn simulate_failure(self: *Driver) !void {
        self.pending.clearRetainingCapacity();
        const floor = self.db.inactivity_floor();
        const end = self.db.bounds().end;
        self.db.deinit();
        self.db = try self.open();
        try testing.expectEqual(floor, self.db.inactivity_floor());
        try testing.expectEqual(end, self.db.bounds().end);
        try self.check_all();
    }

    fn check_all(self: *Driver) !void {
        try testing.expectEqual(self.model.count() == 0, self.db.is_empty());
        try testing.expectEqual(self.model.count(), self.db.active_keys);
        for (0..256) |seed| {
            const key = key_of(@intCast(seed));
            try self.expect_committed(&key, try self.db.get(&key));
        }
        try self.get_metadata();
    }

    fn step(self: *Driver, op: Operation) !void {
        switch (op) {
            .update => |u| try self.pending.put(gpa, key_of(u.key), value_of(u.value)),
            .delete => |seed| try self.pending.put(gpa, key_of(seed), null),
            .commit => |c| try self.commit(c.metadata, c.plan),
            .get => |seed| try self.get(seed),
            .get_many => |m| try self.get_many(m.keys[0..m.count]),
            .get_metadata => try self.get_metadata(),
            .sync => try self.db.sync(),
            .prune => {
                const before = self.db.bounds().start;
                try self.db.prune(self.db.inactivity_floor());
                const start = self.db.bounds().start;
                try testing.expect(start >= before and start <= self.db.inactivity_floor());
            },
            .op_count => try testing.expect(self.db.bounds().end > self.db.inactivity_floor()),
            .simulate_failure => try self.simulate_failure(),
        }
    }
};

fn run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var driver: Driver = undefined;
    try driver.init();
    defer driver.deinit();
    var count: usize = 0;
    while (count < max_operations and !reader.done()) : (count += 1) {
        try driver.step(Operation.decode(&reader));
    }
    driver.pending.clearRetainingCapacity();
    try driver.db.commit();
    try driver.check_all();
    try driver.simulate_failure();
}

test "fuzz qmdb_store_operations (seeded)" {
    try fuzz_bytes.seeded(256, 0x73746f72, 48, run);
}

test "fuzz qmdb_store_operations" {
    try testing.fuzz({}, fuzz_bytes.smith(256, run), .{});
}
