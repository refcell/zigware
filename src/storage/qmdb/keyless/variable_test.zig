//! Tests of the keyless database over variable values (`Vec<u8>`, commonware's
//! `qmdb/keyless/variable.rs`): every read hands the caller an owned copy, and batches own and
//! free the values given to them. The leak-checking allocator catches any slip.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const value = @import("../value.zig");
const verify = @import("../verify.zig");
const keyless = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };

const Bytes = []const u8;
const Encoding = value.Variable(Bytes);

fn TestDb(comptime F: type) type {
    return keyless.Db(F, Encoding, variable.Journal(keyless.Operation(F, Encoding)), Sha256);
}

/// An owned value of `len` copies of `byte` (commonware's `vec![byte; len]`).
fn make(byte: u8, len: usize) !Bytes {
    const bytes = try gpa.alloc(u8, len);
    @memset(bytes, byte);
    return bytes;
}

/// Checks `got` (owned, freed here) against `len` copies of `byte`, or null.
fn expect_value(expected: ?struct { u8, usize }, got: ?Bytes) !void {
    defer codec.free(?Bytes, gpa, got);
    const want = expected orelse return testing.expectEqual(@as(?Bytes, null), got);
    try testing.expectEqual(want[1], got.?.len);
    for (got.?) |byte| try testing.expectEqual(want[0], byte);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness, comptime F: type) !TestDb(F) {
        self.registry.deinit();
        self.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&self.registry).child("db");
        const cfg: TestDb(F).Cfg = .{
            .merkle = .{
                .journal_partition = "journal-partition",
                .metadata_partition = "metadata-partition",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = .{
                .partition = "log-journal-partition",
                .items_per_section = 7,
                .codec_config = .{ .range = .inclusive(0, 10000) },
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
        return TestDb(F).init(gpa, self.storage.interface(), scope, cfg, null);
    }
};

/// Appends `count` values (`i + 1` repeated `i` times) with `metadata`, and applies them.
fn append_batch(comptime F: type, db: *TestDb(F), count: u8, metadata: ?u8) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| {
            const made = try make(@intCast(i + 1), i);
            errdefer gpa.free(made);
            try batch.append(made);
        }
        if (metadata) |byte| batch.with_metadata(try make(byte, 3));
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

test "keyless variable reads return owned copies across reopen" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        errdefer db.deinit();
        try append_batch(F, &db, 4, 9);
        try expect_value(.{ 9, 3 }, try db.get_metadata());
        try expect_value(.{ 1, 0 }, try db.get(1));
        try expect_value(.{ 4, 3 }, try db.get(4));
        try expect_value(.{ 9, 3 }, try db.get(5));
        try db.sync();
        const root = db.root();
        db.deinit();
        db = try harness.open(F);
        try testing.expect(db.root().eql(root));
        var out: [3]?Bytes = undefined;
        try db.get_many(&.{ 0, 2, 5 }, &out);
        try expect_value(null, out[0]);
        try expect_value(.{ 2, 1 }, out[1]);
        try expect_value(.{ 9, 3 }, out[2]);
        var proved = try db.proof(1, 4);
        defer proved.deinit(gpa);
        try testing.expectEqual(@as(usize, 2), proved.items[2].append.len);
        const Op = TestDb(F).Operation;
        const ok = try verify.verify(F, Sha256, Op, gpa, &proved.proof, 1, proved.items, &root);
        try testing.expect(ok);
        try db.destroy();
    }
}

test "keyless variable batches own their values" {
    inline for (families) |F| {
        var harness = try Harness.init();
        defer harness.deinit();
        var db = try harness.open(F);
        defer db.deinit();
        try append_batch(F, &db, 2, null);
        // A dropped batch frees its appends and its replaced metadata.
        var dropped = try db.new_batch();
        try dropped.append(try make(7, 5));
        dropped.with_metadata(try make(8, 2));
        dropped.with_metadata(try make(8, 4));
        try expect_value(.{ 7, 5 }, try dropped.get(4, &db));
        dropped.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.append(try make(5, 6));
        parent_batch.with_metadata(try make(6, 1));
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try child_batch.append(try make(3, 2));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // The child keeps the released parent's values alive.
        parent.release();
        var out: [3]?Bytes = undefined;
        try child.get_many(&.{ 2, 4, 6 }, &db, &out);
        try expect_value(.{ 2, 1 }, out[0]);
        try expect_value(.{ 5, 6 }, out[1]);
        try expect_value(.{ 3, 2 }, out[2]);
        try expect_value(.{ 6, 1 }, try child.get(5, &db));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(.{ 5, 6 }, try db.get(4));
        try expect_value(null, try db.get_metadata());
    }
}
