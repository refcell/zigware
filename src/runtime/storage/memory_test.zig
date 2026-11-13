//! Tests of the memory storage backend (commonware `storage::memory::tests`).

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const testing = std.testing;
const iface = @import("../storage.zig");
const header = @import("header.zig");
const memory = @import("memory.zig");
const suite = @import("tests.zig");
const deterministic = @import("../deterministic.zig");

const Storage = memory.Storage;
const expect_read = suite.expect_read;

test "memory storage passes the storage suite" {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    const result = try runner.start(suite.run_storage_tests, .{
        runner.io(),
        testing.allocator,
        storage.storage(),
    });
    try result;
}

// Opens stay exclusive until closed or removed; removal permits a replacement while the old
// incarnation stays readable (commonware `assert_logical_open_contract`).
test "memory logical open contract" {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    const s = storage.storage();
    for ([_]?[]const u8{ "blob", null }) |name| {
        const first = (try s.open("partition", "blob")).blob;
        try first.write_at(0, "saved", .{ .sync = true });
        try testing.expectError(error.BlobAlreadyOpen, s.open("partition", "blob"));
        const versions: iface.VersionRange = .only(iface.default_blob_version);
        try testing.expectError(
            error.BlobAlreadyOpen,
            s.open_versioned("partition", "blob", versions),
        );
        first.close();
        const old = try s.open("partition", "blob");
        try testing.expectEqual(@as(u64, 5), old.len);
        try s.remove("partition", name);
        const current = try s.open("partition", "blob");
        try testing.expectEqual(@as(u64, 0), current.len);
        try expect_read(old.blob, 0, "saved");
        old.blob.close();
        try testing.expectError(error.BlobAlreadyOpen, s.open("partition", "blob"));
        try current.blob.write_at(0, "fresh", .{ .sync = true });
        current.blob.close();
        const reopened = try s.open("partition", "blob");
        try testing.expectEqual(@as(u64, 5), reopened.len);
        try expect_read(reopened.blob, 0, "fresh");
        reopened.blob.close();
        try s.remove("partition", null);
    }
}

test "memory empty write semantics" {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    // An empty plain write still extends the blob; an empty synced write does nothing.
    const plain = try storage.open("partition", "plain");
    try plain.blob.write_at(8, "", .{});
    try plain.blob.sync();
    plain.blob.close();
    const plain_reopened = try storage.open("partition", "plain");
    plain_reopened.blob.close();
    try testing.expectEqual(@as(u64, 8), plain_reopened.len);
    const synced = try storage.open("partition", "sync");
    try synced.blob.write_at(8, "", .{ .sync = true });
    synced.blob.close();
    const synced_reopened = try storage.open("partition", "sync");
    synced_reopened.blob.close();
    try testing.expectEqual(@as(u64, 0), synced_reopened.len);
}

test "memory concurrent sync preserves durable append" {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    for ([_]bool{ true, false }) |range| {
        const name = if (range) "range" else "full";
        const blob = (try storage.open("partition", name)).blob;
        try blob.write_at(0, "old", .{ .sync = true });
        try blob.sync();
        try blob.write_at(3, "new", .{ .sync = range });
        if (!range) try blob.sync();
        try expect_read(blob, 0, "oldnew");
        blob.close();
        const reopened = try storage.open("partition", name);
        defer reopened.blob.close();
        try testing.expectEqual(@as(u64, 6), reopened.len);
        try expect_read(reopened.blob, 0, "oldnew");
    }
}

test "memory set_raw_blob retires the live generation" {
    const gpa = testing.allocator;
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    const stale = (try storage.open("partition", "blob")).blob;
    try stale.write_at(0, "stale", .{});
    const installed = try header.blob_bytes(gpa, .v1, 0, "current");
    defer gpa.free(installed);
    try storage.set_raw_blob("partition", "blob", installed);
    try testing.expectError(error.BlobMissing, stale.sync());
    const raw = (try storage.raw_blob(gpa, "partition", "blob")).?;
    defer gpa.free(raw);
    try testing.expectEqualSlices(u8, installed, raw);
    const fresh = try storage.open_versioned("partition", "blob", .only(0));
    try testing.expectEqual(@as(u64, 7), fresh.len);
    try testing.expectEqual(@as(iface.BlobVersion, 0), fresh.version);
    try expect_read(fresh.blob, 0, "current");
    stale.close();
    try testing.expectError(error.BlobAlreadyOpen, storage.open("partition", "blob"));
    fresh.blob.close();
    (try storage.open("partition", "blob")).blob.close();
}

test "memory v0 writer reopens with the current layout" {
    const gpa = testing.allocator;
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    const version: iface.BlobVersion = 7;
    const opened = try storage.open_layout("legacy", "blob", .v0, .only(version));
    try testing.expectEqual(@as(u64, 0), opened.len);
    try testing.expectEqual(version, opened.version);
    try opened.blob.write_at(0, "payload", .{ .sync = true });
    opened.blob.close();
    const raw = (try storage.raw_blob(gpa, "legacy", "blob")).?;
    defer gpa.free(raw);
    try testing.expectEqualSlices(u8, "CWIC", raw[0..4]);
    try testing.expectEqualSlices(u8, "payload", raw[8..]);
    storage.crash();
    const current = try storage.open_versioned("legacy", "blob", .only(version));
    try testing.expectEqual(@as(u64, 7), current.len);
    try testing.expectEqual(version, current.version);
    try expect_read(current.blob, 0, "payload");
    try current.blob.write_at(7, "!", .{ .sync = true });
    current.blob.close();
    const reopened = try storage.open_versioned("legacy", "blob", .only(version));
    defer reopened.blob.close();
    try testing.expectEqual(@as(u64, 8), reopened.len);
    try expect_read(reopened.blob, 0, "payload!");
}

fn expect_raw(storage: *Storage, name: []const u8, expected: []const u8) !void {
    const raw = (try storage.raw_blob(testing.allocator, "partition", name)).?;
    defer testing.allocator.free(raw);
    try testing.expectEqualSlices(u8, expected, raw);
}

test "memory blob header handling" {
    const gpa = testing.allocator;
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    // A new blob is V1 with logical size 0 and one header page.
    const blob = try storage.open("partition", "test");
    defer blob.blob.close();
    try testing.expectEqual(@as(u64, 0), blob.len);
    const region = try header.blob_bytes(gpa, .v1, 0, "");
    defer gpa.free(region);
    try expect_raw(&storage, "test", region);
    // Logical offset 0 is stored at the data offset.
    try blob.blob.write_at(0, "hello world", .{});
    try blob.blob.sync();
    const synced = try header.blob_bytes(gpa, .v1, 0, "hello world");
    defer gpa.free(synced);
    try expect_raw(&storage, "test", synced);
    try expect_read(blob.blob, 0, "hello world");
    // A legacy V0 blob places data right after the 8-byte header and stays usable.
    const v0 = try header.blob_bytes(gpa, .v0, 0, "hello world");
    defer gpa.free(v0);
    try storage.set_raw_blob("partition", "v0", v0);
    const legacy = try storage.open_versioned("partition", "v0", .only(0));
    defer legacy.blob.close();
    try testing.expectEqual(@as(u64, 11), legacy.len);
    try expect_read(legacy.blob, 0, "hello world");
    try legacy.blob.write_at(11, "!", .{});
    try legacy.blob.sync();
    try expect_raw(&storage, "v0", "CWIC\x00\x00\x00\x00hello world!");
    // A blob shorter than the prelude is recreated with a fresh header page.
    try storage.set_raw_blob("partition", "corrupted", &.{ 0, 0 });
    const recovered = try storage.open("partition", "corrupted");
    defer recovered.blob.close();
    try testing.expectEqual(@as(u64, 0), recovered.len);
    try expect_raw(&storage, "corrupted", region);
}

test "memory rejects corrupt headers" {
    const gpa = testing.allocator;
    var storage: Storage = .init(gpa);
    defer storage.deinit();
    // Foreign magic, not a prefix of any canonical header.
    try storage.set_raw_blob("partition", "bad_magic", "XXXXXXXX");
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "bad_magic"));
    // Nonzero V1 header padding.
    const padded = try header.blob_bytes(gpa, .v1, 0, "payload");
    defer gpa.free(padded);
    padded[header.parse_len] = 0xff;
    try storage.set_raw_blob("partition", "dirty_padding", padded);
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "dirty_padding"));
    // A zero payload past the header region with its CRC rotted away: healing would erase it.
    const zeros: [100]u8 = @splat(0);
    const rotted = try header.blob_bytes(gpa, .v1, 0, &zeros);
    defer gpa.free(rotted);
    @memset(rotted[8..12], 0);
    try storage.set_raw_blob("partition", "rotted", rotted);
    try testing.expectError(error.BlobCorrupt, storage.open("partition", "rotted"));
    try expect_raw(&storage, "rotted", rotted);
}

test "memory audit separates partition and blob names" {
    var storage_a: Storage = .init(testing.allocator);
    defer storage_a.deinit();
    const blob_a = (try storage_a.open("a", "bc")).blob;
    defer blob_a.close();
    try blob_a.write_at(0, "d", .{});
    try blob_a.sync();
    var storage_b: Storage = .init(testing.allocator);
    defer storage_b.deinit();
    const blob_b = (try storage_b.open("ab", "c")).blob;
    defer blob_b.close();
    try blob_b.write_at(0, "d", .{});
    try blob_b.sync();
    try testing.expect(!std.mem.eql(u8, &storage_a.audit(), &storage_b.audit()));
}

test "memory torn creation recovers" {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    const quiet = testing.log_level;
    testing.log_level = .err; // Healing logs a warning.
    defer testing.log_level = quiet;
    var region: [header.region_max]u8 = undefined;
    const created = header.create(.all, .only(0), &region);
    try storage.set_raw_blob("partition", "torn_0", created.region[0..10]);
    const healed = try storage.open_versioned("partition", "torn_0", .only(0));
    try testing.expectEqual(@as(u64, 0), healed.len);
    try healed.blob.write_at(0, "data", .{});
    try healed.blob.sync();
    healed.blob.close();
    const reopened = try storage.open_versioned("partition", "torn_0", .only(0));
    defer reopened.blob.close();
    try testing.expectEqual(@as(u64, 4), reopened.len);
    try expect_read(reopened.blob, 0, "data");
}

const Expect = enum { recreated, kept, rejected };

/// The recovery a torn V0 creation image must get, per the header spec: a sub-prelude file
/// is recreated, an intact prelude parses, and anything else heals only as a canonical V1
/// creation prefix, which a V0 image satisfies only through the shared "CWI" brand.
fn expect_v0_image(image: []const u8, canonical_v0: []const u8) Expect {
    assert(image.len <= canonical_v0.len);
    var written: usize = image.len;
    while (written > 0 and image[written - 1] == 0) written -= 1;
    if (image.len < canonical_v0.len) return .recreated;
    if (std.mem.eql(u8, image, canonical_v0)) return .kept;
    if (std.mem.eql(u8, image[0..6], canonical_v0[0..6])) return .rejected;
    if (written <= 3 and std.mem.eql(u8, image[0..written], canonical_v0[0..written])) {
        return .recreated;
    }
    return .rejected;
}

// Every torn V0 creation image (each persisted length, each zero-hole subset) recovers as
// the oracle requires (commonware `test_v0_creation_images_exhaustive`).
test "memory v0 creation images exhaustive" {
    const gpa = testing.allocator;
    const quiet = testing.log_level;
    testing.log_level = .err; // Healing logs a warning per image.
    defer testing.log_level = quiet;
    for ([_]iface.BlobVersion{ 0, 3, 0x0100, 0xffff }) |version| {
        var storage: Storage = .init(gpa);
        defer storage.deinit();
        (try storage.open_versioned("partition", "v1", .only(version))).blob.close();
        const canonical_v1 = (try storage.raw_blob(gpa, "partition", "v1")).?;
        defer gpa.free(canonical_v1);
        (try storage.open_layout("partition", "v0", .v0, .only(version))).blob.close();
        const canonical_v0 = (try storage.raw_blob(gpa, "partition", "v0")).?;
        defer gpa.free(canonical_v0);
        try testing.expectEqual(@as(usize, 8), canonical_v0.len);
        for (0..canonical_v0.len + 1) |len| {
            for (0..@as(u32, 1) << @intCast(len)) |mask| {
                var image: [8]u8 = canonical_v0[0..8].*;
                for (image[0..len], 0..) |*byte, bit| {
                    if (mask & (@as(u32, 1) << @intCast(bit)) != 0) byte.* = 0;
                }
                const canonical: [2][]const u8 = .{ canonical_v0, canonical_v1 };
                try expect_v0_recovery(&storage, image[0..len], canonical, version);
            }
        }
    }
}

fn expect_v0_recovery(
    storage: *Storage,
    image: []const u8,
    canonical: [2][]const u8,
    version: iface.BlobVersion,
) !void {
    const canonical_v0, const canonical_v1 = canonical;
    try storage.set_raw_blob("partition", "v0", image);
    const result = storage.open_versioned("partition", "v0", .only(version));
    switch (expect_v0_image(image, canonical_v0)) {
        .recreated => {
            const opened = try result;
            opened.blob.close();
            try testing.expectEqual(@as(u64, 0), opened.len);
            try testing.expectEqual(version, opened.version);
            try expect_raw(storage, "v0", canonical_v1);
        },
        .kept => {
            const opened = try result;
            opened.blob.close();
            try testing.expectEqual(@as(u64, 0), opened.len);
            try testing.expectEqual(version, opened.version);
            try expect_raw(storage, "v0", image);
        },
        .rejected => {
            if (result) |opened| {
                opened.blob.close();
                return error.TestUnexpectedResult;
            } else |_| {}
            try expect_raw(storage, "v0", image);
        },
    }
}

test "memory crash keeps only durable contents" {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    const blob = (try storage.open("partition", "blob")).blob;
    defer blob.close();
    try blob.write_at(0, "durable", .{});
    try blob.sync();
    try blob.write_at(7, " lost", .{});
    storage.crash();
    // The old handle can no longer publish, and the blob reopens with its synced contents.
    try testing.expectError(error.BlobMissing, blob.sync());
    const reopened = try storage.open("partition", "blob");
    defer reopened.blob.close();
    try testing.expectEqual(@as(u64, 7), reopened.len);
    try expect_read(reopened.blob, 0, "durable");
}

// Audit digests match commonware's `storage_audit` for the same operations, computed with
// commonware's deterministic runtime: open "storage-conformance"/<seed big-endian>, write
// [seed, 1, 2, 3] and sync, then open "other-part"/"zz" and write [9, 9, 9] at 5 unsynced.
test "memory audit matches commonware" {
    const vectors = [_]struct { seed: u64, audit: []const u8 }{
        .{ .seed = 0, .audit = "f2a4f84c" },
        .{ .seed = 7, .audit = "0b45ccc3" },
        .{ .seed = 300, .audit = "42de64fc" },
    };
    for (vectors) |vector| {
        var storage: Storage = .init(testing.allocator);
        defer storage.deinit();
        var name: [8]u8 = undefined;
        std.mem.writeInt(u64, &name, vector.seed, .big);
        const blob = (try storage.open("storage-conformance", &name)).blob;
        defer blob.close();
        try blob.write_at(0, &.{ @truncate(vector.seed), 1, 2, 3 }, .{});
        try blob.sync();
        const other = (try storage.open("other-part", "zz")).blob;
        defer other.close();
        try other.write_at(5, &.{ 9, 9, 9 }, .{});
        const audit = storage.audit();
        try testing.expectEqualStrings(vector.audit, &std.fmt.bytesToHex(audit, .lower));
    }
    var empty: Storage = .init(testing.allocator);
    defer empty.deinit();
    try testing.expectEqualStrings("193f5cb3", &std.fmt.bytesToHex(empty.audit(), .lower));
}

// Seeded fuzz: random writes, resizes, syncs, reopens, and crashes on one blob, checked
// against a model that tracks the live (handle) and durable (synced) contents.

const Model = struct {
    live: std.ArrayList(u8) = .empty,
    durable: std.ArrayList(u8) = .empty,

    fn deinit(model: *Model) void {
        model.live.deinit(testing.allocator);
        model.durable.deinit(testing.allocator);
    }

    fn write(model: *Model, offset: usize, bytes: []const u8) !void {
        const end = offset + bytes.len;
        if (end > model.live.items.len) {
            try model.live.appendNTimes(testing.allocator, 0, end - model.live.items.len);
        }
        @memcpy(model.live.items[offset..end], bytes);
    }

    fn resize(model: *Model, length: usize) !void {
        if (length > model.live.items.len) {
            try model.live.appendNTimes(testing.allocator, 0, length - model.live.items.len);
        } else model.live.shrinkRetainingCapacity(length);
    }

    fn reset_live(model: *Model) !void {
        model.live.clearRetainingCapacity();
        try model.live.appendSlice(testing.allocator, model.durable.items);
    }
};

fn fuzz_memory(_: void, smith: *std.testing.Smith) anyerror!void {
    var storage: Storage = .init(testing.allocator);
    defer storage.deinit();
    var model: Model = .{};
    defer model.deinit();
    var blob = (try storage.open("fuzz", "blob")).blob;
    defer blob.close();
    var steps: u32 = 0;
    while (steps < 64 and !smith.eos()) : (steps += 1) {
        switch (smith.valueRangeAtMost(u8, 0, 5)) {
            0, 1 => {
                var bytes: [16]u8 = undefined;
                const length = smith.slice(&bytes);
                const offset = smith.valueRangeAtMost(u32, 0, 64);
                try blob.write_at(offset, bytes[0..length], .{});
                try model.write(offset, bytes[0..length]);
            },
            2 => {
                const length = smith.valueRangeAtMost(u32, 0, 80);
                try blob.resize(length);
                try model.resize(length);
            },
            3 => {
                try blob.sync();
                model.durable.clearRetainingCapacity();
                try model.durable.appendSlice(testing.allocator, model.live.items);
            },
            4, 5 => |op| {
                // Close and reopen, after a crash for op 5: unsynced changes are lost.
                if (op == 5) storage.crash();
                blob.close();
                const opened = try storage.open("fuzz", "blob");
                blob = opened.blob;
                try model.reset_live();
                try testing.expectEqual(@as(u64, model.durable.items.len), opened.len);
            },
            else => unreachable,
        }
        try expect_read(blob, 0, model.live.items);
        var byte: [1]u8 = undefined;
        const past = blob.read_at(model.live.items.len, &byte);
        try testing.expectError(error.BlobInsufficientLength, past);
    }
    const logical = (try storage.logical_blob(testing.allocator, "fuzz", "blob")).?;
    defer testing.allocator.free(logical);
    try testing.expectEqualSlices(u8, model.durable.items, logical);
}

test "fuzz memory storage against a model" {
    const build_options = @import("build_options");
    var prng = std.Random.DefaultPrng.init(0x6d65_6d6f ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [512]u8 = undefined;
    const total: u64 = @as(u64, 300) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        const length = random.uintAtMost(usize, input.len);
        random.bytes(input[0..length]);
        var smith: std.testing.Smith = .{ .in = input[0..length] };
        fuzz_memory({}, &smith) catch |err| {
            std.debug.print("fuzz: iteration {d} failed: {t}\n", .{ iteration, err });
            return err;
        };
    }
    try std.testing.fuzz({}, fuzz_memory, .{});
}
