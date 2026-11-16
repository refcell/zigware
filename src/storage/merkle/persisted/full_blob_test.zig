//! Blob-level `init_sync` tests of `full.zig`, ported from commonware's
//! `storage/src/merkle/persisted/full.rs`. Every test runs under both families. Commonware
//! counts the syncs and reads `init_sync` issues through recording contexts; here a storage
//! wrapper records which node blobs `init_sync` opens, which is what those counts detect.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const merkle = @import("../mod.zig");
const full = @import("full.zig");
const support = @import("full_test.zig");

const D = support.D;
const Harness = support.Harness;
const Key = support.Key;
const Merkle = support.Merkle;
const add_digests = support.add_digests;
const gpa = support.gpa;
const hasher = &support.hasher;
const max_pins = merkle.max_pinned_nodes;
const Storage = runtime.storage.Storage;
const node_blobs = "journal-partition-blobs";

/// Forwards to `inner`, recording the index of every node blob opened.
const Recording = struct {
    inner: Storage,
    opened: std.ArrayList(u64) = .empty,

    fn deinit(self: *Recording) void {
        self.opened.deinit(gpa);
    }

    fn storage(self: *Recording) Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Storage.VTable = .{
        .open_versioned = open_versioned,
        .remove = remove,
        .scan = scan,
    };

    fn from(ptr: *anyopaque) *Recording {
        return @ptrCast(@alignCast(ptr));
    }

    fn open_versioned(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: runtime.storage.VersionRange,
    ) runtime.storage.Error!runtime.storage.Opened {
        const self = from(ptr);
        if (std.mem.eql(u8, partition, node_blobs)) {
            assert(name.len == 8); // Node blobs are named by big-endian index.
            const index = std.mem.readInt(u64, name[0..8], .big);
            self.opened.append(gpa, index) catch return error.Io;
        }
        return self.inner.open_versioned(partition, name, versions);
    }

    fn remove(
        ptr: *anyopaque,
        partition: []const u8,
        name: ?[]const u8,
    ) runtime.storage.Error!void {
        return from(ptr).inner.remove(partition, name);
    }

    fn scan(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        partition: []const u8,
    ) runtime.storage.Error!runtime.storage.Names {
        return from(ptr).inner.scan(allocator, partition);
    }
};

/// Tears the tail page of node blob `index`, so opening it must repair it.
fn tear_node_blob(harness: *Harness, index: u64) !void {
    var name: [8]u8 = undefined;
    std.mem.writeInt(u64, &name, index, .big);
    const opened = try harness.storage.interface().open(node_blobs, &name);
    defer opened.blob.close();
    try opened.blob.resize(opened.len - 1);
    try opened.blob.sync();
}

/// Plants a metadata pin no boundary uses; `init_sync` must drop it.
fn plant_stale_pin(comptime F: type, harness: *Harness) !void {
    var store = try Merkle(F).Store.init(gpa, harness.storage.interface(), .{
        .partition = "metadata-partition",
        .codec_config = .{ .range = .full(), .item = {} },
    });
    defer store.deinit();
    const key = Key.init(full.node_prefix, std.math.maxInt(u64));
    const digest = support.test_digest(std.math.maxInt(u64));
    if (try store.put(key, try gpa.dupe(u8, &digest.bytes))) |old| gpa.free(old);
    try store.sync();
}

fn expect_no_stale_pin(comptime F: type, harness: *Harness) !void {
    var store = try Merkle(F).Store.init(gpa, harness.storage.interface(), .{
        .partition = "metadata-partition",
        .codec_config = .{ .range = .full(), .item = {} },
    });
    defer store.deinit();
    try testing.expect(store.get(Key.init(full.node_prefix, std.math.maxInt(u64))) == null);
}

fn sync_recorded(
    comptime F: type,
    harness: *Harness,
    recording: *Recording,
    start: u64,
    end: u64,
    pins: ?[]const D,
) !Merkle(F) {
    return Merkle(F).init_sync(gpa, recording.storage(), .{
        .config = harness.cfg(),
        .range = .{ .start = start, .end = end },
        .pinned_nodes = pins,
    });
}

/// Over a stored tree extending past the range end, `init_sync` removes the node blobs wholly
/// beyond the end without opening them, so a torn tail there costs no repair.
fn ahead_skips_discarded_blobs(comptime F: type, stored_leaves: u64, torn: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const end_pos = F.location_to_position(20);
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 20);
    const target_root = try structure.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(7, &pins_buffer);
    try add_digests(F, &structure, 20, stored_leaves);
    try structure.sync();
    const newest = (structure.size() - 1) / harness.items_per_blob;
    try testing.expect(newest * harness.items_per_blob >= end_pos);
    structure.deinit();
    try plant_stale_pin(F, &harness);
    if (torn) try tear_node_blob(&harness, newest);

    var recording: Recording = .{ .inner = harness.storage.interface() };
    defer recording.deinit();
    structure = try sync_recorded(F, &harness, &recording, 7, 20, pins);
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
    structure.deinit();
    // Only blobs holding nodes below the range end were opened.
    for (recording.opened.items) |index| {
        try testing.expect(index * harness.items_per_blob < end_pos);
    }
    try expect_no_stale_pin(F, &harness);
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
}

/// A stored tree extending past the range end within the blob holding the end is truncated
/// inside that blob.
fn ahead_within_end_blob(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const end_pos = F.location_to_position(20);
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 20);
    const target_root = try structure.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(7, &pins_buffer);
    var next: u64 = 20;
    while (structure.size() <= end_pos) : (next += 1) {
        try add_digests(F, &structure, next, next + 1);
    }
    try structure.sync();
    const newest = (structure.size() - 1) / harness.items_per_blob;
    try testing.expectEqual(end_pos / harness.items_per_blob, newest);
    structure.deinit();
    try plant_stale_pin(F, &harness);

    structure = try Merkle(F).init_sync(gpa, harness.storage.interface(), .{
        .config = harness.cfg(),
        .range = .{ .start = 7, .end = 20 },
        .pinned_nodes = pins,
    });
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
    structure.deinit();
    try expect_no_stale_pin(F, &harness);
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(@as(u64, 20), structure.leaves());
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
}

/// A 50-leaf tree pruned to 30, past the range end: returns the root, the pins at 7, the
/// bounds, and the first retained node blob.
fn pruned_past_range(comptime F: type, harness: *Harness, pins: *[max_pins]D) !struct {
    root: D,
    pins: []D,
    bounds: merkle.Range,
    first_blob: u64,
} {
    var structure = try harness.open(F);
    defer structure.deinit();
    try add_digests(F, &structure, 0, 50);
    const root = try structure.root(hasher, 0);
    const pinned = try structure.pinned_nodes_at(7, pins);
    try structure.sync();
    try structure.prune(30);
    try structure.sync();
    try testing.expect(structure.bounds().start > 20);
    const first_blob = structure.journal.pruning_boundary() / harness.items_per_blob;
    const bounds = structure.bounds();
    return .{ .root = root, .pins = pinned, .bounds = bounds, .first_blob = first_blob };
}

/// Every retained node lies beyond the range, so the reset opens none of their blobs.
fn reset_leaves_retained_blobs_unopened(comptime F: type, torn: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var pins_buffer: [max_pins]D = undefined;
    const stored = try pruned_past_range(F, &harness, &pins_buffer);
    if (torn) {
        const structure = try harness.open(F);
        var reopened = structure;
        const newest = (reopened.size() - 1) / harness.items_per_blob;
        reopened.deinit();
        try tear_node_blob(&harness, newest);
    }
    var recording: Recording = .{ .inner = harness.storage.interface() };
    defer recording.deinit();
    var structure = try sync_recorded(F, &harness, &recording, 7, 20, stored.pins);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(merkle.Range{ .start = 7, .end = 7 }, structure.bounds());
    for (recording.opened.items) |index| try testing.expect(index < stored.first_blob);
    // Replaying leaves 7..50 over the supplied pins rebuilds the 50-leaf root.
    try add_digests(F, &structure, 7, 50);
    try testing.expect((try structure.root(hasher, 0)).eql(stored.root));
}

/// Pins of the wrong length fail before the reset, leaving the pruned journal intact.
fn invalid_pins_leave_pruned_journal_intact(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var pins_buffer: [max_pins + 1]D = undefined;
    const stored = try pruned_past_range(F, &harness, pins_buffer[0..max_pins]);
    pins_buffer[stored.pins.len] = support.test_digest(std.math.maxInt(u64));
    const pins = pins_buffer[0 .. stored.pins.len + 1];
    const storage = harness.storage.interface();
    try testing.expectError(error.InvalidPinnedNodes, Merkle(F).init_sync(gpa, storage, .{
        .config = harness.cfg(),
        .range = .{ .start = 7, .end = 20 },
        .pinned_nodes = pins,
    }));
    var structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(stored.bounds, structure.bounds());
    try testing.expect((try structure.root(hasher, 0)).eql(stored.root));
}

test "persisted merkle init_sync ahead skips discarded blobs" {
    inline for (support.families) |F| {
        try ahead_skips_discarded_blobs(F, 50, false);
        try ahead_skips_discarded_blobs(F, 80, false);
        try ahead_skips_discarded_blobs(F, 80, true);
        try ahead_within_end_blob(F);
    }
}

test "persisted merkle init_sync reset leaves retained blobs unopened" {
    inline for (support.families) |F| {
        try reset_leaves_retained_blobs_unopened(F, false);
        try reset_leaves_retained_blobs_unopened(F, true);
        try invalid_pins_leave_pruned_journal_intact(F);
    }
}
