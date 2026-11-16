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
const fixed = @import("../../journal/contiguous/fixed.zig");
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

/// Makes every node durable through the journal while its recovery watermark stays behind
/// (commonware drives a parked `start_sync`; `commit` syncs data without the watermark).
fn flush_without_watermark(comptime F: type, structure: *Merkle(F)) !void {
    try structure.flush();
    try structure.journal.commit();
}

fn persisted_watermark(harness: *Harness) !u64 {
    const storage = harness.storage.interface();
    const watermark = try fixed.Journal(D).persisted_watermark(gpa, storage, "journal-partition");
    return watermark orelse error.TestUnexpectedResult;
}

/// A torn tail inside the range, beyond the recovery watermark, is a crash shape: recovery
/// drops the torn page, and re-adding what it dropped rebuilds the target.
fn repairs_retained_torn_tail(comptime F: type, torn: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const end = 22;
    const end_pos = F.location_to_position(end);
    const items_per_blob = harness.items_per_blob;
    // The newest blob holds more than a page of nodes, so a torn tail page leaves nodes
    // ending mid-page that recovery must rewrite rather than only shrink away.
    const nodes = (end_pos - 1) % items_per_blob + 1;
    try testing.expect(nodes * @sizeOf(D) > 111);
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, end);
    const target_root = try structure.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(7, &pins_buffer);
    try flush_without_watermark(F, &structure);
    try testing.expectEqual(end_pos, structure.size());
    structure.deinit();
    const newest = (end_pos - 1) / items_per_blob;
    try testing.expect(try persisted_watermark(&harness) <= newest * items_per_blob);
    if (torn) try tear_node_blob(&harness, newest);

    structure = try Merkle(F).init_sync(gpa, harness.storage.interface(), .{
        .config = harness.cfg(),
        .range = .{ .start = 7, .end = end },
        .pinned_nodes = pins,
    });
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    if (torn) {
        try testing.expect(structure.leaves() < end);
    } else {
        try testing.expectEqual(@as(u64, end), structure.leaves());
    }
    try add_digests(F, &structure, structure.leaves(), end);
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
}

/// A retained start inside the range cannot serve it: the journal is reset without opening
/// any retained blob, so a torn tail there costs no repair.
fn start_below_retained_leaves_blobs_unopened(comptime F: type, torn: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const restart = 20;
    const end = 60;
    const items_per_blob = harness.items_per_blob;
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try structure.pinned_nodes_at(restart, &pins_buffer);
    try structure.sync();
    try structure.prune(30);
    // The journal keeps whole blobs: its retained start lies inside the range.
    const boundary = F.location_to_position(structure.bounds().start);
    const retained = boundary / items_per_blob * items_per_blob;
    try testing.expect(F.location_to_position(restart) < retained);
    try testing.expect(retained < F.location_to_position(end));
    // Extend past the persisted watermark, so the newest blob holds only unacknowledged nodes.
    try add_digests(F, &structure, 50, end);
    const target_root = try structure.root(hasher, 0);
    try flush_without_watermark(F, &structure);
    const newest = (structure.size() - 1) / items_per_blob;
    const first_blob = structure.journal.pruning_boundary() / items_per_blob;
    structure.deinit();
    try testing.expect(try persisted_watermark(&harness) <= newest * items_per_blob);
    try plant_stale_pin(F, &harness);
    if (torn) try tear_node_blob(&harness, newest);

    var recording: Recording = .{ .inner = harness.storage.interface() };
    defer recording.deinit();
    structure = try sync_recorded(F, &harness, &recording, restart, end, pins);
    try testing.expectEqual(merkle.Range{ .start = restart, .end = restart }, structure.bounds());
    for (recording.opened.items) |index| try testing.expect(index < first_blob);
    try add_digests(F, &structure, restart, end);
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
    structure.deinit();
    try expect_no_stale_pin(F, &harness);
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(merkle.Range{ .start = restart, .end = restart }, structure.bounds());
}

test "persisted merkle init_sync repairs a retained torn tail" {
    inline for (support.families) |F| {
        try repairs_retained_torn_tail(F, false);
        try repairs_retained_torn_tail(F, true);
    }
}

test "persisted merkle init_sync start below retained leaves blobs unopened" {
    inline for (support.families) |F| {
        try start_below_retained_leaves_blobs_unopened(F, false);
        try start_below_retained_leaves_blobs_unopened(F, true);
    }
}

/// Reusing durable nodes whose watermark lags publishes the watermark without a later sync.
fn publishes_watermark(comptime F: type) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 50);
    const size = structure.size();
    try flush_without_watermark(F, &structure);
    structure.deinit();
    try testing.expect(try persisted_watermark(&harness) < size);
    const leaves = F.position_to_location(size).?;
    structure = try Merkle(F).init_sync(gpa, harness.storage.interface(), .{
        .config = harness.cfg(),
        .range = .{ .start = 0, .end = leaves },
    });
    try testing.expectEqual(size, structure.size());
    structure.deinit();
    try testing.expectEqual(size, try persisted_watermark(&harness));
}

test "persisted merkle init_sync publishes the watermark" {
    inline for (support.families) |F| try publishes_watermark(F);
}

/// A stored tree ending wholly below the range start is stale: the journal is reset without
/// opening any of its blobs, so a torn tail there costs no repair.
fn stale_below_start_leaves_blobs_unopened(comptime F: type, torn: bool) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const restart = 30;
    const items_per_blob = harness.items_per_blob;
    const reference_cfg = harness.cfg_in("journal-reference", "metadata-reference");
    const storage = harness.storage.interface();
    var reference = try Merkle(F).init(gpa, storage, hasher, reference_cfg);
    try add_digests(F, &reference, 0, 50);
    const target_root = try reference.root(hasher, 0);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try reference.pinned_nodes_at(restart, &pins_buffer);
    try reference.destroy();

    var structure = try harness.open(F);
    try add_digests(F, &structure, 0, 20);
    try flush_without_watermark(F, &structure);
    const newest = (structure.size() - 1) / items_per_blob;
    structure.deinit();
    const watermark = try fixed.Journal(D).persisted_watermark(gpa, storage, "journal-partition");
    try testing.expect((watermark orelse 0) <= newest * items_per_blob);
    try testing.expect((newest + 1) * items_per_blob <= F.location_to_position(restart));
    try plant_stale_pin(F, &harness);
    if (torn) try tear_node_blob(&harness, newest);

    var recording: Recording = .{ .inner = storage };
    defer recording.deinit();
    structure = try sync_recorded(F, &harness, &recording, restart, 50, pins);
    try testing.expectEqual(merkle.Range{ .start = restart, .end = restart }, structure.bounds());
    for (recording.opened.items) |index| try testing.expect(index > newest);
    try add_digests(F, &structure, restart, 50);
    try testing.expect((try structure.root(hasher, 0)).eql(target_root));
    structure.deinit();
    try expect_no_stale_pin(F, &harness);
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    try testing.expectEqual(merkle.Range{ .start = restart, .end = restart }, structure.bounds());
}

test "persisted merkle init_sync stale below start leaves blobs unopened" {
    inline for (support.families) |F| {
        try stale_below_start_leaves_blobs_unopened(F, false);
        try stale_below_start_leaves_blobs_unopened(F, true);
    }
}

/// The sorted indices of the node blobs in storage.
fn node_blob_indices(harness: *Harness, out: []u64) ![]u64 {
    const names = try harness.storage.interface().scan(gpa, node_blobs);
    defer names.deinit(gpa);
    if (names.items.len > out.len) return error.TestUnexpectedResult;
    for (names.items, out[0..names.items.len]) |name, *index| {
        index.* = std.mem.readInt(u64, name[0..8], .big);
    }
    std.mem.sort(u64, out[0..names.items.len], {}, std.sort.asc(u64));
    return out[0..names.items.len];
}

const Roots = struct { boundary: D, end: D };

/// One blob holds exactly the tree of `boundary` leaves, and the tree of twice as many spans
/// blobs 0 through 2. Syncs both, keeping both roots; with 11 leaves, prunes to 10 so some
/// boundary pins sit in metadata and the rest in the journal.
fn seed_two_blobs(comptime F: type, harness: *Harness, boundary: u64) !Roots {
    var structure = try harness.open(F);
    defer structure.deinit();
    try add_digests(F, &structure, 0, boundary);
    try structure.sync();
    const at_boundary = try structure.root(hasher, 0);
    try add_digests(F, &structure, boundary, 2 * boundary);
    try structure.sync();
    if (boundary == 11) try structure.prune(10);
    try testing.expectEqual(@as(u64, 0), structure.journal.pruning_boundary());
    return .{ .boundary = at_boundary, .end = try structure.root(hasher, 0) };
}

/// A bounded open crashed after removing the blobs past its cap but before creating the
/// empty tail, leaving only blob 0 with the watermark at the boundary: the journal's blob span
/// ends at the sync start, so `init_sync` must probe the highest boundary pin missing from
/// metadata (inside the span) instead of the sync start. Commonware parks the open's sync to
/// freeze it there; this sweeps a mutation budget and checks every budget reaching that state.
fn after_interrupted_bounded_publication(comptime F: type, boundary: u64) !void {
    const boundary_pos = F.location_to_position(boundary);
    var reached: u32 = 0;
    var budget: u64 = 0;
    while (budget < 200) : (budget += 1) {
        var harness = try Harness.init();
        defer harness.deinit();
        harness.items_per_blob = boundary_pos;
        const roots = try seed_two_blobs(F, &harness, boundary);
        var buffer: [8]u64 = undefined;
        const stored = try node_blob_indices(&harness, &buffer);
        try testing.expectEqualSlices(u64, &.{ 0, 1, 2 }, stored);
        harness.storage.allow_mutations(budget);
        const storage = harness.storage.interface();
        const capped = open_at_most_result(F, &harness, storage, boundary);
        harness.storage.mutations_allowed = null;
        harness.storage.crash();
        if (capped) break;
        const blobs = try node_blob_indices(&harness, &buffer);
        if (blobs.len != 1 or try persisted_watermark(&harness) != boundary_pos) continue;
        reached += 1;

        var structure = try init_sync(F, &harness, boundary, 2 * boundary, null);
        const synced: merkle.Range = .{ .start = boundary, .end = boundary };
        try testing.expectEqual(synced, structure.bounds());
        try testing.expect((try structure.root(hasher, 0)).eql(roots.boundary));
        try add_digests(F, &structure, boundary, 2 * boundary);
        try testing.expect((try structure.root(hasher, 0)).eql(roots.end));
        try structure.sync();
        structure.deinit();
        structure = try harness.open(F);
        defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
        const reopened: merkle.Range = .{ .start = boundary, .end = 2 * boundary };
        try testing.expectEqual(reopened, structure.bounds());
        try testing.expect((try structure.root(hasher, 0)).eql(roots.end));
    }
    try testing.expect(reached > 0); // Some budget stopped the open at the crash shape.
}

/// Whether a bounded open completed; a storage failure leaves it to the crash.
fn open_at_most_result(comptime F: type, harness: *Harness, storage: Storage, cap: u64) bool {
    var structure = Merkle(F).init_at_most(gpa, storage, hasher, harness.cfg(), cap) catch
        return false;
    structure.deinit();
    return true;
}

fn init_sync(
    comptime F: type,
    harness: *Harness,
    start: u64,
    end: u64,
    pins: ?[]const D,
) !Merkle(F) {
    return Merkle(F).init_sync(gpa, harness.storage.interface(), .{
        .config = harness.cfg(),
        .range = .{ .start = start, .end = end },
        .pinned_nodes = pins,
    });
}

test "persisted merkle init_sync after an interrupted bounded publication" {
    inline for (support.families) |F| {
        try after_interrupted_bounded_publication(F, 8);
        try after_interrupted_bounded_publication(F, 11);
    }
}

const ClearCase = struct { start: u64, target: u64, end: u64, removed: bool, pinned: bool };

/// Durably drops every pin from metadata, keeping the pruning boundary.
fn drop_pins(comptime F: type, harness: *Harness) !void {
    var store = try Merkle(F).Store.init(gpa, harness.storage.interface(), .{
        .partition = "metadata-partition",
        .codec_config = .{ .range = .full(), .item = {} },
    });
    defer store.deinit();
    store.retain({}, struct {
        fn keep(_: void, key: Key, _: *const []const u8) bool {
            return key.prefix() != full.node_prefix;
        }
    }.keep);
    try store.sync();
}

/// A node-journal clear to `target` was staged (and with `removed`, its blobs removed) after
/// a sync to `start` persisted its boundary; `init_sync` must leave the journal empty at the
/// sync start whichever route it takes.
fn after_interrupted_clear(comptime F: type, case: ClearCase) !void {
    var harness = try Harness.init();
    defer harness.deinit();
    const local_start = 7;
    const local_end = 12;
    const reference_cfg = harness.cfg_in("journal-reference", "metadata-reference");
    const storage = harness.storage.interface();
    var reference = try Merkle(F).init(gpa, storage, hasher, reference_cfg);
    try add_digests(F, &reference, 0, case.end);
    const root = try reference.root(hasher, 0);
    var local_buffer: [max_pins]D = undefined;
    const local_pins = try reference.pinned_nodes_at(local_start, &local_buffer);
    var pins_buffer: [max_pins]D = undefined;
    const pins = try reference.pinned_nodes_at(case.start, &pins_buffer);
    try reference.destroy();

    // A local tree synced from a mid-blob start.
    var structure = try init_sync(F, &harness, local_start, local_end, local_pins);
    try add_digests(F, &structure, local_start, local_end);
    try structure.sync();
    structure.deinit();
    // The sync's boundary metadata, then its staged clear.
    try drop_pins(F, &harness);
    try support.write_boundary(F, &harness, case.start, pins);
    const target = F.location_to_position(case.target);
    try fixed.Journal(D).test_stage_clear(gpa, storage, "journal-partition", target);
    if (case.removed) try storage.remove(node_blobs, null);

    structure = try init_sync(F, &harness, case.start, case.end, if (case.pinned) pins else null);
    try testing.expectEqual(F.location_to_position(case.start), structure.size());
    try add_digests(F, &structure, case.start, case.end);
    try testing.expect((try structure.root(hasher, 0)).eql(root));
    try structure.sync();
    structure.deinit();
    structure = try harness.open(F);
    defer structure.destroy() catch unreachable; // The in-memory storage cannot fail here.
    const synced: merkle.Range = .{ .start = case.start, .end = case.end };
    try testing.expectEqual(synced, structure.bounds());
    try testing.expect((try structure.root(hasher, 0)).eql(root));
}

test "persisted merkle init_sync after an interrupted clear" {
    // The local tree starts mid-blob, so its checkpoint records that start.
    try testing.expect(merkle.mmr.Family.location_to_position(7) % 7 != 0);
    // A start equal to the target models one interrupted reset, above or below the local
    // tree; a start below the target, a retry that persisted its boundary first.
    const ranges = [_][3]u64{ .{ 20, 20, 28 }, .{ 4, 4, 12 }, .{ 9, 20, 16 } };
    inline for (support.families) |F| {
        for (ranges) |range| {
            const flag_cases = [_][2]bool{
                .{ false, true }, .{ false, false }, .{ true, true }, .{ true, false },
            };
            for (flag_cases) |flags| {
                try after_interrupted_clear(F, .{
                    .start = range[0],
                    .target = range[1],
                    .end = range[2],
                    .removed = flags[0],
                    .pinned = flags[1],
                });
            }
        }
    }
}
