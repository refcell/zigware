//! Tests for the oversized journal, ported from commonware's `segmented/oversized.rs`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const oversized = @import("oversized.zig");

const gpa = testing.allocator;
const Storage = mocks.Storage;

/// Index entry storing an id and the location of its value.
pub const TestEntry = struct {
    id: u64,
    value_offset: u64,
    value_size: u32,

    pub fn value_location(self: TestEntry) oversized.Location {
        return .{ .offset = self.value_offset, .size = self.value_size };
    }

    pub fn with_location(self: TestEntry, offset: u64, size: u32) TestEntry {
        return .{ .id = self.id, .value_offset = offset, .value_size = size };
    }

    pub const fixed_size: usize = 8 + 8 + 4;

    pub fn encode_size(_: TestEntry) usize {
        return fixed_size;
    }

    pub fn write(self: TestEntry, writer: *codec.Writer) void {
        writer.write_int(u64, self.id);
        writer.write_int(u64, self.value_offset);
        writer.write_int(u32, self.value_size);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!TestEntry {
        return .{
            .id = try reader.read_int(u64),
            .value_offset = try reader.read_int(u64),
            .value_size = try reader.read_int(u32),
        };
    }
};

pub const TestValue = [16]u8;
pub const Journal = oversized.Oversized(TestEntry, TestValue);

pub const Harness = struct {
    storage: Storage,
    cache_ref: paged.CacheRef,

    pub fn init() !Harness {
        return init_page(64);
    }

    /// commonware's `entry_cfg` passes the entry size, so each index page holds one entry.
    pub fn init_page(page_size: u16) !Harness {
        const cache_ref = try paged.CacheRef.init(gpa, page_size, 8);
        return .{ .storage = Storage.init(gpa), .cache_ref = cache_ref };
    }

    pub fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    pub fn cfg(self: *Harness) Journal.Cfg {
        return .{
            .index_partition = "test-index",
            .value_partition = "test-values",
            .index_cache_ref = &self.cache_ref,
            .index_write_buffer = 1024,
            .value_write_buffer = 1024,
            .replay_buffer = 4096,
            .codec_config = {},
        };
    }

    pub fn open_checkpoint(self: *Harness, checkpoint: oversized.Checkpoint) !Journal {
        return Journal.init_with_checkpoint(gpa, self.storage.interface(), self.cfg(), checkpoint);
    }

    pub fn open_tracked(self: *Harness) !Journal {
        const iface = self.storage.interface();
        var recovery = try Journal.init_with_markers(gpa, iface, self.cfg(), "test-markers");
        try recovery.drain();
        return recovery.finish();
    }
};

pub fn entry(id: u64) TestEntry {
    return .{ .id = id, .value_offset = 0, .value_size = 0 };
}

pub fn value_of(id: u64) TestValue {
    return @splat(@truncate(id));
}

test "oversized: append and get" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    const appended = try journal.append(1, entry(42), value_of(42));
    try testing.expectEqual(0, appended.position);
    const stored = try journal.get(1, appended.position);
    try testing.expectEqual(42, stored.id);
    try testing.expectEqual(appended.offset, stored.value_offset);
    try testing.expectEqual(appended.size, stored.value_size);
    const value = try journal.get_value(1, stored.value_offset, stored.value_size);
    try testing.expectEqual(value_of(42), value);
    try journal.destroy();
}

test "oversized: tracked persistence and recovery" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..5) |id| _ = try journal.append(1, entry(id), value_of(id));
    try journal.sync(&.{1});
    journal.deinit();
    journal = try h.open_tracked();
    try testing.expectEqual(5 * Journal.Index.chunk, try journal.size(1));
    for (0..5) |position| {
        const stored = try journal.get(1, position);
        try testing.expectEqual(position, stored.id);
        const value = try journal.get_value(1, stored.value_offset, stored.value_size);
        try testing.expectEqual(value_of(position), value);
    }
    try journal.destroy();
}

test "oversized: recovery truncates entries whose values were lost" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (0..3) |id| _ = try journal.append(1, entry(id), value_of(id));
    try journal.sync(&.{1});
    // Later entries reach the index but their values are lost to the crash.
    for (3..6) |id| _ = try journal.append(1, entry(id), value_of(id));
    try journal.index.sync(&.{1});
    journal.deinit();
    h.storage.crash();
    journal = try h.open_tracked();
    try testing.expectEqual(3 * Journal.Index.chunk, try journal.size(1));
    try testing.expectEqual(try journal.value_size(1), try journal.values.size(1));
    try journal.destroy();
}

test "oversized: checkpoint restore discards later data" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_checkpoint(.{ .section = 0, .size = 0 });
    for (1..4) |section| {
        for (0..3) |id| _ = try journal.append(section, entry(id), value_of(id));
    }
    try journal.sync_all();
    journal.deinit();
    journal = try h.open_checkpoint(.{ .section = 2, .size = 2 * Journal.Index.chunk });
    try testing.expectEqual(3 * Journal.Index.chunk, try journal.size(1));
    try testing.expectEqual(2 * Journal.Index.chunk, try journal.size(2));
    try testing.expectEqual(2, journal.newest_section());
    try testing.expectEqual(try journal.value_size(2), try journal.values.size(2));
    try journal.destroy();
}

test "oversized: prune" {
    var h = try Harness.init();
    defer h.deinit();
    var journal = try h.open_tracked();
    for (1..6) |section| _ = try journal.append(section, entry(section), value_of(section));
    try journal.sync_all();
    try testing.expect(try journal.prune(3));
    try testing.expect(journal.pruned(2));
    try testing.expect(!journal.pruned(3));
    try testing.expectEqual(3, journal.oldest_section());
    try testing.expectError(error.AlreadyPrunedToSection, journal.get(1, 0));
    try journal.destroy();
}

test "oversized: metrics register under index, values, and metadata" {
    const metrics = runtime.telemetry.metrics;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var h = try Harness.init();
    defer h.deinit();
    var cfg = h.cfg();
    cfg.metrics = metrics.Scope.init(&registry).child("oversized");
    var recovery = try Journal.init_with_markers(gpa, h.storage.interface(), cfg, "test-markers");
    try recovery.drain();
    var journal = try recovery.finish();
    defer journal.deinit();
    for (1..6) |section| _ = try journal.append(section, entry(section), value_of(section));
    try journal.sync_all();
    try testing.expect(try journal.prune(3));
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    // Sections 3, 4, and 5 remain in each journal after pruning 1 and 2.
    try testing.expect(metrics.has_metric_value(text, "oversized_index_tracked", "3"));
    try testing.expect(metrics.has_metric_value(text, "oversized_index_pruned_total", "2"));
    try testing.expect(metrics.has_metric_value(text, "oversized_values_tracked", "3"));
    try testing.expect(metrics.has_metric_value(text, "oversized_values_pruned_total", "2"));
    try testing.expect(metrics.has_metric_value(text, "oversized_index_synced_total", "5"));
    try testing.expect(std.mem.indexOf(u8, text, "oversized_metadata_keys") != null);
}

/// Fails the removal numbered `fail_at` (from zero) with `failure` and counts every removal
/// attempted, so a test sees whether `destroy` mutated anything after a failed step.
const RemoveFault = struct {
    inner: runtime.storage.Storage,
    fail_at: u64,
    failure: runtime.storage.Error,
    attempts: u64 = 0,

    const vtable: runtime.storage.Storage.VTable = .{
        .open_versioned = open_versioned,
        .remove = remove,
        .scan = scan,
    };

    fn interface(self: *RemoveFault) runtime.storage.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *RemoveFault {
        return @ptrCast(@alignCast(ptr));
    }

    fn open_versioned(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: runtime.storage.VersionRange,
    ) runtime.storage.Error!runtime.storage.Opened {
        return from(ptr).inner.open_versioned(partition, name, versions);
    }

    fn remove(
        ptr: *anyopaque,
        partition: []const u8,
        name: ?[]const u8,
    ) runtime.storage.Error!void {
        const self = from(ptr);
        defer self.attempts += 1;
        if (self.attempts == self.fail_at) return self.failure;
        return self.inner.remove(partition, name);
    }

    fn scan(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        partition: []const u8,
    ) runtime.storage.Error!runtime.storage.Names {
        return from(ptr).inner.scan(allocator, partition);
    }
};

test "oversized: destroy stops at its first failed or cancelled removal" {
    // A failed step must issue no later mutation (commonware returns at the first error), and
    // a cancelled one must not go on to park the next journal's removals.
    for ([_]runtime.storage.Error{ error.Io, error.Canceled }) |failure| {
        var fail_at: u64 = 0;
        while (true) : (fail_at += 1) {
            var h = try Harness.init();
            defer h.deinit();
            var faulty: RemoveFault = .{
                .inner = h.storage.interface(),
                .fail_at = fail_at,
                .failure = failure,
            };
            const storage = faulty.interface();
            var recovery = try Journal.init_with_markers(gpa, storage, h.cfg(), "test-markers");
            try recovery.drain();
            var journal = try recovery.finish();
            for (1..3) |section| {
                _ = try journal.append(section, entry(section), value_of(section));
            }
            try journal.sync_all();
            try journal.sync(&.{});
            faulty.attempts = 0;
            if (journal.destroy()) |_| {
                try testing.expect(fail_at > 0);
                break;
            } else |err| {
                try testing.expectEqual(failure, err);
                try testing.expectEqual(fail_at + 1, faulty.attempts);
            }
        }
    }
}
