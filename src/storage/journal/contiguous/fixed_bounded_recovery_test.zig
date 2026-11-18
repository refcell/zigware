//! commonware's `journal/contiguous/fixed.rs` bounded-recovery tests: holes after a full
//! blob, recovery read counts, huge blob capacities, append-path fallbacks, cached reads at the
//! stack-buffer boundary, empty prefixes, rebuilt gaps and tails, and `init_at_most` retried
//! after storage faults (on `runtime.storage.faulty`).
//!
//! The `View` ownership tests are Rust-specific (shared byte buffers) and are not ported.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const Sha256 = @import("cryptography").sha256.Sha256;
const Digest = @import("cryptography").sha256.Digest;
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const fixed = @import("fixed.zig");
const contiguous = @import("mod.zig");
const manager_mod = @import("../segmented/manager.zig");
const Checkpoint = @import("checkpoint.zig").Checkpoint;

const gpa = testing.allocator;
const Bounds = contiguous.Bounds;
const max = std.math.maxInt(u64);

fn test_digest(value: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return Sha256.hash(&.{&bytes});
}

fn bounds(start: u64, end: u64) Bounds {
    return .{ .start = start, .end = end };
}

const Options = struct {
    partition: []const u8 = "test-partition",
    items_per_blob: u64 = 5,
    page_size: u16 = 44,
    cache_pages: u32 = 3,
    write_buffer: usize = 2048,
    replay_buffer: usize = 2048,
};

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    options: Options,

    fn init(options: Options) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, options.page_size, options.cache_pages),
            .options = options,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness) fixed.Config {
        return .{
            .partition = self.options.partition,
            .items_per_blob = self.options.items_per_blob,
            .cache_ref = &self.cache_ref,
            .write_buffer = self.options.write_buffer,
            .replay_buffer = self.options.replay_buffer,
        };
    }

    fn iface(self: *Harness) runtime.storage.Storage {
        return self.storage.interface();
    }

    fn open(self: *Harness, comptime A: type) !fixed.Journal(A) {
        return fixed.Journal(A).init(gpa, self.iface(), self.cfg());
    }

    fn open_at_most(self: *Harness, comptime A: type, cap: u64) !fixed.Journal(A) {
        return fixed.Journal(A).init_at_most(gpa, self.iface(), self.cfg(), cap);
    }

    fn recovery(self: *Harness, comptime A: type, cap: ?u64) !fixed.Recovery(A) {
        return fixed.Recovery(A).open(gpa, self.iface(), self.cfg(), cap);
    }

    /// Durably write the integers `[start, end)` from an `init_at_size(start)` journal.
    fn seed_integers(self: *Harness, start: u64, end: u64) !void {
        var journal = try fixed.Journal(u64).init_at_size(gpa, self.iface(), self.cfg(), start);
        defer journal.deinit();
        for (start..end) |value| _ = try journal.append(value);
        try journal.sync();
    }

    fn blob_name(self: *Harness, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(buffer, "{s}-blobs", .{self.options.partition}) catch unreachable;
    }

    fn resize_blob(self: *Harness, index: u64, len: u64) !void {
        var buffer: [64]u8 = undefined;
        const name = self.blob_name(&buffer);
        const opened = try self.iface().open(name, &manager_mod.section_name(index));
        defer opened.blob.close();
        try opened.blob.resize(len);
        try opened.blob.sync();
    }
};

// A hole after a blob's full capacity of items is trimmed by an unbounded open.
test "fixed: unbounded recovery repairs a hole after full capacity" {
    const partition = "initialization-extra-tail";
    var h = try Harness.init(.{
        .partition = partition,
        .items_per_blob = 2,
        .page_size = 8,
        .cache_pages = 8,
        .write_buffer = 128,
        .replay_buffer = 128,
    });
    defer h.deinit();
    const blobs = partition ++ "-blobs";
    const name = manager_mod.section_name(0);
    {
        const opened = try h.iface().open(blobs, &name);
        var writer = try paged.Writer.init(gpa, opened.blob, opened.len, 128, &h.cache_ref);
        defer writer.deinit();
        const ones: [32]u8 = @splat(1);
        _ = try writer.append(&ones);
        try writer.sync();
    }
    try paged.corrupt_page(h.iface(), blobs, &name, 2, 8);
    var journal = try h.open(u64);
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 2), journal.get_bounds());
    const item = std.mem.readInt(u64, &@as([8]u8, @splat(1)), .big);
    try testing.expectEqual(item, try journal.read(0));
    try testing.expectEqual(item, try journal.read(1));
}

// A bounded recovery reads only what it needs: one read when the cap ends a page early
// enough, otherwise two, whatever the blob capacity.
test "fixed: bounded recovery read count" {
    for ([_]u64{ 257, 4097 }) |count| {
        for ([_]u64{ 10_000, max }) |capacity| {
            var h = try Harness.init(.{
                .items_per_blob = capacity,
                .page_size = 256,
                .replay_buffer = 1,
            });
            defer h.deinit();
            try h.seed_integers(0, count);
            const caps = [_]?u64{ null, 33, 32, count, count + 1, max };
            for (caps) |cap| {
                const watermark = try fixed.Journal(u64).persisted_watermark(
                    gpa,
                    h.iface(),
                    h.options.partition,
                );
                try testing.expectEqual(count, watermark.?);
                // zigware's recovery opens the checkpoint itself; commonware opens it
                // before recording, so count the checkpoint's own reads separately.
                const checkpoint_reads = try count_checkpoint_reads(&h);
                const reads_before = h.storage.reads + checkpoint_reads;
                var recovery = try h.recovery(u64, cap);
                defer recovery.deinit();
                try testing.expectEqual(@min(count, cap orelse count), recovery.size());
                try testing.expectEqual(count * 8, recovery.pending.items[0].writer.size());
                const expected: u64 = if (cap == 32) 1 else 2;
                try testing.expectEqual(expected, h.storage.reads - reads_before);
            }
        }
    }
}

/// The blob reads that opening the journal's checkpoint alone performs.
fn count_checkpoint_reads(h: *Harness) !u64 {
    const before = h.storage.reads;
    var checkpoint = try Checkpoint.open(gpa, h.iface(), h.options.partition);
    checkpoint.deinit();
    const reads = h.storage.reads - before;
    std.debug.assert(reads <= 2); // One read per metadata blob.
    return reads;
}

test "fixed: recovery with a huge blob capacity" {
    for ([_]u64{ 0, 1 }) |count| {
        for ([_]?u64{ null, 0, 1, max / 8 + 1, max }) |cap| {
            var h = try Harness.init(.{ .items_per_blob = max });
            defer h.deinit();
            try h.seed_integers(0, count);
            var journal = if (cap) |c| try h.open_at_most(u64, c) else try h.open(u64);
            defer journal.deinit();
            const retained = @min(count, cap orelse max);
            try testing.expectEqual(bounds(0, retained), journal.get_bounds());
            if (retained != 0) try testing.expectEqual(0, try journal.read(0));
        }
    }
}

// Direct and prepared appends mixed across buffer and blob boundaries, with a write buffer
// of one page and of many.
test "fixed: appends fall back across buffers and rotations" {
    for ([_]usize{ 44, 2048 }) |write_buffer| {
        var h = try Harness.init(.{ .items_per_blob = 7, .write_buffer = write_buffer });
        defer h.deinit();
        var journal = try h.open(Digest);
        for (0..20) |i| {
            const position = if (i >= 3 and i % 3 == 0) prepared: {
                var prepared = try journal.prepare_append(&.{&.{test_digest(i)}});
                break :prepared try journal.append_prepared(&prepared);
            } else try journal.append(test_digest(i));
            try testing.expectEqual(i, position);
            try testing.expectEqual(i + 1, journal.size());
        }
        try journal.sync();
        journal.deinit();
        journal = try h.open(Digest);
        try testing.expectEqual(20, journal.size());
        for (0..20) |i| try testing.expectEqual(test_digest(i), try journal.read(i));
        try journal.destroy();
    }
}

/// Append two `size`-byte items and read both back through the synchronous path.
fn check_cached_read(comptime size: usize) !void {
    var h = try Harness.init(.{ .items_per_blob = 3 });
    defer h.deinit();
    var journal = try h.open([size]u8);
    _ = try journal.append(@splat(7));
    _ = try journal.append(@splat(8));
    try testing.expectEqual(@as([size]u8, @splat(7)), journal.try_read_sync(0).?);
    try testing.expectEqual(@as([size]u8, @splat(8)), journal.try_read_sync(1).?);
    try journal.destroy();
}

// commonware's `SYNC_READ_STACK_SIZE` (128) and one past it.
test "fixed: cached reads at the stack buffer boundary" {
    try check_cached_read(128);
    try check_cached_read(129);
}

test "fixed: a bounded empty prefix at the maximum position" {
    var h = try Harness.init(.{ .items_per_blob = 1 });
    defer h.deinit();
    {
        var journal = try fixed.Journal(u64).init_at_size(gpa, h.iface(), h.cfg(), max - 1);
        defer journal.deinit();
        _ = try journal.append(99);
        _ = try journal.prune(max);
        try journal.sync();
    }
    var journal = try h.open_at_most(u64, max);
    try testing.expectEqual(bounds(max, max), journal.get_bounds());
    journal.deinit();
    journal = try h.open(u64);
    defer journal.deinit();
    try testing.expectEqual(bounds(max, max), journal.get_bounds());
}

// Initialization interrupted after its durable repair and before publication.
test "fixed: a bounded empty prefix survives an interrupted repair" {
    var h = try Harness.init(.{});
    defer h.deinit();
    {
        var journal = try fixed.Journal(Digest).init_at_size(gpa, h.iface(), h.cfg(), 7);
        defer journal.deinit();
        for (7..13) |i| _ = try journal.append(test_digest(i));
        try journal.sync();
    }
    {
        var recovery = try h.recovery(Digest, 7);
        defer recovery.deinit();
        try recovery.truncate(7);
    }
    var journal = try h.open(Digest);
    defer journal.deinit();
    try testing.expectEqual(bounds(7, 7), journal.get_bounds());
}

// An unacknowledged prefix blob is lost while newer blobs survive; recovery truncates to
// empty and rebuilds with values the surviving blobs never held. The two-page write buffer
// holds two digests, so the third in each blob takes the owned fallback.
test "fixed: recovery rebuilds a pending gap" {
    var h = try Harness.init(.{ .write_buffer = 88 });
    defer h.deinit();
    {
        var journal = try h.open(Digest);
        defer journal.deinit();
        for (0..13) |i| _ = try journal.append(test_digest(i));
        try journal.commit();
    }
    try h.resize_blob(0, 0);
    var recovery = try h.recovery(Digest, null);
    try testing.expectEqual(0, recovery.size());
    try testing.expectEqual(0, recovery.recovery_watermark());
    try recovery.truncate(0);
    for (0..13) |i| try recovery.append(test_digest(100 + i));
    var journal = try recovery.publish(13);
    try journal.sync();
    journal.deinit();
    journal = try h.open(Digest);
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 13), journal.get_bounds());
    for (0..13) |i| try testing.expectEqual(test_digest(100 + i), try journal.read(i));
}

// A bounded publication raises the watermark to the retained end, so the rebuilt tail must
// be durable before the raise.
test "fixed: bounded publish syncs the rebuilt tail before raising the watermark" {
    var h = try Harness.init(.{});
    defer h.deinit();
    {
        var recovery = try h.recovery(Digest, 7);
        try recovery.truncate(0);
        for (0..7) |i| try recovery.append(test_digest(i));
        var journal = try recovery.publish(7);
        defer journal.deinit();
        try testing.expectEqual(7, journal.size());
        try testing.expectEqual(7, journal.recovery_watermark());
    }
    h.storage.crash();
    var journal = try h.open(Digest);
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 7), journal.get_bounds());
    for (0..7) |i| try testing.expectEqual(test_digest(i), try journal.read(i));
}

test "fixed: init at most survives restart and append" {
    for ([_]u64{ 0, 7 }) |start| {
        for ([_]u64{ 0, 1, 5, 7, 8, 10, 13, 20, max }) |cap| {
            var h = try Harness.init(.{});
            defer h.deinit();
            try h.seed_integers(start, 13);
            try check_restart_and_append(&h, start, cap);
        }
    }
}

fn check_restart_and_append(h: *Harness, start: u64, cap: u64) !void {
    if (cap < start) {
        try testing.expectError(error.ItemPruned, h.open_at_most(u64, cap));
        var journal = try h.open(u64);
        defer journal.deinit();
        try testing.expectEqual(bounds(start, 13), journal.get_bounds());
        return;
    }
    const end: u64 = @min(cap, 13);
    var journal = try h.open_at_most(u64, cap);
    try testing.expectEqual(bounds(start, end), journal.get_bounds());
    for (start..end) |value| try testing.expectEqual(value, try journal.read(value));
    journal.deinit();
    // Opening alone durably establishes the selected prefix.
    journal = try h.open(u64);
    try testing.expectEqual(bounds(start, end), journal.get_bounds());
    for (end..end + 8) |value| try testing.expectEqual(value, try journal.append(value + 100));
    try journal.sync();
    journal.deinit();
    journal = try h.open(u64);
    defer journal.deinit();
    for (start..end + 8) |value| {
        const expected = if (value < end) value else value + 100;
        try testing.expectEqual(expected, try journal.read(value));
    }
}

// A damaged blob above the cap is discarded unread.
test "fixed: init at most skips discarded blobs" {
    var h = try Harness.init(.{});
    defer h.deinit();
    try h.seed_integers(0, 23);
    try h.resize_blob(3, 1);
    var journal = try h.open_at_most(u64, 7);
    try testing.expectEqual(bounds(0, 7), journal.get_bounds());
    journal.deinit();
    journal = try h.open(u64);
    defer journal.deinit();
    try testing.expectEqual(bounds(0, 7), journal.get_bounds());
}

/// A journal over fault-injecting storage, for bounded opens that fail partway.
const FaultyHarness = struct {
    const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

    inner: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    storage: Faulty,
    cache_ref: paged.CacheRef,

    fn init(self: *FaultyHarness) !void {
        self.inner = .init(gpa);
        self.rng = .init(0);
        self.storage = .init(gpa, &self.inner, &self.rng, .{});
        self.cache_ref = try paged.CacheRef.init(gpa, 44, 3);
    }

    fn deinit(self: *FaultyHarness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
        self.inner.deinit();
    }

    fn cfg(self: *FaultyHarness) fixed.Config {
        return .{
            .partition = "test-partition",
            .items_per_blob = 5,
            .cache_ref = &self.cache_ref,
            .write_buffer = 2048,
            .replay_buffer = 2048,
        };
    }

    fn open(self: *FaultyHarness, cap: ?u64) !fixed.Journal(u64) {
        const storage = self.storage.storage();
        if (cap) |c| return fixed.Journal(u64).init_at_most(gpa, storage, self.cfg(), c);
        return fixed.Journal(u64).init(gpa, storage, self.cfg());
    }

    fn crash(self: *FaultyHarness) !void {
        try self.storage.crash();
        self.inner.crash();
    }
};

// A bounded open that fails on a sync, remove, or resize fault at rates from 10% to 100%
// leaves storage a later bounded or ordinary open recovers to the same prefix.
test "fixed: bounded initialization retries after storage faults" {
    for ([_]u64{ 0, 7 }) |start| {
        for (0..3) |kind| {
            for ([_]u64{ 1, 3, 7, 10 }) |numerator| {
                try check_fault_retry(start, kind, utils.Probability.init(numerator, 10).?);
            }
        }
    }
}

fn check_fault_retry(start: u64, kind: usize, rate: utils.Probability) !void {
    var h: FaultyHarness = undefined;
    try h.init();
    defer h.deinit();
    {
        const storage = h.storage.storage();
        var journal = try fixed.Journal(u64).init_at_size(gpa, storage, h.cfg(), start);
        defer journal.deinit();
        for (start..13) |value| _ = try journal.append(value);
        try journal.sync();
    }
    h.storage.config = .{
        .sync_rate = if (kind == 0) rate else null,
        .remove_rate = if (kind == 1) rate else null,
        .resize_rate = if (kind == 2) .{ .failure_rate = rate, .partial_rate = rate } else null,
    };
    const succeeded = if (h.open(7)) |opened| ok: {
        var journal = opened;
        journal.deinit();
        break :ok true;
    } else |_| false;
    try h.crash();
    h.storage.config = .{};
    if (succeeded) {
        var journal = try h.open(null);
        defer journal.deinit();
        try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    }
    var journal = try h.open(7);
    try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    for (start..7) |value| try testing.expectEqual(value, try journal.read(value));
    journal.deinit();
    journal = try h.open(null);
    try testing.expectEqual(bounds(start, 7), journal.get_bounds());
    _ = try journal.append(99);
    try journal.sync();
    journal.deinit();
    journal = try h.open(null);
    defer journal.deinit();
    try testing.expectEqual(bounds(start, 8), journal.get_bounds());
    try testing.expectEqual(99, try journal.read(7));
}
