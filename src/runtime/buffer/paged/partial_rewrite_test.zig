//! commonware's `test_replay_preserves_tail_during_partial_page_rewrite` (`paged/sealed.rs`):
//! a replay captured before a partial-page rewrite keeps its frozen tail while the rewrite's
//! write is torn on disk. `SplitBlob` (commonware `SplitWriteBlob`) writes a paused write's
//! prefix, parks it, and writes the rest once the test resumes it; the flushing call runs as
//! a spawned task on the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const iface = @import("../../storage.zig");
const memory = @import("../../storage/memory.zig");
const deterministic = @import("../../deterministic.zig");
const paged = @import("mod.zig");

const gpa = testing.allocator;
const Context = deterministic.Context;
const Completion = iface.Completion;
const page_size: usize = 103;
const physical_page_size: usize = page_size + paged.checksum_size;
const buffer_size: usize = page_size * 2;
/// Bytes of a checksum slot's length field (commonware `CHECKSUM_SLOT_LEN_SIZE`).
const slot_len_size: usize = 2;
const durable_tail: usize = 3;
const snapshot_tail: usize = 7;

const Pause = struct {
    offset: u64,
    prefix_len: usize,
    started: Completion,
    resume_write: Completion,
};

/// Exposes a write's prefix while its remaining bytes are still pending.
const SplitBlob = struct {
    inner: iface.Blob,
    pause: ?Pause = null,

    const vtable: iface.Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
        .start_sync = start_sync,
    };

    fn blob(self: *SplitBlob) iface.Blob {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn from(ptr: *anyopaque) *SplitBlob {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(
        ptr: *anyopaque,
        offset: u64,
        buf: []u8,
        options: iface.ReadOptions,
    ) iface.Error!void {
        return from(ptr).inner.read_at_options(offset, buf, options);
    }

    fn write_at(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) iface.Error!void {
        const self = from(ptr);
        const pause = self.pause orelse
            return self.inner.write_at_vectored(offset, chunks, options);
        self.pause = null;
        assert(offset == pause.offset);
        const bytes = std.mem.concat(gpa, u8, chunks) catch return error.Io;
        defer gpa.free(bytes);
        assert(pause.prefix_len < bytes.len);
        try self.inner.write_at(offset, bytes[0..pause.prefix_len], options);
        pause.started.finish({});
        try pause.resume_write.wait();
        try self.inner.write_at(offset + pause.prefix_len, bytes[pause.prefix_len..], options);
    }

    fn resize(ptr: *anyopaque, length: u64) iface.Error!void {
        return from(ptr).inner.resize(length);
    }

    fn sync(ptr: *anyopaque) iface.Error!void {
        return from(ptr).inner.sync();
    }

    fn start_sync(ptr: *anyopaque) iface.Error!Completion {
        return from(ptr).inner.start_sync();
    }

    fn close(ptr: *anyopaque) void {
        from(ptr).inner.close();
    }
};

const Case = struct { full_pages: usize, next_len: usize, sync_snapshot: bool };

fn fill(list: *std.ArrayList(u8), byte: u8, len: usize) ![]const u8 {
    const start = list.items.len;
    try list.appendNTimes(gpa, byte, len);
    return list.items[start..];
}

/// The active checksum of the physical page at `offset`, read from the raw blob.
fn active_checksum(split: *SplitBlob, offset: u64) !paged.ActiveChecksum {
    var page: [physical_page_size]u8 = undefined;
    try split.inner.read_at(offset, &page);
    return paged.Checksum.validate_page(&page) orelse error.InvalidChecksum;
}

fn drain(replay: *paged.Replay) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (try replay.ensure(1)) {
        const chunk = replay.bytes();
        try out.appendSlice(gpa, chunk);
        replay.advance(chunk.len);
    }
    return out.toOwnedSlice(gpa);
}

fn flushing_replay(ctx: Context, writer: *paged.Writer, out: *?paged.Replay) anyerror!void {
    _ = ctx;
    out.* = try writer.replay(buffer_size, .{});
}

/// Persist a short partial page, extend it without advancing its durable slot, snapshot it,
/// and write the extension to disk unsynced. Returns the checksum slot the next flush of
/// the partial page rewrites.
fn prepare(
    split: *SplitBlob,
    writer: *paged.Writer,
    expected: *std.ArrayList(u8),
    case: Case,
) !paged.Slot {
    _ = try writer.append(try fill(expected, 0xAA, case.full_pages * page_size + durable_tail));
    try writer.sync();
    _ = try writer.append(try fill(expected, 0xBB, snapshot_tail - durable_tail));
    var flushed = try writer.replay(buffer_size, .{});
    flushed.deinit();
    // The synced control has a durable fallback that already includes the snapshot.
    if (case.sync_snapshot) try writer.sync();
    const active = try active_checksum(split, case.full_pages * physical_page_size);
    try testing.expectEqual(@as(u16, snapshot_tail), active.len);
    return if (case.sync_snapshot) active.slot.other() else active.slot;
}

fn preserves_tail(ctx: Context, case: Case, writer_replay: bool) !void {
    var storage = memory.Storage.init(gpa);
    defer storage.deinit();
    var cache_ref = try paged.CacheRef.init(gpa, page_size, buffer_size);
    defer cache_ref.deinit();
    const opened = try storage.storage().open("snapshot-replay-race", "blob");
    var split: SplitBlob = .{ .inner = opened.blob };
    var writer = try paged.Writer.init(gpa, split.blob(), opened.len, buffer_size, &cache_ref);
    defer writer.deinit();
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);
    const offset = case.full_pages * physical_page_size;
    const rewritten_slot = try prepare(&split, &writer, &expected, case);
    var snapshot = try writer.snapshot();
    defer snapshot.deinit();
    // Capture the replay before the rewrite, including its frozen partial tail.
    var replay = if (writer_replay)
        try writer.replay(buffer_size, .{})
    else
        try snapshot.replay(buffer_size, .{});
    defer replay.deinit();
    const replay_len = expected.items.len;
    try testing.expectEqual(@as(u64, replay_len), replay.blob_size());
    // A short backend write exposes the new slot length before its CRC, while the other slot
    // still validates the durable prefix.
    var extension: std.ArrayList(u8) = .empty;
    defer extension.deinit(gpa);
    _ = try writer.append(try fill(&extension, 0xCC, case.next_len - snapshot_tail));
    const started = try Completion.init_pending(gpa, ctx.io());
    defer started.release();
    const resume_write = try Completion.init_pending(gpa, ctx.io());
    defer resume_write.release();
    split.pause = .{
        .offset = offset,
        .prefix_len = page_size + rewritten_slot.offset() + slot_len_size,
        .started = started,
        .resume_write = resume_write,
    };
    var flushed: ?paged.Replay = null;
    const handle = try ctx.child("flushing").spawn(flushing_replay, .{ &writer, &flushed });
    try started.wait();
    try testing.expect(flushed == null);
    // Inspect the paused disk image and both read paths before the write can finish.
    const fallback_len = (try active_checksum(&split, offset)).len;
    const read = try gpa.alloc(u8, replay_len);
    defer gpa.free(read);
    try snapshot.read_at(0, read);
    const replayed = drain(&replay);
    defer if (replayed) |bytes| gpa.free(bytes) else |_| {};
    resume_write.finish({});
    try try handle.join();
    flushed.?.deinit();
    try writer.sync();
    const fallback: usize = if (case.sync_snapshot) snapshot_tail else durable_tail;
    try testing.expectEqual(fallback, fallback_len);
    try testing.expectEqualSlices(u8, expected.items, read);
    try testing.expectEqualSlices(u8, expected.items[0..replay_len], try replayed);
}

test "sealed: replay preserves its tail during a partial-page rewrite" {
    // The rstest cases: partial, page_boundary, next_page, and synced_snapshot, each with the
    // writer's and the snapshot's replay.
    const cases = [_]Case{
        .{ .full_pages = 0, .next_len = 13, .sync_snapshot = false },
        .{ .full_pages = 1, .next_len = page_size, .sync_snapshot = false },
        .{ .full_pages = 1, .next_len = page_size + 7, .sync_snapshot = false },
        .{ .full_pages = 1, .next_len = 13, .sync_snapshot = true },
    };
    for (cases) |case| {
        for ([_]bool{ false, true }) |writer_replay| {
            var runner = try deterministic.Runner.init(gpa, .{});
            defer runner.deinit();
            try (try runner.start_context(preserves_tail, .{ case, writer_replay }));
        }
    }
}
