//! A writer that buffers content at the tip of a blob (commonware's `buffer/write.rs`).
//!
//! Writes that fall within `[tip offset, tip offset + capacity)` merge into the tip buffer;
//! others flush the tip as needed and go to the blob directly. Reads see buffered data.
//! `sync` flushes the tip and makes every accepted write durable.
//!
//! A `Write` owns its blob and closes it in `deinit`. Mutating methods leave the writer failed
//! after an error (commonware consumes it); only `deinit` may follow.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage = @import("../storage.zig");
const SyncState = @import("mod.zig").SyncState;
const Tip = @import("tip.zig").Buffer;

const Blob = storage.Blob;
pub const Error = storage.Error;

pub const Write = struct {
    blob: Blob,
    buffer: Tip,
    gpa: Allocator,
    /// Freshly opened blobs may hold unsynced writes from an earlier handle.
    sync_state: SyncState = .dirty,
    failed: bool = false,

    /// Wrap `blob` (holding `len` bytes) with a tip buffer of `capacity` bytes. On error the
    /// caller still owns `blob`.
    pub fn init(gpa: Allocator, blob: Blob, len: u64, capacity: usize) Allocator.Error!Write {
        assert(capacity > 0);
        const buffer = try Tip.init(gpa, len, capacity);
        assert(buffer.size() == len);
        return .{ .blob = blob, .buffer = buffer, .gpa = gpa };
    }

    /// Close the blob (dropping unsynced bytes) and free the buffer.
    pub fn deinit(self: *Write) void {
        self.sync_state.deinit();
        self.blob.close();
        self.buffer.deinit(self.gpa);
        self.* = undefined;
    }

    /// The logical size of the blob including buffered data.
    pub fn size(self: *const Write) u64 {
        return self.buffer.size();
    }

    /// Whether `sync` would write buffered bytes or sync the blob.
    pub fn needs_sync(self: *const Write) bool {
        return !self.buffer.is_empty() or !self.sync_state.is_clean();
    }

    /// Read exactly `buf.len` bytes at `offset`, including buffered data.
    pub fn read_at(self: *Write, offset: u64, buf: []u8) Error!void {
        const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
        if (end > self.buffer.size()) return error.BlobInsufficientLength;
        if (buf.len == 0) return;
        const tip_offset = self.buffer.offset;
        if (offset >= tip_offset) {
            const start: usize = @intCast(offset - tip_offset);
            @memcpy(buf, self.buffer.bytes()[start..][0..buf.len]);
            return;
        }
        if (end <= tip_offset) return self.blob.read_at(offset, buf);
        const blob_len: usize = @intCast(tip_offset - offset);
        @memcpy(buf[blob_len..], self.buffer.bytes()[0 .. buf.len - blob_len]);
        try self.blob.read_at(offset, buf[0..blob_len]);
    }

    /// Merge `bytes` at `offset` into the tip buffer if they fit without I/O.
    pub fn try_write_at(self: *Write, offset: u64, bytes: []const u8) bool {
        assert(!self.failed);
        if (bytes.len == 0) return true;
        _ = std.math.add(u64, offset, bytes.len) catch return false;
        return self.buffer.merge(bytes, offset);
    }

    /// Write `bytes` at `offset`.
    pub fn write_at(self: *Write, offset: u64, bytes: []const u8) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        const end = std.math.add(u64, offset, bytes.len) catch return error.OffsetOverflow;
        if (bytes.len == 0) return;
        if (self.buffer.merge(bytes, offset)) return;
        // Flush an overlapping or preceding tip, then try buffering again.
        if (self.buffer.offset < end) {
            if (self.buffer.take()) |taken| {
                const old, const old_offset = taken;
                try self.sync_state.write_at(self.blob, old_offset, old, false);
                if (self.buffer.merge(bytes, offset)) return;
            }
        }
        try self.sync_state.write_at(self.blob, offset, bytes, false);
        self.buffer.offset = @max(self.buffer.offset, end);
        assert(self.buffer.size() >= end);
    }

    /// Resize the blob to `len`, flushing buffered data that a grow keeps.
    pub fn resize(self: *Write, len: u64) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        if (self.buffer.resize(len)) |flushed| {
            const data, const offset = flushed;
            try self.sync_state.write_at(self.blob, offset, data, false);
        }
        try self.sync_state.resize(self.blob, len);
        assert(self.size() == len);
    }

    /// Flush buffered data and make every accepted write durable.
    pub fn sync(self: *Write) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        if (self.buffer.take()) |taken| {
            const data, const offset = taken;
            try self.sync_state.write_at(self.blob, offset, data, true);
        } else {
            try self.sync_state.sync(self.blob);
        }
        assert(!self.needs_sync());
    }

    /// Flush buffered data and start making every accepted write durable, returning a
    /// completion (one reference, owned by the caller). Waiting on it gives `sync`'s guarantee
    /// for the state flushed by this call. Later `sync`s and blob mutations first wait for it;
    /// its failure is reported by the completion and by the next such call. Flush errors are
    /// returned directly.
    pub fn start_sync(self: *Write) Error!storage.Completion {
        assert(!self.failed);
        errdefer self.failed = true;
        if (self.buffer.take()) |taken| {
            const data, const offset = taken;
            try self.sync_state.write_at(self.blob, offset, data, false);
        }
        assert(self.buffer.is_empty());
        return self.sync_state.start_sync(self.blob);
    }

    /// Wait for an outstanding `start_sync` (commonware `wait_for_sync`).
    pub fn wait_for_sync(self: *Write) Error!void {
        assert(!self.failed);
        errdefer self.failed = true;
        try self.sync_state.wait_for_pending();
        assert(self.sync_state != .pending);
    }

    /// Durably shorten to `len` (a section buffer's truncate). A larger `len` changes nothing.
    pub fn truncate(self: *Write, len: u64) Error!void {
        if (len >= self.size()) return;
        try self.resize(len);
        try self.sync();
    }
};

const testing = std.testing;
const mocks = @import("mocks.zig");

const Harness = struct {
    storage: mocks.Storage,

    fn writer(self: *Harness, name: []const u8, capacity: usize) !Write {
        const opened = try self.storage.open("partition", name);
        errdefer opened.blob.close();
        return Write.init(testing.allocator, opened.blob, opened.len, capacity);
    }

    /// The durable contents of `name`, read through a fresh handle. Caller frees.
    fn contents(self: *Harness, name: []const u8) ![]u8 {
        const opened = try self.storage.open("partition", name);
        defer opened.blob.close();
        const buf = try testing.allocator.alloc(u8, @intCast(opened.len));
        errdefer testing.allocator.free(buf);
        try opened.blob.read_at(0, buf);
        return buf;
    }

    fn durable(self: *Harness, name: []const u8) !?u64 {
        return self.storage.durable_len("partition", name);
    }

    fn expect(self: *Harness, name: []const u8, expected: []const u8) !void {
        const actual = try self.contents(name);
        defer testing.allocator.free(actual);
        try testing.expectEqualSlices(u8, expected, actual);
    }
};

fn harness() Harness {
    return .{ .storage = mocks.Storage.init(testing.allocator) };
}

test "write basic, multiple flushes, and large data" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("basic", 8);
    try w.write_at(0, "hello");
    try testing.expectEqual(@as(u64, 5), w.size());
    try w.sync();
    try testing.expectEqual(@as(u64, 5), w.size());
    w.deinit();
    try h.expect("basic", "hello");

    w = try h.writer("multi", 4);
    try w.write_at(0, "abc");
    try w.write_at(3, "defg");
    try testing.expectEqual(@as(u64, 7), w.size());
    try w.sync();
    w.deinit();
    try h.expect("multi", "abcdefg");

    w = try h.writer("large", 4);
    try w.write_at(0, "abc");
    try w.write_at(3, "defghijklmnopqrstuvwxyz");
    try testing.expectEqual(@as(u64, 26), w.size());
    try w.sync();
    w.deinit();
    try h.expect("large", "abcdefghijklmnopqrstuvwxyz");

    w = try h.writer("append", 10);
    try w.write_at(0, "hello");
    try w.write_at(5, " world");
    try w.sync();
    try testing.expectEqual(@as(u64, 11), w.size());
    w.deinit();
    try h.expect("append", "hello world");
}

test "write into the middle of and before the buffer" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("middle", 20);
    try w.write_at(0, "abcdefghij");
    try w.write_at(2, "01234");
    try testing.expectEqual(@as(u64, 10), w.size());
    try w.sync();
    w.deinit();
    try h.expect("middle", "ab01234hij");
    w = try h.writer("middle", 20);
    try w.write_at(10, "klmnopqrst");
    try w.write_at(9, "wxyz");
    try testing.expectEqual(@as(u64, 20), w.size());
    try w.sync();
    w.deinit();
    try h.expect("middle", "ab01234hiwxyznopqrst");

    w = try h.writer("before", 10);
    try w.write_at(10, "0123456789");
    try w.write_at(0, "abcde");
    try testing.expectEqual(@as(u64, 20), w.size());
    try w.sync();
    w.deinit();
    var expected: [20]u8 = @splat(0);
    @memcpy(expected[0..5], "abcde");
    @memcpy(expected[10..20], "0123456789");
    try h.expect("before", &expected);
    w = try h.writer("before", 10);
    try w.write_at(5, "fghij");
    try w.sync();
    w.deinit();
    @memcpy(expected[0..10], "abcdefghij");
    try h.expect("before", &expected);
}

test "write resize" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("resize", 10);
    try w.write_at(0, "hello world");
    try w.sync();
    w.deinit();
    w = try h.writer("resize", 10);
    try w.resize(5);
    try testing.expectEqual(@as(u64, 5), w.size());
    try w.sync();
    w.deinit();
    try h.expect("resize", "hello");
    w = try h.writer("resize", 10);
    try w.write_at(0, "X");
    try testing.expectEqual(@as(u64, 5), w.size());
    try w.sync();
    w.deinit();
    try h.expect("resize", "Xello");
    w = try h.writer("resize", 10);
    try w.resize(10);
    try w.sync();
    w.deinit();
    try h.expect("resize", "Xello" ++ [_]u8{ 0, 0, 0, 0, 0 });

    w = try h.writer("zero", 10);
    try w.write_at(0, "some data");
    try w.sync();
    try w.resize(0);
    try testing.expectEqual(@as(u64, 0), w.size());
    try w.sync();
    w.deinit();
    try h.expect("zero", "");
}

test "write resize grow flushes buffered data" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("grow", 10);
    defer w.deinit();
    try w.write_at(0, "hello");
    try w.resize(10);
    try w.sync();
    var read: [5]u8 = undefined;
    try w.read_at(0, &read);
    try testing.expectEqualStrings("hello", &read);
}

test "write read at on the writer" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("read", 10);
    try w.write_at(0, "buffered");
    var four: [4]u8 = undefined;
    try w.read_at(0, &four);
    try testing.expectEqualStrings("buff", &four);
    try w.read_at(4, &four);
    try testing.expectEqualStrings("ered", &four);
    var one: [1]u8 = undefined;
    try testing.expectError(error.BlobInsufficientLength, w.read_at(8, &one));
    try w.write_at(8, " and flushed");
    try testing.expectEqual(@as(u64, 20), w.size());
    try w.sync();
    try w.read_at(0, &four);
    try testing.expectEqualStrings("buff", &four);
    var seven: [7]u8 = undefined;
    try w.read_at(13, &seven);
    try testing.expectEqualStrings("flushed", &seven);
    try w.write_at(20, " more data");
    try testing.expectEqual(@as(u64, 30), w.size());
    var five: [5]u8 = undefined;
    try w.read_at(20, &five);
    try testing.expectEqualStrings(" more", &five);
    // A read across the blob and the buffer.
    var combo: [12]u8 = undefined;
    try w.read_at(16, &combo);
    try testing.expectEqualStrings("shed more da", &combo);
    try w.sync();
    w.deinit();
    try h.expect("read", "buffered and flushed more data");
}

test "write zero-length read past the end errors" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("probe", 8);
    defer w.deinit();
    try w.write_at(0, "abc");
    try w.read_at(3, &.{});
    try testing.expectError(error.BlobInsufficientLength, w.read_at(4, &.{}));
}

test "write try write at merges only when it fits" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("try", 4);
    defer w.deinit();
    try testing.expect(w.try_write_at(0, "ab"));
    try testing.expect(w.try_write_at(2, "cd"));
    try testing.expect(!w.try_write_at(4, "e"));
    try testing.expect(w.try_write_at(9, ""));
    try testing.expect(!w.try_write_at(std.math.maxInt(u64), "x"));
    try testing.expectEqual(@as(u64, 4), w.size());
    try testing.expectEqual(@as(u64, 0), h.storage.writes);
}

test "write needs sync tracks sync work" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("needs", 4);
    defer w.deinit();
    // A fresh writer may hold another handle's unsynced writes.
    try testing.expect(w.needs_sync());
    try w.sync();
    try testing.expect(!w.needs_sync());
    try w.write_at(0, "ab");
    try testing.expect(w.needs_sync());
    // A started sync needs observation even after it completes.
    const started = try w.start_sync();
    try started.wait();
    started.release();
    try testing.expect(w.needs_sync());
    try w.wait_for_sync();
    try testing.expect(!w.needs_sync());
    // A direct write leaves the blob dirty with an empty buffer.
    try w.write_at(0, "0123456789");
    try testing.expect(w.needs_sync());
    try w.sync();
    try testing.expect(!w.needs_sync());
    try w.resize(3);
    try testing.expect(w.needs_sync());
}

test "write truncate is durable and ignores growth" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("truncate", 4);
    try w.write_at(0, "abcdef");
    try w.truncate(10);
    try testing.expectEqual(@as(u64, 6), w.size());
    try w.truncate(2);
    try testing.expect(!w.needs_sync());
    h.storage.crash();
    w.deinit();
    try h.expect("truncate", "ab");
}

test "write straddling a gap and an overlap that cannot merge" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("write_straddle", 10);
    try w.write_at(0, "0123456789");
    try w.write_at(15, "abc");
    try testing.expectEqual(@as(u64, 18), w.size());
    try w.sync();
    w.deinit();
    try h.expect("write_straddle", "0123456789\x00\x00\x00\x00\x00abc");
    w = try h.writer("write_straddle2", 10);
    try w.write_at(0, "0123456789");
    try w.write_at(5, "ABCDEFGHIJKL");
    try testing.expectEqual(@as(u64, 17), w.size());
    try w.sync();
    w.deinit();
    try h.expect("write_straddle2", "01234ABCDEFGHIJKL");
}

test "write close, direct writes, and an in-buffer overwrite that extends" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("write_close", 8);
    try w.write_at(0, "pending");
    try w.sync();
    w.deinit();
    try h.expect("write_close", "pending");
    // Larger than the buffer: written directly.
    w = try h.writer("write_direct_size", 5);
    try w.write_at(0, "0123456789");
    try w.sync();
    w.deinit();
    try h.expect("write_direct_size", "0123456789");
    w = try h.writer("write_direct_size", 5);
    try w.write_at(10, "abc");
    try testing.expectEqual(@as(u64, 13), w.size());
    var small: [3]u8 = undefined;
    try w.read_at(10, &small);
    try testing.expectEqualStrings("abc", &small);
    try w.sync();
    w.deinit();
    try h.expect("write_direct_size", "0123456789abc");
    w = try h.writer("overwrite_extend_buf", 15);
    try w.write_at(0, "0123456789");
    try w.write_at(5, "ABCDEFGHIJ");
    try testing.expectEqual(@as(u64, 15), w.size());
    var all: [15]u8 = undefined;
    try w.read_at(0, &all);
    try testing.expectEqualStrings("01234ABCDEFGHIJ", &all);
    try w.sync();
    w.deinit();
    try h.expect("overwrite_extend_buf", "01234ABCDEFGHIJ");
}

test "write appends at the size after syncs, gaps, and a resize" {
    var h = harness();
    defer h.storage.deinit();
    var w = try h.writer("write_multiple_appends_at_size", 5);
    for ([_][]const u8{ "AAA", "BBB", "CCC" }) |chunk| {
        try w.write_at(w.size(), chunk);
        try w.sync();
    }
    try testing.expectEqual(@as(u64, 9), w.size());
    w.deinit();
    try h.expect("write_multiple_appends_at_size", "AAABBBCCC");
    w = try h.writer("write_non_contiguous_then_append", 10);
    try w.write_at(0, "INITIAL");
    try w.write_at(20, "NONCONTIG");
    try testing.expectEqual(@as(u64, 29), w.size());
    try w.sync();
    try w.write_at(w.size(), "APPEND");
    try testing.expectEqual(@as(u64, 35), w.size());
    try w.sync();
    w.deinit();
    var expected: [35]u8 = @splat(0);
    expected[0..7].* = "INITIAL".*;
    expected[20..29].* = "NONCONTIG".*;
    expected[29..35].* = "APPEND".*;
    try h.expect("write_non_contiguous_then_append", &expected);
    w = try h.writer("resize_then_append_at_size", 10);
    try w.write_at(0, "0123456789ABCDEF");
    try w.sync();
    try w.resize(5);
    try w.sync();
    try testing.expectEqual(@as(u64, 5), w.size());
    try w.write_at(w.size(), "XXXXX");
    try w.sync();
    try testing.expectEqual(@as(u64, 10), w.size());
    w.deinit();
    try h.expect("resize_then_append_at_size", "01234XXXXX");
}

test "write sync persists a mutation made before wrapping and earlier direct flushes" {
    var h = harness();
    defer h.storage.deinit();
    {
        const opened = try h.storage.open("partition", "pre_wrapped");
        try opened.blob.write_at(0, "abc", .{});
        var w = Write.init(testing.allocator, opened.blob, 3, 8) catch |err| {
            opened.blob.close();
            return err;
        };
        defer w.deinit();
        // A fresh writer starts dirty, so its first sync covers the unsynced "abc".
        try w.sync();
        try testing.expectEqual(@as(?u64, 3), try h.durable("pre_wrapped"));
        try w.write_at(3, "d");
        try w.sync();
    }
    try h.expect("pre_wrapped", "abcd");
    var w = try h.writer("direct_then_tip", 4);
    defer w.deinit();
    try w.write_at(0, "abcdef");
    try w.write_at(6, "g");
    const writes = h.storage.writes;
    try w.sync();
    try testing.expectEqual(@as(?u64, 7), try h.durable("direct_then_tip"));
    // A clean writer's sync writes nothing more.
    try w.sync();
    try testing.expectEqual(writes + 1, h.storage.writes);
    try w.write_at(7, "h");
    try w.sync();
    try testing.expectEqual(@as(?u64, 8), try h.durable("direct_then_tip"));
}
