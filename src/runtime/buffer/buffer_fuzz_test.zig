//! Buffered blob wrappers under arbitrary operation sequences (commonware
//! `runtime/fuzz/fuzz_targets/buffer.rs`): a `Read`, a `Write`, and a paged `Writer` share one
//! storage and page cache while random operations create, read, write, resize, sync,
//! recover, replay, and poison the cache. Beyond commonware's checks (no crash, and replay of
//! uncorrupted data succeeds), each wrapper is held to what it promises: the reader returns
//! the blob's bytes or fails without moving, a write or append reads back at once, and a
//! paged replay returns the same bytes as `read_at`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const utils = @import("utils");
const memory = @import("../storage/memory.zig");
const buffer = @import("mod.zig");
const paged = @import("paged/mod.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const Storage = memory.Storage;
const Read = buffer.Read;
const Write = buffer.Write;
const Writer = paged.Writer;
const CacheRef = paged.CacheRef;
const gpa = testing.allocator;

const partition = "test_partition";
const size_max = 1024 * 1024;
const cache_bytes_max = 4 * 1024 * 1024;
const operations_max = 50;
/// Drawn data is at most this long (commonware's arbitrary `Vec<u8>` is input-bounded).
const data_max = 2048;
/// Fuzzed cache ids sit above every real blob id, so poisoned pages never shadow a writer's
/// data (commonware only checks for crashes, so it may let them collide).
const poison_id_base: u64 = 1 << 32;

const Operation = enum {
    create_read,
    create_write,
    create_append,
    read,
    read_seek_to,
    read_resize,
    write_at,
    write_resize,
    write_sync,
    append_data,
    append_reopen_at_most,
    append_sync,
    page_cache,
    read_position,
    read_buffer_remaining,
    read_blob_remaining,
    read_blob_size,
    write_size,
    write_read_at,
    append_size,
    append_as_reader,
    append_read_at,
};

fn pattern(out: []u8) void {
    for (out, 0..) |*byte, index| byte.* = @truncate(index);
}

fn draw_data(r: *FuzzRng) ![]u8 {
    const data = try gpa.alloc(u8, rng.range_at_most(r, usize, 0, data_max));
    r.fill_bytes(data);
    return data;
}

const State = struct {
    storage: Storage,
    cache: ?CacheRef = null,
    reader: ?Read = null,
    /// The read blob's live and durable contents (closing a handle discards unsynced
    /// writes), and the size its reader was given.
    read_model: std.ArrayList(u8) = .empty,
    read_durable: std.ArrayList(u8) = .empty,
    read_size: u64 = 0,
    writer: ?Write = null,
    append: ?Writer = null,

    fn deinit(state: *State) void {
        if (state.reader) |*reader| reader.deinit();
        if (state.writer) |*writer| writer.deinit();
        if (state.append) |*append| append.deinit();
        if (state.cache) |*cache| cache.deinit();
        state.read_model.deinit(gpa);
        state.read_durable.deinit(gpa);
        state.storage.deinit();
    }

    fn create_read(state: *State, blob_size: u16, buffer_size: u16) !void {
        if (state.reader) |*reader| reader.deinit();
        state.reader = null;
        state.read_model.clearRetainingCapacity();
        try state.read_model.appendSlice(gpa, state.read_durable.items);
        const opened = try state.storage.open(partition, "read_blob");
        errdefer opened.blob.close();
        try testing.expectEqual(@as(u64, state.read_durable.items.len), opened.len);
        if (opened.len == 0 and blob_size > 0) {
            try state.read_model.resize(gpa, blob_size);
            pattern(state.read_model.items);
            try opened.blob.write_at(0, state.read_model.items, .{});
        }
        state.read_size = @min(blob_size, opened.len);
        state.reader = try Read.init(gpa, opened.blob, state.read_size, @max(buffer_size, 1));
    }

    fn read(state: *State, size: u16) !void {
        const reader = &(state.reader orelse return);
        const start = reader.position();
        const out = try gpa.alloc(u8, size);
        defer gpa.free(out);
        reader.read(out) catch |err| {
            try testing.expectEqual(error.BlobInsufficientLength, err);
            try testing.expect(start + size > state.read_size);
            try testing.expectEqual(start, reader.position());
            return;
        };
        try testing.expect(start + size <= state.read_size);
        const from: usize = @intCast(start);
        try testing.expectEqualSlices(u8, state.read_model.items[from..][0..size], out);
        try testing.expectEqual(start + size, reader.position());
    }

    fn read_seek_to(state: *State, position: u16) !void {
        const reader = &(state.reader orelse return);
        if (reader.seek_to(position)) {
            try testing.expectEqual(@as(u64, position), reader.position());
        } else |err| {
            try testing.expectEqual(error.BlobInsufficientLength, err);
            try testing.expect(position > state.read_size);
        }
    }

    fn read_resize(state: *State, new_size: u16) !void {
        const reader = &(state.reader orelse return);
        defer state.reader = null;
        try reader.resize(new_size); // Consumes the reader, even on error.
        const old = state.read_model.items.len;
        try state.read_model.resize(gpa, new_size);
        if (new_size > old) @memset(state.read_model.items[old..], 0);
        state.read_durable.clearRetainingCapacity();
        try state.read_durable.appendSlice(gpa, state.read_model.items);
    }

    fn read_accessors(state: *State) !void {
        const reader = &(state.reader orelse return);
        try testing.expect(reader.position() <= state.read_size);
        try testing.expectEqual(state.read_size - reader.position(), reader.blob_remaining());
        try testing.expect(reader.buffer_remaining() <= reader.buffer.len);
        try testing.expectEqual(state.read_size, reader.blob_size);
    }

    fn create_write(state: *State, initial_size: u16, capacity: u16) !void {
        if (state.writer) |*writer| writer.deinit();
        state.writer = null;
        const opened = try state.storage.open(partition, "write_blob");
        errdefer opened.blob.close();
        state.writer = try Write.init(gpa, opened.blob, initial_size, @max(capacity, 1));
    }

    fn write_at(state: *State, offset: u16, data: []const u8) !void {
        const writer = &(state.writer orelse return);
        const size = writer.size();
        writer.write_at(offset, data) catch return state.drop_writer();
        const end = if (data.len == 0) size else @max(size, @as(u64, offset) + data.len);
        try testing.expectEqual(end, writer.size());
        const back = try gpa.alloc(u8, data.len);
        defer gpa.free(back);
        writer.read_at(offset, back) catch return state.drop_writer();
        try testing.expectEqualSlices(u8, data, back);
    }

    fn write_resize(state: *State, new_size: u16) !void {
        const writer = &(state.writer orelse return);
        writer.resize(new_size) catch return state.drop_writer();
        try testing.expectEqual(@as(u64, new_size), writer.size());
    }

    fn write_sync(state: *State) !void {
        const writer = &(state.writer orelse return);
        writer.sync() catch return state.drop_writer();
        try testing.expect(!writer.needs_sync());
    }

    fn write_read_at(state: *State, size: u16, offset: u16) !void {
        const writer = &(state.writer orelse return);
        const out = try gpa.alloc(u8, size);
        defer gpa.free(out);
        // In bounds a read may still miss bytes the writer was told exist (initial_size).
        writer.read_at(offset, out) catch |err| {
            if (@as(u64, offset) + size > writer.size()) {
                try testing.expectEqual(error.BlobInsufficientLength, err);
            }
            return;
        };
        try testing.expect(@as(u64, offset) + size <= writer.size());
    }

    fn drop_writer(state: *State) void {
        state.writer.?.deinit();
        state.writer = null;
    }

    fn create_append(state: *State, r: *FuzzRng) !void {
        const buffer_size = rng.range_at_most(r, usize, 0, std.math.maxInt(u16));
        // Small pages exercise multi-page paths; any page size up to u16 stays reachable.
        const page_max: u16 = if (rng.boolean(r)) 256 else std.math.maxInt(u16);
        const page_size = rng.range_at_most(r, u16, 1, page_max);
        const cache_capacity = rng.range_at_most(r, u32, 1, 64);
        if (state.append) |*previous| {
            // Reopening requires exclusive ownership and a durable source tail.
            defer state.append = null;
            defer previous.deinit();
            previous.sync() catch return error.Stop;
        }
        // One cache for the run: the page size is part of the blob's CRC records.
        if (state.cache == null) {
            const capacity_max: u32 = @intCast(@max(cache_bytes_max / @as(u32, page_size), 1));
            state.cache = try CacheRef.init(gpa, page_size, @min(cache_capacity, capacity_max));
        }
        const opened = try state.storage.open(partition, "append_blob");
        // Half the opens claim the blob's real size, so recovery succeeds and appends run.
        const claimed = rng.range_at_most(r, u64, 0, std.math.maxInt(u16));
        const initial_size = if (rng.boolean(r)) opened.len else claimed;
        const cache = &state.cache.?;
        state.append = Writer.init(gpa, opened.blob, initial_size, buffer_size, cache) catch |err| {
            opened.blob.close();
            if (err == error.OutOfMemory) return err;
            return;
        };
    }

    fn append_data(state: *State, data: []const u8) !void {
        const append = &(state.append orelse return);
        const start = append.size();
        const offset = append.append(data) catch return error.Stop;
        try testing.expectEqual(start, offset);
        try testing.expectEqual(start + data.len, append.size());
        const back = try gpa.alloc(u8, data.len);
        defer gpa.free(back);
        try append.read_at(start, back);
        try testing.expectEqualSlices(u8, data, back);
    }

    fn append_reopen_at_most(state: *State, r: *FuzzRng) !void {
        const append = &(state.append orelse return);
        const size = append.size();
        // Half the targets fall inside the data, so recovery really shortens it.
        const below = rng.range_at_most(r, u64, 0, size);
        const new_size = if (rng.boolean(r)) below else draw_u16(r);
        {
            defer state.append = null;
            defer append.deinit();
            append.sync() catch return error.Stop;
        }
        const opened = try state.storage.open(partition, "append_blob");
        const cache = &state.cache.?;
        state.append = Writer.open_recovery(gpa, opened.blob, opened.len, size_max, cache) catch {
            opened.blob.close();
            return error.Stop;
        };
        const recovery = &state.append.?;
        recovery.truncate(new_size) catch return error.Stop;
        recovery.finish_recovery();
        try testing.expectEqual(@min(size, new_size), recovery.size());
    }

    fn append_sync(state: *State) !void {
        const append = &(state.append orelse return);
        append.sync() catch return error.Stop;
        try testing.expect(!append.needs_sync());
    }

    fn page_cache(state: *State, blob_id: u16, data: []const u8, offset: u16) void {
        const cache = &(state.cache orelse return);
        if (data.len < cache.page_size) return;
        const aligned = offset / cache.page_size * cache.page_size;
        const rest = cache.cache(poison_id_base + blob_id, data[0..cache.page_size], aligned);
        assert(rest == 0);
    }

    /// Uncorrupted data must replay, and replay the bytes `read_at` returns.
    fn append_as_reader(state: *State, buffer_size: u16) !void {
        const append = &(state.append orelse return);
        const size: usize = @intCast(append.size());
        const expected = try gpa.alloc(u8, size);
        defer gpa.free(expected);
        try append.read_at(0, expected);
        var replay = try append.replay(@max(buffer_size, 1), .{});
        defer replay.deinit();
        try testing.expectEqual(@as(u64, size), replay.blob_size());
        var done: usize = 0;
        while (try replay.ensure(1)) {
            const chunk = replay.bytes();
            try testing.expect(done + chunk.len <= size);
            try testing.expectEqualSlices(u8, expected[done..][0..chunk.len], chunk);
            done += chunk.len;
            replay.advance(chunk.len);
        }
        try testing.expectEqual(size, done);
    }

    fn append_read_at(state: *State, size: u16, offset: u16) !void {
        const append = &(state.append orelse return);
        if (size == 0) return;
        const out = try gpa.alloc(u8, size);
        defer gpa.free(out);
        if (@as(u64, offset) + size <= append.size()) return append.read_at(offset, out);
        try testing.expectError(error.BlobInsufficientLength, append.read_at(offset, out));
    }
};

fn prefill_shared(storage: *Storage, seed: u64) !void {
    const opened = try storage.open(partition, "shared_blob");
    defer opened.blob.close();
    const prefill: usize = @intCast(seed & 0x0fff);
    if (prefill == 0 or opened.len != 0) return;
    const data = try gpa.alloc(u8, prefill);
    defer gpa.free(data);
    pattern(data);
    try opened.blob.write_at(0, data, .{});
}

fn draw_u16(r: *FuzzRng) u16 {
    return rng.range_at_most(r, u16, 0, std.math.maxInt(u16));
}

fn step(state: *State, r: *FuzzRng, operation: Operation) !void {
    switch (operation) {
        .create_read => try state.create_read(draw_u16(r), draw_u16(r)),
        .create_write => try state.create_write(draw_u16(r), draw_u16(r)),
        .create_append => try state.create_append(r),
        .read => try state.read(draw_u16(r)),
        .read_seek_to => try state.read_seek_to(draw_u16(r)),
        .read_resize => try state.read_resize(draw_u16(r)),
        .write_at, .append_data, .page_cache => {
            const data = try draw_data(r);
            defer gpa.free(data);
            switch (operation) {
                .write_at => try state.write_at(draw_u16(r), data),
                .append_data => try state.append_data(data),
                .page_cache => state.page_cache(draw_u16(r), data, draw_u16(r)),
                else => unreachable,
            }
        },
        .write_resize => try state.write_resize(draw_u16(r)),
        .write_sync => try state.write_sync(),
        .append_reopen_at_most => try state.append_reopen_at_most(r),
        .append_sync => try state.append_sync(),
        .read_position,
        .read_buffer_remaining,
        .read_blob_remaining,
        .read_blob_size,
        => try state.read_accessors(),
        .write_size => if (state.writer) |*writer| assert(writer.size() >= writer.buffer.offset),
        .write_read_at => try state.write_read_at(draw_u16(r), draw_u16(r)),
        .append_size => {},
        .append_as_reader => try state.append_as_reader(draw_u16(r)),
        .append_read_at => try state.append_read_at(draw_u16(r), draw_u16(r)),
    }
}

fn fuzz_buffers(_: void, r: *FuzzRng) !void {
    var state: State = .{ .storage = .init(gpa) };
    defer state.deinit();
    try prefill_shared(&state.storage, r.next_u64());
    const count = rng.range_at_most(r, u8, 0, operations_max);
    for (0..count) |_| {
        const index = rng.range_less_than(r, u8, 0, std.enums.values(Operation).len);
        step(&state, r, @fromBackingInt(@intCast(index))) catch |err| {
            if (err == error.Stop) return;
            return err;
        };
    }
}

test "fuzz buffered blob wrappers" {
    const quiet = testing.log_level;
    testing.log_level = .err; // Recovery logs a warning when it trims a torn tail.
    defer testing.log_level = quiet;
    try utils.fuzz.run({}, fuzz_buffers, 0x6275_6666_6572, 200);
}
