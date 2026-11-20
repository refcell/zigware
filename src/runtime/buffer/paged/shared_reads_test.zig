//! commonware `paged/cache.rs`'s shared-read tests: readers that miss the same page share one
//! blob read once the cache shares reads (`CacheRef.share_reads`). They run on the deterministic
//! runtime over a blob whose page reads wait at a gate per page until the test opens it (their
//! `GatedBlob`, `ControlledBlob`, and `BlockingBlob`). Batched reads go through
//! `View.read_ranges_into` (commonware's `read_after_misses`), single page faults through
//! `View.read_at` (`read_after_miss`).
//!
//! One difference from commonware: there, every waiter drives a shared read future, so a
//! canceled first fetcher's read goes on for its followers. A canceled zigware read ends with
//! its task, so its followers read the page again, one of them for the rest
//! ("followers keep single flight": two reads, not one).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const mocks = @import("../mocks.zig");
const paged = @import("mod.zig");
const writer_mod = @import("writer.zig");
const storage_iface = @import("../../storage.zig");
const deterministic = @import("../../deterministic.zig");

const Blob = storage_iface.Blob;
const Error = paged.Error;
const CacheRef = paged.CacheRef;
const View = paged.View;
const gpa = testing.allocator;
const page_size: usize = 64;
const physical_page_size: usize = page_size + paged.checksum_size;
const pages_max = 32;

/// `pages` synced pages, page `i` full of byte `i`, behind a gate per page: a read waits until
/// every page it covers is open. Counts the reads that started of each page.
const Gated = struct {
    storage: mocks.Storage,
    inner: Blob,
    io: Io,
    pages: usize,
    gates: [pages_max]Io.Event = @splat(.unset),
    reads: [pages_max]u32 = @splat(0),
    /// A page whose reads return a corrupted page.
    corrupt: ?usize = null,
    /// A page whose reads fail with `ReadFailed`.
    failing: ?usize = null,
    /// How long each read takes once its gates are open.
    delay_ns: u64 = 0,

    fn init(self: *Gated, io: Io, pages: usize) !void {
        assert(pages <= pages_max);
        self.* = .{ .storage = .init(gpa), .inner = undefined, .io = io, .pages = pages };
        errdefer self.storage.deinit();
        var cache_ref = try CacheRef.init(gpa, page_size, 2);
        defer cache_ref.deinit();
        const opened = try self.storage.open("partition", "gated");
        var w = try writer_mod.Writer.init(gpa, opened.blob, 0, page_size * 2, &cache_ref);
        for (0..pages) |page| _ = try w.append(&(@as([page_size]u8, @splat(@intCast(page)))));
        try w.sync();
        w.deinit();
        self.inner = (try self.storage.open("partition", "gated")).blob;
    }

    fn deinit(self: *Gated) void {
        self.inner.close();
        self.storage.deinit();
    }

    fn open_all(self: *Gated) void {
        for (self.gates[0..self.pages]) |*gate| gate.set(self.io);
    }

    fn view(self: *Gated, cache_ref: *CacheRef) View {
        const size = self.pages * page_size;
        const blob: Blob = .{ .ptr = self, .vtable = &vtable };
        return .{
            .blob = blob,
            .cache_ref = cache_ref,
            .id = 0,
            .size = size,
            .tail_offset = size,
            .tail = &.{},
        };
    }

    const vtable: Blob.VTable = .{
        .read_at = read_at,
        .write_at = write_at,
        .resize = resize,
        .sync = sync,
        .close = close,
    };

    fn from(ptr: *anyopaque) *Gated {
        return @ptrCast(@alignCast(ptr));
    }

    fn read_at(
        ptr: *anyopaque,
        offset: u64,
        out: []u8,
        options: storage_iface.ReadOptions,
    ) storage_iface.Error!void {
        const self = from(ptr);
        assert(offset % physical_page_size == 0 and out.len % physical_page_size == 0);
        const first: usize = @intCast(offset / physical_page_size);
        const count = out.len / physical_page_size;
        for (self.reads[first..][0..count]) |*reads| {
            _ = @atomicRmw(u32, reads, .Add, 1, .monotonic);
        }
        for (first..first + count) |page| try self.gates[page].wait(self.io);
        if (self.delay_ns > 0) try self.io.sleep(.fromNanoseconds(self.delay_ns), .awake);
        for (first..first + count) |page| {
            if (self.failing == page) return error.ReadFailed;
        }
        try self.inner.read_at_options(offset, out, options);
        if (self.corrupt) |page| {
            if (page >= first and page < first + count) {
                out[(page - first) * physical_page_size] ^= 1;
            }
        }
    }

    fn write_at(
        _: *anyopaque,
        _: u64,
        _: []const []const u8,
        _: storage_iface.WriteOptions,
    ) storage_iface.Error!void {
        unreachable; // The tests only read.
    }

    fn resize(_: *anyopaque, _: u64) storage_iface.Error!void {
        unreachable;
    }

    fn sync(_: *anyopaque) storage_iface.Error!void {}

    fn close(_: *anyopaque) void {}
};

/// The first byte of each of `pages` (ascending), with one batched read.
fn read_first_bytes(view: View, pages: []const u64, out: []u8) Error!void {
    assert(out.len == pages.len);
    var ranges: [pages_max]paged.view.Range = undefined;
    for (pages, 0..) |page, index| ranges[index] = .{ .offset = page * page_size, .len = 1 };
    _ = try view.read_ranges_into(out, ranges[0..pages.len]);
}

/// The first byte of page `page`, from a page fault.
fn read_first_byte(view: View, page: u64, out: *u8) Error!void {
    try view.read_at(page * page_size, out[0..1]);
}

/// Runs the scheduler until every started read has reached its gate.
fn settle(io: Io) !void {
    for (0..4) |_| try io.sleep(.fromMilliseconds(1), .awake);
}

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try deterministic.Runner.init(gpa, .{ .timeout_ns = 5 * std.time.ns_per_s });
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
}

/// A cache of `capacity` pages that shares reads.
fn sharing_cache(io: Io, capacity: u32) !CacheRef {
    var cache_ref = try CacheRef.init(gpa, page_size, capacity);
    errdefer cache_ref.deinit();
    try cache_ref.share_reads(io);
    return cache_ref;
}

fn joins_fetch_in_flight(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 10);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    // Another reader starts fetching page 0.
    var first_byte: u8 = 0xff;
    var first = try io.concurrent(read_first_byte, .{ view, 0, &first_byte });
    try settle(io);
    // A batch over every page joins that fetch rather than reading page 0 again, although its
    // own insertions evict page 0 once that fetch completes.
    const pages = [_]u64{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var bytes: [10]u8 = undefined;
    var second = try io.concurrent(read_first_bytes, .{ view, &pages, &bytes });
    try settle(io);
    gated.gates[0].set(io);
    try first.await(io);
    try testing.expectEqual(0, first_byte);
    gated.open_all();
    try second.await(io);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, &bytes);
    try testing.expectEqual(1, gated.reads[0]);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "a batched read joins a page fetch in flight (test_read_many_into_joins_fetch_in_flight)" {
    try run(joins_fetch_in_flight);
}

fn overlapping_reads(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 7);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 16);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    // A batch of pages 0-3 starts reading. An overlapping batch of pages 2-5 joins it for
    // pages 2 and 3 and reads only pages 4 and 5.
    var first_bytes: [4]u8 = undefined;
    var first = try io.concurrent(read_first_bytes, .{ view, &.{ 0, 1, 2, 3 }, &first_bytes });
    try settle(io);
    var second_bytes: [4]u8 = undefined;
    var second = try io.concurrent(read_first_bytes, .{ view, &.{ 2, 3, 4, 5 }, &second_bytes });
    try settle(io);
    // A batch of pages 1, 5, and 6 joins both batches and reads only page 6, and a single read
    // of page 3 joins the first batch.
    var third_bytes: [3]u8 = undefined;
    var third = try io.concurrent(read_first_bytes, .{ view, &.{ 1, 5, 6 }, &third_bytes });
    var single_byte: u8 = 0xff;
    var single = try io.concurrent(read_first_byte, .{ view, 3, &single_byte });
    try settle(io);
    gated.open_all();
    try first.await(io);
    try second.await(io);
    try third.await(io);
    try single.await(io);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, &first_bytes);
    try testing.expectEqualSlices(u8, &.{ 2, 3, 4, 5 }, &second_bytes);
    try testing.expectEqualSlices(u8, &.{ 1, 5, 6 }, &third_bytes);
    try testing.expectEqual(3, single_byte);
    for (gated.reads[0..7]) |reads| try testing.expectEqual(1, reads);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "overlapping reads read each page once (test_overlapping_reads_read_each_page_once)" {
    try run(overlapping_reads);
}

fn many_join_one_page(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 2);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var bytes: [8]u8 = @splat(0xff);
    var readers: [8]Io.Future(Error!void) = undefined;
    for (&readers, &bytes) |*reader, *byte| {
        reader.* = try io.concurrent(read_first_byte, .{ view, 1, byte });
    }
    try settle(io);
    gated.open_all();
    for (&readers) |*reader| try reader.await(io);
    try testing.expectEqualSlices(u8, &(@as([8]u8, @splat(1))), &bytes);
    try testing.expectEqual(1, gated.reads[1]);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "many reads join one page fetch (test_many_reads_join_one_page)" {
    try run(many_join_one_page);
}

fn failed_page_fails_its_readers(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 3);
    defer gated.deinit();
    gated.corrupt = 1;
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    // A batch over pages 0-2 fetches page 1, which fails validation; a single read joined it.
    var batch_bytes: [3]u8 = undefined;
    var batch = try io.concurrent(read_first_bytes, .{ view, &.{ 0, 1, 2 }, &batch_bytes });
    try settle(io);
    var single_byte: u8 = 0xff;
    var single = try io.concurrent(read_first_byte, .{ view, 1, &single_byte });
    try settle(io);
    gated.open_all();
    try testing.expectError(error.InvalidChecksum, batch.await(io));
    try testing.expectError(error.InvalidChecksum, single.await(io));
    try testing.expectEqual(1, gated.reads[1]);
    // The failed fetch is gone: once the page reads clean, a new read fetches it again.
    try testing.expectEqual(0, cache_ref.fetches_active());
    gated.corrupt = null;
    var byte: u8 = 0xff;
    try read_first_byte(view, 1, &byte);
    try testing.expectEqual(1, byte);
    try testing.expectEqual(2, gated.reads[1]);
}

test "a failed page fails its readers, then reads again (test_failed_page_fails_its_readers)" {
    // Also commonware `test_page_fetch_error_removes_entry_for_all_waiters`.
    try run(failed_page_fails_its_readers);
}

fn canceled_fetcher_leaves_no_fetch(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 1);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var byte: u8 = 0xff;
    var first = try io.concurrent(read_first_byte, .{ view, 0, &byte });
    try settle(io);
    try testing.expectEqual(1, cache_ref.fetches_active());
    try testing.expectError(error.Canceled, first.cancel(io));
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "a canceled first fetcher leaves no fetch behind" {
    // commonware `test_page_fetches_entry_removed_when_first_fetcher_cancelled`.
    try run(canceled_fetcher_leaves_no_fetch);
}

fn followers_after_canceled_fetcher(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 1);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var bytes: [3]u8 = @splat(0xff);
    var first = try io.concurrent(read_first_byte, .{ view, 0, &bytes[0] });
    try settle(io);
    var second = try io.concurrent(read_first_byte, .{ view, 0, &bytes[1] });
    var third = try io.concurrent(read_first_byte, .{ view, 0, &bytes[2] });
    try settle(io);
    try testing.expectEqual(1, gated.reads[0]);
    // Cancel the fetcher: one follower reads the page again, and the other joins that read.
    try testing.expectError(error.Canceled, first.cancel(io));
    try settle(io);
    try testing.expectEqual(2, gated.reads[0]);
    gated.open_all();
    try second.await(io);
    try third.await(io);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, bytes[1..]);
    try testing.expectEqual(2, gated.reads[0]);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "followers keep one read in flight after the first fetcher is canceled" {
    // commonware `test_followers_keep_single_flight_after_first_fetcher_cancellation`.
    try run(followers_after_canceled_fetcher);
}

fn canceled_joiner(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 1);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var bytes: [3]u8 = @splat(0xff);
    var first = try io.concurrent(read_first_byte, .{ view, 0, &bytes[0] });
    try settle(io);
    var second = try io.concurrent(read_first_byte, .{ view, 0, &bytes[1] });
    var third = try io.concurrent(read_first_byte, .{ view, 0, &bytes[2] });
    try settle(io);
    try testing.expectError(error.Canceled, second.cancel(io));
    gated.open_all();
    try first.await(io);
    try third.await(io);
    try testing.expectEqual(0, bytes[0]);
    try testing.expectEqual(0, bytes[2]);
    try testing.expectEqual(1, gated.reads[0]);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "a canceled joiner does not disturb the other readers" {
    // commonware `test_cancelled_joins_do_not_disturb_other_reads`.
    try run(canceled_joiner);
}

fn stale_waiter_and_new_fetch(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 1);
    defer gated.deinit();
    gated.failing = 0;
    var cache_ref = try sharing_cache(io, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var bytes: [4]u8 = @splat(0xff);
    // A failing fetch, joined by a follower that has yet to collect its result.
    var first = try io.concurrent(read_first_byte, .{ view, 0, &bytes[0] });
    try settle(io);
    var stale = try io.concurrent(read_first_byte, .{ view, 0, &bytes[1] });
    try settle(io);
    try testing.expectEqual(1, gated.reads[0]);
    gated.gates[0].set(io);
    try testing.expectError(error.ReadFailed, first.await(io));
    // A retry starts a new fetch while the old one still holds the follower's result.
    gated.gates[0].reset();
    var retry = try io.concurrent(read_first_byte, .{ view, 0, &bytes[2] });
    try settle(io);
    try testing.expectEqual(2, gated.reads[0]);
    try testing.expectError(error.ReadFailed, stale.cancel(io));
    // The old follower leaving keeps the retry joinable.
    var joined = try io.concurrent(read_first_byte, .{ view, 0, &bytes[3] });
    try settle(io);
    try testing.expectEqual(2, gated.reads[0]);
    gated.gates[0].set(io);
    try testing.expectError(error.ReadFailed, retry.await(io));
    try testing.expectError(error.ReadFailed, joined.await(io));
    try testing.expectEqual(2, gated.reads[0]);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "a stale waiter leaving keeps the new fetch" {
    // commonware `test_cancelled_stale_waiter_preserves_new_fetch`.
    try run(stale_waiter_and_new_fetch);
}

fn pages_route_to_their_joiners(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 4);
    defer gated.deinit();
    var cache_ref = try sharing_cache(io, 8);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var batch_bytes: [4]u8 = undefined;
    var batch = try io.concurrent(read_first_bytes, .{ view, &.{ 0, 1, 2, 3 }, &batch_bytes });
    try settle(io);
    var one: u8 = 0xff;
    var two: u8 = 0xff;
    var reader_one = try io.concurrent(read_first_byte, .{ view, 1, &one });
    var reader_two = try io.concurrent(read_first_byte, .{ view, 2, &two });
    try settle(io);
    gated.open_all();
    try batch.await(io);
    try reader_one.await(io);
    try reader_two.await(io);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, &batch_bytes);
    try testing.expectEqual(1, one);
    try testing.expectEqual(2, two);
    for (gated.reads[0..4]) |reads| try testing.expectEqual(1, reads);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "each page reaches its own joiners (test_each_page_routes_to_its_joiners_only)" {
    try run(pages_route_to_their_joiners);
}

fn concurrent_reads_read_each_page_once(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, pages_max);
    defer gated.deinit();
    gated.open_all();
    var cache_ref = try sharing_cache(io, 2 * pages_max);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var pages: [pages_max]u64 = undefined;
    for (&pages, 0..) |*page, index| page.* = index;
    var bytes: [4][pages_max]u8 = undefined;
    var readers: [4]Io.Future(Error!void) = undefined;
    for (&readers, &bytes) |*reader, *out| {
        reader.* = try io.concurrent(read_first_bytes, .{ view, &pages, out });
    }
    for (&readers) |*reader| try reader.await(io);
    for (&bytes) |*out| {
        for (out, 0..) |byte, page| try testing.expectEqual(page, byte);
    }
    // Pages are read in runs of `max_run_pages`, joined or not, and no page twice.
    for (gated.reads[0..pages_max]) |reads| try testing.expectEqual(1, reads);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "concurrent reads read each page once (test_concurrent_reads_read_each_page_once)" {
    try run(concurrent_reads_read_each_page_once);
}

/// Readers on worker threads race to read overlapping runs of a slow blob's pages through a
/// cache that holds every page, so every page is read once however the races land.
fn racing_threads(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, pages_max);
    defer gated.deinit();
    gated.open_all();
    gated.delay_ns = 200 * std.time.ns_per_us;
    var cache_ref = try sharing_cache(io, 2 * pages_max);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    const readers_count = 8;
    var pages: [readers_count][pages_max]u64 = undefined;
    var counts: [readers_count]usize = undefined;
    var bytes: [readers_count][pages_max]u8 = undefined;
    var readers: [readers_count]Io.Future(Error!void) = undefined;
    for (&readers, 0..) |*reader, index| {
        // Reader `index` reads every page whose number shares a bit with `index + 1`, so
        // the readers' runs overlap in many ways, ascending or descending through the blob.
        var count: usize = 0;
        for (0..pages_max) |page| {
            if (page & (index + 1) == 0 and page % 3 != index % 3) continue;
            pages[index][count] = page;
            count += 1;
        }
        counts[index] = count;
        reader.* = try io.concurrent(read_first_bytes, .{
            view,
            pages[index][0..count],
            bytes[index][0..count],
        });
    }
    for (&readers) |*reader| try reader.await(io);
    for (0..readers_count) |index| {
        for (pages[index][0..counts[index]], bytes[index][0..counts[index]]) |page, byte| {
            try testing.expectEqual(page, byte);
        }
    }
    for (gated.reads[0..pages_max]) |reads| try testing.expectEqual(1, reads);
    try testing.expectEqual(0, cache_ref.fetches_active());
}

test "readers on threads share page reads" {
    const production = @import("../../production/runner.zig");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [128]u8 = undefined;
    const directory = std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path}) catch
        unreachable; // The buffer fits the fixed-length temporary path.
    for (0..20) |_| {
        var runner: production.Runner = undefined;
        try runner.init(gpa, .{ .storage_directory = directory, .worker_threads = 8 });
        defer runner.deinit();
        try runner.start(racing_threads, .{runner.io()});
    }
}

fn unshared_reads_read_alone(io: Io) !void {
    var gated: Gated = undefined;
    try gated.init(io, 1);
    defer gated.deinit();
    var cache_ref = try CacheRef.init(gpa, page_size, 4);
    defer cache_ref.deinit();
    const view = gated.view(&cache_ref);
    var bytes: [2]u8 = @splat(0xff);
    var first = try io.concurrent(read_first_byte, .{ view, 0, &bytes[0] });
    var second = try io.concurrent(read_first_byte, .{ view, 0, &bytes[1] });
    try settle(io);
    gated.open_all();
    try first.await(io);
    try second.await(io);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, &bytes);
    try testing.expectEqual(2, gated.reads[0]);
}

test "a cache that does not share reads reads each miss alone" {
    try run(unshared_reads_read_alone);
}

/// Opens a writer on `runner`'s storage over `cache_ref`, then reports whether the cache now
/// shares reads under `runner`'s `Io`.
fn open_on(runner: *deterministic.Runner, cache_ref: *CacheRef) !bool {
    const opened = try runner.storage().open("shared_reads", "blob");
    errdefer opened.blob.close();
    var writer = try writer_mod.Writer.init(gpa, opened.blob, opened.len, page_size, cache_ref);
    defer writer.deinit();
    const io = cache_ref.io orelse return false;
    return io.userdata == runner.io().userdata;
}

test "a writer on runtime storage shares reads by default, across runners" {
    // commonware's page cache always shares in-flight reads. A cache outliving its runner (a
    // restarted test) moves to the next runner's `Io` while no fetch is live.
    var cache_ref = try CacheRef.init(gpa, page_size, 4);
    defer cache_ref.deinit();
    for (0..2) |_| {
        var runner = try deterministic.Runner.init(gpa, .{});
        defer runner.deinit();
        try testing.expect(try open_on(&runner, &cache_ref));
    }
    // A backend without an `Io` keeps every miss private.
    var memory = mocks.Storage.init(gpa);
    defer memory.deinit();
    var unshared = try CacheRef.init(gpa, page_size, 4);
    defer unshared.deinit();
    const opened = try memory.interface().open("shared_reads", "blob");
    var writer = try writer_mod.Writer.init(gpa, opened.blob, opened.len, page_size, &unshared);
    defer writer.deinit();
    try testing.expectEqual(null, unshared.io);
}
