//! Shared setup of the journal benchmarks (commonware `storage/src/journal/benches/bench.rs`):
//! the production storage in a temporary directory (commonware's tokio runtime), the journal
//! configurations, and random item fills drawn from `test_rng` as commonware draws them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bench = @import("bench");
const runtime = @import("runtime");
const utils = @import("utils");
const storage = @import("storage");

const paged = runtime.buffer.paged;
const contiguous = storage.journal.contiguous;

pub const CacheRef = paged.CacheRef;
pub const ReadOptions = runtime.storage.ReadOptions;
pub const Bounds = contiguous.Bounds;

/// The size of the write buffer used by the journal (1 MiB).
pub const write_buffer: usize = 1024 * 1024;
/// The size of the buffer used to replay the journal (1 MiB).
pub const replay_buffer: usize = 1024 * 1024;
/// A "prod sized" page: runtime's `BLOB_PAGE_SIZE` less its checksum.
pub const page_size: u16 = paged.page_size(runtime.storage.blob_page_size);
/// Pages in the page cache: big enough to be fast, small enough to fault on larger inputs.
pub const page_cache_size: u32 = 10_000;

pub fn FixedJournal(comptime size: usize) type {
    return contiguous.fixed.Journal([size]u8);
}

pub fn VariableJournal(comptime size: usize) type {
    return contiguous.variable.Journal([size]u8);
}

/// Where a benchmark's journals live: the production storage over a fresh directory under
/// `.zig-cache/tmp` when measured (commonware's tokio runtime), and the in-memory storage
/// for the smoke run under `zig build test`, which only checks that each benchmark runs and
/// should not wait on disk syncs. `deinit` removes the directory.
pub const Disk = struct {
    io: Io,
    backend: union(enum) {
        memory: runtime.storage.memory.Storage,
        production: runtime.production.storage.WithRing,
    },
    directory: [96]u8 = undefined,
    directory_len: usize = 0,

    pub fn init(disk: *Disk, io: Io, gpa: Allocator, tag: []const u8, inputs: bench.Inputs) !void {
        assert(tag.len > 0 and tag.len <= 48);
        disk.io = io;
        disk.directory_len = 0;
        if (inputs == .smoke) {
            disk.backend = .{ .memory = .init(gpa) };
            return;
        }
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const name = try std.fmt.bufPrint(&disk.directory, ".zig-cache/tmp/bench-{s}-{x}", .{
            tag,
            std.mem.readInt(u64, &nonce, .little),
        });
        disk.directory_len = name.len;
        const root = try Io.Dir.cwd().createDirPathOpen(io, name, .{});
        disk.backend = .{ .production = .{} };
        try disk.backend.production.init(io, gpa, root, bench.io_uring);
        assert(disk.directory_len > 0);
    }

    pub fn deinit(disk: *Disk) void {
        switch (disk.backend) {
            .memory => |*memory| memory.deinit(),
            .production => |*production| {
                assert(disk.directory_len > 0);
                production.deinit();
                const name = disk.directory[0..disk.directory_len];
                Io.Dir.cwd().deleteTree(disk.io, name) catch |err|
                    std.log.warn("bench: removing {s}: {t}", .{ name, err });
            },
        }
        disk.* = undefined;
    }

    pub fn interface(disk: *Disk) runtime.storage.Storage {
        return switch (disk.backend) {
            .memory => |*memory| memory.storage(),
            .production => |*production| production.storage.storage(),
        };
    }
};

/// Open the fixed journal at `partition` (commonware `get_fixed_journal`).
pub fn open_fixed(
    comptime size: usize,
    gpa: Allocator,
    disk: *Disk,
    cache_ref: *CacheRef,
    partition: []const u8,
    items_per_blob: u64,
) !FixedJournal(size) {
    assert(items_per_blob > 0);
    assert(cache_ref.page_size == page_size);
    return FixedJournal(size).init(gpa, disk.interface(), .{
        .partition = partition,
        .items_per_blob = items_per_blob,
        .cache_ref = cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
}

/// Open the uncompressed variable journal at `partition` (commonware `get_variable_journal`).
pub fn open_variable(
    comptime size: usize,
    gpa: Allocator,
    disk: *Disk,
    cache_ref: *CacheRef,
    partition: []const u8,
    items_per_section: u64,
) !VariableJournal(size) {
    assert(items_per_section > 0);
    assert(cache_ref.page_size == page_size);
    return VariableJournal(size).init(gpa, disk.interface(), .{
        .partition = partition,
        .items_per_section = items_per_section,
        .codec_config = {},
        .cache_ref = cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
}

/// Append `count` items of `test_rng` bytes, then sync (commonware `append_fixed_random_data`).
pub fn append_random(journal: anytype, comptime size: usize, count: u64) !void {
    const size_before = journal.size();
    var rng = utils.rng.test_rng();
    var item: [size]u8 = undefined;
    for (0..count) |_| {
        rng.fill_bytes(&item);
        _ = try journal.append(item);
    }
    try journal.sync();
    assert(journal.size() == size_before + count);
}

/// `rand` 0.10's `random_range(0..bound)` over `u64`.
pub fn below(rng: *utils.rng.TestRng, bound: u64) u64 {
    assert(bound > 0);
    const value = utils.rng.range_less_than(rng, u64, 0, bound);
    assert(value < bound);
    return value;
}

/// Sort `positions` and remove duplicates, returning the distinct prefix.
pub fn sort_dedup(positions: []u64) []u64 {
    std.sort.pdq(u64, positions, {}, std.sort.asc(u64));
    var len: usize = 0;
    for (positions) |position| {
        if (len > 0 and positions[len - 1] == position) continue;
        positions[len] = position;
        len += 1;
    }
    assert(len <= positions.len);
    return positions[0..len];
}

/// Drain a replay, returning the items seen.
pub fn drain(replay: anytype) !u64 {
    var seen: u64 = 0;
    while (try replay.next()) |batch| {
        // One opaque use of a copy of each item, as Rust's `black_box(item)`. Passed by
        // value, std's `doNotOptimizeAway` emits one barrier per byte of an array item.
        for (batch.items) |item| std.mem.doNotOptimizeAway(&item);
        seen += batch.items.len;
    }
    return seen;
}

/// `rand` 0.10's `SliceRandom::shuffle`: Fisher-Yates with `IncreasingUniform`, which draws
/// one `u32` per run of indices whose product of ranges fits in it.
pub fn shuffle(comptime T: type, rng: *utils.rng.TestRng, items: []T) void {
    if (items.len <= 1) return;
    assert(items.len <= std.math.maxInt(u32));
    var n: u32 = 0;
    var chunk: u32 = 0;
    var chunk_remaining: u8 = 1; // `n == 0` starts with one free index.
    for (0..items.len) |i| {
        const next_n = n + 1;
        var next_remaining: u8 = undefined;
        if (chunk_remaining == 0) {
            const bound, const remaining = bound_u32(next_n);
            chunk = utils.rng.range_less_than(rng, u32, 0, bound);
            next_remaining = remaining - 1;
        } else {
            next_remaining = chunk_remaining - 1;
        }
        const index = if (next_remaining == 0) chunk else index: {
            const result = chunk % next_n;
            chunk /= next_n;
            break :index result;
        };
        assert(index <= i);
        std.mem.swap(T, &items[i], &items[index]);
        chunk_remaining = next_remaining;
        n = next_n;
    }
}

/// The product `m * (m + 1) * ...` while it fits in a `u32`, and how many factors it has.
fn bound_u32(m: u32) struct { u32, u8 } {
    assert(m > 0);
    var product = m;
    var current = m + 1;
    // At most 13 factors fit in a `u32` (13! < 2^32 < 14!).
    for (0..32) |_| {
        product = std.math.mul(u32, product, current) catch {
            return .{ product, @intCast(current - m) };
        };
        current += 1;
    }
    unreachable;
}
