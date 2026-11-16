//! Configuration of a `Heap`, mirroring commonware's `allocator::mimalloc` options: the arena
//! geometry constants, the purge and reservation policies, `Config` with mimalloc's defaults,
//! and `Status` and `Effective`, which report what a heap runs with.
//!
//! Durations are nanoseconds (`u64`); commonware's `Duration` options keep millisecond
//! precision, which the helpers below reproduce.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const word_size: usize = @sizeOf(usize);
const ns_per_ms: u64 = std.time.ns_per_ms;

/// Log2 of the arena slice size: mimalloc's default `13 + log2(word size)`.
pub const arena_slice_shift: u6 = 13 + @ctz(word_size);

/// Size of an arena slice, the unit arenas are carved into and the smallest page size.
pub const arena_slice_size: usize = 1 << arena_slice_shift;

/// Size of an arena chunk, the unit reservations are rounded down to: 512 slices, or 32 MiB
/// on 64-bit targets.
pub const arena_chunk_size: usize = 64 * word_size * arena_slice_size;

/// Largest allocation served from a shared page of its size class (eight slices, 512 KiB).
/// Larger objects get a page of their own.
pub const large_object_limit: usize = word_size * arena_slice_size;

/// Largest page an arena can hold, and the cap on `Config.arena_max_object_size`: seven
/// chunks, or 224 MiB on 64-bit targets.
pub const arena_max_object_size: usize = (word_size - 1) * arena_chunk_size;

/// Size of an arena's metadata group: eight chunks, or 256 MiB on 64-bit targets. Allocations
/// aligned to a whole group or more are refused.
pub const metadata_group_size: usize = word_size * arena_chunk_size;

/// Longest purge delay `Purge.after_ns` applies (about 24 days): milliseconds in an `i32`.
pub const max_purge_delay_ns: u64 = std.math.maxInt(i32) * ns_per_ms;

comptime {
    assert(arena_slice_size == 64 * 1024 or word_size != 8);
    assert(large_object_limit == 8 * arena_slice_size or word_size != 8);
    assert(arena_max_object_size < 8 * arena_chunk_size);
}

/// When memory freed back to an arena is purged (decommitted). Pinned reservations and pages
/// mapped on their own are never purged; the latter are unmapped on release.
pub const Purge = union(enum) {
    /// Never purge arena memory.
    never,
    /// Purge freed memory after a delay: the first free into an arena after a purge sets a
    /// deadline this far ahead, and the arena is purged at the first collection after it.
    /// Delays above `max_purge_delay_ns` are clamped, and one below a millisecond purges each
    /// page as it is freed.
    after_ns: u64,
};

/// When the arenas a heap reserves on demand count as committed.
pub const EagerCommit = enum {
    /// Commit each slice when it is first used.
    never,
    /// Commit the whole arena when it is reserved.
    always,
    /// Commit eagerly on systems that overcommit memory (Linux), on first use otherwise.
    if_overcommit,
};

/// Memory reserved before the first allocation.
pub const Reserve = struct {
    /// Bytes to reserve, rounded down to whole `arena_chunk_size` chunks. A reservation below
    /// one chunk fails.
    bytes: usize,
    /// A pinned reservation is never purged. An unpinned one is purged like any arena.
    pinned: bool,
    /// Touch every page of a pinned reservation up front so first use never faults.
    prefault: bool = false,

    /// A pinned reservation that is faulted in on first use.
    pub fn init_pinned(bytes: usize) Reserve {
        return .{ .bytes = bytes, .pinned = true };
    }

    /// A reservation purged like any other arena.
    pub fn init_unpinned(bytes: usize) Reserve {
        return .{ .bytes = bytes, .pinned = false };
    }
};

/// Configuration a `Heap` applies when it is created.
pub const Config = struct {
    purge: Purge,
    reserve: ?Reserve,
    /// Recorded and reported; zigware maps arenas through the backing allocator, which
    /// decides the OS page size.
    allow_large_os_pages: bool,
    /// Recorded and reported; zigware sets no process-wide huge page flag.
    transparent_huge_pages: bool,
    arena_eager_commit: EagerCommit,
    /// Base size of the arenas reserved on demand once existing arenas are full, rounded up
    /// to KiB and then to whole chunks. Zero disables on-demand arenas: pages that no
    /// existing arena can hold are mapped on their own and unmapped on release.
    arena_reserve: usize,
    /// Largest page carved from an arena, rounded up to a slice and clamped between one
    /// slice and `arena_max_object_size`. Larger pages are mapped on their own.
    arena_max_object_size: usize,
    /// Recorded and reported. A zigware heap keeps exact statistics under its lock, so there
    /// is nothing to merge.
    stats_merge_threshold: usize,

    /// mimalloc's defaults, with the arena object-size limit capped at
    /// `arena_max_object_size`.
    pub const default: Config = .{
        .purge = .{ .after_ns = 4 * std.time.ns_per_s },
        .reserve = null,
        .allow_large_os_pages = false,
        .transparent_huge_pages = builtin.abi != .android,
        .arena_eager_commit = .if_overcommit,
        .arena_reserve = if (word_size > 4) 1 << 30 else 128 << 20,
        .arena_max_object_size = arena_max_object_size,
        .stats_merge_threshold = 4 << 20,
    };
};

/// Outcome of the reservation requested by `Config.reserve`.
pub const ReserveOutcome = enum {
    not_requested,
    /// The reservation is a pinned arena that is never purged.
    pinned,
    /// The reservation is an ordinary arena.
    reserved,
    /// The backing allocator refused the reservation, or it was below one chunk. Allocation
    /// continues from on-demand arenas.
    failed,
};

/// A heap's configuration state.
pub const Status = struct {
    configured: bool,
    reserve: ReserveOutcome,
};

/// The options a heap runs with.
pub const Effective = struct {
    /// Arena purge delay in nanoseconds (millisecond precision), or null if purging is off.
    purge_ns: ?u64,
    /// Whether a purge decommits memory rather than resetting it.
    purge_decommits: bool,
    /// Arena commit policy as mimalloc stores it: 0 lazy, 1 eager, 2 eager on overcommit.
    arena_eager_commit: i64,
    allow_large_os_pages: bool,
    transparent_huge_pages: bool,
    /// Base size of arenas reserved on demand.
    arena_reserve: usize,
    /// Largest page carved from an arena.
    arena_max_object_size: usize,
    stats_merge_threshold: usize,

    /// The options `config` resolves to, rounded and bounded as mimalloc stores them.
    pub fn from_config(config: Config) Effective {
        const delay: ?u64 = switch (config.purge) {
            .never => null,
            .after_ns => |ns| arena_purge_delay(purge_millis(ns), 1),
        };
        const eager: i64 = switch (config.arena_eager_commit) {
            .never => 0,
            .always => 1,
            .if_overcommit => 2,
        };
        const reserve_kib = size_option(std.math.divCeil(usize, config.arena_reserve, 1024) catch
            unreachable); // 1024 is not zero.
        const effective: Effective = .{
            .purge_ns = delay,
            .purge_decommits = true,
            .arena_eager_commit = eager,
            .allow_large_os_pages = config.allow_large_os_pages,
            .transparent_huge_pages = config.transparent_huge_pages,
            .arena_reserve = @as(usize, @intCast(reserve_kib)) *| 1024,
            .arena_max_object_size = max_object_size(config.arena_max_object_size),
            .stats_merge_threshold = config.stats_merge_threshold,
        };
        assert(effective.arena_max_object_size >= arena_slice_size);
        assert(effective.arena_max_object_size <= arena_max_object_size);
        return effective;
    }
};

/// Rounds `bytes` down to whole arena chunks, or null below one chunk.
pub fn whole_chunks(bytes: usize) ?usize {
    const size = bytes / arena_chunk_size * arena_chunk_size;
    assert(size <= bytes);
    if (size == 0) return null;
    return size;
}

/// Bounds a size option in KiB so its value in bytes fits a C `long`.
pub fn size_option(kib: usize) c_long {
    const bound: usize = @intCast(@divTrunc(std.math.maxInt(c_long), 1024));
    return @intCast(@min(kib, bound));
}

/// A purge delay in the milliseconds mimalloc stores, bounded by `max_purge_delay_ns`.
pub fn purge_millis(delay_ns: u64) c_long {
    const millis = @min(delay_ns, max_purge_delay_ns) / ns_per_ms;
    assert(millis <= std.math.maxInt(i32));
    return @intCast(millis);
}

/// The arena purge delay from the raw options, as mimalloc computes it: a negative value
/// disables purging, and an overflowing product falls back to the bare delay.
pub fn arena_purge_delay(delay: c_long, mult: c_long) ?u64 {
    if (delay < 0 or mult < 0) return null;
    const delay_ms: u64 = @intCast(delay);
    const mult_u: u64 = @intCast(mult);
    var total = delay_ms;
    if (std.math.mul(u64, delay_ms, mult_u)) |product| {
        if (product <= std.math.maxInt(c_long)) total = product;
    } else |_| {}
    return total *| ns_per_ms;
}

/// The largest page an arena holds for a configured limit: KiB rounded up, capped at
/// `arena_max_object_size`, then rounded up to a slice and at least one slice.
pub fn max_object_size(limit_bytes: usize) usize {
    const kib_limit = size_option(std.math.divCeil(usize, limit_bytes, 1024) catch unreachable);
    const kib_cap = size_option(arena_max_object_size / 1024);
    const kib: usize = @intCast(@min(kib_limit, kib_cap));
    const bytes = std.mem.alignForward(usize, kib * 1024, arena_slice_size);
    const size = std.math.clamp(bytes, arena_slice_size, arena_max_object_size);
    assert(size % arena_slice_size == 0);
    return size;
}

const testing = std.testing;

test "purge delay is bounded and mirrors mimalloc" {
    try testing.expectEqual(@as(c_long, std.math.maxInt(i32)), purge_millis(std.math.maxInt(u64)));
    try testing.expectEqual(@as(c_long, 5), purge_millis(5 * ns_per_ms));
    try testing.expectEqual(@as(?u64, 4 * std.time.ns_per_s), arena_purge_delay(1000, 4));
    try testing.expectEqual(@as(?u64, 0), arena_purge_delay(0, 4));
    try testing.expectEqual(@as(?u64, null), arena_purge_delay(-1, 4));
    try testing.expectEqual(@as(?u64, null), arena_purge_delay(1000, -1));
    const max: c_long = std.math.maxInt(c_long);
    const saturated: u64 = @as(u64, @intCast(max)) *| ns_per_ms;
    try testing.expectEqual(@as(?u64, saturated), arena_purge_delay(max, 2));
}

test "arena object limit rounds up and is bounded" {
    // Bytes round up to KiB, and KiB round up to a slice.
    const above_chunk = max_object_size(arena_chunk_size + 1);
    try testing.expectEqual(arena_chunk_size + arena_slice_size, above_chunk);
    try testing.expectEqual(arena_slice_size, max_object_size(1));
    try testing.expectEqual(arena_max_object_size, max_object_size(std.math.maxInt(usize)));
    const largest_kib = @divTrunc(std.math.maxInt(c_long), 1024);
    try testing.expectEqual(largest_kib, size_option(std.math.maxInt(usize)));
}

test "reservations are trimmed to chunks" {
    try testing.expectEqual(@as(?usize, null), whole_chunks(arena_chunk_size - 1));
    try testing.expectEqual(@as(?usize, arena_chunk_size), whole_chunks(arena_chunk_size * 3 / 2));
    const max = std.math.maxInt(usize);
    const trimmed = max / arena_chunk_size * arena_chunk_size;
    try testing.expectEqual(@as(?usize, trimmed), whole_chunks(max));
}

test "unpinned and default configs are constructible" {
    try testing.expect(!Reserve.init_unpinned(1).pinned);
    try testing.expect(Reserve.init_pinned(1).pinned);
    const effective = Effective.from_config(Config.default);
    try testing.expectEqual(@as(?u64, 4 * std.time.ns_per_s), effective.purge_ns);
    try testing.expectEqual(@as(i64, 2), effective.arena_eager_commit);
    try testing.expectEqual(arena_max_object_size, effective.arena_max_object_size);
    try testing.expectEqual(Config.default.arena_reserve, effective.arena_reserve);
    // The rest of commonware's `allocator/tests/default_config.rs`.
    try testing.expect(Config.default.reserve == null);
    try testing.expect(!effective.allow_large_os_pages);
    try testing.expect(effective.transparent_huge_pages == Config.default.transparent_huge_pages);
    const merge = Config.default.stats_merge_threshold;
    try testing.expectEqual(merge, effective.stats_merge_threshold);
}

test "constants match mimalloc's 64-bit geometry" {
    if (word_size != 8) return error.SkipZigTest;
    try testing.expectEqual(@as(usize, 64 << 10), arena_slice_size);
    try testing.expectEqual(@as(usize, 32 << 20), arena_chunk_size);
    try testing.expectEqual(@as(usize, 512 << 10), large_object_limit);
    try testing.expectEqual(@as(usize, 224 << 20), arena_max_object_size);
}
