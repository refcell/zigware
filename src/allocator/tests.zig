//! Tests of `Heap`, ported from commonware's `allocator/src/mimalloc/mod.rs` where they apply
//! to a native heap, plus purge, own-page, threaded, and fuzz tests.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const allocator = @import("root.zig");

const Heap = allocator.Heap;
const Alignment = std.mem.Alignment;
const chunk = allocator.arena_chunk_size;
const slice = allocator.arena_slice_size;

/// A test configuration: small on-demand arenas so tests map little memory.
fn small_config() allocator.Config {
    var config = allocator.Config.default;
    config.arena_reserve = 2 * chunk;
    return config;
}

const purge_delay_ns = 3600 * std.time.ns_per_s;
const stats_merge_threshold = 3 << 20;
/// A limit between slice boundaries, so the rounding is observable.
const max_object = chunk + 1;

fn pinned_heap() Heap {
    var config = small_config();
    config.purge = .{ .after_ns = purge_delay_ns };
    config.reserve = .init_pinned(2 * chunk);
    config.transparent_huge_pages = false;
    config.arena_max_object_size = max_object;
    config.stats_merge_threshold = stats_merge_threshold;
    return Heap.init(testing.io, config);
}

test "config is applied before use" {
    var heap = pinned_heap();
    defer heap.deinit();
    try testing.expect(heap.status.configured);
    try testing.expectEqual(allocator.ReserveOutcome.pinned, heap.status.reserve);
    const effective = heap.effective;
    try testing.expectEqual(@as(?u64, purge_delay_ns), effective.purge_ns);
    try testing.expect(effective.purge_decommits);
    try testing.expect(!effective.transparent_huge_pages);
    try testing.expectEqual(@as(usize, stats_merge_threshold), effective.stats_merge_threshold);
    try testing.expectEqual(chunk + slice, effective.arena_max_object_size);
    const probe = try heap.allocator().create(u8);
    defer heap.allocator().destroy(probe);
    try testing.expect(heap.contains(probe));
    var outside: u8 = 0;
    try testing.expect(!heap.contains(&outside));
    try testing.expectEqual(@as(usize, 4096), allocator.good_size(4096));
    try testing.expectEqual(@as(usize, 5120), allocator.good_size(4096 + 32));
}

fn alloc_raw(gpa: std.mem.Allocator, len: usize, alignment: usize) ![*]u8 {
    return gpa.rawAlloc(len, .fromByteUnits(alignment), @returnAddress()) orelse
        error.OutOfMemory;
}

test "fast paths hand out aligned memory" {
    var heap = Heap.init(testing.io, small_config());
    defer heap.deinit();
    const gpa = heap.allocator();
    const layouts = [_][2]usize{
        .{ 100, 1 },  .{ 100, 8 },     .{ 100, 16 },   .{ 1, 16 },        .{ 8, 16 },
        .{ 16, 16 },  .{ 24, 16 },     .{ 32, 16 },    .{ 48, 16 },       .{ 3, 8 },
        .{ 100, 64 }, .{ 4096, 4096 }, .{ 100, 4096 }, .{ 100, 1 << 20 },
    };
    for (layouts) |layout| {
        const size, const alignment = layout;
        var live: [16][*]u8 = undefined;
        for (&live) |*block| {
            block.* = try alloc_raw(gpa, size, alignment);
            try testing.expectEqual(@as(usize, 0), @intFromPtr(block.*) % alignment);
            @memset(block.*[0..size], 0xab);
        }
        for (live) |block| {
            // Growing to 10,000 bytes moves the block and keeps the alignment.
            const grown = try alloc_raw(gpa, 10_000, alignment);
            try testing.expectEqual(@as(usize, 0), @intFromPtr(grown) % alignment);
            @memcpy(grown[0..size], block[0..size]);
            gpa.rawFree(block[0..size], .fromByteUnits(alignment), @returnAddress());
            try testing.expectEqual(@as(u8, 0xab), grown[size - 1]);
            gpa.rawFree(grown[0..10_000], .fromByteUnits(alignment), @returnAddress());
        }
    }
    try testing.expectEqual(@as(u64, 0), heap.read_stats().allocated_bytes);
}

test "resize stays in place only within a half-used block" {
    var heap = Heap.init(testing.io, small_config());
    defer heap.deinit();
    const gpa = heap.allocator();
    const block = try alloc_raw(gpa, 48, 16);
    const memory = block[0..48];
    try testing.expect(gpa.rawResize(memory, .fromByteUnits(16), 40, @returnAddress()));
    try testing.expect(!gpa.rawResize(memory, .fromByteUnits(16), 8, @returnAddress()));
    try testing.expect(!gpa.rawResize(memory, .fromByteUnits(16), 4096, @returnAddress()));
    gpa.rawFree(block[0..40], .fromByteUnits(16), @returnAddress());
}

test "stats reflect reservation and huge allocations" {
    var heap = pinned_heap();
    defer heap.deinit();
    const gpa = heap.allocator();
    const warm = try gpa.alloc(u8, 64);
    defer gpa.free(warm);
    const before = heap.read_stats();
    // The pinned reservation serves the working set, so nothing else is reserved.
    try testing.expect(before.pinned_bytes >= 2 * chunk);
    try testing.expect(before.arenas >= 1);
    try testing.expect(before.reserved_bytes < 2 * chunk);
    try testing.expect(before.committed_bytes > 0);
    try testing.expect(before.threads >= 1);

    const largest = try gpa.alloc(u8, allocator.large_object_limit);
    try testing.expectEqual(before.huge_allocations, heap.read_stats().huge_allocations);
    gpa.free(largest);

    const size = allocator.large_object_limit + 1;
    const block = try gpa.alloc(u8, size);
    @memset(block, 1);
    const after = heap.read_stats();
    try testing.expect(after.huge_allocations > before.huge_allocations);
    try testing.expect(after.huge_bytes >= before.huge_bytes + size);
    try testing.expect(after.allocated_bytes >= before.allocated_bytes + size);
    gpa.free(block);
    try testing.expect(heap.read_stats().allocated_bytes < after.allocated_bytes);
}

test "smallest size class pages stay within block counts" {
    var heap = Heap.init(testing.io, small_config());
    defer heap.deinit();
    const gpa = heap.allocator();
    const count = std.math.maxInt(u16) + 4096;
    const boxes = try testing.allocator.alloc(*u8, count);
    defer testing.allocator.free(boxes);
    for (boxes, 0..) |*box, index| {
        box.* = try gpa.create(u8);
        box.*.* = @truncate(index);
    }
    const addresses = try testing.allocator.alloc(usize, count);
    defer testing.allocator.free(addresses);
    for (boxes, addresses) |box, *address| address.* = @intFromPtr(box);
    std.sort.pdq(usize, addresses, {}, std.sort.asc(usize));
    for (addresses[1..], addresses[0 .. count - 1]) |next, previous| {
        try testing.expect(next != previous);
    }
    for (boxes, 0..) |box, index| {
        try testing.expectEqual(@as(u8, @truncate(index)), box.*);
        gpa.destroy(box);
    }
    const stats = heap.read_stats();
    try testing.expectEqual(@as(u64, 0), stats.allocated_bytes);
    try testing.expectEqual(@as(u64, 0), stats.pages);
}

test "unpinned and default configs are constructible" {
    var config = small_config();
    config.reserve = .init_unpinned(chunk);
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    try testing.expectEqual(allocator.ReserveOutcome.reserved, heap.status.reserve);
    try testing.expectEqual(@as(u64, chunk), heap.read_stats().reserved_bytes);

    config.reserve = .init_pinned(chunk - 1);
    var refused = Heap.init(testing.io, config);
    defer refused.deinit();
    try testing.expectEqual(allocator.ReserveOutcome.failed, refused.status.reserve);
}

test "configuration is per heap" {
    var first = pinned_heap();
    defer first.deinit();
    var config = small_config();
    config.purge = .never;
    var second = Heap.init(testing.io, config);
    defer second.deinit();
    const block = try second.allocator().create(u64);
    second.allocator().destroy(block);
    try testing.expectEqual(@as(?u64, purge_delay_ns), first.effective.purge_ns);
    try testing.expectEqual(@as(?u64, null), second.effective.purge_ns);
    try testing.expectEqual(allocator.ReserveOutcome.not_requested, second.status.reserve);
}

test "a zero purge delay purges freed pages at once" {
    var config = small_config();
    config.purge = .{ .after_ns = 0 };
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    const gpa = heap.allocator();
    const block = try gpa.alloc(u8, 1000);
    @memset(block, 7);
    gpa.free(block);
    const stats = heap.read_stats();
    try testing.expectEqual(@as(u64, 1), stats.arena_purges);
    try testing.expect(stats.purged_bytes >= slice);
    try testing.expectEqual(@as(u64, 0), stats.pages);
}

test "delayed purges wait for a collection after the deadline" {
    var config = small_config();
    config.purge = .{ .after_ns = std.time.ns_per_ms };
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    const gpa = heap.allocator();
    gpa.free(try gpa.alloc(u8, 1000));
    try testing.expectEqual(@as(u64, 0), heap.read_stats().purged_bytes);
    try testing.io.sleep(.fromMilliseconds(2), .awake);
    heap.collect();
    try testing.expect(heap.read_stats().purged_bytes >= slice);

    // A never-purging heap keeps freed memory.
    config.purge = .never;
    var keeping = Heap.init(testing.io, config);
    defer keeping.deinit();
    keeping.allocator().free(try keeping.allocator().alloc(u8, 1000));
    keeping.collect();
    try testing.expectEqual(@as(u64, 0), keeping.read_stats().purged_bytes);
}

test "pages above the arena limit and without on-demand arenas get their own mapping" {
    var config = small_config();
    config.arena_max_object_size = slice;
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    const gpa = heap.allocator();
    const big = try gpa.alloc(u8, allocator.large_object_limit + 1);
    // A page mapped on its own is reserved and committed, but it is not an arena.
    try testing.expectEqual(@as(u64, 0), heap.read_stats().arenas);
    try testing.expect(heap.read_stats().reserved_bytes > allocator.large_object_limit);
    try testing.expect(heap.read_stats().committed_bytes > allocator.large_object_limit);
    gpa.free(big);
    try testing.expectEqual(@as(u64, 0), heap.read_stats().reserved_bytes);
    try testing.expectEqual(@as(u64, 0), heap.read_stats().committed_bytes);

    config = small_config();
    config.arena_reserve = 0;
    var direct = Heap.init(testing.io, config);
    defer direct.deinit();
    const small = try direct.allocator().alloc(u8, 32);
    try testing.expectEqual(@as(u64, 0), direct.read_stats().arenas);
    try testing.expectEqual(@as(u64, 1), direct.read_stats().mmap_calls);
    try testing.expect(direct.read_stats().reserved_bytes >= slice);
    direct.allocator().free(small);
    try testing.expectEqual(@as(u64, 0), direct.read_stats().reserved_bytes);
}

// Ported from commonware's `allocator/tests/arena_object_limit_floor.rs`.
test "arena object limit is at least a slice" {
    var config = small_config();
    config.arena_max_object_size = 0;
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    try testing.expectEqual(slice, heap.effective.arena_max_object_size);
}

// Ported from commonware's `allocator/tests/arena_object_limit.rs`. The pages are mapped but
// never touched, so the test commits little physical memory.
test "huge objects are placed as documented" {
    var heap = Heap.init(testing.io, .default);
    defer heap.deinit();
    const gpa = heap.allocator();
    try testing.expectEqual(allocator.arena_max_object_size, heap.effective.arena_max_object_size);

    // The largest page an arena can hold comes from an arena and stays reserved after free.
    var before = heap.read_stats();
    const largest = try alloc_raw(gpa, allocator.arena_max_object_size, 1);
    var held = heap.read_stats();
    gpa.rawFree(largest[0..allocator.arena_max_object_size], .@"1", @returnAddress());
    var after = heap.read_stats();
    try testing.expectEqual(before.huge_allocations + 1, held.huge_allocations);
    try testing.expectEqual(held.reserved_bytes, after.reserved_bytes);

    // One slice more is mapped from the operating system without reserving an arena, and is
    // unmapped on free.
    const size = allocator.arena_max_object_size + slice;
    before = heap.read_stats();
    const page = try alloc_raw(gpa, size, 1);
    held = heap.read_stats();
    gpa.rawFree(page[0..size], .@"1", @returnAddress());
    after = heap.read_stats();
    try testing.expectEqual(before.huge_allocations + 1, held.huge_allocations);
    try testing.expectEqual(before.arenas, held.arenas);
    try testing.expect(held.mmap_calls > before.mmap_calls);
    try testing.expect(held.reserved_bytes >= before.reserved_bytes + size);
    try testing.expect(held.reserved_bytes >= after.reserved_bytes + size);

    // An alignment beyond a slice is also served by a fresh mapping. An alignment of a whole
    // metadata group is refused.
    before = heap.read_stats();
    const block = try alloc_raw(gpa, 64, 2 * slice);
    try testing.expectEqual(@as(usize, 0), @intFromPtr(block) % (2 * slice));
    held = heap.read_stats();
    gpa.rawFree(block[0..64], .fromByteUnits(2 * slice), @returnAddress());
    after = heap.read_stats();
    try testing.expect(held.mmap_calls > before.mmap_calls);
    try testing.expect(held.reserved_bytes >= after.reserved_bytes + slice);
    const group: Alignment = .fromByteUnits(allocator.metadata_group_size);
    try testing.expectEqual(null, gpa.rawAlloc(64, group, @returnAddress()));
}

// Ported from commonware's `allocator/tests/config_options.rs`.
test "configured options are effective" {
    var config = allocator.Config.default;
    config.purge = .never;
    config.reserve = .init_unpinned(chunk + 1);
    config.allow_large_os_pages = true;
    config.arena_eager_commit = .never;
    config.arena_reserve = chunk + 1;
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    try testing.expect(heap.status.configured);
    try testing.expectEqual(allocator.ReserveOutcome.reserved, heap.status.reserve);
    try testing.expect(heap.read_stats().reserved_bytes >= chunk);
    const effective = heap.effective;
    try testing.expectEqual(@as(?u64, null), effective.purge_ns);
    try testing.expectEqual(@as(i64, 0), effective.arena_eager_commit);
    try testing.expect(effective.allow_large_os_pages);
    try testing.expectEqual(chunk + 1024, effective.arena_reserve);
}

/// One thread allocates huge blocks and hands them to another, which frees them.
const CrossThread = struct {
    /// Twice the largest object a shared page serves, so every block is huge.
    const block_bytes = 2 * allocator.large_object_limit;
    const blocks = 64;
    const Queue = std.Io.Queue([]u8);

    fn produce(heap: *Heap, queue: *Queue) void {
        for (0..blocks) |_| {
            const block = heap.allocator().alloc(u8, block_bytes) catch @panic("out of memory");
            @memset(block, 1);
            queue.putOneUncancelable(heap.io, block) catch unreachable; // Closed only below.
        }
        queue.close(heap.io);
    }

    fn consume(heap: *Heap, queue: *Queue) void {
        // A thread that has allocated, as every runtime thread has.
        heap.allocator().destroy(heap.allocator().create(u8) catch @panic("out of memory"));
        var freed: usize = 0;
        while (queue.getOneUncancelable(heap.io)) |block| : (freed += 1) {
            assert(block.len == block_bytes and block[block_bytes - 1] == 1);
            heap.allocator().free(block);
        } else |err| assert(err == error.Closed);
        assert(freed == blocks);
    }
};

// Ported from commonware's `allocator/tests/cross_thread_stats.rs`, the regression test for
// commonwarexyz/monorepo#5483. mimalloc's per-thread counters drift there by up to a merge
// threshold; a zigware heap counts under its lock, so the statistics are exact.
test "stats stay exact while one thread frees what another allocates" {
    var heap = Heap.init(testing.io, small_config());
    defer heap.deinit();
    const gpa = heap.allocator();
    var held: [8][]u8 = undefined;
    for (&held) |*block| block.* = try gpa.alloc(u8, CrossThread.block_bytes);
    defer for (held) |block| gpa.free(block);
    const before = heap.read_stats();

    var buffer: [8][]u8 = undefined;
    var queue: CrossThread.Queue = .init(&buffer);
    var group: std.Io.Group = .init;
    try group.concurrent(testing.io, CrossThread.consume, .{ &heap, &queue });
    try group.concurrent(testing.io, CrossThread.produce, .{ &heap, &queue });
    try group.await(testing.io);

    const after = heap.read_stats();
    try testing.expect(after.pages >= held.len);
    try testing.expectEqual(before.pages, after.pages);
    try testing.expectEqual(before.allocated_bytes, after.allocated_bytes);
    try testing.expectEqual(before.huge_allocations + CrossThread.blocks, after.huge_allocations);
}

const Stress = struct {
    fn run(heap: *Heap, seed: u64) void {
        var prng: std.Random.DefaultPrng = .init(seed);
        const random = prng.random();
        var live: [64]?[]u8 = @splat(null);
        for (0..4_000) |_| {
            const slot = random.uintLessThan(usize, live.len);
            if (live[slot]) |block| {
                for (block) |byte| assert(byte == @as(u8, @truncate(seed)));
                heap.allocator().free(block);
                live[slot] = null;
            } else {
                const len = random.intRangeAtMost(usize, 1, 20_000);
                const block = heap.allocator().alloc(u8, len) catch @panic("out of memory");
                @memset(block, @truncate(seed));
                live[slot] = block;
            }
        }
        for (live) |maybe| if (maybe) |block| heap.allocator().free(block);
    }
};

test "threads allocate and free concurrently" {
    var heap = Heap.init(testing.io, small_config());
    defer heap.deinit();
    var group: std.Io.Group = .init;
    for (0..4) |seed| try group.concurrent(testing.io, Stress.run, .{ &heap, seed + 1 });
    try group.await(testing.io);
    const stats = heap.read_stats();
    try testing.expectEqual(@as(u64, 0), stats.allocated_bytes);
    try testing.expectEqual(@as(u64, 0), stats.pages);
    try testing.expect(stats.threads >= 1);
}

/// Runs random allocations and frees driven by `rng`, checking contents, alignment, and that
/// `allocated_bytes` equals the block sizes of the live allocations.
fn fuzz_heap(random: std.Random) !void {
    var config = small_config();
    config.purge = .{ .after_ns = random.uintAtMost(u64, 2) * std.time.ns_per_ms };
    config.arena_reserve = if (random.boolean()) 0 else 2 * chunk;
    var heap = Heap.init(testing.io, config);
    defer heap.deinit();
    const gpa = heap.allocator();
    const Live = struct { memory: []u8, alignment: Alignment, fill: u8 };
    var live: [32]?Live = @splat(null);
    var expected: u64 = 0;
    for (0..200) |step| {
        const slot = random.uintLessThan(usize, live.len);
        if (live[slot]) |entry| {
            for (entry.memory) |byte| try testing.expectEqual(entry.fill, byte);
            expected -= block_size(entry.memory.len, entry.alignment);
            gpa.rawFree(entry.memory, entry.alignment, @returnAddress());
            live[slot] = null;
            continue;
        }
        const len = switch (random.uintLessThan(u8, 4)) {
            0 => random.intRangeAtMost(usize, 0, 64),
            1 => random.intRangeAtMost(usize, 65, 100_000),
            2 => random.intRangeAtMost(usize, 100_001, 2 << 20),
            else => random.intRangeAtMost(usize, 1, 4096),
        };
        const alignment: Alignment = @fromBackingInt(@intCast(random.intRangeAtMost(u6, 0, 17)));
        const pointer = gpa.rawAlloc(len, alignment, @returnAddress()) orelse continue;
        try testing.expect(alignment.check(@intFromPtr(pointer)));
        const fill: u8 = @truncate(step);
        @memset(pointer[0..len], fill);
        live[slot] = .{ .memory = pointer[0..len], .alignment = alignment, .fill = fill };
        expected += block_size(len, alignment);
        try testing.expectEqual(expected, heap.read_stats().allocated_bytes);
    }
    for (live) |maybe| if (maybe) |entry| gpa.rawFree(entry.memory, entry.alignment, 0);
    try testing.expectEqual(@as(u64, 0), heap.read_stats().allocated_bytes);
    try testing.expectEqual(@as(u64, 0), heap.read_stats().pages);
}

/// The block size a heap uses for `len` bytes at `alignment`, derived from mimalloc's classes.
fn block_size(len: usize, alignment: Alignment) usize {
    const bytes = alignment.toByteUnits();
    if (len <= allocator.large_object_limit and bytes <= slice) {
        var size = allocator.good_size(len);
        // Classes grow until one divides the alignment; the largest classes are slice multiples.
        while (size % bytes != 0) size = allocator.good_size(size + 1);
        return size;
    }
    return allocator.good_size(len);
}

test "fuzz heap seeded" {
    const build_options = @import("build_options");
    const iterations: u64 = 32 * @as(u64, build_options.fuzz_soak);
    var seeds: std.Random.DefaultPrng = .init(0x6865_6170 ^ build_options.fuzz_seed);
    for (0..iterations) |_| {
        var prng: std.Random.DefaultPrng = .init(seeds.random().int(u64));
        try fuzz_heap(prng.random());
    }
}

test "fuzz heap" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var seed: [8]u8 = undefined;
            smith.bytes(&seed);
            var prng: std.Random.DefaultPrng = .init(std.mem.readInt(u64, &seed, .little));
            try fuzz_heap(prng.random());
        }
    }.run, .{});
}
