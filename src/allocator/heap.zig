//! `Heap`: a `std.mem.Allocator` with mimalloc's layout, configured in the program like
//! commonware's `MiMalloc`.
//!
//! Requests up to `large_object_limit` get a block of their mimalloc size class from a shared
//! page; larger ones, and alignments beyond a slice, get a page of their own, and alignments of
//! a whole `metadata_group_size` or more are refused, as in mimalloc. Pages come from
//! arenas: a reservation first, then arenas reserved on demand; a page above
//! `arena_max_object_size` (or any page, when on-demand arenas are disabled) is mapped on its
//! own and unmapped on release. A freed page's slices are purged after the configured delay at
//! the next collection, which runs every `collect_interval` allocations or on `collect`.
//!
//! One lock guards the heap, so statistics are exact. All OS memory goes through `os.zig`.

const std = @import("std");
const assert = std.debug.assert;
const config_module = @import("config.zig");
const size_class = @import("size_class.zig");
const os = @import("os.zig");
const arena_module = @import("arena.zig");
const Stats = @import("stats.zig").Stats;

const Arena = arena_module.Arena;
const Page = arena_module.Page;
const Block = arena_module.Block;
const Config = config_module.Config;
const Effective = config_module.Effective;
const Status = config_module.Status;
const slice_size = config_module.arena_slice_size;
const chunk_size = config_module.arena_chunk_size;

/// The most arenas, including pages mapped on their own, a heap manages at once.
pub const arenas_max = 1024;
/// The most distinct threads a heap counts.
pub const threads_max = 256;
/// Allocations between automatic collections, as mimalloc's default.
pub const collect_interval = 10_000;

/// Pages of one size class that have free blocks.
const Queue = struct {
    first: ?*Page = null,

    fn push(queue: *Queue, page: *Page) void {
        assert(!page.queued);
        page.prev = null;
        page.next = queue.first;
        if (queue.first) |first| first.prev = page;
        queue.first = page;
        page.queued = true;
    }

    fn remove(queue: *Queue, page: *Page) void {
        assert(page.queued);
        if (page.prev) |prev| prev.next = page.next else queue.first = page.next;
        if (page.next) |next| next.prev = page.prev;
        page.prev = null;
        page.next = null;
        page.queued = false;
    }
};

pub const Heap = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    config: Config,
    effective: Effective,
    status: Status,
    /// Arenas in creation order, the reservation first: the order pages are searched.
    arenas: [arenas_max]*Arena = undefined,
    /// The same arenas sorted by address, to find the page of a freed block.
    by_address: [arenas_max]*Arena = undefined,
    arenas_len: usize = 0,
    queues: [size_class.bin_huge]Queue = @splat(.{}),
    stats: Stats = .{},
    allocations: u64 = 0,
    thread_ids: [threads_max]std.Thread.Id = undefined,

    /// A heap with `config` applied, including its reservation.
    pub fn init(io: std.Io, config: Config) Heap {
        var heap: Heap = .{
            .io = io,
            .config = config,
            .effective = .from_config(config),
            .status = .{ .configured = true, .reserve = .not_requested },
        };
        if (config.reserve) |reserve| heap.status.reserve = heap.reserve_at_init(reserve);
        assert(heap.arenas_len <= 1);
        return heap;
    }

    /// Unmaps every arena. Allocations still live become invalid.
    pub fn deinit(heap: *Heap) void {
        for (heap.arenas[0..heap.arenas_len]) |arena| os.unmap(arena.region);
        heap.arenas_len = 0;
        heap.* = undefined;
    }

    fn reserve_at_init(heap: *Heap, request: config_module.Reserve) config_module.ReserveOutcome {
        const size = config_module.whole_chunks(request.bytes) orelse return .failed;
        const kind: arena_module.Kind = if (request.pinned) .pinned else .normal;
        const arena = heap.new_arena(size, kind, slice_size) orelse return .failed;
        if (request.pinned and request.prefault) os.prefault(arena.region);
        return if (request.pinned) .pinned else .reserved;
    }

    pub fn allocator(heap: *Heap) std.mem.Allocator {
        return .{ .ptr = heap, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc_entry,
        .resize = resize_entry,
        .remap = remap_entry,
        .free = free_entry,
    };

    /// The current statistics.
    pub fn read_stats(heap: *Heap) Stats {
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        return heap.stats;
    }

    /// Whether `pointer` lies in memory this heap manages (mimalloc's `mi_is_in_heap_region`).
    pub fn contains(heap: *Heap, pointer: *const anyopaque) bool {
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        return heap.lookup(@intFromPtr(pointer)) != null;
    }

    /// Purges every arena whose purge delay has passed.
    pub fn collect(heap: *Heap) void {
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        heap.collect_locked(heap.now_ns());
    }

    fn now_ns(heap: *Heap) u64 {
        const now = std.Io.Clock.awake.now(heap.io).nanoseconds;
        assert(now >= 0);
        return @intCast(now);
    }

    fn collect_locked(heap: *Heap, now: u64) void {
        for (heap.arenas[0..heap.arenas_len]) |arena| {
            const deadline = arena.purge_deadline_ns orelse continue;
            if (deadline > now) continue;
            heap.purge_arena(arena);
        }
    }

    fn purge_arena(heap: *Heap, arena: *Arena) void {
        assert(arena.kind == .normal);
        const purged = arena.purge();
        heap.stats.purged_bytes += purged.bytes;
        heap.stats.purge_calls += purged.calls;
        heap.stats.arena_purges += 1;
        assert(arena.purge_deadline_ns == null);
    }

    fn lookup(heap: *Heap, address: usize) ?*Arena {
        var low: usize = 0;
        var high: usize = heap.arenas_len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const arena = heap.by_address[middle];
            if (address < arena.base) {
                high = middle;
            } else if (address >= arena.base + arena.region.len) {
                low = middle + 1;
            } else {
                return arena;
            }
        }
        return null;
    }

    fn commit(heap: *Heap, bytes: usize) void {
        if (bytes == 0) return;
        heap.stats.commit_calls += 1;
        heap.stats.committed_bytes += bytes;
        heap.stats.committed_peak_bytes =
            @max(heap.stats.committed_peak_bytes, heap.stats.committed_bytes);
    }

    /// Maps and registers an arena of `size` bytes.
    fn new_arena(heap: *Heap, size: usize, kind: arena_module.Kind, page_align: usize) ?*Arena {
        if (heap.arenas_len == arenas_max) return null;
        heap.stats.mmap_calls += 1;
        const region = os.map(size, @max(page_align, slice_size)) orelse return null;
        const arena = Arena.create(region, kind, page_align) orelse {
            os.unmap(region);
            return null;
        };
        if (kind == .pinned) {
            heap.stats.pinned_bytes += size;
        } else {
            heap.stats.reserved_bytes += size;
        }
        const eager = kind == .transient or heap.config.arena_eager_commit == .always;
        heap.commit(if (eager) size else arena.meta_slices * slice_size);
        if (eager) @memset(arena.committed_bits, std.math.maxInt(u64));
        heap.register(arena);
        return arena;
    }

    fn register(heap: *Heap, arena: *Arena) void {
        assert(heap.arenas_len < arenas_max);
        heap.arenas[heap.arenas_len] = arena;
        var index = heap.arenas_len;
        while (index > 0 and heap.by_address[index - 1].base > arena.base) : (index -= 1) {
            heap.by_address[index] = heap.by_address[index - 1];
        }
        heap.by_address[index] = arena;
        heap.arenas_len += 1;
        // As in mimalloc, a page mapped on its own is not an arena.
        if (arena.kind != .transient) heap.stats.arenas += 1;
        assert(heap.stats.arenas <= heap.arenas_len);
    }

    fn unregister(heap: *Heap, arena: *Arena) void {
        const len = heap.arenas_len;
        const order = std.mem.indexOfScalar(*Arena, heap.arenas[0..len], arena).?;
        const sorted = std.mem.indexOfScalar(*Arena, heap.by_address[0..len], arena).?;
        std.mem.copyForwards(*Arena, heap.arenas[order .. len - 1], heap.arenas[order + 1 .. len]);
        const tail = heap.by_address[sorted + 1 .. len];
        std.mem.copyForwards(*Arena, heap.by_address[sorted .. len - 1], tail);
        heap.arenas_len -= 1;
        assert(heap.stats.arenas <= heap.arenas_len);
        // Only arenas holding one page of their own are released, and those commit eagerly.
        assert(arena.kind == .transient);
        heap.stats.reserved_bytes -= arena.region.len;
        heap.stats.committed_bytes -= arena.region.len;
        os.unmap(arena.region);
    }

    /// Takes a page of `page_bytes`, aligned to `page_align`, from an arena: an existing one,
    /// a new on-demand arena, or an arena of its own.
    fn take_page(heap: *Heap, page_bytes: usize, page_align: usize) ?*Page {
        assert(page_bytes % slice_size == 0);
        const slices = page_bytes / slice_size;
        const fits = page_bytes <= heap.effective.arena_max_object_size and
            page_align <= slice_size;
        if (fits) {
            for (heap.arenas[0..heap.arenas_len]) |arena| {
                if (arena.kind == .transient) continue;
                if (arena.alloc_page(slices)) |taken| return heap.took(taken);
            }
            if (heap.effective.arena_reserve > 0) {
                const size = heap.on_demand_size(page_bytes);
                if (heap.new_arena(size, .normal, slice_size)) |arena| {
                    if (arena.alloc_page(slices)) |taken| return heap.took(taken);
                }
            }
        }
        const size = Arena.transient_size(page_bytes, page_align);
        const arena = heap.new_arena(size, .transient, page_align) orelse return null;
        const taken = arena.alloc_page(slices) orelse unreachable; // Sized to hold the page.
        assert(taken.page.start() % page_align == 0);
        return heap.took(taken);
    }

    /// An on-demand arena's size: the configured base in whole chunks, at least two chunks,
    /// and enough for `page_bytes` beside its metadata.
    fn on_demand_size(heap: *Heap, page_bytes: usize) usize {
        const base = std.mem.alignForward(usize, heap.effective.arena_reserve, chunk_size);
        const transient = Arena.transient_size(page_bytes, slice_size);
        const needed = std.mem.alignForward(usize, transient, chunk_size);
        return @max(base, 2 * chunk_size, needed);
    }

    fn took(heap: *Heap, taken: Arena.Taken) *Page {
        heap.commit(taken.committed_slices * slice_size);
        heap.stats.pages += 1;
        heap.note_thread();
        return taken.page;
    }

    fn note_thread(heap: *Heap) void {
        const id = std.Thread.getCurrentId();
        const known = heap.thread_ids[0..heap.stats.threads];
        if (std.mem.indexOfScalar(std.Thread.Id, known, id) != null) return;
        if (heap.stats.threads == threads_max) return;
        heap.thread_ids[heap.stats.threads] = id;
        heap.stats.threads += 1;
    }

    /// Returns a page with no live blocks to its arena and schedules or performs its purge.
    fn retire(heap: *Heap, page: *Page) void {
        assert(page.used == 0 and !page.queued);
        const arena = page.arena;
        arena.free_page(page);
        heap.stats.pages -= 1;
        if (arena.kind == .transient) {
            assert(arena.used_slices == 0);
            return heap.unregister(arena);
        }
        if (arena.kind == .pinned) return;
        const delay = heap.effective.purge_ns orelse return;
        if (delay < std.time.ns_per_ms) return heap.purge_arena(arena);
        if (arena.purge_deadline_ns == null) arena.purge_deadline_ns = heap.now_ns() + delay;
    }

    /// The smallest size class of at least `len` bytes whose blocks are all aligned to
    /// `alignment` (pages start slice-aligned), or null.
    fn class_for(len: usize, alignment: usize) ?usize {
        if (len > config_module.large_object_limit or alignment > slice_size) return null;
        var bin = size_class.bin(len);
        while (bin < size_class.bin_huge) : (bin += 1) {
            if (size_class.bin_size(bin) % alignment == 0) return bin;
        }
        return null;
    }

    fn alloc_small(heap: *Heap, bin: usize) ?[*]u8 {
        const queue = &heap.queues[bin];
        const page = queue.first orelse page: {
            const block_size = size_class.bin_size(bin);
            const page = heap.take_page(size_class.page_size(block_size), slice_size) orelse
                return null;
            page.bin = @intCast(bin);
            page.block_size = block_size;
            page.capacity = @intCast(page.bytes() / block_size);
            queue.push(page);
            break :page page;
        };
        assert(page.used < page.capacity);
        const block: usize = if (page.free) |free| block: {
            page.free = free.next;
            break :block @intFromPtr(free);
        } else block: {
            assert(page.carved < page.capacity);
            page.carved += 1;
            break :block page.start() + (page.carved - 1) * page.block_size;
        };
        page.used += 1;
        if (page.used == page.capacity) queue.remove(page);
        heap.account_alloc(page.block_size);
        return @ptrFromInt(block);
    }

    fn alloc_huge(heap: *Heap, len: usize, alignment: usize) ?[*]u8 {
        const block_size = size_class.good_size(len);
        const page_bytes = std.mem.alignForward(usize, block_size, slice_size);
        const page = heap.take_page(page_bytes, @max(alignment, slice_size)) orelse return null;
        page.bin = size_class.bin_huge;
        page.block_size = block_size;
        page.capacity = 1;
        page.carved = 1;
        page.used = 1;
        if (len > config_module.large_object_limit) {
            heap.stats.huge_allocations += 1;
            heap.stats.huge_bytes += block_size;
        }
        heap.account_alloc(block_size);
        return @ptrFromInt(page.start());
    }

    fn account_alloc(heap: *Heap, bytes: usize) void {
        heap.stats.allocated_bytes += bytes;
        heap.stats.allocated_peak_bytes =
            @max(heap.stats.allocated_peak_bytes, heap.stats.allocated_bytes);
    }

    fn free_block(heap: *Heap, page: *Page, address: usize) void {
        assert(page.used > 0);
        heap.stats.allocated_bytes -= page.block_size;
        page.used -= 1;
        if (page.bin == size_class.bin_huge) return heap.retire(page);
        assert((address - page.start()) % page.block_size == 0);
        const block: *Block = @ptrFromInt(address);
        block.next = page.free;
        page.free = block;
        const queue = &heap.queues[page.bin];
        if (page.used == 0) {
            if (page.queued) queue.remove(page);
            return heap.retire(page);
        }
        if (!page.queued) queue.push(page);
    }

    fn alloc_entry(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        _: usize,
    ) ?[*]u8 {
        const heap: *Heap = @ptrCast(@alignCast(context));
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        heap.allocations += 1;
        if (heap.allocations % collect_interval == 0) heap.collect_locked(heap.now_ns());
        const align_bytes = alignment.toByteUnits();
        if (align_bytes >= config_module.metadata_group_size) return null;
        const block = if (class_for(len, align_bytes)) |bin|
            heap.alloc_small(bin)
        else
            heap.alloc_huge(len, align_bytes);
        if (block) |pointer| assert(alignment.check(@intFromPtr(pointer)));
        return block;
    }

    fn free_entry(context: *anyopaque, memory: []u8, _: std.mem.Alignment, _: usize) void {
        const heap: *Heap = @ptrCast(@alignCast(context));
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        const address = @intFromPtr(memory.ptr);
        const arena = heap.lookup(address) orelse unreachable; // Freed memory came from here.
        heap.free_block(arena.page_at(address), address);
    }

    /// Resizes in place when the block already holds `new_len` and stays at least half used
    /// (mimalloc's in-place `realloc`), or a page of its own keeps the same block size.
    fn resize_entry(
        context: *anyopaque,
        memory: []u8,
        _: std.mem.Alignment,
        new_len: usize,
        _: usize,
    ) bool {
        const heap: *Heap = @ptrCast(@alignCast(context));
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        const address = @intFromPtr(memory.ptr);
        const page = (heap.lookup(address) orelse unreachable).page_at(address);
        if (page.bin == size_class.bin_huge) {
            return size_class.good_size(new_len) == page.block_size;
        }
        return new_len <= page.block_size and new_len >= page.block_size / 2;
    }

    fn remap_entry(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        if (resize_entry(context, memory, alignment, new_len, return_address)) return memory.ptr;
        return null;
    }
};
