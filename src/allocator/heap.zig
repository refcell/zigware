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
//! Each thread gets a cache in the heap (mimalloc's per-thread heap): it owns its small pages,
//! allocates from them and frees into them without the heap's lock, and pushes a block it
//! frees into another thread's page onto that page's deferred list, which the owner drains
//! when it runs out of pages or calls `collect` (mimalloc's delayed free). A cache keeps a size
//! class's last emptied pages for a few refills instead of releasing them at once, as
//! mimalloc retires pages; `collect` releases them. Huge blocks, page moves, and threads past
//! `locals_max` take the heap's lock. Statistics change under the lock
//! except allocated bytes, which each cache counts and `read_stats` sums: exact once no thread
//! is allocating, with the peak taken at locked operations and reads. All OS memory goes
//! through `os.zig`.

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
/// Allocations under the lock between automatic collections, as mimalloc's default.
pub const collect_interval = 10_000;
/// The most threads with a cache in one heap; later threads take the lock for every block.
pub const locals_max = 64;
/// Refills an emptied page outlives before it is released (mimalloc's `MI_RETIRE_CYCLES`).
const retire_cycles = 16;
/// The most emptied pages a size class keeps (mimalloc's `MI_RETIRE_MAX_PAGES`).
const retire_pages_max = 3;
/// Block sizes below this keep up to `retire_pages_max` emptied pages, larger ones only their
/// last page (mimalloc's `MI_SMALL_SIZE_MAX`).
const retire_small_size: usize = 128 * @sizeOf(usize);

/// A list of pages linked through their `next` and `prev`, marked by their `flag` field.
fn List(comptime flag: []const u8) type {
    return struct {
        const Self = @This();
        first: ?*Page = null,
        count: u32 = 0,

        fn push(list: *Self, page: *Page) void {
            assert(!page.queued and !page.full);
            list.count += 1;
            page.prev = null;
            page.next = list.first;
            if (list.first) |first| first.prev = page;
            list.first = page;
            @field(page, flag) = true;
        }

        fn remove(list: *Self, page: *Page) void {
            assert(@field(page, flag) and list.count > 0);
            list.count -= 1;
            if (page.prev) |prev| prev.next = page.next else list.first = page.next;
            if (page.next) |next| next.prev = page.prev;
            page.prev = null;
            page.next = null;
            @field(page, flag) = false;
        }
    };
}

/// Pages of one size class that have free blocks.
const Queue = List("queued");

/// One thread's cache in a heap: the small pages it owns, by size class, and its full ones.
const Local = struct {
    thread_id: std.Thread.Id,
    index: u16,
    queues: [size_class.bin_huge]Queue = @splat(.{}),
    full: List("full") = .{},
    /// Bytes this thread allocated less bytes it freed; only this thread writes it.
    allocated: std.atomic.Value(i64) = .init(0),
    /// Raised by another thread when it starts a deferred list on one of these pages.
    pending: std.atomic.Value(u32) = .init(0),
    /// The size classes that may hold emptied pages kept for reuse; none when min > max.
    retired_min: u8 = size_class.bin_huge,
    retired_max: u8 = 0,

    fn add_allocated(local: *Local, bytes: usize, sign: enum { alloc, free }) void {
        const delta: i64 = @intCast(bytes);
        const before = local.allocated.load(.monotonic);
        local.allocated.store(if (sign == .alloc) before + delta else before - delta, .monotonic);
    }
};

/// The calling thread's cache of the heap it used last. `id` tells a heap from an earlier one
/// at the same address.
const Cached = struct { heap: ?*const Heap = null, id: u64 = 0, index: u16 = 0 };
threadlocal var cached: Cached = .{};
var next_heap_id: std.atomic.Value(u64) = .init(1);

/// What a thread's cache gets when its queue for a size class is empty.
const Refill = union(enum) { page: *Page, block: [*]u8, none };

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
    /// Pages no thread owns, by size class.
    queues: [size_class.bin_huge]Queue = @splat(.{}),
    stats: Stats = .{},
    /// Unique per `init`, so thread caches of a heap freed earlier at this address miss.
    id: u64,
    /// Arenas kept until `deinit` (all but pages mapped on their own): appended under the
    /// lock, read without it to find the page of a block.
    lasting: [arenas_max]*Arena = undefined,
    lasting_len: std.atomic.Value(usize) = .init(0),
    locals: [locals_max]Local = undefined,
    locals_len: usize = 0,
    /// Bytes allocated less bytes freed under the lock; the caches count the rest.
    locked_allocated: i64 = 0,
    allocations: u64 = 0,
    thread_ids: [threads_max]std.Thread.Id = undefined,

    /// A heap with `config` applied, including its reservation.
    pub fn init(io: std.Io, config: Config) Heap {
        var heap: Heap = .{
            .io = io,
            .config = config,
            .effective = .from_config(config),
            .status = .{ .configured = true, .reserve = .not_requested },
            .id = next_heap_id.fetchAdd(1, .monotonic),
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
        heap.note_peak();
        var stats = heap.stats;
        stats.allocated_bytes = heap.allocated_now();
        assert(stats.allocated_bytes <= stats.allocated_peak_bytes);
        return stats;
    }

    /// Allocated bytes: the locked count plus every cache's (lock held).
    fn allocated_now(heap: *const Heap) u64 {
        var total: i64 = heap.locked_allocated;
        for (heap.locals[0..heap.locals_len]) |*local| total += local.allocated.load(.monotonic);
        assert(heap.locals_len <= locals_max);
        return @intCast(@max(total, 0));
    }

    fn note_peak(heap: *Heap) void {
        const now = heap.allocated_now();
        heap.stats.allocated_peak_bytes = @max(heap.stats.allocated_peak_bytes, now);
    }

    /// Whether `pointer` lies in memory this heap manages (mimalloc's `mi_is_in_heap_region`).
    pub fn contains(heap: *Heap, pointer: *const anyopaque) bool {
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        return heap.lookup(@intFromPtr(pointer)) != null;
    }

    /// Moves the blocks other threads freed into the calling thread's pages and releases its
    /// empty pages (mimalloc's `mi_collect`), then purges every arena whose purge delay has
    /// passed.
    pub fn collect(heap: *Heap) void {
        if (heap.local_of()) |local| {
            heap.drain_local(local);
            heap.collect_retired(local, true);
        }
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
        if (arena.kind != .transient) {
            heap.stats.arenas += 1;
            const len = heap.lasting_len.load(.monotonic);
            heap.lasting[len] = arena;
            heap.lasting_len.store(len + 1, .release);
        }
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

    /// A fresh page for size class `bin`, in no list.
    fn new_small_page(heap: *Heap, bin: usize) ?*Page {
        const block_size = size_class.bin_size(bin);
        const page = heap.take_page(size_class.page_size(block_size), slice_size) orelse
            return null;
        page.bin = @intCast(bin);
        page.block_size = block_size;
        page.capacity = @intCast(page.bytes() / block_size);
        assert(page.capacity > 0 and page.owner == 0);
        return page;
    }

    /// Hands out a free or never-used block of `page`, which has room.
    fn take_block(page: *Page) [*]u8 {
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
        return @ptrFromInt(block);
    }

    /// A block from a page no thread owns (lock held).
    fn alloc_small(heap: *Heap, bin: usize) ?[*]u8 {
        const queue = &heap.queues[bin];
        const page = queue.first orelse page: {
            const page = heap.new_small_page(bin) orelse return null;
            queue.push(page);
            break :page page;
        };
        assert(page.owner == 0);
        const block = take_block(page);
        if (page.used == page.capacity) queue.remove(page);
        heap.account_alloc(page.block_size);
        return block;
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
        heap.locked_allocated += @intCast(bytes);
        heap.note_peak();
    }

    /// Frees a block of a page no thread owns (lock held).
    fn free_block(heap: *Heap, page: *Page, address: usize) void {
        assert(page.used > 0 and page.owner == 0);
        heap.locked_allocated -= @intCast(page.block_size);
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
        const align_bytes = alignment.toByteUnits();
        if (align_bytes >= config_module.metadata_group_size) return null;
        const bin = class_for(len, align_bytes) orelse return heap.alloc_locked(len, align_bytes);
        const local = heap.local_of() orelse return heap.alloc_locked(len, align_bytes);
        const block = heap.alloc_local(local, bin) orelse return null;
        assert(alignment.check(@intFromPtr(block)));
        return block;
    }

    /// Huge blocks, and blocks for a thread without a cache, under the lock.
    fn alloc_locked(heap: *Heap, len: usize, align_bytes: usize) ?[*]u8 {
        @branchHint(.cold);
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        heap.count_allocation();
        const block = if (class_for(len, align_bytes)) |bin|
            heap.alloc_small(bin)
        else
            heap.alloc_huge(len, align_bytes);
        if (block) |pointer| assert(@intFromPtr(pointer) % align_bytes == 0);
        return block;
    }

    /// Counts an allocation under the lock and collects every `collect_interval` of them.
    fn count_allocation(heap: *Heap) void {
        heap.allocations += 1;
        if (heap.allocations % collect_interval == 0) heap.collect_locked(heap.now_ns());
        assert(heap.allocations > 0);
    }

    /// The calling thread's cache, or null once `locals_max` threads have one.
    fn local_of(heap: *Heap) ?*Local {
        const entry = cached;
        if (entry.heap == heap and entry.id == heap.id) {
            assert(entry.index < heap.locals_len);
            return &heap.locals[entry.index];
        }
        return heap.attach();
    }

    /// Finds or makes the calling thread's cache. A thread that reuses a finished thread's id
    /// inherits its pages, as mimalloc's reclaiming of abandoned pages does.
    fn attach(heap: *Heap) ?*Local {
        @branchHint(.cold);
        const id = std.Thread.getCurrentId();
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        const index = for (heap.locals[0..heap.locals_len], 0..) |*local, index| {
            if (local.thread_id == id) break index;
        } else index: {
            if (heap.locals_len == locals_max) return null;
            const index = heap.locals_len;
            heap.locals[index] = .{ .thread_id = id, .index = @intCast(index) };
            heap.locals_len += 1;
            break :index index;
        };
        assert(heap.locals[index].thread_id == id);
        cached = .{ .heap = heap, .id = heap.id, .index = @intCast(index) };
        return &heap.locals[index];
    }

    /// A block of size class `bin` from the thread's own pages, without the lock.
    fn alloc_local(heap: *Heap, local: *Local, bin: usize) ?[*]u8 {
        const queue = &local.queues[bin];
        const page = queue.first orelse switch (heap.refill(local, bin)) {
            .page => |page| page,
            .block => |block| return block,
            .none => return null,
        };
        assert(page.owner == local.index + 1 and page.bin == bin);
        const block = take_block(page);
        if (page.used == page.capacity) {
            queue.remove(page);
            local.full.push(page);
        }
        local.add_allocated(page.block_size, .alloc);
        return block;
    }

    /// Gives the thread's empty queue for `bin` a page: one its deferred frees refilled, a
    /// new page it owns, or, when the page has to be mapped on its own (and no thread may
    /// own it), a block from a page under the lock.
    fn refill(heap: *Heap, local: *Local, bin: usize) Refill {
        @branchHint(.cold);
        if (local.pending.load(.acquire) > 0) heap.drain_local(local);
        heap.collect_retired(local, false);
        if (local.queues[bin].first) |page| return .{ .page = page };
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        heap.count_allocation();
        if (heap.queues[bin].first == null) {
            const page = heap.new_small_page(bin) orelse return .none;
            if (page.arena.kind != .transient) {
                page.owner = local.index + 1;
                local.queues[bin].push(page);
                return .{ .page = page };
            }
            heap.queues[bin].push(page);
        }
        const block = heap.alloc_small(bin) orelse return .none;
        return .{ .block = block };
    }

    /// The page of `address` if it lies in an arena kept until `deinit`, found without the
    /// lock: the caller holds a live block there, so the page cannot change under it.
    fn lasting_page(heap: *Heap, address: usize) ?*Page {
        const len = heap.lasting_len.load(.acquire);
        assert(len <= arenas_max);
        for (heap.lasting[0..len]) |arena| {
            if (arena.contains(address)) return arena.page_at(address);
        }
        return null;
    }

    fn free_entry(context: *anyopaque, memory: []u8, _: std.mem.Alignment, _: usize) void {
        const heap: *Heap = @ptrCast(@alignCast(context));
        const address = @intFromPtr(memory.ptr);
        if (heap.lasting_page(address)) |page| {
            if (page.owner != 0) return heap.free_owned(page, address);
        }
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        const arena = heap.lookup(address) orelse unreachable; // Freed memory came from here.
        heap.free_block(arena.page_at(address), address);
    }

    /// Frees a block of a page a thread owns: onto its free list on the owning thread,
    /// otherwise onto its deferred list.
    fn free_owned(heap: *Heap, page: *Page, address: usize) void {
        const block_size = page.block_size;
        assert(page.bin != size_class.bin_huge);
        assert((address - page.start()) % block_size == 0);
        const block: *Block = @ptrFromInt(address);
        if (heap.local_of()) |local| {
            local.add_allocated(block_size, .free);
            if (page.owner == local.index + 1) return heap.free_local(local, page, block);
        } else {
            heap.mutex.lockUncancelable(heap.io);
            defer heap.mutex.unlock(heap.io);
            heap.locked_allocated -= @intCast(block_size);
        }
        heap.free_deferred(page, block);
    }

    fn free_local(heap: *Heap, local: *Local, page: *Page, block: *Block) void {
        assert(page.used > 0 and page.owner == local.index + 1);
        block.next = page.free;
        page.free = block;
        page.used -= 1;
        heap.after_free(local, page);
    }

    /// Moves a page that has room again off its owner's full list and, once it is empty,
    /// keeps it for reuse or releases it (mimalloc's `_mi_page_retire`).
    fn after_free(heap: *Heap, local: *Local, page: *Page) void {
        assert(page.owner == local.index + 1 and page.used < page.capacity);
        if (page.full) {
            local.full.remove(page);
            local.queues[page.bin].push(page);
        }
        if (page.used > 0 or page.retire_expire != 0) return;
        const queue = &local.queues[page.bin];
        assert(page.queued and queue.count > 0);
        const keep = queue.count <= retire_pages_max and
            (queue.count == 1 or page.block_size < retire_small_size);
        if (!keep) return heap.retire_owned(local, page);
        const small = page.block_size <= size_class.small_max_object_size;
        page.retire_expire = if (small) retire_cycles else retire_cycles / 4;
        local.retired_min = @min(local.retired_min, page.bin);
        local.retired_max = @max(local.retired_max, page.bin);
    }

    /// Ages the kept empty pages, releasing those whose cycles ran out, or all of them when
    /// `force`; a kept page that was used again is no longer kept (mimalloc's
    /// `_mi_theap_collect_retired`). Kept pages are among the first of their queue.
    fn collect_retired(heap: *Heap, local: *Local, force: bool) void {
        var min: u8 = size_class.bin_huge;
        var max: u8 = 0;
        var bin = local.retired_min;
        while (bin <= local.retired_max) : (bin += 1) {
            assert(bin < size_class.bin_huge);
            var next = local.queues[bin].first;
            for (0..retire_pages_max) |_| {
                const page = next orelse break;
                next = page.next;
                if (page.retire_expire == 0) continue;
                if (page.used > 0) {
                    page.retire_expire = 0;
                    continue;
                }
                page.retire_expire -= 1;
                if (page.retire_expire == 0 or force) {
                    heap.retire_owned(local, page);
                } else {
                    min = @min(min, bin);
                    max = @max(max, bin);
                }
            }
        }
        local.retired_min = min;
        local.retired_max = max;
        assert(min == size_class.bin_huge or min <= max);
    }

    /// Pushes a block another thread freed onto its page's deferred list, and raises the
    /// owner's `pending` when the list was empty (mimalloc's `mi_free_block_mt`). The page may
    /// be drained and released as soon as the push lands, so the owner is read first.
    fn free_deferred(heap: *Heap, page: *Page, block: *Block) void {
        assert(page.owner > 0 and page.owner <= heap.locals_len);
        const owner = &heap.locals[page.owner - 1];
        var head = page.thread_free.load(.monotonic);
        while (true) {
            block.next = @ptrFromInt(head);
            const desired = @intFromPtr(block);
            head = page.thread_free.cmpxchgWeak(head, desired, .release, .monotonic) orelse break;
        }
        if (head == 0) _ = owner.pending.fetchAdd(1, .release);
    }

    /// Moves `page`'s deferred blocks to its free list, releasing it if it empties.
    fn drain_page(heap: *Heap, local: *Local, page: *Page) void {
        assert(page.owner == local.index + 1);
        var list: ?*Block = @ptrFromInt(page.thread_free.swap(0, .acquire));
        var count: u32 = 0;
        while (list) |block| : (count += 1) {
            assert(count < page.used);
            list = block.next;
            block.next = page.free;
            page.free = block;
        }
        if (count == 0) return;
        page.used -= count;
        heap.after_free(local, page);
    }

    /// Drains every page of `list`, one of the thread's own lists.
    fn drain_list(heap: *Heap, local: *Local, list: anytype) void {
        var next = list.first;
        var visited: usize = 0;
        while (next) |page| : (visited += 1) {
            assert(visited < heap.stats.pages + 1);
            next = page.next;
            heap.drain_page(local, page);
        }
    }

    fn drain_local(heap: *Heap, local: *Local) void {
        _ = local.pending.swap(0, .acquire);
        heap.drain_list(local, &local.full);
        for (&local.queues) |*queue| heap.drain_list(local, queue);
    }

    /// Takes an empty page off its owner's lists and releases it under the lock.
    fn retire_owned(heap: *Heap, local: *Local, page: *Page) void {
        @branchHint(.cold);
        assert(page.used == 0 and page.thread_free.load(.monotonic) == 0);
        local.queues[page.bin].remove(page);
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        page.owner = 0;
        page.free = null;
        page.retire_expire = 0;
        heap.retire(page);
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
        const address = @intFromPtr(memory.ptr);
        if (heap.lasting_page(address)) |page| {
            if (page.owner != 0) return fits_in_place(page, new_len);
        }
        heap.mutex.lockUncancelable(heap.io);
        defer heap.mutex.unlock(heap.io);
        return fits_in_place((heap.lookup(address) orelse unreachable).page_at(address), new_len);
    }

    fn fits_in_place(page: *const Page, new_len: usize) bool {
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
