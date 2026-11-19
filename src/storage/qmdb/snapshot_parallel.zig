//! Parallel snapshot build for partitioned indexes (commonware qmdb/snapshot.rs
//! `build_snapshot_parallel`, `ParallelPlan`, and `SnapshotBuild::Concurrency`).
//!
//! An `init_concurrency` budget is split, as in commonware, between decode units, which read
//! contiguous chunks of the log and route each keyed operation to the worker owning its
//! partition, and insert workers, each of which fills its own `Range` of the partitioned index
//! and resolves collisions with its own `location -> key` cache. The full index then absorbs
//! every range, and the activity bitmap is the set of locations the ranges hold plus the last
//! commit.
//!
//! Commonware pipelines the units over channels on spawned tasks. Here the build runs in steps
//! over a strategy: step `s` decodes chunk `s` while the workers apply chunk `s - 1`, all as one
//! `map_into`, so the decode of one chunk overlaps the inserts of the previous one. A worker
//! applies a chunk's routed operations in decoder order, which is log order, so each partition
//! sees exactly the operations, in the order, the serial build gives it. The snapshot, active
//! key count, and bitmap are therefore the serial build's under every strategy shape. Every
//! unit of a step joins before a failure surfaces, so no unit outlives a failed build
//! (commonware's cleanup invariant).
//!
//! Units allocate from `gpa` (and the index's allocator) concurrently, so a parallel build
//! needs thread-safe allocators.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const parallel = @import("parallel");
const value = @import("value.zig");
const snapshot = @import("snapshot.zig");
const Cache = @import("cache.zig").Cache;
const partitioned = @import("../index/partitioned/mod.zig");
const Bounds = @import("../journal/contiguous/mod.zig").Bounds;

/// Operations per decode chunk. Small in tests so ordinary logs cross chunk boundaries.
const decode_chunk: u64 = if (builtin.is_test) 64 else 1 << 17;
/// The most decode units a step runs. Commonware spawns decoders lazily, one per chunk in
/// flight, so a huge budget never holds more than the chunks; this bounds the routed lists.
const decode_units_max = 16;
/// Bytes a decoder's replay buffers per read.
const replay_buffer_bytes = 1 << 16;

/// Worker counts, partition ranges, and cache allocation for a parallel build (commonware's
/// `ParallelPlan`).
pub const Plan = struct {
    /// Total partitions to distribute.
    partitions: usize,
    /// Decode units. Zero means one unit decodes each chunk, as commonware's coordinator does.
    decoders: usize,
    /// Insert workers, each owning a nonempty partition range.
    workers: usize,
    /// Maximum partitions per worker. Partition `p` routes to worker `p / range_size`.
    range_size: usize,
    /// Cache entries per worker; null disables caching, including when the share rounds to 0.
    per_worker_cache: ?usize,

    /// Plans the allocation, or returns null to build serially.
    pub fn init(partitions: usize, concurrency: usize, cache_size: ?usize) ?Plan {
        assert(concurrency >= 1);
        // Inserts cost more than decoding; throughput peaks near two decoders per five tasks.
        var decoders: usize = 0;
        var workers: usize = concurrency - 1;
        if (concurrency > 3) {
            // Divide before multiplying to keep the ratio without overflowing large budgets.
            const share = concurrency / 5 * 2 + concurrency % 5 * 2 / 5;
            decoders = @min(@max(share, 2), concurrency / 2);
            workers = concurrency - decoders;
        }
        workers = @min(workers, partitions);
        if (workers == 0) return null;
        // Proof: divCeil fails only on a zero divisor, and `workers` is nonzero here.
        const range_size = std.math.divCeil(usize, partitions, workers) catch unreachable;
        // `range_size` rounds up, so the last ranges could start at or past `partitions`: keep
        // only the nonempty ones, so routing stays in `[0, workers)`.
        // Proof: `range_size` is at least one since `partitions >= workers > 0`.
        workers = std.math.divCeil(usize, partitions, range_size) catch unreachable;
        const share = if (cache_size) |n| n / workers else 0;
        const cache: ?usize = if (share == 0) null else share;
        assert(workers >= 1 and workers <= partitions);
        return .{
            .partitions = partitions,
            .decoders = decoders,
            .workers = workers,
            .range_size = range_size,
            .per_worker_cache = cache,
        };
    }

    pub const Span = struct { lo: usize, len: usize };

    /// Worker `worker`'s first partition and partition count.
    pub fn range(plan: Plan, worker: usize) Span {
        assert(worker < plan.workers);
        const lo = worker * plan.range_size;
        assert(lo < plan.partitions);
        return .{ .lo = lo, .len = @min(plan.range_size, plan.partitions - lo) };
    }

    /// Decode units per chunk.
    fn decode_units(plan: Plan) usize {
        return std.math.clamp(plan.decoders, 1, decode_units_max);
    }
};

/// Whether `I` is a partitioned index, which can build in parallel. Other indexes build
/// serially (commonware's `Concurrency = ()`).
pub fn is_partitioned(comptime I: type) bool {
    if (!@hasDecl(I, "Translator")) return false;
    return @hasDecl(I.Translator, "partition_count");
}

/// The worker range type of partitioned index `I`.
fn RangeOf(comptime I: type) type {
    comptime assert(is_partitioned(I));
    const Tr = I.Translator;
    const T = @FieldType(Tr, "inner");
    const P = Tr.prefix_length;
    if (@hasDecl(I, "absorb")) return partitioned.ordered.Range(T, I.Value, P);
    return partitioned.unordered.Range(T, I.Value, P);
}

/// `T` on cache lines of its own, so workers' hot state does not share a line.
fn Padded(comptime T: type) type {
    return struct { value: T align(std.atomic.cache_line) };
}

fn Routed(comptime Key: type) type {
    return struct { key: Key, location: u64, is_delete: bool };
}

/// The state of one build: per-worker ranges and caches, and two buffers of routed operations
/// (`[decoder][worker]` lists), one being decoded while the other is applied.
fn Build(comptime Op: type, comptime I: type, comptime Reader: type) type {
    const R = Routed(Op.Key);
    const List = std.ArrayList(R);
    const Range = RangeOf(I);
    return struct {
        const Self = @This();

        gpa: Allocator,
        plan: Plan,
        reader: Reader,
        floor: u64,
        end: u64,
        /// One cache line or more per worker: a range's counters change on every insert.
        ranges: []Padded(Range),
        /// Ranges already moved into the full index (and freed by `install`).
        installed: usize = 0,
        caches: []Padded(?Cache(Op.Key)),
        buffers: [2][]List,

        fn init(gpa: Allocator, plan: Plan, reader: Reader, full: *const I, floor: u64) !Self {
            var self: Self = .{
                .gpa = gpa,
                .plan = plan,
                .reader = reader,
                .floor = floor,
                .end = reader.get_bounds().end,
                .ranges = try gpa.alloc(Padded(Range), plan.workers),
                .caches = &.{},
                .buffers = .{ &.{}, &.{} },
            };
            for (self.ranges, 0..) |*slot, worker| {
                const span = plan.range(worker);
                slot.value = Range.init(full, @intCast(span.lo), @intCast(span.len));
            }
            errdefer self.deinit();
            self.caches = try gpa.alloc(Padded(?Cache(Op.Key)), plan.workers);
            @memset(self.caches, .{ .value = null });
            if (plan.per_worker_cache) |size| {
                for (self.caches) |*slot| slot.value = try Cache(Op.Key).init(gpa, size);
            }
            const list_count = plan.decode_units() * plan.workers;
            for (&self.buffers) |*buffer| {
                buffer.* = try gpa.alloc(List, list_count);
                @memset(buffer.*, .empty);
            }
            return self;
        }

        /// Frees everything, including ranges not yet installed.
        fn deinit(self: *Self) void {
            for (self.buffers) |buffer| {
                for (buffer) |*list| list.deinit(self.gpa);
                self.gpa.free(buffer);
            }
            for (self.caches) |*slot| if (slot.value) |*c| c.deinit(self.gpa);
            self.gpa.free(self.caches);
            for (self.ranges[self.installed..]) |*slot| slot.value.deinit();
            self.gpa.free(self.ranges);
            self.* = undefined;
        }

        fn chunks(self: *const Self) u64 {
            // Proof: `decode_chunk` is a nonzero constant.
            return std.math.divCeil(u64, self.end - self.floor, decode_chunk) catch unreachable;
        }

        fn lists(self: *Self, parity: usize, decoder: usize) []List {
            const workers = self.plan.workers;
            return self.buffers[parity][decoder * workers ..][0..workers];
        }

        /// Decoder `decoder`'s share of chunk `chunk`: `[start, end)` locations.
        fn share(self: *const Self, chunk: u64, decoder: usize) [2]u64 {
            const start = self.floor + chunk * decode_chunk;
            const len = @min(decode_chunk, self.end - start);
            const units: u64 = self.plan.decode_units();
            const lo = start + len * decoder / units;
            const hi = start + len * (decoder + 1) / units;
            assert(lo <= hi and hi <= self.end);
            return .{ lo, hi };
        }

        /// Whether decoders stream the log with `replay_options`, as commonware's decoders
        /// replay it, instead of a `read` (a page cache lookup) per operation. Replayed items
        /// are borrowed, so only operations that own no memory take it.
        const streams = @hasDecl(std.meta.Child(Reader), "replay_options") and
            !codec.owns_memory(Op);

        /// Reads decoder `decoder`'s share of `chunk` and routes each keyed update or delete
        /// to its worker's list.
        fn decode(self: *Self, parity: usize, decoder: usize, chunk: u64) !void {
            const bounds = self.share(chunk, decoder);
            const routed = self.lists(parity, decoder);
            for (routed) |list| assert(list.items.len == 0);
            if (bounds[0] == bounds[1]) return;
            if (comptime streams) {
                const range: Bounds = .{ .start = bounds[0], .end = bounds[1] };
                var replay = try self.reader.replay_options(range, replay_buffer_bytes, .{
                    .dont_cache = true, // Init reads every operation once.
                });
                defer replay.deinit();
                var location = bounds[0];
                while (try replay.next()) |batch| {
                    assert(batch.start == location);
                    for (batch.items) |*op| {
                        try self.route(routed, location, op);
                        location += 1;
                    }
                }
                assert(location == bounds[1]);
                return;
            }
            var location = bounds[0];
            while (location < bounds[1]) : (location += 1) {
                var op: Op = try self.reader.read(location);
                defer codec.free(Op, self.gpa, op);
                try self.route(routed, location, &op);
            }
        }

        fn route(self: *Self, routed: []List, location: u64, op: *const Op) !void {
            const key = op.key() orelse return;
            const is_delete = op.is_delete();
            if (!is_delete and !op.is_update()) return;
            const bytes = value.bytes(Op.Key, key);
            const prefix = I.Translator.prefix_length;
            const partition = partitioned.partition_index_and_sub_key(prefix, bytes).partition;
            const worker = partition / self.plan.range_size;
            assert(worker < self.plan.workers);
            try routed[worker].append(self.gpa, .{
                .key = key.*,
                .location = location,
                .is_delete = is_delete,
            });
        }

        /// Applies a chunk's routed operations for `worker`, in decoder (log) order.
        fn apply(self: *Self, parity: usize, worker: usize) !void {
            const range = &self.ranges[worker].value;
            const cache: ?*Cache(Op.Key) = if (self.caches[worker].value) |*c| c else null;
            const gpa = self.gpa;
            for (0..self.plan.decode_units()) |decoder| {
                const list = &self.lists(parity, decoder)[worker];
                defer list.clearRetainingCapacity();
                for (list.items) |*routed| {
                    const key = &routed.key;
                    const reader = self.reader;
                    if (routed.is_delete) {
                        _ = try snapshot.delete_key(Op, gpa, range, reader, key, cache);
                        continue;
                    }
                    const location = routed.location;
                    _ = try snapshot.update_key(Op, gpa, range, reader, key, location, cache);
                    // This update is now a candidate for later operations on its key.
                    if (cache) |c| c.put(gpa, location, try value.clone(Op.Key, gpa, routed.key));
                }
            }
        }

        /// Step `step` as one unit: units below `decode_units()` decode chunk `step` (when it
        /// exists), and the rest apply chunk `step - 1` (when it exists).
        fn unit(self: *Self, step: u64, index: usize) !void {
            const units = self.plan.decode_units();
            if (index < units) {
                if (step < self.chunks()) try self.decode(@intCast(step % 2), index, step);
                return;
            }
            if (step >= 1) try self.apply(@intCast((step - 1) % 2), index - units);
        }

        const Unit = struct {
            build: *Self,
            step: u64,

            pub fn map(op: Unit, index: usize) ?anyerror {
                op.build.unit(op.step, index) catch |err| return err;
                return null;
            }
        };

        /// Runs every step through `strategy`. The first failing unit (in unit order) of a
        /// step fails the build after the whole step joins.
        fn run(self: *Self, strategy: anytype) !void {
            const count = self.plan.decode_units() + self.plan.workers;
            const results = try self.gpa.alloc(?anyerror, count);
            defer self.gpa.free(results);
            const chunk_count = self.chunks();
            var step: u64 = 0;
            while (step <= chunk_count) : (step += 1) {
                @memset(results, null);
                strategy.map_into(parallel.Range.upto(count), results, Unit{
                    .build = self,
                    .step = step,
                });
                for (results) |result| if (result) |err| return err;
            }
            for (self.buffers) |buffer| for (buffer) |list| assert(list.items.len == 0);
        }

        const Mark = struct {
            activity: *snapshot.ActivityBitMap,
            floor: u64,
            count: *usize,

            fn visit(mark: *const Mark, location: *const u64) void {
                assert(location.* >= mark.floor);
                mark.activity.set(location.* - mark.floor, true);
                mark.count.* += 1;
            }
        };

        /// Marks every location the ranges hold active, installs the ranges into `full` in
        /// worker order, and returns the active key count.
        fn finish(self: *Self, full: *I, activity: *snapshot.ActivityBitMap) !usize {
            var active_keys: usize = 0;
            const mark: Mark = .{
                .activity = activity,
                .floor = self.floor,
                .count = &active_keys,
            };
            for (self.ranges) |*slot| slot.value.for_each_value(&mark, Mark.visit);
            assert(self.installed == 0);
            for (self.ranges) |*slot| {
                try slot.value.install(full);
                self.installed += 1;
            }
            assert(self.installed == self.ranges.len);
            assert(full.keys() <= active_keys);
            return active_keys;
        }
    };
}

/// Builds the snapshot of partitioned index `full` from `floor` with an `init_concurrency`
/// budget of `concurrency` tasks run through `strategy` (commonware's `build_snapshot_parallel`).
/// Falls back to the serial build when the plan leaves no worker. Returns what `snapshot.build`
/// returns, for every strategy shape and every budget.
pub fn build(
    comptime Op: type,
    gpa: Allocator,
    floor: u64,
    reader: anytype,
    full: anytype,
    cache_size: ?usize,
    concurrency: usize,
    strategy: anytype,
) !snapshot.Build {
    const I = @typeInfo(@TypeOf(full)).pointer.child;
    comptime assert(is_partitioned(I));
    comptime assert(!codec.owns_memory(Op.Key)); // Routed keys are copied by value.
    assert(concurrency >= 1);
    const cache: ?usize = if (cache_size) |n| (if (n == 0) null else n) else null;
    const partitions: usize = I.Translator.partition_count;
    const plan = Plan.init(partitions, concurrency, cache) orelse
        return snapshot.build(Op, gpa, floor, reader, full, cache);
    const bounds = reader.get_bounds();
    if (floor < bounds.start) return error.ItemPruned;
    if (floor > bounds.end) return error.DataCorrupted;
    assert(full.keys() == 0);
    var state = try Build(Op, I, @TypeOf(reader)).init(gpa, plan, reader, full, floor);
    defer state.deinit();
    try state.run(strategy);
    var activity = try snapshot.ActivityBitMap.zeroes(gpa, bounds.end - floor);
    errdefer activity.deinit(gpa);
    const active_keys = try state.finish(full, &activity);
    // The last operation is the final commit, which stays active. An empty log has none.
    if (bounds.end > floor) activity.set(bounds.end - 1 - floor, true);
    return .{ .active_keys = active_keys, .activity = activity };
}

/// `build` on a pool of up to `concurrency - 1` threads started through `io`, the calling
/// thread running units too (commonware spawns the build's tasks on its runtime context).
pub fn build_on_io(
    comptime Op: type,
    gpa: Allocator,
    io: std.Io,
    floor: u64,
    reader: anytype,
    full: anytype,
    cache_size: ?usize,
    concurrency: usize,
) !snapshot.Build {
    assert(concurrency >= 1);
    const I = @typeInfo(@TypeOf(full)).pointer.child;
    const partitions: usize = I.Translator.partition_count;
    const plan = Plan.init(partitions, concurrency, cache_size) orelse
        return snapshot.build(Op, gpa, floor, reader, full, cache_size);
    const tasks = @min(plan.decode_units() + plan.workers, parallel.max_chunks);
    const pool = try parallel.ThreadPool.create(gpa, io, .{ .threads = @intCast(tasks - 1) });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool).with_parallelism(tasks);
    return build(Op, gpa, floor, reader, full, cache_size, concurrency, strategy);
}

test {
    _ = @import("snapshot_parallel_test.zig");
}
