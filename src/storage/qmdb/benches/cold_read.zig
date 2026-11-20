//! Cold random-read harness (commonware's `qmdb/benches/cold_read.rs`): seeds a large unordered
//! fixed-value `any` database over MMB on disk, then times batches of random keys, printing
//! `/proc/diskstats` deltas beside each batch (Linux; zeros elsewhere). Pages a batch reads
//! stay in the page cache, so size `keys` to keep later batches' hits small.
//!
//! Seed a directory once, drop the OS page cache, then run `read` or `blob` against it:
//!
//! ```sh
//! zig build qmdb-cold-read -- seed <dir> <keys> [seed_batch] [page] [logical] [blob] [cache] \
//!     [threads] [workers] [blocking]
//! zig build qmdb-cold-read -- read <dir> <keys> <mode> [batch] [iters] [depth] [rseed] [disk] \
//!     [page] [logical] [blob] [cache] [threads] [workers] [blocking]
//! zig build qmdb-cold-read -- blob <dir> <mode> [batch] [iters] [rseed] [disk] [workers] \
//!     [blocking]
//! ```
//!
//! Without a subcommand, or with a `--` flag first, the harness does nothing. Pass `read` the
//! `keys`, `page`, `logical`, and `blob` the directory was seeded with. The stage and pipeline
//! modes commit updates to the sampled keys, so compare them on a fresh copy of the seed.
//!
//! - read modes: get_many, chunked (8 get_many chunks), shared (`depth` get_many of the same
//!   batch), get_concurrent and get_serial (one `get` per key), stage (stage, merkleize, apply,
//!   commit), pipeline (prefetch the next batch with get_many, then stage this one, then
//!   commit; the prefetch runs beside the stage), sustained (`2 * iters` batches with `depth`
//!   in flight, one result)
//! - blob modes (random 4 KiB reads of the first log blob, no QMDB or page cache):
//!   blob_read_at and blob_read_many
//! - defaults: seed_batch 1,000,000; batch 1500; iters 20; depth 2; rseed 1234; disk nvme1n1;
//!   page 4096 (the only physical page size zigware's storage writes); logical 0 (no
//!   override); blob 10,000,000 items; cache 65,536 pages; threads 8; workers 8; blocking 512
//!
//! The modes commonware runs as concurrent futures (chunked, shared, get_concurrent, pipeline,
//! sustained) read the database from up to `harness.join_max` tasks at once through
//! `*const Db`, as commonware's futures share `&db`; get_concurrent spreads its keys over that
//! many tasks rather than one future per key. blob_read_many still reads its pages one by
//! one. `threads`, `workers`, and `blocking` are accepted for commonware's command lines and
//! reported only.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const common = @import("common.zig");
const harness = @import("harness.zig");

const Digest = common.Digest;
const Sha256 = common.Sha256;
const TestRng = common.TestRng;
const Db = common.AnyDb(common.mmb, .unordered, common.FixedDigest);
const Session = common.Session(Db);
const rng_mod = utils.rng;

const Phase = enum { seed, read, blob };
const ReadMode = enum {
    get_many,
    chunked,
    shared,
    get_concurrent,
    get_serial,
    stage,
    pipeline,
    sustained,
};
const BlobMode = enum { blob_read_at, blob_read_many };
const blob_page_bytes: u64 = 4096;

pub const Args = struct {
    phase: Phase,
    dir: []const u8,
    keys: u64 = 0,
    batch: usize = 1500,
    iters: usize = 20,
    page: u32 = 4096,
    cache: u32 = 65_536,
    blob: u64 = 10_000_000,
    workers: u64 = 8,
    blocking: u64 = 512,
    read_mode: ReadMode = .get_many,
    blob_mode: BlobMode = .blob_read_at,
    disk: []const u8 = "nvme1n1",
    seed: u64 = 1_000_000,
    threads: u64 = 8,
    rseed: u64 = 1234,
    logical: u16 = 0,
    depth: usize = 2,

    /// Parses `<subcommand> <dir> ...` as listed in the module docs. Null is a parse failure.
    fn parse(argv: []const []const u8) ?Args {
        if (argv.len < 2) return null;
        const phase = std.meta.stringToEnum(Phase, argv[0]) orelse return null;
        var args: Args = .{ .phase = phase, .dir = argv[1] };
        var p: harness.Positional = .{ .args = argv[2..] };
        switch (args.phase) {
            .seed => {
                args.keys = p.required(u64) orelse return null;
                args.seed = p.optional(u64, args.seed) orelse return null;
                args.parse_layout(&p) orelse return null;
            },
            .read => {
                args.keys = p.required(u64) orelse return null;
                const mode = p.required([]const u8) orelse return null;
                args.read_mode = std.meta.stringToEnum(ReadMode, mode) orelse return null;
                args.parse_batches(&p) orelse return null;
                args.depth = p.optional(usize, args.depth) orelse return null;
                if (args.depth == 0 or args.depth > harness.join_max) return null;
                args.parse_sampling(&p) orelse return null;
                args.parse_layout(&p) orelse return null;
            },
            .blob => {
                const mode = p.required([]const u8) orelse return null;
                args.blob_mode = std.meta.stringToEnum(BlobMode, mode) orelse return null;
                args.parse_batches(&p) orelse return null;
                args.parse_sampling(&p) orelse return null;
            },
        }
        args.workers = p.optional(u64, args.workers) orelse return null;
        args.blocking = p.optional(u64, args.blocking) orelse return null;
        if (!p.done() or args.disk.len == 0) return null;
        return args;
    }

    fn parse_batches(args: *Args, p: *harness.Positional) ?void {
        args.batch = p.optional(usize, args.batch) orelse return null;
        args.iters = p.optional(usize, args.iters) orelse return null;
        if (args.batch == 0 or args.iters == 0) return null;
    }

    fn parse_sampling(args: *Args, p: *harness.Positional) ?void {
        args.rseed = p.optional(u64, args.rseed) orelse return null;
        args.disk = p.optional([]const u8, args.disk) orelse return null;
    }

    /// The database layout and page cache options shared by `seed` and `read`.
    fn parse_layout(args: *Args, p: *harness.Positional) ?void {
        args.page = p.optional(u32, args.page) orelse return null;
        args.logical = p.optional(u16, args.logical) orelse return null;
        args.blob = p.optional(u64, args.blob) orelse return null;
        args.cache = p.optional(u32, args.cache) orelse return null;
        args.threads = p.optional(u64, args.threads) orelse return null;
        if (args.page != runtime.storage.blob_page_size) return null;
        if (args.blob == 0 or args.cache == 0) return null;
    }
};

const usage_text =
    \\usage:
    \\  seed <dir> <keys> [seed_batch] [page] [logical] [blob] [cache] [threads] [workers] [blocking]
    \\  read <dir> <keys> <mode> [batch] [iters] [depth] [rseed] [disk] [page] [logical] [blob] [cache] [threads] [workers] [blocking]
    \\      mode: get_many|chunked|shared|get_concurrent|get_serial|stage|pipeline|sustained
    \\  blob <dir> <mode> [batch] [iters] [rseed] [disk] [workers] [blocking]
    \\      mode: blob_read_at|blob_read_many
    \\
;

pub fn main(init: std.process.Init) !u8 {
    return harness.main(init, usage_text, run);
}

/// Runs the harness on `args` (without the program name).
pub fn run(
    gpa: Allocator,
    io: Io,
    argv: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !void {
    if (argv.len == 0 or std.mem.startsWith(u8, argv[0], "--")) return;
    const args = Args.parse(argv) orelse return error.Usage;
    try print_header(&args, err);
    var disk: common.Disk = .at(io, args.dir);
    try disk.open(gpa);
    defer disk.close();
    if (args.phase == .blob) return blob_phase(gpa, io, &disk, &args, out, err);

    const start = harness.now_ns(io);
    var session: Session = undefined;
    try session.open(gpa, &disk, .{
        .items_per_blob = args.blob,
        .init_cache = 1 << 20,
        .page_cache_pages = args.cache,
        .logical_page_size = if (args.logical > 0)
            args.logical
        else
            runtime.buffer.paged.page_size(runtime.storage.blob_page_size),
        .names = .{
            .merkle_journal = "cold-merkle",
            .merkle_metadata = "cold-merkle-meta",
            .log = "cold-log",
        },
    });
    defer session.shut();
    const db = &session.db;
    const bounds = db.bounds();
    try err.print("init: {d:.2} ms bounds={d}..{d}\n", .{
        harness.elapsed_ms(io, start), bounds.start, bounds.end,
    });
    try err.flush();
    if (bounds.end > 1 or args.phase == .read) {
        // Sequential seeding commits a prefix of the keyspace before any timed updates.
        if (args.keys == 0) return error.Usage;
        if (try db.get(&common.key_at(args.keys - 1)) == null) return error.IncompleteSeed;
    }
    switch (args.phase) {
        .seed => try seed(io, db, &args, err),
        .read => try read_phase(gpa, io, db, &args, out),
        .blob => unreachable,
    }
}

fn print_header(args: *const Args, err: *Io.Writer) !void {
    assert(args.dir.len > 0);
    switch (args.phase) {
        .seed => try err.print("cold_read seed dir={s} keys={d} seed_batch={d} ", .{
            args.dir, args.keys, args.seed,
        }),
        .read => try err.print("cold_read read dir={s} keys={d} mode={t} batch={d} " ++
            "iters={d} depth={d} rseed={d} disk={s} ", .{
            args.dir,   args.keys,  args.read_mode, args.batch,
            args.iters, args.depth, args.rseed,     args.disk,
        }),
        .blob => try err.print("cold_read blob dir={s} mode={t} batch={d} iters={d} " ++
            "rseed={d} disk={s} ", .{
            args.dir, args.blob_mode, args.batch, args.iters, args.rseed, args.disk,
        }),
    }
    if (args.phase != .blob) {
        try err.print("page={d} logical={d} blob={d} cache={d} threads={d} ", .{
            args.page, args.logical, args.blob, args.cache, args.threads,
        });
    }
    try err.print("workers={d} blocking={d}\n", .{ args.workers, args.blocking });
    try err.flush();
}

/// Commonware's `Sha256::hash(&[&value.to_be_bytes()])` for a `u32` or `u64`.
fn hash_be(comptime T: type, value: T) Digest {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    const digest = Sha256.hash(&.{&bytes});
    assert(digest.bytes.len == 32);
    return digest;
}

/// Seeds `keys` keys in `seed_batch`-key committed batches, unless the database holds data.
fn seed(io: Io, db: *Db, args: *const Args, err: *Io.Writer) !void {
    assert(args.seed > 0);
    const start = harness.now_ns(io);
    if (db.bounds().end > 1) {
        try err.print("db already seeded (bounds end={d}); skipping seed\n", .{db.bounds().end});
        return;
    }
    var rng: TestRng = .init(42);
    var i: u64 = 0;
    while (i < args.keys) {
        const end = @min(i + args.seed, args.keys);
        var batch: ?Db.UnmerkleizedBatch = try db.new_batch();
        errdefer if (batch) |*pending| pending.deinit();
        for (i..end) |k| {
            try common.write(Db, db.gpa, &batch.?, common.key_at(k), hash_be(u32, rng.next_u32()));
        }
        try common.flush(Db, db, &batch, true, false);
        i = end;
        if ((i / args.seed) % 10 == 0) {
            try err.print("seeded {d} keys in {d:.2} ms\n", .{ i, harness.elapsed_ms(io, start) });
            try err.flush();
        }
    }
    try db.sync();
    const ms = harness.elapsed_ms(io, start);
    try err.print("seed done: {d} keys in {d:.2} ms\n", .{ args.keys, ms });
    assert(db.bounds().end > args.keys);
}

/// `count` sorted, deduplicated batches of `batch` random keys below `keys`.
const Batches = struct {
    keys: []Digest,
    lens: []usize,
    stride: usize,

    fn init(gpa: Allocator, rng: *TestRng, count: usize, batch: usize, keys: u64) !Batches {
        assert(count > 0 and batch > 0);
        const all = try gpa.alloc(Digest, count * batch);
        errdefer gpa.free(all);
        const lens = try gpa.alloc(usize, count);
        for (lens, 0..) |*len, index| {
            const slice = all[index * batch ..][0..batch];
            for (slice) |*key| key.* = common.key_at(rng_mod.range_less_than(rng, u64, 0, keys));
            len.* = harness.sort_dedup(slice).len;
        }
        return .{ .keys = all, .lens = lens, .stride = batch };
    }

    fn get(self: *const Batches, index: usize) []const Digest {
        assert(index < self.lens.len);
        return self.keys[index * self.stride ..][0..self.lens[index]];
    }

    fn deinit(self: *Batches, gpa: Allocator) void {
        gpa.free(self.keys);
        gpa.free(self.lens);
        self.* = undefined;
    }
};

/// Reads `keys` with one get_many, asserting every key is present.
fn read_many(db: *const Db, keys: []const Digest, values: []?Digest) !void {
    assert(keys.len <= values.len);
    try db.get_many(keys, values[0..keys.len]);
    for (values[0..keys.len]) |value| if (value == null) return error.MissingKey;
    std.mem.doNotOptimizeAway(values);
}

fn read_phase(gpa: Allocator, io: Io, db: *Db, args: *const Args, out: *Io.Writer) !void {
    assert(args.keys > 0);
    if (args.read_mode == .sustained) return sustained(gpa, io, db, args, out);
    var rng: TestRng = .init(args.rseed);
    // Every batch's keys up front, so a pipeline iteration can prefetch the next batch.
    var batches: Batches = try .init(gpa, &rng, args.iters + 1, args.batch, args.keys);
    defer batches.deinit(gpa);
    const values = try gpa.alloc(?Digest, args.batch);
    defer gpa.free(values);
    const times = try gpa.alloc(f64, args.iters);
    defer gpa.free(times);
    for (times, 0..) |*time, iter| {
        const keys = batches.get(iter);
        const before = harness.diskstats(gpa, io, args.disk);
        const start = harness.now_ns(io);
        var detail_buffer: [160]u8 = undefined;
        const detail = try read_iteration(io, db, args, &batches, iter, values, &detail_buffer);
        time.* = harness.elapsed_ms(io, start);
        const after = harness.diskstats(gpa, io, args.disk);
        try out.print("iter={d} keys={d} ms={d:.2}{s} | ", .{ iter, keys.len, time.*, detail });
        try harness.print_disk_delta(out, before, after, time.*);
        try out.writeByte('\n');
        try out.flush();
    }
    try out.print("RESULT mode={t} keys={d} batch={d} page={d} cache={d} blob={d} ", .{
        args.read_mode, args.keys, args.batch, args.page, args.cache, args.blob,
    });
    try print_summary(out, args.workers, args.blocking, times);
}

fn print_summary(out: *Io.Writer, workers: u64, blocking: u64, times: []f64) !void {
    assert(times.len > 0);
    const average = harness.mean(times);
    try out.print("workers={d} blocking={d} p50={d:.2} mean={d:.2} min={d:.2} max={d:.2}\n", .{
        workers, blocking,                       harness.percentile(times, 0.5),
        average, harness.percentile(times, 0.0), harness.percentile(times, 1.0),
    });
    try out.flush();
}

/// Runs one timed batch of a read mode, returning its detail text.
fn read_iteration(
    io: Io,
    db: *Db,
    args: *const Args,
    batches: *const Batches,
    iter: usize,
    values: []?Digest,
    buffer: []u8,
) ![]const u8 {
    const keys = batches.get(iter);
    assert(keys.len > 0 and keys.len <= values.len);
    switch (args.read_mode) {
        .get_many => try read_many(db, keys, values),
        .get_serial => for (keys) |*key| {
            const value = try db.get(key) orelse return error.MissingKey;
            std.mem.doNotOptimizeAway(value);
        },
        .get_concurrent => {
            const reads: Reads = .{ .db = db, .keys = keys, .values = values };
            try harness.join_all(io, @min(keys.len, harness.join_max), &reads, Reads.gets);
        },
        .chunked => {
            const chunk = @max(std.math.divCeil(usize, keys.len, 8) catch unreachable, 1);
            const reads: Reads = .{ .db = db, .keys = keys, .values = values, .chunk = chunk };
            const chunks = std.math.divCeil(usize, keys.len, chunk) catch unreachable;
            try harness.join_all(io, chunks, &reads, Reads.chunk_get_many);
        },
        .shared => {
            // Concurrent readers of one batch miss the same pages at the same time.
            const all = try db.gpa.alloc(?Digest, keys.len * args.depth);
            defer db.gpa.free(all);
            const reads: Reads = .{ .db = db, .keys = keys, .values = all, .chunk = keys.len };
            try harness.join_all(io, args.depth, &reads, Reads.whole_get_many);
            return std.fmt.bufPrint(buffer, " depth={d}", .{args.depth});
        },
        .stage => return stage_commit(io, db, keys, iter, values, buffer, null),
        .pipeline => {
            const next = if (iter + 1 < args.iters) batches.get(iter + 1) else &.{};
            return stage_commit(io, db, keys, iter, values, buffer, next);
        },
        .sustained => unreachable, // `read_phase` runs it on its own.
    }
    return "";
}

/// Reads one batch's keys from several tasks; task `index` uses `values` from
/// `index * chunk`. `chunk` is zero for per-key gets.
const Reads = struct {
    db: *const Db,
    keys: []const Digest,
    values: []?Digest,
    chunk: usize = 0,

    /// Gets every key at `index` modulo the task count.
    fn gets(reads: *const Reads, index: usize) !void {
        const tasks = @min(reads.keys.len, harness.join_max);
        assert(index < tasks);
        var at = index;
        while (at < reads.keys.len) : (at += tasks) {
            const value = try reads.db.get(&reads.keys[at]) orelse return error.MissingKey;
            std.mem.doNotOptimizeAway(value);
        }
    }

    /// One get_many of the `index`th chunk of the keys.
    fn chunk_get_many(reads: *const Reads, index: usize) !void {
        const start = index * reads.chunk;
        assert(reads.chunk > 0 and start < reads.keys.len);
        const end = @min(start + reads.chunk, reads.keys.len);
        try read_many(reads.db, reads.keys[start..end], reads.values[start..end]);
    }

    /// One get_many of all the keys, into the `index`th values slice.
    fn whole_get_many(reads: *const Reads, index: usize) !void {
        assert(reads.chunk == reads.keys.len);
        const values = reads.values[index * reads.chunk ..][0..reads.chunk];
        try read_many(reads.db, reads.keys, values);
    }
};

/// Stages `keys`, merkleizes a put to each, applies, and commits. With `prefetch` (the pipeline
/// mode), first reads the next batch's keys with get_many, as an app given the keys ahead.
fn stage_commit(
    io: Io,
    db: *Db,
    keys: []const Digest,
    iter: usize,
    values: []?Digest,
    buffer: []u8,
    prefetch: ?[]const Digest,
) ![]const u8 {
    assert(keys.len > 0);
    const next = prefetch orelse &.{};
    const next_values = try db.gpa.alloc(?Digest, next.len);
    defer db.gpa.free(next_values);
    var batch = try db.new_batch();
    var join: StageJoin = .{
        .io = io,
        .db = db,
        .batch = &batch,
        .keys = keys,
        .values = values[0..keys.len],
        .next = next,
        .next_values = next_values,
    };
    const joined = if (prefetch == null)
        join.run(1)
    else
        harness.join_all(io, 2, &join, StageJoin.run);
    joined catch |err| {
        if (join.staged) |*staged| staged.deinit() else batch.deinit();
        return err;
    };
    var staged = join.staged.?;
    const prefetch_ms = join.prefetch_ms;
    const stage_ms = join.stage_ms;
    const slots = slots: {
        errdefer staged.deinit();
        for (values[0..keys.len]) |value| if (value == null) return error.MissingKey;
        break :slots try db.gpa.alloc(Db.Slot, keys.len);
    };
    defer db.gpa.free(slots);
    for (slots, 0..) |*slot, i| slot.* = .{ .put = hash_be(u64, @as(u64, iter) * 1_000_000 + i) };
    const merkle_start = harness.now_ns(io);
    const merkleized = merkleized: {
        errdefer staged.deinit();
        break :merkleized try staged.merkleize(slots, &.{}, db);
    };
    defer merkleized.release();
    const merkle_ms = harness.elapsed_ms(io, merkle_start);
    try db.apply_batch(merkleized);
    try db.commit();
    const commit_ms = harness.elapsed_ms(io, merkle_start) - merkle_ms;
    if (prefetch == null) {
        return std.fmt.bufPrint(buffer, " stage={d:.2} merkleize={d:.2} apply+commit={d:.2}", .{
            stage_ms, merkle_ms, commit_ms,
        });
    }
    return std.fmt.bufPrint(buffer, " prefetch_next={d:.2} stage={d:.2} merkleize={d:.2} " ++
        "apply+commit={d:.2}", .{ prefetch_ms, stage_ms, merkle_ms, commit_ms });
}

/// The pipeline mode's prefetch of the next batch beside this batch's stage (commonware's
/// `join!`): task 0 reads `next` into `next_values`, task 1 stages `keys` into `values`.
const StageJoin = struct {
    io: Io,
    db: *const Db,
    batch: *Db.UnmerkleizedBatch,
    keys: []const Digest,
    values: []?Digest,
    next: []const Digest,
    next_values: []?Digest,
    staged: ?Db.StagedBatch = null,
    prefetch_ms: f64 = 0,
    stage_ms: f64 = 0,

    fn run(join: *StageJoin, index: usize) !void {
        assert(index < 2);
        assert(join.values.len == join.keys.len);
        const start = harness.now_ns(join.io);
        if (index == 0) {
            if (join.next.len > 0) try read_many(join.db, join.next, join.next_values);
            join.prefetch_ms = harness.elapsed_ms(join.io, start);
        } else {
            join.staged = try join.batch.stage(join.keys, join.db, join.values);
            join.stage_ms = harness.elapsed_ms(join.io, start);
        }
    }
};

/// `2 * iters` batches from their own key stream, timed from the first read as one result.
fn sustained(gpa: Allocator, io: Io, db: *Db, args: *const Args, out: *Io.Writer) !void {
    assert(args.depth > 0);
    var rng: TestRng = .init(args.rseed +% 99);
    const total = args.iters * 2;
    var pool: Batches = try .init(gpa, &rng, total, args.batch, args.keys);
    defer pool.deinit(gpa);
    const values = try gpa.alloc(?Digest, args.batch * args.depth);
    defer gpa.free(values);
    var inflight: Inflight = .{ .db = db, .pool = &pool, .values = values, .batch = args.batch };
    const before = harness.diskstats(gpa, io, args.disk);
    const start = harness.now_ns(io);
    try harness.join_all(io, args.depth, &inflight, Inflight.drain);
    const ms = harness.elapsed_ms(io, start);
    assert(inflight.next.load(.monotonic) >= total);
    const after = harness.diskstats(gpa, io, args.disk);
    const per_batch = ms / @as(f64, @floatFromInt(total));
    try out.print("sustained:  depth={d} batches={d} ms_per_batch={d:.2} | total_ms={d:.1} | ", .{
        args.depth, total, per_batch, ms,
    });
    try harness.print_disk_delta(out, before, after, ms);
    try out.writeByte('\n');
    try out.flush();
}

/// Keeps `depth` batches in flight for the whole sustained run: each of `depth` tasks takes
/// the next unread batch of the pool as its last one completes (commonware's refilled
/// `FuturesUnordered`).
const Inflight = struct {
    db: *const Db,
    pool: *const Batches,
    values: []?Digest,
    batch: usize,
    next: std.atomic.Value(usize) = .init(0),

    fn drain(inflight: *Inflight, index: usize) !void {
        const values = inflight.values[index * inflight.batch ..][0..inflight.batch];
        assert(values.len == inflight.batch);
        const total = inflight.pool.lens.len;
        // Each pass takes a distinct batch, so a task runs at most `total` passes.
        for (0..total) |_| {
            const taken = inflight.next.fetchAdd(1, .monotonic);
            if (taken >= total) return;
            try read_many(inflight.db, inflight.pool.get(taken), values);
        }
    }
};

/// Raw reads of random 4 KiB pages of the log's first data blob, bypassing QMDB and the page
/// cache (commonware's `blob_phase`).
fn blob_phase(
    gpa: Allocator,
    io: Io,
    disk: *common.Disk,
    args: *const Args,
    out: *Io.Writer,
    err: *Io.Writer,
) !void {
    var name: [8]u8 = undefined;
    std.mem.writeInt(u64, &name, 0, .big);
    const opened = try disk.storage().open("cold-log-blobs", &name);
    defer opened.blob.close();
    const pages = opened.len / blob_page_bytes;
    try err.print("blob phase: blob size {d} ({d} pages)\n", .{ opened.len, pages });
    try err.flush();
    if (pages == 0) return error.EmptyBlob;
    var rng: TestRng = .init(args.rseed);
    const offsets = try gpa.alloc(u64, args.batch);
    defer gpa.free(offsets);
    const times = try gpa.alloc(f64, args.iters);
    defer gpa.free(times);
    var page: [blob_page_bytes]u8 = undefined;
    for (times, 0..) |*time, iter| {
        for (offsets) |*offset| {
            offset.* = rng_mod.range_less_than(&rng, u64, 0, pages) * blob_page_bytes;
        }
        std.mem.sort(u64, offsets, {}, std.sort.asc(u64));
        const unique = dedup(offsets);
        const before = harness.diskstats(gpa, io, args.disk);
        const start = harness.now_ns(io);
        for (unique) |offset| {
            try opened.blob.read_at_options(offset, &page, .{ .dont_cache = true });
            std.mem.doNotOptimizeAway(&page);
        }
        time.* = harness.elapsed_ms(io, start);
        const after = harness.diskstats(gpa, io, args.disk);
        try out.print("iter={d} reads={d} ms={d:.2} | ", .{ iter, unique.len, time.* });
        try harness.print_disk_delta(out, before, after, time.*);
        try out.writeByte('\n');
    }
    try out.print("RESULT mode={t} batch={d} ", .{ args.blob_mode, args.batch });
    try print_summary(out, args.workers, args.blocking, times);
}

fn dedup(sorted: []u64) []u64 {
    var len: usize = 0;
    for (sorted) |value| {
        if (len > 0 and sorted[len - 1] == value) continue;
        sorted[len] = value;
        len += 1;
    }
    assert(len <= sorted.len);
    return sorted[0..len];
}

test "cold_read: smoke run seeds, reads in every mode, and reads the raw blob" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp: harness.SmokeDir = .init();
    defer tmp.cleanup();
    const dir = tmp.sub("cold");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const seed_args = [_][]const u8{ "seed", dir, "300", "100", "4096", "0", "1000", "64" };
    try run(gpa, io, &seed_args, &out.writer, &err.writer);
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "seed done: 300 keys") != null);
    inline for (comptime std.enums.values(ReadMode)) |mode| {
        const args = [_][]const u8{
            "read", dir,    "300",  @tagName(mode), "20",   "2",  "2",
            "7",    "none", "4096", "0",            "1000", "64",
        };
        try run(gpa, io, &args, &out.writer, &err.writer);
    }
    try std.testing.expectEqual(@as(usize, 7), std.mem.count(u8, out.written(), "RESULT mode="));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "sustained:  depth=2") != null);
    for ([_][]const u8{ "blob_read_at", "blob_read_many" }) |mode| {
        try run(gpa, io, &.{ "blob", dir, mode, "8", "2" }, &out.writer, &err.writer);
    }
    try std.testing.expectEqual(@as(usize, 9), std.mem.count(u8, out.written(), "RESULT mode="));
    // A read past the seeded keys finds the seed incomplete; no subcommand does nothing.
    const past = [_][]const u8{
        "read", dir, "301", "get_many", "20", "2", "2", "7", "none", "4096", "0", "1000", "64",
    };
    const incomplete = run(gpa, io, &past, &out.writer, &err.writer);
    try std.testing.expectError(error.IncompleteSeed, incomplete);
    try run(gpa, io, &.{}, &out.writer, &err.writer);
    const usage = run(gpa, io, &.{ "read", dir }, &out.writer, &err.writer);
    try std.testing.expectError(error.Usage, usage);
}
