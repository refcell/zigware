//! Constantinople-shape harness (commonware's `qmdb/benches/constantinople.rs`): staged load,
//! staged merkleize, and root of 32k updates over 1M keys, the production validator shape.
//!
//! ```sh
//! zig build qmdb-constantinople -- <db> [depth] [iters] [keys] [reads] [read_chunks] \
//!     [updates] [threads] [page_cache] [policy]
//! ```
//!
//! - db: `any::unordered::fixed::mmb`, `any::ordered::fixed::mmb`,
//!   `any::unordered::variable::mmb`, `current::unordered::fixed::mmb`, or
//!   `current::ordered::fixed::mmb`. Without it, or with a `--` flag first, the harness does
//!   nothing.
//! - depth: pending ancestor batches under the timed batch (default 0)
//! - iters: timed iterations (default 15); keys: seeded keys (default 1,000,000)
//! - reads: keys loaded per batch (default 32,768); read_chunks: split the reads into `stage`
//!   plus `expand` chunks (default 1); updates: keys written per batch (default 32,768)
//! - threads: accepted for commonware's command line; zigware merkleizes on one thread
//! - page_cache: page cache capacity in pages (default 131,072)
//! - policy: the timed merkleize's floor policy, `proportional` (default), `fixed` (one entry
//!   per distinct written key plus one, unlimited skips: the proportional allowance, so the
//!   roots match), or `fixed-bounded` (the same entries, at most `updates` skips)
//!
//! Each iteration prints its latency, the load and merkleize split, and the speculative root
//! (a parity check: any optimization must reproduce the same roots), then a RESULT line.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const storage = @import("storage");
const common = @import("common.zig");
const harness = @import("harness.zig");

const floor = storage.qmdb.floor;
const Digest = common.Digest;
const Sha256 = common.Sha256;
const TestRng = common.TestRng;
const AnyDb = common.AnyDb;

const page_cache_pages_default: u32 = 131_072;
const items_per_blob: u64 = 10_000_000;
const churn_batches: u64 = 4;
const init_cache: usize = 1 << 18;

/// The databases the harness runs (commonware's `db` argument).
pub const variants = .{
    common.Variant("any::unordered::fixed::mmb", AnyDb(common.mmb, .unordered, common.FixedDigest)),
    common.Variant("any::ordered::fixed::mmb", AnyDb(common.mmb, .ordered, common.FixedDigest)),
    common.Variant(
        "any::unordered::variable::mmb",
        AnyDb(common.mmb, .unordered, common.VariableDigest),
    ),
    common.Variant(
        "current::unordered::fixed::mmb",
        common.CurrentDb(common.mmb, .unordered, common.FixedDigest),
    ),
    common.Variant(
        "current::ordered::fixed::mmb",
        common.CurrentDb(common.mmb, .ordered, common.FixedDigest),
    ),
};

const Policy = enum {
    proportional,
    fixed,
    @"fixed-bounded",

    /// The fixed limits for a batch writing `distinct_keys` existing keys out of `updates`
    /// slots, or null for the proportional policy.
    fn bounded(policy: Policy, distinct_keys: usize, updates: u64) ?floor.Bounded {
        assert(updates > 0);
        assert(distinct_keys <= updates);
        const entries = distinct_keys + 1;
        return switch (policy) {
            .proportional => null,
            .fixed => .{ .entries = entries, .skips = std.math.maxInt(u64) },
            .@"fixed-bounded" => .{ .entries = entries, .skips = updates },
        };
    }
};

pub const Args = struct {
    db: []const u8,
    depth: u8 = 0,
    iters: usize = 15,
    num_keys: u64 = 1_000_000,
    num_reads: u64 = 32_768,
    read_chunks: usize = 1,
    num_updates: u64 = 32_768,
    threads: u64 = 8,
    page_cache: u32 = page_cache_pages_default,
    policy: Policy = .proportional,

    /// Commonware's lenient parse: a malformed number takes the default.
    fn parse(args: []const []const u8) !Args {
        assert(args.len > 0);
        var result: Args = .{ .db = args[0] };
        const at = struct {
            fn get(list: []const []const u8, comptime T: type, index: usize, default: T) T {
                if (index >= list.len) return default;
                return harness.parse(T, list[index]) orelse default;
            }
        }.get;
        result.depth = at(args, u8, 1, result.depth);
        result.iters = at(args, usize, 2, result.iters);
        result.num_keys = at(args, u64, 3, result.num_keys);
        result.num_reads = at(args, u64, 4, result.num_reads);
        result.read_chunks = at(args, usize, 5, result.read_chunks);
        result.num_updates = at(args, u64, 6, result.num_updates);
        result.threads = at(args, u64, 7, result.threads);
        result.page_cache = at(args, u32, 8, result.page_cache);
        if (args.len > 9) result.policy = std.meta.stringToEnum(Policy, args[9]) orelse
            return error.Usage;
        if (result.iters == 0 or result.num_keys == 0 or result.num_updates == 0) {
            return error.Usage;
        }
        if (result.num_reads < result.num_updates or result.read_chunks == 0) return error.Usage;
        if (result.page_cache == 0) return error.Usage;
        return result;
    }
};

const usage_text = "usage: constantinople <db> [depth] [iters] [keys] [reads] [read_chunks] " ++
    "[updates] [threads] [page_cache] [proportional|fixed|fixed-bounded]\n  db: " ++
    "any::unordered::fixed::mmb|any::ordered::fixed::mmb|any::unordered::variable::mmb\n";

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = try harness.strip_bench_flag(init.arena.allocator(), argv[@min(argv.len, 1)..]);
    var out_buffer: [4096]u8 = undefined;
    var out = Io.File.stdout().writer(io, &out_buffer);
    var err_buffer: [4096]u8 = undefined;
    var err = Io.File.stderr().writer(io, &err_buffer);
    defer out.interface.flush() catch {};
    defer err.interface.flush() catch {};
    run(init.gpa, io, args, &out.interface, &err.interface) catch |e| switch (e) {
        error.Usage => {
            try err.interface.writeAll(usage_text);
            return 2;
        },
        else => return e,
    };
    return 0;
}

/// Runs the harness on `args` (without the program name), with production disk storage
/// under `.zig-cache/tmp`, destroyed at the end.
pub fn run(
    gpa: Allocator,
    io: Io,
    args: []const []const u8,
    out: *Io.Writer,
    err: *Io.Writer,
) !void {
    if (args.len == 0 or std.mem.startsWith(u8, args[0], "--")) return;
    const parsed = try Args.parse(args);
    try err.print("constantinople db={s} depth={d} iters={d} keys={d} reads={d} ", .{
        parsed.db, parsed.depth, parsed.iters, parsed.num_keys, parsed.num_reads,
    });
    try err.print("read_chunks={d} updates={d} threads={d} page_cache={d} policy={t}\n", .{
        parsed.read_chunks, parsed.num_updates, parsed.threads, parsed.page_cache, parsed.policy,
    });
    try err.flush();
    inline for (variants) |V| {
        if (std.mem.eql(u8, parsed.db, V.name)) return pipeline(V, gpa, io, parsed, out, err);
    }
    return error.Usage;
}

const Mutation = struct { key: Digest, value: Digest };

/// Commonware's `gen_muts`: random keys below `num_keys`, each with a fresh value.
fn gen_muts(rng: *TestRng, out: []Mutation, num_keys: u64) void {
    assert(num_keys > 0);
    for (out) |*mutation| {
        mutation.key = common.key_at(rng.next_u64() % num_keys);
        mutation.value = digest_value(rng);
    }
    assert(out.len == 0 or out[out.len - 1].key.bytes.len == 32);
}

/// Commonware's `Sha256::hash(&[&rng.next_u32().to_be_bytes()])`.
fn digest_value(rng: *TestRng) Digest {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, rng.next_u32(), .big);
    const value = Sha256.hash(&.{&bytes});
    assert(value.bytes.len == 32);
    return value;
}

fn pipeline(
    comptime V: type,
    gpa: Allocator,
    io: Io,
    args: Args,
    out: *Io.Writer,
    err: *Io.Writer,
) !void {
    const D = V.Db;
    comptime assert(D.Value == Digest);
    var disk: common.Disk = .{ .io = io, .memory = false };
    try disk.open(gpa);
    defer disk.close();
    var session: common.Session(D) = undefined;
    try session.open(gpa, &disk, .{
        .items_per_blob = items_per_blob,
        .init_cache = init_cache,
        .page_cache_pages = args.page_cache,
        .names = .{
            .merkle_journal = "constantinople-merkle-journal",
            .merkle_metadata = "constantinople-merkle-metadata",
            .log = if (comptime @hasField(@FieldType(D.Cfg, "log"), "items_per_section"))
                "constantinople-var-log"
            else
                "constantinople-log",
            .grafted_metadata = "constantinople-grafted-metadata",
        },
    });
    defer session.close() catch |e| std.log.warn("constantinople: destroy failed: {t}", .{e});
    const db = &session.db;
    const seed_start = harness.now_ns(io);
    try seed_and_churn(D, gpa, db, args);
    try err.print("seed+churn done in {d:.2} ms\n", .{harness.elapsed_ms(io, seed_start)});
    try err.flush();

    const times = try gpa.alloc(f64, args.iters);
    defer gpa.free(times);
    var rng: TestRng = .init(99);
    for (times, 0..) |*time, iter| {
        time.* = try iteration(D, gpa, io, db, args, &rng, iter, out);
    }
    try report(V.name, args, times, out);
    assert(db.bounds().end > args.num_keys);
}

/// Seeds every key in one committed batch, then applies `churn_batches` overwrite batches so
/// inactive operations accumulate above the floor, commits, and syncs.
fn seed_and_churn(comptime D: type, gpa: Allocator, db: *D, args: Args) !void {
    var rng: TestRng = .init(42);
    var batch: ?D.UnmerkleizedBatch = try db.new_batch();
    errdefer if (batch) |*pending| pending.deinit();
    for (0..args.num_keys) |i| {
        try common.write(D, gpa, &batch.?, common.key_at(i), digest_value(&rng));
    }
    try common.flush(D, db, &batch, true, true);
    const muts = try gpa.alloc(Mutation, args.num_updates);
    defer gpa.free(muts);
    for (0..churn_batches) |index| {
        gen_muts(&rng, muts, args.num_keys);
        for (muts) |m| try common.write(D, gpa, &batch.?, m.key, m.value);
        try common.flush(D, db, &batch, false, index + 1 < churn_batches);
    }
    try db.commit();
    try db.sync();
    assert(batch == null);
    assert(db.bounds().end > args.num_keys);
}

/// Pending ancestors, rebuilt per iteration and never applied (untimed).
fn build_chain(
    comptime D: type,
    db: *D,
    args: Args,
    rng: *TestRng,
    muts: []Mutation,
    chain: []*D.MerkleizedBatch,
) !usize {
    assert(chain.len == args.depth);
    var built: usize = 0;
    errdefer for (chain[0..built]) |batch| batch.release();
    for (chain) |*slot| {
        var batch = if (built == 0) try db.new_batch() else chain[built - 1].new_batch();
        errdefer batch.deinit();
        gen_muts(rng, muts, args.num_keys);
        for (muts) |m| try common.write(D, db.gpa, &batch, m.key, m.value);
        slot.* = try batch.merkleize(db);
        built += 1;
    }
    assert(built == chain.len);
    return built;
}

/// One timed iteration: loads every read key through `stage` and `expand`, merkleizes the
/// selected updates, and reads the root. Prints the iteration line and returns its ms.
fn iteration(
    comptime D: type,
    gpa: Allocator,
    io: Io,
    db: *D,
    args: Args,
    rng: *TestRng,
    iter: usize,
    out: *Io.Writer,
) !f64 {
    var chain_buffer: [std.math.maxInt(u8)]*D.MerkleizedBatch = undefined;
    const muts = try gpa.alloc(Mutation, args.num_updates);
    defer gpa.free(muts);
    const chain = chain_buffer[0..args.depth];
    _ = try build_chain(D, db, args, rng, muts, chain);
    defer for (0..chain.len) |i| chain[chain.len - 1 - i].release();

    var plan = try Plan(D).init(gpa, args, rng);
    defer plan.deinit(gpa);
    const values = try gpa.alloc(?Digest, plan.keys.len);
    defer gpa.free(values);

    const start = harness.now_ns(io);
    var batch = if (chain.len == 0) try db.new_batch() else chain[chain.len - 1].new_batch();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try stage_chunks(D, &batch, db, plan.keys, values, args.read_chunks);
    };
    std.mem.doNotOptimizeAway(values);
    const load_ms = harness.elapsed_ms(io, start);
    const merkleized = merkleized: {
        errdefer staged.deinit();
        const bounded = args.policy.bounded(plan.distinct_keys, args.num_updates);
        if (bounded) |limits| {
            var policy = limits;
            break :merkleized try staged.merkleize_with(plan.slots, &.{}, db, &policy);
        }
        break :merkleized try staged.merkleize(plan.slots, &.{}, db);
    };
    defer merkleized.release();
    const root = merkleized.root();
    const ms = harness.elapsed_ms(io, start);
    try out.print("iter={d} ms={d:.2} load={d:.2} merkleize={d:.2} root={f}\n", .{
        iter, ms, load_ms, ms - load_ms, root,
    });
    try out.flush();
    assert(ms >= load_ms);
    return ms;
}

/// Stages `keys` in `read_chunks` chunks: the first through `stage`, the rest through `expand`.
fn stage_chunks(
    comptime D: type,
    batch: *D.UnmerkleizedBatch,
    db: *D,
    keys: []const Digest,
    values: []?Digest,
    read_chunks: usize,
) !D.StagedBatch {
    assert(keys.len > 0);
    assert(keys.len == values.len);
    const chunks = @max(@min(read_chunks, keys.len), 1);
    const chunk_len = std.math.divCeil(usize, keys.len, chunks) catch unreachable; // chunks > 0
    const first = @min(chunk_len, keys.len);
    var staged = try batch.stage(keys[0..first], db, values[0..first]);
    errdefer staged.deinit();
    var start = first;
    while (start < keys.len) : (start += chunk_len) {
        const end = @min(start + chunk_len, keys.len);
        _ = try staged.expand(keys[start..end], db, values[start..end]);
    }
    assert(staged.len() == keys.len);
    return staged;
}

/// The read keys and update slots of one iteration, computed before the timer starts.
fn Plan(comptime D: type) type {
    return struct {
        const Self = @This();

        keys: []Digest,
        slots: []D.Slot,
        distinct_keys: usize,

        fn init(gpa: Allocator, args: Args, rng: *TestRng) !Self {
            const reads = try gpa.alloc(Mutation, args.num_reads);
            defer gpa.free(reads);
            gen_muts(rng, reads, args.num_keys);
            const indices = try gpa.alloc(usize, reads.len);
            defer gpa.free(indices);
            for (indices, 0..) |*index, i| index.* = i;
            const updates: usize = @intCast(args.num_updates);
            for (0..updates) |i| {
                const j = i + @as(usize, @intCast(rng.next_u64() % (indices.len - i)));
                std.mem.swap(usize, &indices[i], &indices[j]);
            }
            const keys = try gpa.alloc(Digest, reads.len);
            errdefer gpa.free(keys);
            const slots = try gpa.alloc(D.Slot, reads.len);
            errdefer gpa.free(slots);
            @memset(slots, .keep);
            var distinct: std.AutoHashMapUnmanaged(Digest, void) = .empty;
            defer distinct.deinit(gpa);
            for (indices[0..updates]) |slot| {
                slots[slot] = .{ .put = reads[slot].value };
                try distinct.put(gpa, reads[slot].key, {});
            }
            for (keys, reads) |*key, read| key.* = read.key;
            assert(distinct.count() <= updates);
            return .{ .keys = keys, .slots = slots, .distinct_keys = distinct.count() };
        }

        fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.keys);
            gpa.free(self.slots);
            self.* = undefined;
        }
    };
}

fn report(name: []const u8, args: Args, times: []f64, out: *Io.Writer) !void {
    assert(times.len == args.iters);
    const average = harness.mean(times);
    try out.print("RESULT db={s} depth={d} reads={d} read_chunks={d} updates={d} policy={t} ", .{
        name, args.depth, args.num_reads, args.read_chunks, args.num_updates, args.policy,
    });
    const p10 = harness.percentile(times, 0.1);
    const p50 = harness.percentile(times, 0.5);
    try out.print("p10={d:.2} p50={d:.2} mean={d:.2} max={d:.2}\n", .{
        p10, p50, average, times[times.len - 1],
    });
    try out.flush();
}

test "constantinople: smoke run reproduces the proportional roots with the fixed policy" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var outputs: [2]Io.Writer.Allocating = .{ .init(gpa), .init(gpa) };
    defer for (&outputs) |*output| output.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    for ([_][]const u8{ "proportional", "fixed" }, &outputs) |policy, *output| {
        const args = [_][]const u8{
            "any::ordered::fixed::mmb", "1", "2", "64", "24", "3", "16", "1", "64", policy,
        };
        try run(gpa, io, &args, &output.writer, &err.writer);
        try std.testing.expect(std.mem.indexOf(u8, output.written(), "RESULT db=") != null);
    }
    // The same roots: every line up to its timings differs, so compare the root fields.
    var lines: [2]std.mem.TokenIterator(u8, .scalar) = undefined;
    for (&lines, &outputs) |*it, *output| it.* = std.mem.tokenizeScalar(u8, output.written(), '\n');
    for (0..2) |_| {
        const a = lines[0].next().?;
        const b = lines[1].next().?;
        const root_a = a[std.mem.indexOf(u8, a, "root=").?..];
        try std.testing.expectEqualStrings(root_a, b[std.mem.indexOf(u8, b, "root=").?..]);
    }
    // Current runs the same pipeline.
    const current_args = [_][]const u8{
        "current::ordered::fixed::mmb", "1", "1", "64", "24", "3", "16", "1", "64", "fixed",
    };
    try run(gpa, io, &current_args, &outputs[0].writer, &err.writer);
    // No arguments, or a libtest flag, does nothing.
    try run(gpa, io, &.{}, &outputs[0].writer, &err.writer);
    try run(gpa, io, &.{"--list"}, &outputs[0].writer, &err.writer);
    try std.testing.expectError(error.Usage, run(gpa, io, &.{"nope"}, &err.writer, &err.writer));
}
