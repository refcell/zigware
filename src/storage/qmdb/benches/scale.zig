//! Opt-in large-scale QMDB measurement (commonware's `qmdb/benches/scale.rs`): build a real
//! on-disk database once (`generate`), then time a real reopen (`init`) and random point reads
//! (`get`, `get_many`) against it, at sizes the criterion-style benches cannot reach.
//!
//! ```sh
//! zig build qmdb-scale -- generate <folder> <keyspace> <num_updates> [zipf_exponent] \
//!     [ordered|unordered]
//! zig build qmdb-scale -- init <folder> <cache> <concurrency> [ordered|unordered]
//! zig build qmdb-scale -- get <folder> <keyspace> <num_gets> <readers>[,<readers>...] \
//!     [ordered|unordered] [cache_pages]
//! zig build qmdb-scale -- get_many <folder> <keyspace> <num_gets> <readers>[,...] <batch> \
//!     [ordered|unordered] [cache_pages]
//! zig build qmdb-scale -- destroy <folder>
//! ```
//!
//! - generate: `num_updates` random updates (one in 10 a delete) over a `keyspace`-key space,
//!   Zipf-sampled (exponent 1.0 by default, `0` for uniform), committing when the rng draws a
//!   multiple of 10,000 and pruning to the sync boundary every 100 commits; then prunes, syncs,
//!   and reports the build time.
//! - init: reopens the database and times one `init` with an init cache of `cache` entries
//!   (`0` disables it), reporting the replay region (`end - inactivity floor`).
//! - get / get_many: opens the database (untimed), then for each reader count drops the OS page
//!   cache (passwordless sudo; warns otherwise) and runs a cold pass of `num_gets` uniform gets,
//!   then a warm pass over the same keys. Readers draw from their own `StdRng(reader)` streams.
//!   The page cache is 64 pages unless `cache_pages` says otherwise.
//! - The index flavor (default `ordered`): `ordered` is the P=3 partitioned ordered index,
//!   `unordered` the P=2 (65,536-partition) unordered index. Bench a database with the flavor
//!   it was generated with.
//!
//! zigware's databases are not shared across threads and have no parallel snapshot build, so
//! readers run one after another and `concurrency` is reported only.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const storage = @import("storage");
const utils = @import("utils");
const common = @import("common.zig");
const harness = @import("harness.zig");

const qmdb = storage.qmdb;
const Digest = common.Digest;
const TestRng = common.TestRng;
const rng_mod = utils.rng;

const items_per_blob: u64 = 1_000_000;
const page_cache_pages: u32 = 262_144;
const min_page_cache_pages: u32 = 64;
const commit_frequency: u32 = 10_000;
const prune_frequency: u32 = 100;
const key_zipf_exponent: f64 = 1.0;
const readers_max = 64;

/// The fixed-value `any` database over MMR with a partitioned snapshot index of `P` bytes.
fn PartitionedDb(comptime order: common.Order, comptime P: usize) type {
    const any = qmdb.any;
    const F = common.mmr;
    const E = common.FixedDigest;
    const Op = switch (order) {
        .unordered => any.operation.Unordered(F, Digest, E),
        .ordered => any.operation.Ordered(F, Digest, E),
    };
    const U = switch (order) {
        .unordered => any.operation.update.Unordered(Digest, E),
        .ordered => any.operation.update.Ordered(Digest, E),
    };
    const I = switch (order) {
        .unordered => storage.index.partitioned.unordered.Index(common.Translator, u64, P),
        .ordered => storage.index.partitioned.ordered.Index(common.Translator, u64, P),
    };
    const C = storage.journal.contiguous.fixed.Journal(Op);
    return any.Db(F, U, C, I, common.Sha256, common.chunk_bytes);
}

/// The snapshot index flavor a database is generated and benched with.
const IndexKind = enum {
    ordered,
    unordered,

    fn label(kind: IndexKind) []const u8 {
        return switch (kind) {
            .ordered => "any::ordered::fixed::p3::mmr",
            .unordered => "any::unordered::fixed::p64k::mmr",
        };
    }

    fn Db(comptime kind: IndexKind) type {
        return switch (kind) {
            .ordered => PartitionedDb(.ordered, 3),
            .unordered => PartitionedDb(.unordered, 2),
        };
    }
};

/// `rand_distr`'s `Zipf` (rejection sampling after Jason Crease) over ranks `[1, n]`.
pub const Zipf = struct {
    s: f64,
    t: f64,
    q: f64,

    pub fn init(n: f64, s: f64) Zipf {
        assert(s >= 0);
        assert(n >= 1);
        const q = if (s != 1) 1 / (1 - s) else 0;
        const t = if (s != 1) (std.math.pow(f64, n, 1 - s) - s) * q else 1 + @log(n);
        assert(t > 0);
        return .{ .s = s, .t = t, .q = q };
    }

    fn inv_cdf(zipf: Zipf, p: f64) f64 {
        const pt = p * zipf.t;
        if (pt <= 1) return pt;
        if (zipf.s != 1) return std.math.pow(f64, pt * (1 - zipf.s) + zipf.s, zipf.q);
        return @exp(pt - 1);
    }

    pub fn sample(zipf: Zipf, rng: anytype) f64 {
        // Each round accepts with probability bounded below, so the loop ends.
        while (true) {
            const inv_b = zipf.inv_cdf(rng_mod.float64(rng));
            const x = @floor(inv_b + 1);
            var ratio = std.math.pow(f64, x, -zipf.s);
            if (x > 1) ratio *= std.math.pow(f64, inv_b, zipf.s);
            if (rng_mod.float64(rng) < ratio) {
                assert(x >= 1);
                return x;
            }
        }
    }
};

const usage_text =
    \\usage:
    \\  generate <folder> <keyspace> <num_updates> [zipf_exponent] [ordered|unordered]   build a database (omit exponent => zipf 1.0; 0 => uniform)
    \\  init     <folder> <cache> <concurrency> [ordered|unordered]   reopen + time one init (cache=entries, 0=off)
    \\  get      <folder> <keyspace> <num_gets> <concurrency>[,...] [ordered|unordered] [cache_pages]   time random point reads (cold after an OS cache drop, then warm)
    \\  get_many <folder> <keyspace> <num_gets> <concurrency>[,...] <batch> [ordered|unordered] [cache_pages]   like get, in `batch`-key get_many calls
    \\  destroy  <folder>                          delete the database
    \\
;

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
    const context: Context = .{
        .gpa = init.gpa,
        .io = io,
        .out = &out.interface,
        .err = &err.interface,
    };
    run(context, args) catch |e| switch (e) {
        error.Usage => {
            try err.interface.writeAll(usage_text);
            return 2;
        },
        else => return e,
    };
    return 0;
}

pub const Context = struct {
    gpa: Allocator,
    io: Io,
    out: *Io.Writer,
    err: *Io.Writer,
    /// Whether `get` drops the OS page cache before each cold pass (the smoke test does not).
    drop_caches: bool = true,
    /// Page cache pages of `generate` and `init` (the smoke test shrinks the 1 GiB default).
    page_cache_pages: u32 = page_cache_pages,
};

/// Runs the harness on `args` (without the program name).
pub fn run(context: Context, args: []const []const u8) !void {
    if (args.len < 2) return error.Usage;
    const command = args[0];
    const folder = args[1];
    if (std.mem.eql(u8, command, "generate")) return generate_command(context, folder, args[2..]);
    if (std.mem.eql(u8, command, "init")) return init_command(context, folder, args[2..]);
    if (std.mem.eql(u8, command, "get")) return get_command(context, folder, args[2..], false);
    if (std.mem.eql(u8, command, "get_many")) return get_command(context, folder, args[2..], true);
    if (std.mem.eql(u8, command, "destroy") and args.len == 2) {
        Io.Dir.cwd().deleteTree(context.io, folder) catch |e| {
            try context.err.print("failed to destroy {s}: {t}\n", .{ folder, e });
            return;
        };
        try context.out.print("destroyed {s}\n", .{folder});
        return;
    }
    return error.Usage;
}

/// Whether `folder` exists and holds any entries.
fn dir_nonempty(io: Io, folder: []const u8) bool {
    assert(folder.len > 0);
    var dir = Io.Dir.cwd().openDir(io, folder, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var entries = dir.iterate();
    const first = entries.next(io) catch return false;
    return first != null;
}

fn generate_command(context: Context, folder: []const u8, args: []const []const u8) !void {
    if (args.len < 2) return error.Usage;
    const keyspace = harness.parse(u64, args[0]) orelse return error.Usage;
    const num_updates = harness.parse(u64, args[1]) orelse return error.Usage;
    var zipf_exponent: ?f64 = key_zipf_exponent;
    var index: IndexKind = .ordered;
    for (args[2..]) |arg| {
        if (std.meta.stringToEnum(IndexKind, arg)) |kind| {
            index = kind;
        } else if (harness.parse(f64, arg)) |exponent| {
            zipf_exponent = if (exponent > 0) exponent else null;
        } else return error.Usage;
    }
    if (keyspace == 0) {
        try context.err.writeAll("keyspace must be > 0\n");
        return;
    }
    if (dir_nonempty(context.io, folder)) {
        try context.err.print("{s} already contains data; `destroy` it first or pick a new " ++
            "folder\n", .{folder});
        return;
    }
    const elapsed_ms = switch (index) {
        inline else => |kind| try generate(
            kind.Db(),
            context,
            folder,
            keyspace,
            num_updates,
            zipf_exponent,
        ),
    };
    try context.out.print("generated {d} updates over keyspace {d} at {s} in {d:.2} ms\n", .{
        num_updates, keyspace, folder, elapsed_ms,
    });
}

/// Builds the database (updates, prune, sync), returning the build time in ms.
fn generate(
    comptime D: type,
    context: Context,
    folder: []const u8,
    keyspace: u64,
    num_updates: u64,
    zipf_exponent: ?f64,
) !f64 {
    var disk: common.Disk = .at(context.io, folder);
    try disk.open(context.gpa);
    defer disk.close();
    var session: common.Session(D) = undefined;
    try session.open(context.gpa, &disk, .{
        .items_per_blob = items_per_blob,
        .page_cache_pages = context.page_cache_pages,
    });
    defer session.shut();
    const db = &session.db;
    const start = harness.now_ns(context.io);
    try populate(D, db, keyspace, num_updates, zipf_exponent);
    try db.prune(db.sync_boundary());
    try db.sync();
    assert(db.bounds().end > 0);
    return harness.elapsed_ms(context.io, start);
}

/// Commonware's `gen_random_kv` without a seed phase: the populated set fills as updates
/// sample the keyspace.
fn populate(
    comptime D: type,
    db: *D,
    keyspace: u64,
    num_updates: u64,
    zipf_exponent: ?f64,
) !void {
    assert(keyspace > 0);
    var rng: TestRng = .init(42);
    const zipf: ?Zipf = if (zipf_exponent) |s| .init(@floatFromInt(keyspace), s) else null;
    var commits: u32 = 0;
    var batch: ?D.UnmerkleizedBatch = try db.new_batch();
    errdefer if (batch) |*pending| pending.deinit();
    for (0..num_updates) |_| {
        const index = if (zipf) |z|
            @min(@as(u64, @intFromFloat(z.sample(&rng))) -| 1, keyspace - 1)
        else
            rng.next_u64() % keyspace;
        const key = common.key_at(index);
        if (rng.next_u32() % common.delete_frequency == 0) {
            try common.write(D, db.gpa, &batch.?, key, null);
            continue;
        }
        try common.write(D, db.gpa, &batch.?, key, try common.make_value(Digest, db.gpa, &rng));
        if (rng.next_u32() % commit_frequency == 0) {
            try common.flush(D, db, &batch, true, false);
            commits += 1;
            if (commits % prune_frequency == 0) try db.prune(db.sync_boundary());
            batch = try db.new_batch();
        }
    }
    try common.flush(D, db, &batch, true, false);
    assert(batch == null);
}

fn init_command(context: Context, folder: []const u8, args: []const []const u8) !void {
    if (args.len < 2 or args.len > 3) return error.Usage;
    const cache = harness.parse(usize, args[0]) orelse return error.Usage;
    const concurrency = harness.parse(u64, args[1]) orelse return error.Usage;
    if (concurrency == 0) return error.Usage;
    const index: IndexKind = if (args.len == 3)
        std.meta.stringToEnum(IndexKind, args[2]) orelse return error.Usage
    else
        .ordered;
    if (!dir_nonempty(context.io, folder)) {
        try context.err.print("no database at {s}; run `generate {s} <keyspace> " ++
            "<num_updates>` first\n", .{ folder, folder });
        return;
    }
    const timed = switch (index) {
        inline else => |kind| try time_init(kind.Db(), context, folder, cache),
    };
    if (timed.region == 0) {
        try context.err.print("database at {s} is empty; run `generate {s} <keyspace> " ++
            "<num_updates>` first\n", .{ folder, folder });
        return;
    }
    try context.out.print("init ({s}) {s} cache={d} concurrency={d} region={d} time={d:.2} ms\n", .{
        index.label(), folder, cache, concurrency, timed.region, timed.ms,
    });
}

const Timed = struct { ms: f64, region: u64 };

/// Times one `init` with an init cache of `cache` entries (0: off).
fn time_init(comptime D: type, context: Context, folder: []const u8, cache: usize) !Timed {
    var disk: common.Disk = .at(context.io, folder);
    try disk.open(context.gpa);
    defer disk.close();
    var session: common.Session(D) = undefined;
    const start = harness.now_ns(context.io);
    try session.open(context.gpa, &disk, .{
        .items_per_blob = items_per_blob,
        .page_cache_pages = context.page_cache_pages,
        .init_cache = if (cache == 0) null else cache,
    });
    const ms = harness.elapsed_ms(context.io, start);
    defer session.shut();
    const db = &session.db;
    assert(db.inactivity_floor() <= db.bounds().end);
    return .{ .ms = ms, .region = db.bounds().end -| db.inactivity_floor() };
}

const GetArgs = struct {
    keyspace: u64,
    num_gets: u64,
    readers: [readers_max]u64 = undefined,
    readers_len: usize = 0,
    batch: ?u64 = null,
    index: IndexKind = .ordered,
    cache_pages: u32 = min_page_cache_pages,

    fn parse(args: []const []const u8, many: bool) ?GetArgs {
        if (args.len < 3) return null;
        var result: GetArgs = .{
            .keyspace = harness.parse(u64, args[0]) orelse return null,
            .num_gets = harness.parse(u64, args[1]) orelse return null,
        };
        var counts = std.mem.splitScalar(u8, args[2], ',');
        while (counts.next()) |text| {
            const count = harness.parse(u64, text) orelse return null;
            if (count == 0 or result.readers_len == readers_max) return null;
            result.readers[result.readers_len] = count;
            result.readers_len += 1;
        }
        var options_at: usize = 3;
        if (many) {
            if (args.len < 4) return null;
            result.batch = harness.parse(u64, args[3]) orelse return null;
            if (result.batch == 0) return null;
            options_at = 4;
        }
        for (args[options_at..]) |arg| {
            if (std.meta.stringToEnum(IndexKind, arg)) |kind| {
                result.index = kind;
            } else if (harness.parse(u32, arg)) |pages| {
                if (pages == 0) return null;
                result.cache_pages = pages;
            } else return null;
        }
        return result;
    }
};

fn get_command(context: Context, folder: []const u8, args: []const []const u8, many: bool) !void {
    const parsed = GetArgs.parse(args, many) orelse return error.Usage;
    if (parsed.keyspace == 0 or parsed.num_gets == 0) return error.Usage;
    if (!dir_nonempty(context.io, folder)) {
        try context.err.print("no database at {s}; run `generate {s} <keyspace> " ++
            "<num_updates>` first\n", .{ folder, folder });
        return;
    }
    try context.out.print("get ({s}) {s}  page cache {d} pages, keyspace {d}, reads ", .{
        parsed.index.label(), folder, parsed.cache_pages, parsed.keyspace,
    });
    if (parsed.batch) |batch| {
        try context.out.print("get_many x{d}\n", .{batch});
    } else try context.out.writeAll("point\n");
    try context.out.flush();
    switch (parsed.index) {
        inline else => |kind| try get_bench(kind.Db(), context, folder, &parsed),
    }
}

fn get_bench(comptime D: type, context: Context, folder: []const u8, args: *const GetArgs) !void {
    var disk: common.Disk = .at(context.io, folder);
    try disk.open(context.gpa);
    defer disk.close();
    var session: common.Session(D) = undefined;
    const open_start = harness.now_ns(context.io);
    try session.open(context.gpa, &disk, .{
        .items_per_blob = items_per_blob,
        .page_cache_pages = args.cache_pages,
    });
    defer session.shut();
    try context.out.print("  open (untimed phase): {d:.2} ms\n", .{
        harness.elapsed_ms(context.io, open_start),
    });
    try context.out.flush();
    for (args.readers[0..args.readers_len]) |readers| {
        if (readers > args.num_gets) {
            try context.err.print("  skipping readers={d}: more readers than gets\n", .{readers});
            continue;
        }
        if (context.drop_caches and !drop_os_caches(context.gpa, context.io)) {
            try context.err.writeAll("  warning: OS cache drop failed (needs passwordless " ++
                "sudo); cold pass is not cold\n");
        }
        for ([_][]const u8{ "cold", "warm" }) |pass| {
            const start = harness.now_ns(context.io);
            const found = try run_gets(D, &session.db, args, readers);
            const ms = harness.elapsed_ms(context.io, start);
            const total: f64 = @floatFromInt(args.num_gets);
            try context.out.print("  {s}[readers={d}]: {d} gets ({d} found) in {d:.2} ms  ", .{
                pass, readers, args.num_gets, found, ms,
            });
            try context.out.print("({d:.1} us/get, {d:.0} gets/s)\n", .{
                ms * 1000 / total, total * 1000 / ms,
            });
            try context.out.flush();
        }
    }
}

/// One pass of `num_gets` uniform gets split across `readers` readers (the first
/// `num_gets % readers` take one extra), each on its own `StdRng(reader)` key stream, so a
/// repeat pass replays the same keys. Returns how many found a value.
fn run_gets(comptime D: type, db: *D, args: *const GetArgs, readers: u64) !u64 {
    assert(readers > 0 and readers <= args.num_gets);
    const per_reader = args.num_gets / readers;
    const remainder = args.num_gets % readers;
    var found: u64 = 0;
    var keys: [1024]Digest = undefined;
    var values: [1024]?Digest = undefined;
    for (0..readers) |reader| {
        var rng: TestRng = .init(reader);
        var remaining = per_reader + @intFromBool(reader < remainder);
        while (remaining > 0) {
            const chunk = if (args.batch) |batch| @min(remaining, batch, keys.len) else 1;
            const n: usize = @intCast(chunk);
            for (keys[0..n]) |*key| {
                key.* = common.key_at(rng_mod.range_less_than(&rng, u64, 0, args.keyspace));
            }
            if (args.batch == null) {
                if (try db.get(&keys[0]) != null) found += 1;
            } else {
                try db.get_many(keys[0..n], values[0..n]);
                for (values[0..n]) |value| found += @intFromBool(value != null);
            }
            remaining -= chunk;
        }
    }
    assert(found <= args.num_gets);
    return found;
}

/// Drops the OS page cache (needs passwordless sudo), returning whether it succeeded.
fn drop_os_caches(gpa: Allocator, io: Io) bool {
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .linux => &.{
            "sh",
            "-c",
            "sync && echo 3 | sudo -n tee /proc/sys/vm/drop_caches > /dev/null",
        },
        .macos => &.{ "sudo", "-n", "purge" },
        else => return false,
    };
    const result = std.process.run(gpa, io, .{ .argv = argv }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    return result.term == .exited and result.term.exited == 0;
}

/// `rand_pcg`'s `Pcg32` (`Lcg64Xsh32`), the rng of `rand_distr`'s value-stability tests.
const Pcg32 = struct {
    state: u64,
    increment: u64,

    fn init(state: u64, stream: u64) Pcg32 {
        const increment = (stream << 1) | 1;
        var pcg: Pcg32 = .{ .state = state +% increment, .increment = increment };
        pcg.state = pcg.state *% 6364136223846793005 +% pcg.increment;
        return pcg;
    }

    pub fn next_u32(pcg: *Pcg32) u32 {
        const state = pcg.state;
        pcg.state = state *% 6364136223846793005 +% pcg.increment;
        const xsh: u32 = @truncate(((state >> 18) ^ state) >> 27);
        return std.math.rotr(u32, xsh, @as(u32, @truncate(state >> 59)));
    }

    pub fn next_u64(pcg: *Pcg32) u64 {
        const low: u64 = pcg.next_u32();
        return (@as(u64, pcg.next_u32()) << 32) | low;
    }
};

test "scale: zipf matches rand_distr's value-stability vector" {
    // rand_distr `zipf_value_stability`: `Zipf::new(10., 2.0)` over `test::rng(213)`.
    var pcg: Pcg32 = .init(213, 11634580027462260723);
    const zipf: Zipf = .init(10, 2.0);
    for ([_]f64{ 1, 2, 3, 2 }) |expected| try std.testing.expectEqual(expected, zipf.sample(&pcg));
}

test "scale: zipf matches rand_distr's shape and stays in range" {
    var rng: TestRng = .init(7);
    const zipf: Zipf = .init(100, 1.0);
    var ones: u64 = 0;
    for (0..2000) |_| {
        const x = zipf.sample(&rng);
        try std.testing.expect(x >= 1 and x <= 100);
        ones += @intFromBool(x == 1);
    }
    // P(1) = 1 / H(100) ~ 0.19 for s = 1.
    try std.testing.expect(ones > 300 and ones < 480);
    const uniform: Zipf = .init(10, 0.0);
    var counts: [11]u64 = @splat(0);
    for (0..5000) |_| counts[@intFromFloat(uniform.sample(&rng))] += 1;
    for (counts[1..]) |count| try std.testing.expect(count > 380 and count < 620);
}

test "scale: smoke run generates, reopens, reads, and destroys a database" {
    const gpa = std.testing.allocator;
    var tmp: harness.SmokeDir = .init();
    defer tmp.cleanup();
    const folder = tmp.sub("scale");
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var err: Io.Writer.Allocating = .init(gpa);
    defer err.deinit();
    const context: Context = .{
        .gpa = gpa,
        .io = std.testing.io,
        .out = &out.writer,
        .err = &err.writer,
        .drop_caches = false,
        .page_cache_pages = 64,
    };
    try run(context, &.{ "generate", folder, "500", "3000", "unordered" });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "generated 3000 updates") != null);
    try run(context, &.{ "generate", folder, "500", "3000" }); // Refuses a nonempty folder.
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "already contains data") != null);
    try run(context, &.{ "init", folder, "0", "1", "unordered" });
    try run(context, &.{ "init", folder, "1024", "4", "unordered" });
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, out.written(), "region="));
    try run(context, &.{ "get", folder, "500", "40", "1,3", "unordered", "16" });
    try run(context, &.{ "get_many", folder, "500", "40", "2", "7", "unordered" });
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, out.written(), "found) in"));
    try run(context, &.{ "destroy", folder });
    try std.testing.expect(!dir_nonempty(std.testing.io, folder));
    try std.testing.expectError(error.Usage, run(context, &.{"generate"}));
}
