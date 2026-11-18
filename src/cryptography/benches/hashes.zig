//! Benchmarks of the hashers (commonware `cryptography/src/{blake3,sha256,sha512}/benches`),
//! with commonware's names and cases.
//!
//! `blake3::hash_message` keeps only its `conc=1` rows: zigware's `Blake3.hash_across` does
//! not split one message across threads, so a `conc=8` row would time the same work.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const common = @import("../bls12381/benches/common.zig");
const cases = common.cases;
const skip = common.skip;
const Blake3 = cryptography.blake3.Blake3;
const Sha256 = cryptography.sha256.Sha256;
const Sha512 = cryptography.sha512.Sha512;

/// Workers in the pool behind the parallel rows.
const concurrency = 8;

fn HashMessage(comptime H: type) type {
    return struct {
        message: []const u8,

        pub fn iter(workload: *@This()) H.Digest {
            return H.hash(&.{workload.message});
        }
    };
}

/// `<prefix>/msg_len=<n>[ conc=1]` over random messages of each length `2^exponent`.
fn bench_hash_message(
    comptime H: type,
    runner: *bench.Runner,
    prefix: []const u8,
    exponents: []const u6,
    conc: bool,
) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    for (cases(runner, u6, exponents)) |exponent| {
        const len = @as(usize, 1) << exponent;
        const message = try gpa.alloc(u8, len);
        defer gpa.free(message);
        rng.fill_bytes(message);
        var name = bench.Benchmark.init(prefix).with_param("msg_len", len);
        if (conc) name = name.with_param("conc", 1);
        if (try skip(runner, name)) continue;
        var workload: HashMessage(H) = .{ .message = message };
        try runner.run(name, &workload);
    }
}

fn Individual(comptime H: type) type {
    return struct {
        messages: []const []const u8,
        digests: []H.Digest,

        pub fn iter(workload: *@This()) void {
            for (workload.messages, workload.digests) |message, *digest| {
                digest.* = H.hash(&.{message});
            }
        }
    };
}

fn Batch(comptime H: type, comptime S: type) type {
    return struct {
        messages: []const []const u8,
        digests: []H.Digest,
        strategy: S,

        pub fn iter(workload: *@This()) void {
            H.hash_many(workload.messages, workload.digests, workload.strategy);
        }
    };
}

const HashManyCases = struct { lens: []const usize, counts: []const usize };

/// `<prefix>::individual/count=<c> len=<l>` and `<prefix>::batch/... conc=<1|8>`.
fn bench_hash_many(
    comptime H: type,
    runner: *bench.Runner,
    prefix: []const u8,
    all: HashManyCases,
) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    const pool = try parallel.ThreadPool.create(gpa, runner.io, .{ .threads = concurrency });
    defer pool.destroy();
    const rayon = parallel.Rayon.init(pool);
    var storage: [128][]u8 = undefined;
    var messages: [128][]const u8 = undefined;
    var digests: [128]H.Digest = undefined;
    for (cases(runner, usize, all.lens)) |len| {
        const flat = try gpa.alloc(u8, 128 * len);
        defer gpa.free(flat);
        for (&storage, &messages, 0..) |*message, *view, index| {
            message.* = flat[index * len ..][0..len];
            rng.fill_bytes(message.*);
            view.* = message.*;
        }
        for (cases(runner, usize, all.counts)) |count| {
            assert(count <= messages.len);
            const batch: struct { []const []const u8, []H.Digest } =
                .{ messages[0..count], digests[0..count] };
            try run_hash_many(H, runner, prefix, len, count, batch, rayon);
        }
    }
}

fn run_hash_many(
    comptime H: type,
    runner: *bench.Runner,
    prefix: []const u8,
    len: usize,
    count: usize,
    batch: struct { []const []const u8, []H.Digest },
    rayon: parallel.Rayon,
) !void {
    var buffer: [bench.name_len_max]u8 = undefined;
    const individual = try std.fmt.bufPrint(&buffer, "{s}::individual", .{prefix});
    const name = bench.Benchmark.init(individual).with_param("count", count)
        .with_param("len", len);
    var serial: Individual(H) = .{ .messages = batch[0], .digests = batch[1] };
    try runner.run(name, &serial);
    var batch_buffer: [bench.name_len_max]u8 = undefined;
    const batch_prefix = try std.fmt.bufPrint(&batch_buffer, "{s}::batch", .{prefix});
    const base = bench.Benchmark.init(batch_prefix).with_param("count", count)
        .with_param("len", len);
    var sequential: Batch(H, parallel.Sequential) = .{
        .messages = batch[0],
        .digests = batch[1],
        .strategy = parallel.sequential,
    };
    try runner.run(base.with_param("conc", 1), &sequential);
    var pooled: Batch(H, parallel.Rayon) = .{
        .messages = batch[0],
        .digests = batch[1],
        .strategy = rayon,
    };
    try runner.run(base.with_param("conc", concurrency), &pooled);
}

const HashPair = struct {
    left: []const []const u8,
    right: []const []const u8,

    pub fn iter(workload: *HashPair) [2]cryptography.sha256.Digest {
        return Sha256.hash_pair(workload.left, workload.right, parallel.sequential);
    }
};

fn bench_hash_pair(runner: *bench.Runner) !void {
    var rng = utils.test_rng();
    var messages: [2][72]u8 = undefined;
    for (&messages) |*message| rng.fill_bytes(message);
    const bmt = [2][2][]const u8{
        .{ messages[0][0..32], messages[0][32..64] },
        .{ messages[1][0..32], messages[1][32..64] },
    };
    const mmr = [2][3][]const u8{
        .{ messages[0][0..8], messages[0][8..40], messages[0][40..] },
        .{ messages[1][0..8], messages[1][8..40], messages[1][40..] },
    };
    const name = bench.Benchmark.init("sha256::hash_pair");
    var bmt_pair: HashPair = .{ .left = &bmt[0], .right = &bmt[1] };
    try runner.run(name.with_param("shape", "bmt"), &bmt_pair);
    var mmr_pair: HashPair = .{ .left = &mmr[0], .right = &mmr[1] };
    try runner.run(name.with_param("shape", "mmr"), &mmr_pair);
}

const Digest = cryptography.sha256.Digest;

/// Sorts a fresh copy of the digests each iteration (the copy is untimed).
const DigestSort = struct {
    digests: []const Digest,
    scratch: []Digest,

    pub fn before_iter(workload: *DigestSort) void {
        @memcpy(workload.scratch, workload.digests);
    }

    pub fn iter(workload: *DigestSort) void {
        std.sort.pdq(Digest, workload.scratch, {}, Digest.less_than);
    }
};

const DigestSearch = struct {
    digests: []const Digest,
    sorted: []const Digest,

    pub fn iter(workload: *DigestSearch) usize {
        var found: usize = 0;
        for (workload.digests) |digest| {
            if (std.sort.binarySearch(Digest, workload.sorted, digest, Digest.order) != null) {
                found += 1;
            }
        }
        assert(found == workload.digests.len);
        return found;
    }
};

fn bench_digest_cmp(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    for (cases(runner, u64, &.{ 10, 100, 1_000, 10_000, 50_000, 100_000 })) |n| {
        const digests = try gpa.alloc(Digest, n);
        defer gpa.free(digests);
        for (digests, 0..) |*digest, i| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, i, .big);
            digest.* = Sha256.hash(&.{&bytes});
        }
        const sorted = try gpa.dupe(Digest, digests);
        defer gpa.free(sorted);
        std.sort.pdq(Digest, sorted, {}, Digest.less_than);
        const name = bench.Benchmark.init("sha256::digest_cmp");
        const scratch = try gpa.alloc(Digest, n);
        defer gpa.free(scratch);
        var sort: DigestSort = .{ .digests = digests, .scratch = scratch };
        try runner.run(name.with_param("op", "sort").with_param("n", n), &sort);
        var search: DigestSearch = .{ .digests = digests, .sorted = sorted };
        try runner.run(name.with_param("op", "search").with_param("n", n), &search);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_hash_message(Blake3, runner, "blake3::hash_message", &.{
        8, 12, 16, 17, 18, 19, 20, 24,
    }, true);
    try bench_hash_message(Sha256, runner, "sha256::hash_message", &.{
        8, 12, 16, 19, 20, 24,
    }, false);
    try bench_hash_many(Sha256, runner, "sha256::hash_many", .{
        .lens = &.{ 64, 256, 4096, 16_384, 65_536, 262_144 },
        .counts = &.{ 1, 2, 6, 7, 15, 16, 17, 32, 128 },
    });
    try bench_hash_pair(runner);
    try bench_digest_cmp(runner);
    try bench_hash_many(Sha512, runner, "sha512::hash_many", .{
        .lens = &.{ 96, 1024, 16_384, 65_536, 262_144 },
        .counts = &.{ 1, 2, 7, 8, 9, 16, 32, 128 },
    });
}
