//! Benchmarks of the bloom filter, ChaCha20-Poly1305, LtHash, SAKE, and the Bulletproofs inner
//! product argument (commonware `cryptography/src/{bloomfilter,chacha20_poly1305,lthash}`,
//! `handshake/sake`, and `zk/bulletproofs` benches), with commonware's names and cases.
//!
//! Where commonware rebuilds its inputs before every iteration (`iter_batched`), the inputs
//! here are reset untimed in `before_iter` or built once when no iteration changes them.

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
const BigRational = utils.BigRational;
const LtHash = cryptography.LtHash;

const bloom_item_sizes = [_]usize{ 32, 2048, 4096 };
const bloom_rates = [_]struct { u64, u64, []const u8 }{ .{ 1, 10, "10%" }, .{ 1, 1000, "0.1%" } };

/// Random bloom filter items: `count` items of `item_size` bytes, filled in order.
fn bloom_items(gpa: Allocator, rng: *utils.TestRng, count: usize, item_size: usize) ![]u8 {
    const flat = try gpa.alloc(u8, count * item_size);
    for (0..count) |index| rng.fill_bytes(flat[index * item_size ..][0..item_size]);
    return flat;
}

fn BloomInsert(comptime H: type) type {
    return struct {
        filter: cryptography.BloomFilter(H),
        items: []const u8,
        item_size: usize,
        index: usize = 0,

        /// A fresh (empty) filter for every insert.
        pub fn before_iter(workload: *@This()) void {
            workload.filter.bits.set_all(false);
        }

        pub fn iter(workload: *@This()) void {
            const size = workload.item_size;
            workload.filter.insert(workload.items[workload.index * size ..][0..size]);
            workload.index = (workload.index + 1) % (workload.items.len / size);
        }
    };
}

fn BloomContains(comptime H: type) type {
    return struct {
        filter: *const cryptography.BloomFilter(H),
        items: []const u8,
        item_size: usize,
        index: usize = 0,

        pub fn iter(workload: *@This()) bool {
            const size = workload.item_size;
            const item = workload.items[workload.index * size ..][0..size];
            const result = workload.filter.contains(item);
            workload.index = (workload.index + 1) % (workload.items.len / size);
            return result;
        }
    };
}

const BloomCase = struct { hasher: []const u8, item_size: usize, rate: usize };

/// `bloomfilter::insert/...` and `bloomfilter::contains/... query=<positive|negative>`.
fn bench_bloom(comptime H: type, runner: *bench.Runner, hasher: []const u8) !void {
    const gpa = runner.allocator;
    const num_items = runner.inputs.pick(usize, 100, 10_000, 10_000);
    for (cases(runner, usize, &bloom_item_sizes)) |item_size| {
        const Rate = @TypeOf(bloom_rates[0]);
        const all = &bloom_rates;
        const rates = runner.inputs.pick([]const Rate, all[0..1], all, all);
        for (rates) |rate| {
            const numerator, const denominator, const label = rate;
            var fp_rate = try BigRational.from_frac_u64(gpa, numerator, denominator);
            defer fp_rate.deinit();
            const base = bench.Benchmark.init("bloomfilter::insert").with_param("hasher", hasher)
                .with_param("item_size", item_size).with_param("fp_rate", label);
            if (!try skip(runner, base)) {
                var rng = utils.TestRng.init(42);
                const items = try bloom_items(gpa, &rng, num_items, item_size);
                defer gpa.free(items);
                var workload: BloomInsert(H) = .{
                    .filter = try .with_rate(gpa, num_items, &fp_rate),
                    .items = items,
                    .item_size = item_size,
                };
                defer workload.filter.deinit(gpa);
                try runner.run(base, &workload);
            }
            const contains: ContainsCase = .{
                .hasher = hasher,
                .item_size = item_size,
                .label = label,
                .fp_rate = &fp_rate,
                .num_items = num_items,
            };
            try bench_contains(H, runner, contains, true);
            try bench_contains(H, runner, contains, false);
        }
    }
}

const ContainsCase = struct {
    hasher: []const u8,
    item_size: usize,
    label: []const u8,
    fp_rate: *const BigRational,
    num_items: usize,
};

fn bench_contains(
    comptime H: type,
    runner: *bench.Runner,
    case: ContainsCase,
    positive: bool,
) !void {
    const gpa = runner.allocator;
    const hasher = case.hasher;
    const item_size = case.item_size;
    const label = case.label;
    const num_items = case.num_items;
    const fp_rate = case.fp_rate;
    const name = bench.Benchmark.init("bloomfilter::contains").with_param("hasher", hasher)
        .with_param("item_size", item_size).with_param("fp_rate", label)
        .with_param("query", if (positive) "positive" else "negative");
    if (try skip(runner, name)) return;
    var rng = utils.TestRng.init(42);
    var filter = try cryptography.BloomFilter(H).with_rate(gpa, num_items, fp_rate);
    defer filter.deinit(gpa);
    const inserted = try bloom_items(gpa, &rng, num_items, item_size);
    defer gpa.free(inserted);
    for (0..num_items) |index| filter.insert(inserted[index * item_size ..][0..item_size]);
    // Fresh random items of at least 32 bytes are, with overwhelming probability, not among
    // the inserted ones (commonware redraws on a collision, which never happens).
    const queries = if (positive) inserted else try bloom_items(gpa, &rng, num_items, item_size);
    defer if (!positive) gpa.free(queries);
    var workload: BloomContains(H) = .{
        .filter = &filter,
        .items = queries,
        .item_size = item_size,
    };
    try runner.run(name, &workload);
}

const SealOpen = struct {
    send: cryptography.ChaCha20Poly1305,
    recv: cryptography.ChaCha20Poly1305,
    data: []const u8,
    buffer: []u8,

    pub fn iter(workload: *SealOpen) !void {
        // Copy the plaintext because sealing encrypts it in place.
        @memcpy(workload.buffer, workload.data);
        const tag = try workload.send.seal(&.{}, workload.buffer);
        try workload.recv.open(&.{}, workload.buffer, &tag);
    }
};

fn bench_seal_open(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    // test_rng() has a fixed seed, so both ciphers get the same key.
    var send_rng = utils.test_rng();
    var recv_rng = utils.test_rng();
    var workload: SealOpen = .{
        .send = .random(&send_rng),
        .recv = .random(&recv_rng),
        .data = &.{},
        .buffer = &.{},
    };
    for (cases(runner, usize, &.{ 1 << 12, 1 << 16, 1 << 20 })) |n| {
        const name = bench.Benchmark.init("chacha20_poly1305::seal_open").with_param("n", n);
        if (try skip(runner, name)) continue;
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        @memset(data, 0);
        const buffer = try gpa.alloc(u8, n);
        defer gpa.free(buffer);
        workload.data = data;
        workload.buffer = buffer;
        try runner.run(name, &workload);
    }
}

/// Times `operation` on a copy of `start` (the copy is untimed).
const LtHashOp = struct {
    start: LtHash,
    other: LtHash = .zero,
    lthash: LtHash = .zero,
    data: []const u8,
    operation: enum { add, subtract, combine, update },

    pub fn before_iter(workload: *LtHashOp) void {
        workload.lthash = workload.start;
    }

    pub fn iter(workload: *LtHashOp) ?cryptography.blake3.Digest {
        switch (workload.operation) {
            .add => workload.lthash.add(workload.data),
            .subtract => workload.lthash.subtract(workload.data),
            .combine => workload.lthash.combine(&workload.other),
            .update => {
                workload.lthash.add(workload.data);
                return workload.lthash.checksum();
            },
        }
        return null;
    }
};

const LtHashChecksum = struct {
    lthash: LtHash,

    pub fn iter(workload: *LtHashChecksum) cryptography.blake3.Digest {
        return workload.lthash.checksum();
    }
};

const LtHashFull = struct {
    count: u32,

    pub fn iter(workload: *LtHashFull) cryptography.blake3.Digest {
        var lthash = LtHash.init();
        for (0..workload.count) |i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, @intCast(i), .little);
            lthash.add(&bytes);
        }
        lthash.add("update");
        return lthash.checksum();
    }
};

fn lthash_of_counter(count: u32) LtHash {
    var lthash = LtHash.init();
    for (0..count) |i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(i), .little);
        lthash.add(&bytes);
    }
    return lthash;
}

fn bench_lthash(runner: *bench.Runner) !void {
    const zeroes: [4096]u8 = @splat(0);
    for (cases(runner, usize, &.{ 32, 256, 1024, 4096 })) |size| {
        const name = bench.Benchmark.init("lthash::add").with_param("bytes", size);
        var add: LtHashOp = .{ .start = .zero, .data = zeroes[0..size], .operation = .add };
        try runner.run(name, &add);
    }
    for (cases(runner, usize, &.{ 32, 256, 1024 })) |size| {
        const name = bench.Benchmark.init("lthash::subtract").with_param("bytes", size);
        var start = LtHash.init();
        start.add(zeroes[0..size]);
        var subtract: LtHashOp = .{
            .start = start,
            .data = zeroes[0..size],
            .operation = .subtract,
        };
        try runner.run(name, &subtract);
    }
    var first = LtHash.init();
    first.add("data1");
    var second = LtHash.init();
    second.add("data2");
    var combine: LtHashOp = .{
        .start = first,
        .other = second,
        .data = &.{},
        .operation = .combine,
    };
    try runner.run(bench.Benchmark.init("lthash::combine"), &combine);
    var checksum: LtHashChecksum = .{ .lthash = lthash_of_counter(100) };
    try runner.run(bench.Benchmark.init("lthash::checksum"), &checksum);
    const count = runner.inputs.pick(u32, 100, 10_000, 10_000);
    var incremental: LtHashOp = .{
        .start = lthash_of_counter(count),
        .data = "update",
        .operation = .update,
    };
    const update = bench.Benchmark.init("lthash::update");
    try runner.run(update.with_param("mode", "incremental"), &incremental);
    var full: LtHashFull = .{ .count = count };
    try runner.run(update.with_param("mode", "full"), &full);
}

const sake = cryptography.handshake.sake;
const ed25519 = cryptography.ed25519;
const Protocol = sake.Sake(ed25519.PrivateKey);

/// One full SAKE handshake from a fresh `test_rng`, as commonware's `connect`.
const Connect = struct {
    pub fn iter(_: *Connect) !void {
        var rng = utils.test_rng();
        const dialer = ed25519.PrivateKey.random(&rng);
        const listener = ed25519.PrivateKey.random(&rng);
        const range: sake.Range = .{ .start = 0, .end = 1 };
        const ns = "bench_namespace";
        const dial_context =
            Protocol.Context.init(ns, 0, range, dialer, listener.public_key(), .v1);
        const dial = Protocol.dial_start(&rng, dial_context);
        const listen_context =
            Protocol.Context.init(ns, 0, range, listener, dialer.public_key(), .v1);
        const listen = try Protocol.listen_start(&rng, listen_context, dial.syn);
        const end = try Protocol.dial_end(dial.state, listen.syn_ack);
        _ = try Protocol.listen_end(listen.state, end.ack);
    }
};

const bls12381 = cryptography.bls12381;
const G1 = bls12381.primitives.group.G1;
const Scalar = bls12381.primitives.group.Scalar;
const ipa = cryptography.zk.bulletproofs.ipa;
const Transcript = cryptography.transcript.Transcript;
const Synthetic = @import("math").synthetic.Synthetic(Scalar, G1);

/// commonware's `make_setup`: generators `(i + 1) * G` for `i` in `0..2n+1`.
fn make_setup(gpa: Allocator, len: usize) !ipa.Setup(G1) {
    const pairs = try gpa.alloc([2]G1, len);
    defer gpa.free(pairs);
    for (pairs, 0..) |*pair, i| {
        pair.* = .{
            G1.generator.mul(Scalar.from_u64(2 * i + 2)),
            G1.generator.mul(Scalar.from_u64(2 * i + 3)),
        };
    }
    return ipa.Setup(G1).init(gpa, G1.generator, pairs);
}

const Proved = struct { witness: ipa.Witness(Scalar), claim: ipa.Claim(Scalar, G1) };

/// commonware's honest witness and claim from a fresh `test_rng`: `y`, then `(a_i, b_i)`.
fn make_witness(gpa: Allocator, setup: *const ipa.Setup(G1), len: usize) !Proved {
    var rng = utils.test_rng();
    const y = Scalar.random(&rng);
    const a = try gpa.alloc(Scalar, len);
    defer gpa.free(a);
    const b = try gpa.alloc(Scalar, len);
    defer gpa.free(b);
    for (a, b) |*a_i, *b_i| {
        a_i.* = Scalar.random(&rng);
        b_i.* = Scalar.random(&rng);
    }
    const Witness = ipa.Witness(Scalar);
    const witness, const claim = (try Witness.init_with_claim(G1, gpa, setup, y, a, b)).?;
    return .{ .witness = witness, .claim = claim };
}

fn bench_transcript() Transcript {
    var transcript = Transcript.init("ipa-bench", .v1);
    transcript.commit("context");
    return transcript;
}

fn Prove(comptime S: type) type {
    return struct {
        gpa: Allocator,
        setup: *const ipa.Setup(G1),
        proved: *const Proved,
        strategy: S,

        pub fn iter(workload: *@This()) !void {
            var transcript = bench_transcript();
            const proved = workload.proved;
            var proof = (try ipa.prove(
                G1,
                workload.gpa,
                &transcript,
                workload.setup,
                proved.claim,
                &proved.witness,
                workload.strategy,
            )).?;
            proof.deinit(workload.gpa);
        }
    };
}

const Check = struct { claim: ipa.Claim(Scalar, G1), proof: ipa.Proof(Scalar, G1) };

fn equation(
    check: *const Check,
    gpa: Allocator,
    virtual: *const ipa.Setup(Synthetic),
) !?Synthetic {
    var transcript = bench_transcript();
    return ipa.verify(G1, gpa, &transcript, virtual, check.claim, check.proof);
}

fn Verify(comptime S: type) type {
    return struct {
        gpa: Allocator,
        setup: *const ipa.Setup(G1),
        check: *const Check,
        strategy: S,

        pub fn iter(workload: *@This()) !void {
            const setup = workload.setup;
            const strategy = workload.strategy;
            const result = try setup.eval(workload.gpa, Scalar, workload.check, equation, strategy);
            assert(result.?.eql(G1.zero));
        }
    };
}

/// Whether to build length `len`'s setup and proof: when the filters select any of its rows
/// (listing prints the rows here).
fn ipa_selected(runner: *bench.Runner, len: usize) !bool {
    var selected = false;
    for ([_][]const u8{ "bulletproofs::ipa::prove", "bulletproofs::ipa::verify" }) |prefix| {
        for ([_]u32{ 1, 8 }) |conc| {
            const name = bench.Benchmark.init(prefix).with_param("n", len).with_param("conc", conc);
            if (!try skip(runner, name)) selected = true;
        }
    }
    return selected;
}

/// `bulletproofs::ipa::{prove,verify}/n=<n> conc=<1|8>`. `eval` runs the final multi-scalar
/// multiplication through the row's strategy, as commonware's does.
fn bench_ipa(runner: *bench.Runner, rayon: parallel.Rayon) !void {
    const gpa = runner.allocator;
    for (cases(runner, usize, &.{ 8, 16, 32, 64, 128 })) |len| {
        if (!try ipa_selected(runner, len)) continue;
        var setup = try make_setup(gpa, len);
        defer setup.deinit(gpa);
        var proved = try make_witness(gpa, &setup, len);
        defer proved.witness.deinit(gpa);
        const prove_name = bench.Benchmark.init("bulletproofs::ipa::prove").with_param("n", len);
        var sequential: Prove(parallel.Sequential) = .{
            .gpa = gpa,
            .setup = &setup,
            .proved = &proved,
            .strategy = parallel.sequential,
        };
        try runner.run(prove_name.with_param("conc", 1), &sequential);
        var pooled: Prove(parallel.Rayon) = .{
            .gpa = gpa,
            .setup = &setup,
            .proved = &proved,
            .strategy = rayon,
        };
        try runner.run(prove_name.with_param("conc", 8), &pooled);
        var transcript = bench_transcript();
        const strategy = parallel.sequential;
        const claim = proved.claim;
        const proof =
            (try ipa.prove(G1, gpa, &transcript, &setup, claim, &proved.witness, strategy)).?;
        var check: Check = .{ .claim = claim, .proof = proof };
        defer check.proof.deinit(gpa);
        const verify_name = bench.Benchmark.init("bulletproofs::ipa::verify").with_param("n", len);
        var verify: Verify(parallel.Sequential) = .{
            .gpa = gpa,
            .setup = &setup,
            .check = &check,
            .strategy = strategy,
        };
        try runner.run(verify_name.with_param("conc", 1), &verify);
        var verify_pooled: Verify(parallel.Rayon) = .{
            .gpa = gpa,
            .setup = &setup,
            .check = &check,
            .strategy = rayon,
        };
        try runner.run(verify_name.with_param("conc", 8), &verify_pooled);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_bloom(cryptography.sha256.Sha256, runner, "sha256");
    try bench_bloom(cryptography.blake3.Blake3, runner, "blake3");
    try bench_seal_open(runner);
    try bench_lthash(runner);
    var connect: Connect = .{};
    try runner.run(bench.Benchmark.init("sake::sake"), &connect);
    const pool = try parallel.ThreadPool.create(runner.allocator, runner.io, .{ .threads = 8 });
    defer pool.destroy();
    try bench_ipa(runner, parallel.Rayon.init(pool));
}
