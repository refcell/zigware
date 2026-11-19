//! Benchmarks of the curve25519 package (`zig build bench`).
//!
//! - `batch_verify::verify_batch_bytes_bench` is commonware's `benches/batch_verify.rs`, under
//!   its Criterion name: batches of independent keys over independent 32-byte messages,
//!   sequential and on pools of commonware's concurrency levels.
//! - `curve25519::{sign, verify, x25519}` time single operations, each next to
//!   `std.crypto`'s own (`impl=std`): std's Ed25519 verification is strict RFC 8032 rather
//!   than ZIP-215, so it is a speed reference only.

const std = @import("std");
const assert = std.debug.assert;
const bench = @import("bench");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const signing = @import("signing.zig");
const key_exchange = @import("key_exchange.zig");

const StdEd25519 = std.crypto.sign.Ed25519;
const StdX25519 = std.crypto.dh.X25519;
const VerifyingKey = signing.VerifyingKey;
const Signature = signing.Signature;
const namespace = "_COMMONWARE_CRYPTOGRAPHY_CURVE25519_BATCH_VERIFY_BENCH";
const message_size = 32;

/// `n` signatures by independent keys over independent messages (commonware's
/// `generate_batch`: message `i` starts with `i` as little-endian `u64`).
const Batch = struct {
    keys: []VerifyingKey,
    signatures: []Signature,
    messages: [][message_size]u8,
    entries: []VerifyingKey.Entry,

    fn init(gpa: std.mem.Allocator, n: usize) !Batch {
        assert(n > 0);
        const batch: Batch = .{
            .keys = try gpa.alloc(VerifyingKey, n),
            .signatures = try gpa.alloc(Signature, n),
            .messages = try gpa.alloc([message_size]u8, n),
            .entries = try gpa.alloc(VerifyingKey.Entry, n),
        };
        var rng = utils.test_rng();
        for (0..n) |i| {
            const signing_key = signing.SigningKey.random(&rng);
            batch.messages[i] = @splat(0);
            std.mem.writeInt(u64, batch.messages[i][0..8], i, .little);
            batch.signatures[i] = signing_key.sign(namespace, &batch.messages[i]);
            batch.keys[i] = signing_key.verifying_key();
        }
        for (batch.entries, 0..) |*entry, i| {
            entry.* = .{
                .namespace = namespace,
                .message = &batch.messages[i],
                .public_key = &batch.keys[i],
                .signature = &batch.signatures[i],
            };
        }
        return batch;
    }

    fn deinit(batch: Batch, gpa: std.mem.Allocator) void {
        gpa.free(batch.keys);
        gpa.free(batch.signatures);
        gpa.free(batch.messages);
        gpa.free(batch.entries);
    }
};

fn BatchVerify(comptime Strategy: type) type {
    return struct {
        batch: *const Batch,
        strategy: Strategy,

        pub fn iter(workload: *@This()) bool {
            var rng = utils.TestRng.init(1);
            const entries = workload.batch.entries;
            const valid = VerifyingKey.verify_batch(
                &rng,
                entries,
                cryptography.entries,
                workload.strategy,
            );
            assert(valid);
            return valid;
        }
    };
}

fn bench_batch_verify(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const all = [_]usize{ 1, 10, 100, 1_000, 10_000, 16_384 };
    const sizes = runner.inputs.pick([]const usize, all[0..1], all[0..4], &all);
    // commonware's concurrency levels; a pool of `c - 1` workers plus the caller runs `c`.
    const pooled_levels = [_]u32{ 8, 16, 32 };
    var pools: [pooled_levels.len]*parallel.ThreadPool = undefined;
    var created: usize = 0;
    defer for (pools[0..created]) |pool| pool.destroy();
    for (pooled_levels) |level| {
        pools[created] = try parallel.ThreadPool.create(gpa, runner.io, .{ .threads = level - 1 });
        created += 1;
    }
    for (sizes) |n| {
        const batch = try Batch.init(gpa, n);
        defer batch.deinit(gpa);
        const name = bench.Benchmark.init("batch_verify::verify_batch_bytes_bench")
            .with_param("sigs", n);
        var sequential: BatchVerify(parallel.Sequential) = .{
            .batch = &batch,
            .strategy = parallel.sequential,
        };
        try runner.run(name.with_param("conc", 1), &sequential);
        for (pooled_levels, pools) |level, pool| {
            var pooled: BatchVerify(parallel.Rayon) = .{
                .batch = &batch,
                .strategy = parallel.Rayon.init(pool),
            };
            try runner.run(name.with_param("conc", level), &pooled);
        }
    }
}

const Sign = struct {
    key: signing.SigningKey,
    message: [message_size]u8,

    pub fn iter(workload: *Sign) Signature {
        return workload.key.sign(namespace, &workload.message);
    }
};

const StdSign = struct {
    key: StdEd25519.KeyPair,
    message: [message_size]u8,

    pub fn iter(workload: *StdSign) !StdEd25519.Signature {
        return workload.key.sign(&workload.message, null);
    }
};

const Verify = struct {
    key: VerifyingKey,
    signature: Signature,
    message: [message_size]u8,

    pub fn iter(workload: *Verify) bool {
        // Decodes the key each time, as a key read off the wire would be.
        const key = VerifyingKey.from_bytes(workload.key.bytes);
        const valid = key.verify(namespace, &workload.message, &workload.signature);
        assert(valid);
        return valid;
    }
};

const StdVerify = struct {
    key: StdEd25519.PublicKey,
    signature: StdEd25519.Signature,
    message: [message_size]u8,

    pub fn iter(workload: *StdVerify) !void {
        try workload.signature.verify(&workload.message, workload.key);
    }
};

const Exchange = struct {
    secret: key_exchange.SecretKey,
    public: key_exchange.PublicKey,

    pub fn iter(workload: *Exchange) [32]u8 {
        return workload.secret.exchange(workload.public).?.bytes;
    }
};

const StdExchange = struct {
    secret: [32]u8,
    public: [32]u8,

    pub fn iter(workload: *StdExchange) ![32]u8 {
        return StdX25519.scalarmult(workload.secret, workload.public);
    }
};

fn bench_single(runner: *bench.Runner) !void {
    var rng = utils.test_rng();
    var seed: [32]u8 = undefined;
    rng.fill_bytes(&seed);
    var message: [message_size]u8 = undefined;
    rng.fill_bytes(&message);
    const key = signing.SigningKey.from_seed(seed);
    const std_key = try StdEd25519.KeyPair.generateDeterministic(seed);

    const sign_name = bench.Benchmark.init("curve25519::sign");
    var sign: Sign = .{ .key = key, .message = message };
    try runner.run(sign_name.with_param("impl", "zigware"), &sign);
    var std_sign: StdSign = .{ .key = std_key, .message = message };
    try runner.run(sign_name.with_param("impl", "std"), &std_sign);

    const verify_name = bench.Benchmark.init("curve25519::verify");
    var verify: Verify = .{
        .key = key.verifying_key(),
        .signature = key.sign(namespace, &message),
        .message = message,
    };
    try runner.run(verify_name.with_param("impl", "zigware"), &verify);
    var std_verify: StdVerify = .{
        .key = std_key.public_key,
        .signature = try std_key.sign(&message, null),
        .message = message,
    };
    try runner.run(verify_name.with_param("impl", "std"), &std_verify);

    const secret = key_exchange.SecretKey.random(&rng);
    const peer = key_exchange.SecretKey.random(&rng).public_key();
    const exchange_name = bench.Benchmark.init("curve25519::x25519");
    var exchange: Exchange = .{ .secret = secret, .public = peer };
    try runner.run(exchange_name.with_param("impl", "zigware"), &exchange);
    var std_exchange: StdExchange = .{ .secret = secret.bytes, .public = peer.bytes };
    try runner.run(exchange_name.with_param("impl", "std"), &std_exchange);
}

pub fn run(runner: *bench.Runner) !void {
    try bench_batch_verify(runner);
    try bench_single(runner);
}
