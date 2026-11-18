//! Benchmarks of ed25519 and secp256r1 signing (commonware
//! `cryptography/src/{ed25519,secp256r1}/benches`), with commonware's names and cases.
//!
//! Where commonware draws fresh keys before every iteration (`iter_batched`), the keys and
//! signatures here are built once per benchmark: the timed work is the same, and setups such
//! as 100,000 signatures stay out of every sample.

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
const ed25519 = cryptography.ed25519;
const secp256r1 = cryptography.secp256r1;

const namespace = "namespace";

/// Workers in the pool behind the parallel rows.
const concurrency = 8;

fn Generation(comptime K: type) type {
    return struct {
        key: K,
        message: *const [32]u8,

        pub fn iter(workload: *@This()) K.Signature {
            return workload.key.sign(namespace, workload.message);
        }
    };
}

fn Verification(comptime K: type) type {
    const P = K.PublicKey;
    return struct {
        public: P,
        signature: P.Signature,
        message: *const [32]u8,

        pub fn iter(workload: *@This()) bool {
            const valid = workload.public.verify(namespace, workload.message, &workload.signature);
            assert(valid);
            return valid;
        }
    };
}

/// `<prefix>signature_{generation,verification}/[variant=<v> ]ns_len=9 msg_len=32`.
fn bench_signatures(
    comptime K: type,
    runner: *bench.Runner,
    crate: []const u8,
    variant: ?[]const u8,
) !void {
    var rng = utils.test_rng();
    var message: [32]u8 = undefined;
    rng.fill_bytes(&message);
    const key = K.random(&rng);
    var buffer: [bench.name_len_max]u8 = undefined;
    for ([_][]const u8{ "signature_generation", "signature_verification" }) |module| {
        const prefix = try std.fmt.bufPrint(&buffer, "{s}::{s}", .{ crate, module });
        var name = bench.Benchmark.init(prefix);
        if (variant) |value| name = name.with_param("variant", value);
        name = name.with_param("ns_len", namespace.len).with_param("msg_len", message.len);
        if (std.mem.eql(u8, module, "signature_generation")) {
            var generation: Generation(K) = .{ .key = key, .message = &message };
            try runner.run(name, &generation);
        } else {
            var verification: Verification(K) = .{
                .public = key.public_key(),
                .signature = key.sign(namespace, &message),
                .message = &message,
            };
            try runner.run(name, &verification);
        }
    }
}

const PublicKey = ed25519.PublicKey;
const Signature = PublicKey.Signature;

/// A signed message: commonware's `(PublicKey, Vec<u8>, Signature)` tuple.
const Signed = struct { public: PublicKey, message: []const u8, signature: Signature };

const Projector = struct {
    namespace: []const u8,

    pub fn project(projector: Projector, _: usize, item: *const Signed) PublicKey.Entry {
        return .{
            .namespace = projector.namespace,
            .message = item.message,
            .public_key = &item.public,
            .signature = &item.signature,
        };
    }
};

fn BatchVerify(comptime S: type) type {
    return struct {
        rng: utils.TestRng,
        items: []const Signed,
        namespace: []const u8,
        strategy: S,

        pub fn iter(workload: *@This()) bool {
            const projector: Projector = .{ .namespace = workload.namespace };
            const valid = PublicKey.verify_batch(
                &workload.rng,
                workload.items,
                projector,
                workload.strategy,
            );
            assert(valid);
            return valid;
        }
    };
}

/// Runs a batch verification benchmark over `items` with one worker or `rayon`.
fn run_batch(
    runner: *bench.Runner,
    name: bench.Benchmark,
    items: []const Signed,
    batch_namespace: []const u8,
    conc: u32,
    rayon: parallel.Rayon,
) !void {
    if (conc == 1) {
        var workload: BatchVerify(parallel.Sequential) = .{
            .rng = .init(1),
            .items = items,
            .namespace = batch_namespace,
            .strategy = parallel.sequential,
        };
        return runner.run(name, &workload);
    }
    var workload: BatchVerify(parallel.Rayon) = .{
        .rng = .init(1),
        .items = items,
        .namespace = batch_namespace,
        .strategy = rayon,
    };
    try runner.run(name, &workload);
}

/// Signs `items.len` messages from `messages` (each `msg_len` bytes, filled from `rng`),
/// each with its own key, or all with `shared` when it is set.
fn sign_items(
    rng: *utils.TestRng,
    items: []Signed,
    messages: []u8,
    msg_len: usize,
    item_namespace: []const u8,
    shared: ?ed25519.PrivateKey,
) void {
    assert(messages.len == items.len * msg_len);
    for (items, 0..) |*item, index| {
        const signer = shared orelse ed25519.PrivateKey.random(rng);
        const message = messages[index * msg_len ..][0..msg_len];
        rng.fill_bytes(message);
        item.* = .{
            .public = signer.public_key(),
            .message = message,
            .signature = signer.sign(item_namespace, message),
        };
    }
}

const BatchCase = struct { n: usize, msg_len: usize, conc: u32 };

/// `ed25519::batch_verify/sigs=<n> msg=<len> conc=<c>`: distinct signers and messages.
fn bench_batch_verify(runner: *bench.Runner, rayon: parallel.Rayon) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    const all = [_]BatchCase{
        .{ .n = 10_000, .msg_len = 32, .conc = 8 }, .{ .n = 100_000, .msg_len = 32, .conc = 8 },
        .{ .n = 10_000, .msg_len = 96, .conc = 8 }, .{ .n = 10, .msg_len = 32, .conc = 1 },
        .{ .n = 100, .msg_len = 32, .conc = 1 },
    };
    const smoke = [_]BatchCase{.{ .n = 10, .msg_len = 32, .conc = 1 }};
    for (runner.inputs.pick([]const BatchCase, &smoke, &all, &all)) |case| {
        const name = bench.Benchmark.init("ed25519::batch_verify").with_param("sigs", case.n)
            .with_param("msg", case.msg_len).with_param("conc", case.conc);
        if (try skip(runner, name)) continue;
        const items = try gpa.alloc(Signed, case.n);
        defer gpa.free(items);
        const messages = try gpa.alloc(u8, case.n * case.msg_len);
        defer gpa.free(messages);
        const batch_namespace = "constantinople-tx";
        sign_items(&rng, items, messages, case.msg_len, batch_namespace, null);
        try run_batch(runner, name, items, batch_namespace, case.conc, rayon);
    }
}

/// `ed25519::batch_verify_same_{message,signer}/{pks,msgs}=<n> conc=<1|8>`.
fn bench_batch_same(runner: *bench.Runner, rayon: parallel.Rayon, same_signer: bool) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    var shared_message: [32]u8 = undefined;
    if (!same_signer) rng.fill_bytes(&shared_message);
    const prefix = if (same_signer)
        "ed25519::batch_verify_same_signer"
    else
        "ed25519::batch_verify_same_message";
    const count_key = if (same_signer) "msgs" else "pks";
    for (cases(runner, usize, &.{ 1, 10, 100, 1000, 10000 })) |n| {
        const all_conc = [_]u32{ 1, concurrency };
        const concs = runner.inputs.pick([]const u32, all_conc[0..1], &all_conc, &all_conc);
        for (concs) |conc| {
            const name = bench.Benchmark.init(prefix).with_param(count_key, n)
                .with_param("conc", conc);
            if (try skip(runner, name)) continue;
            const items = try gpa.alloc(Signed, n);
            defer gpa.free(items);
            const messages = try gpa.alloc(u8, n * 32);
            defer gpa.free(messages);
            if (same_signer) {
                const signer = ed25519.PrivateKey.random(&rng);
                sign_items(&rng, items, messages, 32, namespace, signer);
            } else {
                for (items) |*item| {
                    const signer = ed25519.PrivateKey.random(&rng);
                    item.* = .{
                        .public = signer.public_key(),
                        .message = &shared_message,
                        .signature = signer.sign(namespace, &shared_message),
                    };
                }
            }
            try run_batch(runner, name, items, namespace, conc, rayon);
        }
    }
}

pub fn run(runner: *bench.Runner) !void {
    const pool = try parallel.ThreadPool.create(runner.allocator, runner.io, .{
        .threads = concurrency,
    });
    defer pool.destroy();
    const rayon = parallel.Rayon.init(pool);
    try bench_signatures(ed25519.PrivateKey, runner, "ed25519", null);
    try bench_batch_same(runner, rayon, false);
    try bench_batch_same(runner, rayon, true);
    try bench_batch_verify(runner, rayon);
    try bench_signatures(secp256r1.standard.PrivateKey, runner, "secp256r1", "standard");
    try bench_signatures(secp256r1.recoverable.PrivateKey, runner, "secp256r1", "recoverable");
}
