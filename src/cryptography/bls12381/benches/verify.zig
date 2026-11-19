//! Verification, MSM, and polynomial benchmarks of BLS12-381 (commonware
//! `bls12381/benches/{aggregate_verify_*, batch_verify_same_signer, scheme_batch_verify_*,
//! msm, evaluate_point}.rs`). See `../benches.zig` for how inputs are built.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const math = @import("math");
const parallel = @import("parallel");
const utils = @import("utils");

const bls12381 = cryptography.bls12381;
const primitives = bls12381.primitives;
const ops = primitives.ops;
const aggregate = ops.aggregate;
const batch = ops.batch;
const group = primitives.group;
const MinSig = primitives.MinSig;
const Scalar = group.Scalar;
const G1 = group.G1;
const G2 = group.G2;

const common = @import("common.zig");
const cases = common.cases;
const skip = common.skip;
const random_messages = common.random_messages;
const Message = common.Message;

const namespace = "namespace";

/// Combines the public keys, then verifies the aggregate signature over one message.
const AggregateSameMessage = struct {
    public_keys: []const G2,
    signature: aggregate.Signature(MinSig),
    message: *const Message,

    pub fn iter(workload: *AggregateSameMessage) !void {
        const public = aggregate.combine_public_keys(MinSig, workload.public_keys);
        try aggregate.verify_same_message(
            MinSig,
            public,
            namespace,
            workload.message,
            workload.signature,
        );
    }
};

fn bench_aggregate_same_message(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    var message: Message = undefined;
    rng.fill_bytes(&message);
    for (cases(runner, usize, &.{ 10, 100, 1000, 10000 })) |n| {
        const name = bench.Benchmark.init("bls12381::aggregate_verify_same_message")
            .with_param("pks", n);
        if (try skip(runner, name)) continue;
        const public_keys = try gpa.alloc(G2, n);
        defer gpa.free(public_keys);
        const signatures = try gpa.alloc(G1, n);
        defer gpa.free(signatures);
        for (public_keys, signatures) |*public_key, *signature| {
            const keypair = ops.keypair(MinSig, &rng);
            public_key.* = keypair.public;
            signature.* = ops.sign_message(MinSig, keypair.private, namespace, &message);
        }
        var workload: AggregateSameMessage = .{
            .public_keys = public_keys,
            .signature = aggregate.combine_signatures(MinSig, signatures),
            .message = &message,
        };
        try runner.run(name, &workload);
    }
}

/// Combines the message hashes, then verifies one signer's aggregate signature.
const AggregateSameSigner = struct {
    public: G2,
    messages: []const aggregate.NamespacedMessage,
    signature: aggregate.Signature(MinSig),

    pub fn iter(workload: *AggregateSameSigner) !void {
        const combined = aggregate.combine_messages(MinSig, workload.messages);
        try aggregate.verify_same_signer(MinSig, workload.public, combined, workload.signature);
    }
};

/// One signer's signatures over `messages`.
const Signed = struct {
    public: G2,
    signatures: []G1,

    fn init(gpa: Allocator, rng: *utils.TestRng, messages: []const Message) !Signed {
        const keypair = ops.keypair(MinSig, rng);
        const signatures = try gpa.alloc(G1, messages.len);
        for (signatures, messages) |*signature, *message| {
            signature.* = ops.sign_message(MinSig, keypair.private, namespace, message);
        }
        return .{ .public = keypair.public, .signatures = signatures };
    }
};

fn bench_aggregate_same_signer(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    for (cases(runner, usize, &.{ 2, 10, 100, 1000, 10000 })) |n| {
        const name = bench.Benchmark.init("bls12381::aggregate_verify_same_signer")
            .with_param("conc", 1).with_param("msgs", n);
        if (try skip(runner, name)) continue;
        const messages = try random_messages(gpa, &rng, n);
        defer gpa.free(messages);
        const signed = try Signed.init(gpa, &rng, messages);
        defer gpa.free(signed.signatures);
        const namespaced = try gpa.alloc(aggregate.NamespacedMessage, n);
        defer gpa.free(namespaced);
        for (namespaced, messages) |*item, *message| {
            item.* = .{ .namespace = namespace, .message = message };
        }
        var workload: AggregateSameSigner = .{
            .public = signed.public,
            .messages = namespaced,
            .signature = aggregate.combine_signatures(MinSig, signed.signatures),
        };
        try runner.run(name, &workload);
    }
}

const BatchSameSigner = struct {
    rng: utils.TestRng,
    public: G2,
    entries: []const batch.SignerEntry(MinSig),
    strategy: parallel.Rayon,

    pub fn iter(workload: *BatchSameSigner) !void {
        const entries = workload.entries;
        try batch.verify_same_signer(
            MinSig,
            &workload.rng,
            workload.public,
            entries,
            workload.strategy,
        );
    }
};

fn bench_batch_same_signer(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    const threads = try common.pool(runner);
    defer threads.destroy();
    const sizes = cases(runner, usize, &.{ 2, 10, 100, 1000, 10000 });
    for (sizes) |n| for (common.concurrencies) |conc| {
        const name = bench.Benchmark.init("bls12381::batch_verify_same_signer")
            .with_param("conc", conc).with_param("msgs", n);
        if (try skip(runner, name)) continue;
        const messages = try random_messages(gpa, &rng, n);
        defer gpa.free(messages);
        const signed = try Signed.init(gpa, &rng, messages);
        defer gpa.free(signed.signatures);
        const entries = try gpa.alloc(batch.SignerEntry(MinSig), n);
        defer gpa.free(entries);
        for (entries, messages, signed.signatures) |*entry, *message, signature| {
            entry.* = .{ .namespace = namespace, .message = message, .signature = signature };
        }
        var workload: BatchSameSigner = .{
            .rng = .init(1),
            .public = signed.public,
            .entries = entries,
            .strategy = common.strategy(threads, conc),
        };
        try runner.run(name, &workload);
    };
}

const Entry = cryptography.signer.BatchEntry(bls12381.PublicKey);

const SchemeBatch = struct {
    rng: utils.TestRng,
    entries: []const Entry,
    strategy: parallel.Rayon,

    pub fn iter(workload: *SchemeBatch) bool {
        const valid = bls12381.PublicKey.verify_batch(
            &workload.rng,
            workload.entries,
            cryptography.entries,
            workload.strategy,
        );
        assert(valid);
        return valid;
    }
};

const Keyed = struct { public_key: bls12381.PublicKey, signature: bls12381.Signature };

fn bench_scheme_same_message(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    var message: Message = undefined;
    rng.fill_bytes(&message);
    const threads = try common.pool(runner);
    defer threads.destroy();
    const sizes = cases(runner, usize, &.{ 1, 10, 100, 1000, 10000 });
    for (sizes) |n| for (common.concurrencies) |conc| {
        const name = bench.Benchmark.init("bls12381::scheme_batch_verify_same_message")
            .with_param("pks", n).with_param("conc", conc);
        if (try skip(runner, name)) continue;
        const keyed = try gpa.alloc(Keyed, n);
        defer gpa.free(keyed);
        const entries = try gpa.alloc(Entry, n);
        defer gpa.free(entries);
        for (keyed, entries) |*item, *entry| {
            const signer = bls12381.PrivateKey.random(&rng);
            item.* = .{
                .public_key = signer.public_key(),
                .signature = signer.sign(namespace, &message),
            };
            entry.* = .{
                .namespace = namespace,
                .message = &message,
                .public_key = &item.public_key,
                .signature = &item.signature,
            };
        }
        var workload: SchemeBatch = .{
            .rng = .init(1),
            .entries = entries,
            .strategy = common.strategy(threads, conc),
        };
        try runner.run(name, &workload);
    };
}

fn bench_scheme_same_signer(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    const threads = try common.pool(runner);
    defer threads.destroy();
    const sizes = cases(runner, usize, &.{ 1, 10, 100, 1000, 10000 });
    for (sizes) |n| for (common.concurrencies) |conc| {
        const name = bench.Benchmark.init("bls12381::scheme_batch_verify_same_signer")
            .with_param("msgs", n).with_param("conc", conc);
        if (try skip(runner, name)) continue;
        const messages = try random_messages(gpa, &rng, n);
        defer gpa.free(messages);
        const signer = bls12381.PrivateKey.random(&rng);
        const public_key = signer.public_key();
        const signatures = try gpa.alloc(bls12381.Signature, n);
        defer gpa.free(signatures);
        const entries = try gpa.alloc(Entry, n);
        defer gpa.free(entries);
        for (signatures, entries, messages) |*signature, *entry, *message| {
            signature.* = signer.sign(namespace, message);
            entry.* = .{
                .namespace = namespace,
                .message = message,
                .public_key = &public_key,
                .signature = signature,
            };
        }
        var workload: SchemeBatch = .{
            .rng = .init(1),
            .entries = entries,
            .strategy = common.strategy(threads, conc),
        };
        try runner.run(name, &workload);
    };
}

fn Msm(comptime P: type) type {
    return struct {
        points: []const P,
        scalars: []const Scalar,

        pub fn iter(workload: *@This()) P {
            return P.msm(workload.points, workload.scalars);
        }
    };
}

fn bench_msm_group(runner: *bench.Runner, comptime P: type, n: usize) !void {
    const gpa = runner.allocator;
    const name = bench.Benchmark.init("bls12381::msm")
        .with_param("group", if (P == G1) "g1" else "g2")
        .with_param("n", n).with_param("conc", 1);
    if (try skip(runner, name)) return;
    var rng = utils.test_rng();
    const points = try gpa.alloc(P, n);
    defer gpa.free(points);
    for (points) |*point| point.* = P.generator.mul(Scalar.random(&rng));
    const scalars = try gpa.alloc(Scalar, n);
    defer gpa.free(scalars);
    for (scalars) |*scalar| scalar.* = Scalar.random(&rng);
    var workload: Msm(P) = .{ .points = points, .scalars = scalars };
    try runner.run(name, &workload);
}

fn bench_msm(runner: *bench.Runner) !void {
    for (cases(runner, usize, &.{ 10, 50, 100, 200, 1000, 5000 })) |n| {
        try bench_msm_group(runner, G1, n);
        try bench_msm_group(runner, G2, n);
    }
}

const EvaluatePoint = struct {
    gpa: Allocator,
    polynomial: math.poly.Poly(G1),
    scalar: Scalar,

    pub fn iter(workload: *EvaluatePoint) !G1 {
        return workload.polynomial.eval_msm(workload.gpa, Scalar, workload.scalar);
    }
};

fn bench_evaluate_point(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    for (cases(runner, u32, &.{ 5, 10, 20, 50, 100, 250, 500 })) |n| {
        const t = utils.N3f1.quorum(n);
        const name = bench.Benchmark.init("bls12381::evaluate_point")
            .with_param("n", n).with_param("t", t).with_param("conc", 1);
        if (try skip(runner, name)) continue;
        var rng = utils.test_rng();
        var secret = try math.poly.Poly(Scalar).random(gpa, &rng, t - 1);
        defer secret.deinit(gpa);
        var workload: EvaluatePoint = .{
            .gpa = gpa,
            .polynomial = try math.poly.commit(gpa, G1, secret),
            .scalar = Scalar.random(&rng),
        };
        defer workload.polynomial.deinit(gpa);
        try runner.run(name, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_aggregate_same_message(runner);
    try bench_aggregate_same_signer(runner);
    try bench_batch_same_signer(runner);
    try bench_scheme_same_signer(runner);
    try bench_scheme_same_message(runner);
    try bench_evaluate_point(runner);
    try bench_msm(runner);
}
