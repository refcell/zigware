//! Benchmarks of BLS12-381 (commonware `cryptography/src/bls12381/benches`), with
//! commonware's names (`bls12381::<module>`) and cases.
//!
//! Where commonware rebuilds its inputs before every iteration (`iter_batched`), the inputs
//! here are built once per benchmark: no routine consumes or changes them, so the timed work
//! is the same, and setups such as 10,000 keypairs stay out of every sample. The operations
//! are sequential, so only commonware's `conc=1` cases are ported.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const utils = @import("utils");

const bls12381 = cryptography.bls12381;
const primitives = bls12381.primitives;
const ops = primitives.ops;
const aggregate = ops.aggregate;
const group = primitives.group;
const MinSig = primitives.MinSig;
const G1 = group.G1;
const G2 = group.G2;
const Private = group.Private;
const tle = bls12381.tle;
const common = @import("benches/common.zig");
const cases = common.cases;
const skip = common.skip;
const random_messages = common.random_messages;
const Message = common.Message;

const namespace = "namespace";

const SignatureGeneration = struct {
    key: bls12381.PrivateKey,
    message: *const Message,

    pub fn iter(workload: *SignatureGeneration) bls12381.Signature {
        return workload.key.sign(namespace, workload.message);
    }
};

const SignatureVerification = struct {
    public: bls12381.PublicKey,
    signature: bls12381.Signature,
    message: *const Message,

    pub fn iter(workload: *SignatureVerification) bool {
        const valid = workload.public.verify(namespace, workload.message, &workload.signature);
        assert(valid);
        return valid;
    }
};

fn bench_signatures(runner: *bench.Runner) !void {
    var rng = utils.test_rng();
    var message: Message = undefined;
    rng.fill_bytes(&message);
    const key = bls12381.PrivateKey.random(&rng);
    const generation_name = bench.Benchmark.init("bls12381::signature_generation")
        .with_param("ns_len", namespace.len).with_param("msg_len", message.len);
    if (!try skip(runner, generation_name)) {
        var generation: SignatureGeneration = .{ .key = key, .message = &message };
        try runner.run(generation_name, &generation);
    }
    const verification_name = bench.Benchmark.init("bls12381::signature_verification")
        .with_param("ns_len", namespace.len).with_param("msg_len", message.len);
    if (try skip(runner, verification_name)) return;
    var verification: SignatureVerification = .{
        .public = key.public_key(),
        .signature = key.sign(namespace, &message),
        .message = &message,
    };
    try runner.run(verification_name, &verification);
}

const HashToCurve = struct {
    messages: []const Message,
    out: []G1,

    pub fn iter(workload: *HashToCurve) void {
        for (workload.messages, workload.out) |*message, *hm| {
            hm.* = ops.hash_with_namespace(MinSig, MinSig.message, namespace, message);
        }
    }
};

fn bench_hash_to_curve(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    for (cases(runner, usize, &.{ 10, 50, 100, 200 })) |n| {
        const name = bench.Benchmark.init("bls12381::hash_to_curve")
            .with_param("n", n).with_param("conc", 1);
        if (try skip(runner, name)) continue;
        const messages = try random_messages(gpa, &rng, n);
        defer gpa.free(messages);
        const out = try gpa.alloc(G1, n);
        defer gpa.free(out);
        var workload: HashToCurve = .{ .messages = messages, .out = out };
        try runner.run(name, &workload);
    }
}

const tle_namespace = "_BENCH_TLE_";

const TleEncrypt = struct {
    rng: utils.TestRng,
    public: G2,
    target: [8]u8,
    message: tle.Block,

    pub fn iter(workload: *TleEncrypt) !tle.Ciphertext(MinSig) {
        return tle.encrypt(
            MinSig,
            &workload.rng,
            workload.public,
            tle_namespace,
            &workload.target,
            &workload.message,
        );
    }
};

const TleDecrypt = struct {
    signature: G1,
    ciphertext: tle.Ciphertext(MinSig),

    pub fn iter(workload: *TleDecrypt) tle.Block {
        return tle.decrypt(MinSig, workload.signature, workload.ciphertext).?;
    }
};

fn bench_tle(runner: *bench.Runner) !void {
    var rng = utils.test_rng();
    const master = ops.keypair(MinSig, &rng);
    var target: [8]u8 = undefined;
    std.mem.writeInt(u64, &target, 10, .big);
    const message: tle.Block = @splat(0x42);
    var encrypt: TleEncrypt = .{
        .rng = rng,
        .public = master.public,
        .target = target,
        .message = message,
    };
    const encrypt_name = bench.Benchmark.init("bls12381::tle_encrypt");
    if (!try skip(runner, encrypt_name)) try runner.run(encrypt_name, &encrypt);
    const decrypt_name = bench.Benchmark.init("bls12381::tle_decrypt");
    if (try skip(runner, decrypt_name)) return;
    var decrypt: TleDecrypt = .{
        .signature = ops.sign_message(MinSig, master.private, tle_namespace, &target),
        .ciphertext = try encrypt.iter(),
    };
    try runner.run(decrypt_name, &decrypt);
}

const CombinePublicKeys = struct {
    public_keys: []const G2,

    pub fn iter(workload: *CombinePublicKeys) aggregate.PublicKey(MinSig) {
        return aggregate.combine_public_keys(MinSig, workload.public_keys);
    }
};

const CombineSignatures = struct {
    signatures: []const G1,

    pub fn iter(workload: *CombineSignatures) aggregate.Signature(MinSig) {
        return aggregate.combine_signatures(MinSig, workload.signatures);
    }
};

fn bench_combine(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    var rng = utils.test_rng();
    for (cases(runner, usize, &.{ 10, 100, 1000, 10000 })) |n| {
        const name = bench.Benchmark.init("bls12381::combine_public_keys").with_param("pks", n);
        if (try skip(runner, name)) continue;
        const public_keys = try gpa.alloc(G2, n);
        defer gpa.free(public_keys);
        for (public_keys) |*public_key| public_key.* = ops.keypair(MinSig, &rng).public;
        var workload: CombinePublicKeys = .{ .public_keys = public_keys };
        try runner.run(name, &workload);
    }
    for (cases(runner, usize, &.{ 10, 100, 1000, 10000 })) |n| {
        const name = bench.Benchmark.init("bls12381::combine_signatures").with_param("sigs", n);
        if (try skip(runner, name)) continue;
        const messages = try random_messages(gpa, &rng, n);
        defer gpa.free(messages);
        const private = ops.keypair(MinSig, &rng).private;
        const signatures = try gpa.alloc(G1, n);
        defer gpa.free(signatures);
        for (signatures, messages) |*signature, *message| {
            signature.* = ops.sign_message(MinSig, private, namespace, message);
        }
        var workload: CombineSignatures = .{ .signatures = signatures };
        try runner.run(name, &workload);
    }
}

fn BatchToAffine(comptime P: type) type {
    return struct {
        points: []const P.Jacobian,
        out: []P.Affine,
        scratch: []P.Jacobian.Field,

        pub fn iter(workload: *@This()) void {
            P.Jacobian.batch_to_affine(workload.points, workload.out, workload.scratch);
        }
    };
}

fn bench_batch_to_affine_group(runner: *bench.Runner, comptime P: type, n: usize) !void {
    const gpa = runner.allocator;
    const name = bench.Benchmark.init("bls12381::batch_to_affine")
        .with_param("group", if (P == G1) "g1" else "g2").with_param("n", n);
    if (try skip(runner, name)) return;
    var rng = utils.test_rng();
    const points = try gpa.alloc(P.Jacobian, n);
    defer gpa.free(points);
    for (points) |*point| point.* = P.generator.mul(group.Scalar.random(&rng)).point;
    const out = try gpa.alloc(P.Affine, n);
    defer gpa.free(out);
    const scratch = try gpa.alloc(P.Jacobian.Field, n);
    defer gpa.free(scratch);
    var workload: BatchToAffine(P) = .{ .points = points, .out = out, .scratch = scratch };
    try runner.run(name, &workload);
}

fn bench_batch_to_affine(runner: *bench.Runner) !void {
    for (cases(runner, usize, &.{ 10, 50, 100, 200 })) |n| {
        try bench_batch_to_affine_group(runner, G1, n);
        try bench_batch_to_affine_group(runner, G2, n);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try @import("benches/assemble.zig").run(runner);
    try @import("benches/dkg.zig").run(runner);
    try @import("benches/golden.zig").run(runner);
    try @import("benches/threshold.zig").run(runner);
    try @import("benches/verify.zig").run(runner);
    try bench_batch_to_affine(runner);
    try bench_hash_to_curve(runner);
    try bench_combine(runner);
    try bench_signatures(runner);
    try bench_tle(runner);
}
