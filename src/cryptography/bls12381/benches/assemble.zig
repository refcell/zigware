//! Certificate benchmarks of BLS12-381 (commonware `bls12381/benches/{attestation_eq,
//! multisig_optimistic_assemble, threshold_optimistic_assemble}.rs` and their shared
//! `utils/optimistic_assemble.rs`): optimistic assembly of a quorum, with its fallback when
//! some attestations are invalid, for both certificate schemes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const common = @import("common.zig");

const base = cryptography.certificate;
const bls12381 = cryptography.bls12381;
const primitives = bls12381.primitives;
const ops = primitives.ops;
const multisig = bls12381.certificate.multisig;
const threshold = bls12381.certificate.threshold;
const ed25519 = cryptography.ed25519;
const Private = primitives.group.Private;
const MinPk = primitives.MinPk;
const MinSig = primitives.MinSig;
const Mode = primitives.sharing.Mode;
const Share = primitives.group.Share;
const Participant = utils.Participant;
const N3f1 = utils.N3f1;
const sequential = parallel.sequential;

const rng_seed = 1;

/// commonware's `BenchSubject`: the message `hello` under the base namespace.
const BenchSubject = struct {
    pub const Namespace = base.BytesNamespace;

    pub fn namespace(_: BenchSubject, derived: *const Namespace) []const u8 {
        return derived.bytes;
    }

    pub fn message(_: BenchSubject, gpa: Allocator) Allocator.Error![]u8 {
        return gpa.dupe(u8, "hello");
    }
};

const subject: BenchSubject = .{};

const Case = enum {
    /// A quorum of valid attestations.
    valid,
    /// A quorum with one invalid attestation, leaving too few to certify.
    bad,
    /// A quorum plus one attestation, leaving a valid quorum after rejection.
    spare,
    /// A quorum with one invalid attestation in each fallback half.
    split,

    fn expects_certificate(case: Case) bool {
        return case == .valid or case == .spare;
    }
};

/// The pending attestations of `case` from a quorum plus a spare, and its invalid signers.
fn Fixture(comptime S: type) type {
    return struct {
        pending: []S.Attestation,
        invalid: [2]Participant,
        invalid_count: usize,

        fn init(
            gpa: Allocator,
            attestations: []const S.Attestation,
            quorum: usize,
            case: Case,
        ) !@This() {
            assert(attestations.len == quorum + 1);
            var fixture: @This() = .{
                .pending = undefined,
                .invalid = undefined,
                .invalid_count = 0,
            };
            switch (case) {
                .valid => fixture.pending = try gpa.dupe(S.Attestation, attestations[0..quorum]),
                .split => {
                    fixture.pending = try gpa.dupe(S.Attestation, attestations[0..quorum]);
                    const chunk = std.math.divCeil(usize, quorum, 2) catch unreachable;
                    // The spare's signature is well formed but invalid for both signers.
                    const replacement = attestations[quorum].signature;
                    fixture.pending[0].signature = replacement;
                    fixture.pending[chunk].signature = replacement;
                    fixture.invalid = .{ fixture.pending[0].signer, fixture.pending[chunk].signer };
                    fixture.invalid_count = 2;
                },
                .bad, .spare => {
                    var pending = try gpa.dupe(S.Attestation, attestations);
                    // Corrupt the minimum signer so threshold recovery's quorum includes it.
                    var lowest: usize = 0;
                    for (pending, 0..) |attestation, position| {
                        const signer = attestation.signer.get();
                        if (signer < pending[lowest].signer.get()) lowest = position;
                    }
                    const invalid = pending[lowest].signer;
                    const other: usize = if (lowest == 0) 1 else 0;
                    pending[lowest].signature = pending[other].signature;
                    if (case == .bad) {
                        // Remove the last attestation from another signer.
                        var removed = pending.len - 1;
                        if (pending[removed].signer.get() == invalid.get()) removed -= 1;
                        const tail = pending[removed + 1 ..];
                        std.mem.copyForwards(S.Attestation, pending[removed..], tail);
                        pending = try gpa.realloc(pending, pending.len - 1);
                    }
                    fixture.pending = pending;
                    fixture.invalid[0] = invalid;
                    fixture.invalid_count = 1;
                },
            }
            return fixture;
        }

        fn deinit(fixture: *@This(), gpa: Allocator) void {
            gpa.free(fixture.pending);
            fixture.* = undefined;
        }

        fn is_invalid(fixture: *const @This(), signer: Participant) bool {
            for (fixture.invalid[0..fixture.invalid_count]) |item| {
                if (item.get() == signer.get()) return true;
            }
            return false;
        }
    };
}

/// Optimistic assembly, then assembly of any verified quorum retained by the fallback.
/// Returns whether a certificate came out and the invalid signer count.
fn assemble_with_fallback(
    comptime S: type,
    gpa: Allocator,
    scheme: *const S,
    rng: anytype,
    pending: []const S.Attestation,
    quorum: usize,
) !struct { bool, usize } {
    var result = try scheme.optimistic_assemble(gpa, rng, subject, pending, &.{}, sequential);
    defer result.deinit(gpa);
    const verification = switch (result) {
        .certificate => return .{ true, 0 },
        .verification => |value| value,
    };
    if (verification.verified.len < quorum) return .{ false, verification.invalid.len };
    var certificate = try scheme.assemble(gpa, verification.verified, sequential);
    base.deinit_certificate(S.Certificate, gpa, &certificate);
    return .{ true, verification.invalid.len };
}

fn AssembleWorkload(comptime S: type) type {
    return struct {
        gpa: Allocator,
        scheme: *const S,
        rng: utils.TestRng,
        pending: []const S.Attestation,
        quorum: usize,

        pub fn iter(workload: *@This()) !bool {
            const certified, _ = try assemble_with_fallback(
                S,
                workload.gpa,
                workload.scheme,
                &workload.rng,
                workload.pending,
                workload.quorum,
            );
            return certified;
        }
    };
}

/// Checks the case's outcome (commonware asserts it before timing), then benchmarks it.
fn bench_case(
    comptime S: type,
    runner: *bench.Runner,
    name: bench.Benchmark,
    scheme: *const S,
    attestations: []const S.Attestation,
    quorum: usize,
    case: Case,
) !void {
    const gpa = runner.allocator;
    if (!runner.matches(name.name())) return;
    var fixture = try Fixture(S).init(gpa, attestations, quorum, case);
    defer fixture.deinit(gpa);
    const expected_pending: usize = if (case == .spare) quorum + 1 else quorum;
    assert(fixture.pending.len == expected_pending);
    var check_rng = utils.TestRng.init(rng_seed);
    const certified, const invalid = try assemble_with_fallback(
        S,
        gpa,
        scheme,
        &check_rng,
        fixture.pending,
        quorum,
    );
    assert(certified == case.expects_certificate());
    assert(invalid == fixture.invalid_count);
    var workload: AssembleWorkload(S) = .{
        .gpa = gpa,
        .scheme = scheme,
        .rng = .init(rng_seed),
        .pending = fixture.pending,
        .quorum = quorum,
    };
    try runner.run(name, &workload);
}

const cases = [_]Case{ .valid, .bad, .spare, .split };

/// Whether to build a committee's inputs: when the filters select any of its cases.
fn any_selected(runner: *bench.Runner, names: *const [cases.len]bench.Benchmark) !bool {
    var selected = false;
    for (names) |name| {
        if (!try common.skip(runner, name)) selected = true;
    }
    return selected;
}
const committees = [_][2]u32{ .{ 100, 67 }, .{ 298, 199 } };

/// commonware's committees, and a smaller one for the (Debug) smoke run.
fn committee_cases(runner: *const bench.Runner) []const [2]u32 {
    const smoke = [_][2]u32{.{ 10, 7 }};
    return runner.inputs.pick([]const [2]u32, &smoke, &committees, &committees);
}

fn variant_name(comptime V: type) []const u8 {
    return if (V == MinPk) "MinPk" else "MinSig";
}

fn Multisig(comptime V: type) type {
    return multisig.Scheme(BenchSubject, N3f1, ed25519.PublicKey, V);
}

const multisig_namespace = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE";
const pop_namespace = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE_POP";

fn bench_multisig_variant(runner: *bench.Runner, comptime V: type) !void {
    const gpa = runner.allocator;
    const S = Multisig(V);
    const counts = committee_cases(runner);
    for (counts) |committee| {
        const n, const quorum = committee;
        assert(N3f1.quorum(n) == quorum);
        var names: [cases.len]bench.Benchmark = undefined;
        for (&names, cases) |*name, case| {
            name.* = bench.Benchmark.init("bls12381::multisig_optimistic_assemble")
                .with_param("variant", variant_name(V)).with_param("n", n)
                .with_param("case", @tagName(case));
        }
        if (!try any_selected(runner, &names)) continue;
        const pairs = try gpa.alloc(S.Participants.Pair, n);
        defer gpa.free(pairs);
        const keys = try gpa.alloc(Private, n);
        defer gpa.free(keys);
        var rng = utils.TestRng.init(n);
        for (pairs, keys, 0..) |*pair, *key, index| {
            key.* = Private.random(&rng);
            const public = ops.compute_public(V, key.*);
            const proof = ops.sign_proof_of_possession(V, key.*, pop_namespace);
            try ops.verify_proof_of_possession(V, public, pop_namespace, proof);
            pair.* = .{ ed25519.PrivateKey.from_seed(index).public_key(), public };
        }
        var participants = try S.Participants.init(gpa, pairs);
        defer participants.deinit(gpa);
        const attestations = try gpa.alloc(S.Attestation, quorum + 1);
        defer gpa.free(attestations);
        for (attestations, keys[0 .. quorum + 1]) |*attestation, key| {
            const map = try multisig.clone_participants(gpa, &participants);
            var signer = (try S.signer(gpa, multisig_namespace, map, key)).?;
            defer signer.deinit(gpa);
            attestation.* = (try signer.sign(gpa, subject)).?;
        }
        const map = try multisig.clone_participants(gpa, &participants);
        var scheme = try S.verifier(gpa, multisig_namespace, map);
        defer scheme.deinit(gpa);
        for (names, cases) |name, case| {
            try bench_case(S, runner, name, &scheme, attestations, quorum, case);
        }
    }
}

fn Threshold(comptime V: type) type {
    return threshold.Scheme(BenchSubject, N3f1, ed25519.PublicKey, V);
}

const threshold_namespace = "_COMMONWARE_CRYPTOGRAPHY_BLS12381_THRESHOLD_OPTIMISTIC_ASSEMBLE";

fn bench_threshold_case(runner: *bench.Runner, comptime V: type, mode: Mode, n: u32) !void {
    const gpa = runner.allocator;
    const S = Threshold(V);
    const quorum = N3f1.quorum(n);
    var names: [cases.len]bench.Benchmark = undefined;
    for (&names, cases) |*name, case| {
        name.* = bench.Benchmark.init("bls12381::threshold_optimistic_assemble")
            .with_param("variant", variant_name(V)).with_param("mode", common.mode_name(mode))
            .with_param("n", n).with_param("case", @tagName(case));
    }
    if (!try any_selected(runner, &names)) return;
    const publics = try gpa.alloc(ed25519.PublicKey, n);
    defer gpa.free(publics);
    for (publics, 0..) |*public, index| {
        public.* = ed25519.PrivateKey.from_seed(index).public_key();
    }
    var rng = utils.TestRng.init(n);
    const players = try S.Participants.init(gpa, publics);
    const fd = bls12381.dkg.feldman_desmedt;
    var dealt = try fd.deal(V, ed25519.PublicKey, N3f1, gpa, &rng, mode, players);
    defer dealt.deinit(gpa);
    // Sample a quorum plus a spare across the committee's interpolation points.
    const shares = try gpa.dupe(Share, dealt.shares.values);
    defer {
        for (shares) |*share| share.private.zeroize();
        gpa.free(shares);
    }
    common.shuffle(Share, &rng, shares);
    const attestations = try gpa.alloc(S.Attestation, quorum + 1);
    defer gpa.free(attestations);
    for (attestations, shares[0 .. quorum + 1]) |*attestation, share| {
        const set = try dealt.output.players.clone(gpa);
        const sharing = try dealt.output.public.clone(gpa);
        var signer = (try S.signer(gpa, threshold_namespace, set, sharing, share)).?;
        defer signer.deinit(gpa);
        attestation.* = (try signer.sign(gpa, subject)).?;
    }
    const set = try dealt.output.players.clone(gpa);
    const sharing = try dealt.output.public.clone(gpa);
    var scheme = try S.verifier(gpa, threshold_namespace, set, sharing);
    defer scheme.deinit(gpa);
    for (names, cases) |name, case| {
        try bench_case(S, runner, name, &scheme, attestations, quorum, case);
    }
}

fn bench_threshold_variant(runner: *bench.Runner, comptime V: type) !void {
    const counts = committee_cases(runner);
    for ([_]Mode{ .non_zero_counter, .roots_of_unity }) |mode| {
        for (counts) |committee| try bench_threshold_case(runner, V, mode, committee[0]);
    }
}

/// Equality of a stored (decoded) attestation and an incoming one.
const AttestationEq = struct {
    previous: Multisig(MinPk).Attestation,
    incoming: Multisig(MinPk).Attestation,

    pub fn iter(workload: *AttestationEq) bool {
        return workload.previous.eql(workload.incoming);
    }
};

fn bench_attestation_eq(runner: *bench.Runner) !void {
    var rng = utils.test_rng();
    const private = Private.random(&rng);
    const stored = ops.sign_message(MinPk, private, "namespace", "stored");
    const other = ops.sign_message(MinPk, private, "namespace", "other");
    const Attestation = Multisig(MinPk).Attestation;
    const previous = Attestation.init(.init(0), stored);
    // The stored signature was decoded when it was verified.
    assert(previous.signature.get() != null);
    const received = [_]struct { []const u8, MinPk.Signature }{
        .{ "equal", stored },
        .{ "different", other },
    };
    for (received) |item| {
        const name = bench.Benchmark.init("bls12381::attestation_eq").with_param("bytes", item[0]);
        if (try common.skip(runner, name)) continue;
        var workload: AttestationEq = .{
            .previous = previous,
            .incoming = .init(.init(0), item[1]),
        };
        try runner.run(name, &workload);
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_attestation_eq(runner);
    try bench_multisig_variant(runner, MinPk);
    try bench_multisig_variant(runner, MinSig);
    try bench_threshold_variant(runner, MinPk);
    try bench_threshold_variant(runner, MinSig);
}
