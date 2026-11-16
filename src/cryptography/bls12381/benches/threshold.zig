//! Threshold benchmarks of BLS12-381 (commonware `bls12381/benches/{threshold_recover,
//! threshold_batch_verify_same_message[_pre], threshold_batch_verify_same_signer}.rs`).
//!
//! commonware deals a fresh sharing before every iteration, so its partial public keys are
//! computed inside the timed routine except in the `_pre` benchmark. Here the sharing is
//! dealt once and its cache of partial public keys is cleared before every iteration
//! (untimed), which times the same work.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const utils = @import("utils");

const bls12381 = cryptography.bls12381;
const primitives = bls12381.primitives;
const threshold = primitives.ops.threshold;
const sharing_mod = primitives.sharing;
const MinSig = primitives.MinSig;
const Mode = sharing_mod.Mode;
const Sharing = sharing_mod.Sharing(MinSig);
const Partial = primitives.variant.PartialSignature(MinSig);
const N3f1 = utils.N3f1;

const namespace = "benchmark";
const message = "hello";
const modes = [_]Mode{ .non_zero_counter, .roots_of_unity };

/// commonware's `{mode:?}`.
fn mode_name(mode: Mode) []const u8 {
    return switch (mode) {
        .non_zero_counter => "NonZeroCounter",
        .roots_of_unity => "RootsOfUnity",
    };
}

fn cases(runner: *const bench.Runner, all: []const u32) []const u32 {
    return runner.inputs.pick([]const u32, all[0..1], all, all);
}

/// A sharing dealt to `n` players from `test_rng()`, as commonware's `deal` draws it.
const Dealt = struct {
    sharing: Sharing,
    shares: []primitives.group.Share,
    rng: utils.TestRng,

    fn init(gpa: Allocator, mode: Mode, n: u32) !Dealt {
        var rng = utils.test_rng();
        const fd = bls12381.dkg.feldman_desmedt;
        const dealt = try fd.deal_anonymous(MinSig, N3f1, gpa, &rng, mode, n);
        return .{ .sharing = dealt.sharing, .shares = dealt.shares, .rng = rng };
    }

    fn deinit(self: *Dealt, gpa: Allocator) void {
        self.sharing.deinit(gpa);
        for (self.shares) |*share| share.private.zeroize();
        gpa.free(self.shares);
        self.* = undefined;
    }

    /// Every share's partial signature over `message`; the first `invalid` sign under the
    /// wrong namespace.
    fn sign_all(self: *const Dealt, gpa: Allocator, invalid: u32) ![]Partial {
        const partials = try gpa.alloc(Partial, self.shares.len);
        for (partials, self.shares, 0..) |*partial, share, index| {
            const ns = if (index < invalid) "wrong" else namespace;
            partial.* = threshold.sign_message(MinSig, share, ns, message);
        }
        return partials;
    }
};

const Recover = struct {
    gpa: Allocator,
    sharing: Sharing,
    partials: []const Partial,

    pub fn iter(workload: *Recover) !MinSig.Signature {
        return threshold.recover(MinSig, workload.gpa, workload.sharing, workload.partials);
    }
};

fn bench_recover(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const sizes = [_]u32{ 5, 10, 20, 50, 100, 250, 500, 1000, 2000, 4000 };
    for (modes) |mode| {
        for (cases(runner, &sizes)) |n| {
            var dealt = try Dealt.init(gpa, mode, n);
            defer dealt.deinit(gpa);
            const partials = try dealt.sign_all(gpa, 0);
            defer gpa.free(partials);
            var workload: Recover = .{ .gpa = gpa, .sharing = dealt.sharing, .partials = partials };
            const name = bench.Benchmark.init("bls12381::threshold_recover")
                .with_param("mode", mode_name(mode))
                .with_param("n", n).with_param("t", N3f1.quorum(n));
            try runner.run(name, &workload);
        }
    }
}

/// Fisher-Yates, as rand's `SliceRandom::shuffle`.
fn shuffle(rng: *utils.TestRng, items: []Partial) void {
    var index = items.len;
    while (index > 1) {
        index -= 1;
        const other = utils.rng.range_at_most(rng, usize, 0, index);
        std.mem.swap(Partial, &items[index], &items[other]);
    }
}

/// Verifies every partial over one message, shuffling them first when some are invalid.
const SameMessage = struct {
    gpa: Allocator,
    rng: utils.TestRng,
    sharing: Sharing,
    partials: []Partial,
    invalid: u32,
    precomputed: bool,

    pub fn before_iter(workload: *SameMessage) void {
        if (!workload.precomputed) @memset(workload.sharing.evals, null);
    }

    pub fn iter(workload: *SameMessage) !usize {
        if (workload.invalid > 0) shuffle(&workload.rng, workload.partials);
        const invalid = try threshold.batch_verify_same_message(
            MinSig,
            workload.gpa,
            &workload.rng,
            workload.sharing,
            namespace,
            message,
            workload.partials,
        );
        defer workload.gpa.free(invalid);
        assert(invalid.len == workload.invalid);
        return invalid.len;
    }
};

fn bench_same_message(runner: *bench.Runner, precomputed: bool) !void {
    const gpa = runner.allocator;
    const prefix = if (precomputed)
        "bls12381::threshold_batch_verify_same_message_pre"
    else
        "bls12381::threshold_batch_verify_same_message";
    for (modes) |mode| {
        for (cases(runner, &.{ 5, 10, 20, 50, 100, 250, 500 })) |n| {
            const t = N3f1.quorum(n);
            for ([_]u32{ 0, n - t }) |invalid| {
                var dealt = try Dealt.init(gpa, mode, n);
                defer dealt.deinit(gpa);
                if (precomputed) dealt.sharing.precompute_partial_publics();
                const partials = try dealt.sign_all(gpa, invalid);
                defer gpa.free(partials);
                var workload: SameMessage = .{
                    .gpa = gpa,
                    .rng = dealt.rng,
                    .sharing = dealt.sharing,
                    .partials = partials,
                    .invalid = invalid,
                    .precomputed = precomputed,
                };
                const name = bench.Benchmark.init(prefix)
                    .with_param("n", n).with_param("t", t).with_param("invalid", invalid)
                    .with_param("conc", 1).with_param("mode", mode_name(mode));
                try runner.run(name, &workload);
            }
        }
    }
}

const SameSigner = struct {
    gpa: Allocator,
    rng: utils.TestRng,
    sharing: Sharing,
    index: utils.Participant,
    entries: []const threshold.SignerEntry(MinSig),

    pub fn before_iter(workload: *SameSigner) void {
        @memset(workload.sharing.evals, null);
    }

    pub fn iter(workload: *SameSigner) !void {
        try threshold.batch_verify_same_signer(
            MinSig,
            workload.gpa,
            &workload.rng,
            workload.sharing,
            workload.index,
            workload.entries,
        );
    }
};

fn bench_same_signer(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    for (modes) |mode| {
        for (cases(runner, &.{ 5, 10, 20, 50, 100, 250, 500 })) |n| {
            for ([_]u32{ 10, 100 }) |count| {
                var dealt = try Dealt.init(gpa, mode, n);
                defer dealt.deinit(gpa);
                const signer = dealt.shares[0];
                const messages = try gpa.alloc([32]u8, count);
                defer gpa.free(messages);
                const entries = try gpa.alloc(threshold.SignerEntry(MinSig), count);
                defer gpa.free(entries);
                for (messages, entries) |*bytes, *entry| {
                    dealt.rng.fill_bytes(bytes);
                    entry.* = .{
                        .namespace = namespace,
                        .message = bytes,
                        .partial = threshold.sign_message(MinSig, signer, namespace, bytes),
                    };
                }
                var workload: SameSigner = .{
                    .gpa = gpa,
                    .rng = dealt.rng,
                    .sharing = dealt.sharing,
                    .index = signer.index,
                    .entries = entries,
                };
                const name = bench.Benchmark.init("bls12381::threshold_batch_verify_same_signer")
                    .with_param("n", n).with_param("t", N3f1.quorum(n))
                    .with_param("msgs", count).with_param("conc", 1)
                    .with_param("mode", mode_name(mode));
                try runner.run(name, &workload);
            }
        }
    }
}

pub fn run(runner: *bench.Runner) !void {
    try bench_recover(runner);
    try bench_same_message(runner, false);
    try bench_same_message(runner, true);
    try bench_same_signer(runner);
}
