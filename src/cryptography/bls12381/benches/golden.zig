//! Golden DKG benchmarks of BLS12-381 (commonware `bls12381/benches/dkg/golden.rs`): one
//! dealer dealing to `n` receivers, a receiver verifying that dealing (identify, then
//! observe), and the dealing's encoded size. The cost scales with the receivers, so one
//! dealer is enough.
//!
//! The eVRF setup alone hashes tens of thousands of points, which takes minutes in a Debug
//! build, so the Debug smoke run under `zig build test` skips these benchmarks.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");
const common = @import("common.zig");

const golden = cryptography.bls12381.dkg.golden;
const Info = golden.Info;
const Setup = golden.Setup;
const PrivateKey = golden.PrivateKey;
const PublicKey = golden.PublicKey;
const SignedDealerLog = golden.SignedDealerLog;
const Set = utils.ordered.Set;
const N3f1 = utils.N3f1;

const bench_namespace = "bench";

/// One dealer and `n` receivers.
const Round = struct {
    info: Info,
    me: PrivateKey,

    fn init(gpa: Allocator, rng: *utils.TestRng, n: u32) !Round {
        assert(n > 0);
        const me = PrivateKey.random(rng);
        var dealers = try Set(PublicKey).init(gpa, &.{me.public_key()});
        errdefer dealers.deinit(gpa);
        const publics = try gpa.alloc(PublicKey, n);
        defer gpa.free(publics);
        for (publics) |*public| public.* = PrivateKey.random(rng).public_key();
        const players = try Set(PublicKey).init(gpa, publics);
        // `Info.init` takes (and on error releases) the sets.
        const info = try Info.init(N3f1, gpa, bench_namespace, 0, null, dealers, players);
        return .{ .info = info, .me = me };
    }

    fn deinit(round: *Round, gpa: Allocator) void {
        round.info.deinit(gpa);
        round.* = undefined;
    }

    fn deal(
        round: *const Round,
        gpa: Allocator,
        setup: *const Setup,
        rng: anytype,
    ) !SignedDealerLog {
        const strategy = parallel.sequential;
        return golden.deal(gpa, rng, setup, &round.info, &round.me, null, strategy);
    }
};

const Deal = struct {
    gpa: Allocator,
    setup: *const Setup,
    round: *const Round,

    pub fn iter(workload: *Deal) !void {
        var rng = utils.test_rng();
        var signed = try workload.round.deal(workload.gpa, workload.setup, &rng);
        signed.deinit(workload.gpa);
    }
};

/// Identifies a fresh copy of the dealer's log (decoded untimed), then observes the round.
const Verify = struct {
    gpa: Allocator,
    setup: *const Setup,
    round: *const Round,
    encoded: []const u8,
    signed: ?SignedDealerLog = null,

    pub fn before_iter(workload: *Verify) !void {
        if (workload.signed) |*signed| signed.deinit(workload.gpa);
        const cfg: SignedDealerLog.Cfg = .{
            .max_players = workload.round.info.num_players(),
            .max_supported_mode = .v0,
        };
        const encoded = workload.encoded;
        workload.signed = try codec.decode_cfg(SignedDealerLog, workload.gpa, encoded, cfg);
    }

    pub fn iter(workload: *Verify) !void {
        const gpa = workload.gpa;
        const signed = workload.signed.?;
        workload.signed = null;
        const info = &workload.round.info;
        const identified = (try signed.identify(gpa, info)) orelse return error.IdentifyFailed;
        var logs = try golden.Logs.init(gpa, &.{identified});
        defer logs.deinit(gpa);
        var rng = utils.test_rng();
        var output = try golden.observe(gpa, &rng, workload.setup, info, &logs);
        output.deinit(gpa);
    }

    pub fn teardown(workload: *Verify) void {
        if (workload.signed) |*signed| signed.deinit(workload.gpa);
        workload.signed = null;
    }
};

const kinds = [_][]const u8{
    "bls12381::dkg::golden::deal",
    "bls12381::dkg::golden::verify",
    "bls12381::dkg::golden::dealing_size",
};

fn names(n: u32) [kinds.len]bench.Benchmark {
    var out: [kinds.len]bench.Benchmark = undefined;
    for (&out, kinds) |*name, kind| name.* = bench.Benchmark.init(kind).with_param("n", n);
    return out;
}

fn bench_receivers(runner: *bench.Runner, gpa: Allocator, setup: *const Setup, n: u32) !void {
    const deal_name, const verify_name, const size_name = names(n);
    const run_deal = runner.matches(deal_name.name());
    const run_verify = runner.matches(verify_name.name());
    const run_size = runner.matches(size_name.name());
    if (!run_deal and !run_verify and !run_size) return;
    var rng = utils.test_rng();
    var round = try Round.init(gpa, &rng, n);
    defer round.deinit(gpa);
    if (run_deal) {
        var workload: Deal = .{ .gpa = gpa, .setup = setup, .round = &round };
        try runner.run(deal_name, &workload);
    }
    if (!run_verify and !run_size) return;
    var signed = try round.deal(gpa, setup, &rng);
    defer signed.deinit(gpa);
    const encoded = try codec.encode(SignedDealerLog, gpa, signed);
    defer gpa.free(encoded);
    if (run_verify) {
        var workload: Verify = .{ .gpa = gpa, .setup = setup, .round = &round, .encoded = encoded };
        defer workload.teardown();
        try runner.run(verify_name, &workload);
    }
    // commonware reports the size on stdout, not as a timing.
    if (run_size) try runner.out.print("{s}: {d} B\n", .{ size_name.name(), encoded.len });
}

pub fn run(runner: *bench.Runner) !void {
    if (runner.inputs == .smoke and builtin.mode == .debug) return;
    const all = [_]u32{ 5, 10, 15, 20, 25 };
    const standard = [_]u32{ 5, 10, 25 };
    const receivers = runner.inputs.pick([]const u32, all[0..1], &standard, &all);
    var largest: u32 = 0;
    var selected = false;
    for (receivers) |n| {
        for (names(n)) |name| {
            // Lists the timed benchmarks (the size is not one), and builds nothing then.
            const timed = !std.mem.startsWith(u8, name.name(), kinds[2]);
            if (timed and !try common.skip(runner, name)) selected = true;
            if (!timed and runner.matches(name.name()) and !runner.list) selected = true;
        }
        largest = @max(largest, n);
    }
    if (!selected) return;
    // One setup, sized for the largest round, serves every case.
    var setup = try Setup.init(runner.allocator, largest);
    defer setup.deinit(runner.allocator);
    for (receivers) |n| try bench_receivers(runner, runner.allocator, &setup, n);
}
