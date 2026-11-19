//! commonware `mocks/harness.rs`'s durability contracts (lines 1009-2654): a block marshal
//! acknowledged survives crashes and restarts. Generic over a scenario harness `H`, as
//! `scenarios.zig` is.
//!
//! commonware's `start_and_recover` ends a run and recovers its checkpoint. Here one runner
//! starts each run in turn: each start crashes storage first, so only synced writes survive,
//! and a run releases its validator and network before returning, as a crash would.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const harness = @import("harness.zig");
const Application = @import("application.zig").Application;

const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const num_validators = harness.num_validators;

/// commonware `contract_runner`: seeded, with a 30 s hang guard.
fn contract_config(seed: u64) runtime.deterministic.Config {
    return .{ .seed = seed, .timeout_ns = 30 * std.time.ns_per_s };
}

/// commonware `restart_cycles_for_seed`: two to four recoveries, drawn from `seed`.
pub fn restart_cycles_for_seed(seed: u64) u64 {
    var rng = utils.rng.TestRng.init(seed);
    const cycles = 2 + rng.next_u64() % 3;
    assert(cycles >= 2 and cycles <= 4);
    return cycles;
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// One validator on a fresh network inside a run, crashed together at its end.
fn Node(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const App = Application(H.ApplicationBlock);
        pub const Validator = H.Validator(App);

        network: harness.TestNetwork,
        validator: *Validator,

        /// Starts validator 0 of `fixture` under `ctx`, with an auto-acknowledging application.
        pub fn start(self: *Self, ctx: Ctx, fixture: *const H.Fixture) !void {
            const gpa = ctx.gpa();
            const participants = fixture.participants;
            self.network = try .start(gpa, ctx.io(), 1, participants, 1024 * 1024);
            errdefer self.network.stop();
            const application = try App.init(gpa, ctx.io());
            const provider: H.Provider = .init(&fixture.schemes[0]);
            const network = self.network.network;
            self.validator = try Validator.setup(
                ctx,
                network,
                participants[0],
                provider,
                1,
                application,
            );
        }

        pub fn crash(self: *Self) void {
            self.validator.crash();
            self.network.stop();
            self.* = undefined;
        }
    };
}

/// How the first run hands marshal the block.
pub const Acknowledged = enum {
    /// `propose`: persisted as the round's proposal.
    proposed,
    /// `verified`: persisted at the verify stage.
    verified,
    /// `certified`: persisted at the certify stage.
    certified,
};

/// commonware `{proposed,verified,certified}_success_implies_recoverable_after_restart`: once
/// marshal acknowledges block 1 at round 1, the block survives an immediate crash and two to
/// four recoveries. A proposed or verified block comes back from `get_verified(round)` and
/// `get_block(digest)`; a certified one from `get_block(digest)`.
pub fn SuccessRecoverable(comptime H: type, comptime acknowledged: Acknowledged) type {
    return struct {
        const State = struct {
            fixture: H.Fixture,
            block: H.TestBlock,
            seed: u64,
        };

        /// Runs the contract for each of `seeds`.
        pub fn run(gpa: Allocator, seeds: []const u64) !void {
            for (seeds) |seed| try run_seed(gpa, seed);
        }

        fn run_seed(gpa: Allocator, seed: u64) !void {
            var rng = utils.rng.TestRng.init(seed);
            var state: State = .{
                .fixture = try H.fixture(gpa, &rng),
                .block = undefined,
                .seed = seed,
            };
            defer state.fixture.deinit(gpa);
            const parent_commitment = H.genesis_parent_commitment(num_validators);
            const parent = harness.genesis_parent();
            state.block = try H.make_test_block(gpa, parent, parent_commitment, .new(1), 100, 4);
            defer H.Variant.deinit_block(gpa, &state.block);
            var runner = try runtime.deterministic.Runner.init(gpa, contract_config(seed));
            defer runner.deinit();
            try try runner.start_context(acknowledge, .{&state});
            for (0..restart_cycles_for_seed(seed)) |cycle| {
                try try runner.start_context(recover, .{ &state, cycle });
            }
        }

        fn acknowledge(ctx: Ctx, state: *const State) anyerror!void {
            var node: Node(H) = undefined;
            try node.start(ctx.child("validator").with_attribute("index", 0), &state.fixture);
            defer node.crash();
            const round = round_at(1);
            switch (acknowledged) {
                .proposed => try H.propose(node.validator, round, &state.block),
                .verified => try H.verify(node.validator, round, &state.block),
                // certify must ack.
                .certified => if (!try H.certify(node.validator, round, &state.block)) {
                    return error.CertifyNotAcknowledged;
                },
            }
        }

        fn recover(ctx: Ctx, state: *const State, cycle: usize) anyerror!void {
            const gpa = ctx.gpa();
            var node: Node(H) = undefined;
            const child = ctx.child("validator").with_attribute("index", 0)
                .with_attribute("restart", cycle);
            try node.start(child, &state.fixture);
            defer node.crash();
            const digest = H.digest(&state.block);
            const mailbox = &node.validator.mailbox;
            if (acknowledged != .certified) {
                var recovered = (try mailbox.get_verified(round_at(1))) orelse {
                    std.log.err(
                        "block lost after restart (seed={d}, cycle={d})",
                        .{ state.seed, cycle },
                    );
                    return error.BlockLost;
                };
                defer H.Variant.deinit_block(gpa, &recovered);
                if (!H.digest(&recovered).eql(digest)) return error.WrongBlockRecovered;
            }
            var block = (try mailbox.get_block(.{ .digest = digest })) orelse {
                std.log.err(
                    "get_block lost the block (seed={d}, cycle={d})",
                    .{ state.seed, cycle },
                );
                return error.BlockLost;
            };
            defer H.Variant.deinit_block(gpa, &block);
            if (!H.digest(&block).eql(digest)) return error.WrongBlockRecovered;
        }
    };
}
