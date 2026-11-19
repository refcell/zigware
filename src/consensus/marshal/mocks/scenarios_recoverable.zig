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
const simplex_types = @import("../../simplex/types.zig");
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

/// Runs `body(ctx, fixture)` once under a 60 s hang guard (commonware `Runner::timed(60s)`),
/// with validator 0's fixture from the shared test seed.
fn run_timed(gpa: Allocator, comptime H: type, comptime body: anytype) !void {
    var rng = utils.rng.test_rng();
    var fixture = try H.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const config: runtime.deterministic.Config = .{ .timeout_ns = 60 * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
    defer runner.deinit();
    try try runner.start_context(body, .{&fixture});
}

/// Whether `get_block(digest)` finds the block at `validator`.
fn has_block(comptime H: type, validator: anytype, digest: anytype) !bool {
    var block = (try validator.mailbox.get_block(.{ .digest = digest })) orelse return false;
    defer H.Variant.deinit_block(validator.gpa, &block);
    if (!H.digest(&block).eql(digest)) return error.WrongBlock;
    return true;
}

/// commonware `certify_at_later_view_survives_earlier_view_pruning`: a block verified at view 1
/// and certified at view 25 survives retention pruning of view 1, while a verify-only block at
/// view 2 (the negative control) is pruned.
pub fn LaterViewSurvivesPruning(comptime H: type) type {
    return struct {
        const chain_len = 21;

        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, H, body);
        }

        fn body(ctx: Ctx, fixture: *const H.Fixture) anyerror!void {
            const gpa = ctx.gpa();
            var node: Node(H) = undefined;
            try node.start(ctx.child("validator").with_attribute("index", 0), fixture);
            defer node.crash();
            const validator = node.validator;
            const commitment = H.genesis_parent_commitment(num_validators);
            // Heights well beyond the chain below keep both blocks out of the finalized
            // archive, so they live only in the prunable caches.
            var repeated = try H.make_test_block(
                gpa,
                harness.genesis_parent(),
                commitment,
                .new(5_000),
                9_999,
                4,
            );
            defer H.Variant.deinit_block(gpa, &repeated);
            const orphan_parent = harness.Sha256.hash(&.{"orphan"});
            var orphan = try H.make_test_block(
                gpa,
                orphan_parent,
                commitment,
                .new(6_000),
                9_998,
                4,
            );
            defer H.Variant.deinit_block(gpa, &orphan);
            // Verify `repeated` at view 1, then certify it at view 25 (a re-proposal gap).
            try H.verify(validator, round_at(1), &repeated);
            const certified = try H.certify(validator, round_at(25), &repeated);
            if (!certified) return error.CertifyNotAcknowledged;
            // The negative control: verified only, at its own view 2.
            try H.verify(validator, round_at(2), &orphan);
            if (!try has_block(H, validator, H.digest(&orphan))) return error.ControlMissing;
            try drive_chain(ctx, fixture, validator);
            // Retention pruned views 1 and 2: the orphan is gone.
            if (try has_block(H, validator, H.digest(&orphan))) return error.OrphanNotPruned;
            // The certified copy at view 25 still holds the repeated block.
            if (!try has_block(H, validator, H.digest(&repeated))) return error.CertifiedBlockLost;
        }

        /// Finalizes heights 1 through `chain_len` at views 3 onward, which moves the processed
        /// round past view 2's retention boundary (view retention 10, sections of 10) but not
        /// past view 25's, and waits for the application to reach the tip.
        fn drive_chain(ctx: Ctx, fixture: *const H.Fixture, validator: anytype) !void {
            const gpa = ctx.gpa();
            const Proposal = simplex_types.Proposal(H.Commitment);
            var parent = harness.genesis_parent();
            var parent_commitment = H.genesis_parent_commitment(num_validators);
            for (1..chain_len + 1) |i| {
                var block = try H.make_test_block(gpa, parent, parent_commitment, .new(i), i, 4);
                defer H.Variant.deinit_block(gpa, &block);
                const round = round_at(i + 2);
                try H.propose(validator, round, &block);
                const proposal = Proposal.init(round, .new(i), H.commitment(&block));
                var finalization = try H.make_finalization(gpa, fixture, proposal, harness.quorum);
                defer finalization.deinit(gpa);
                _ = validator.mailbox.report(.{ .finalization = finalization });
                parent = H.digest(&block);
                parent_commitment = H.commitment(&block);
            }
            while (true) {
                const tip = validator.application.tip();
                if (tip != null and tip.?.height.get() == chain_len) break;
                try ctx.sleep(.fromMilliseconds(10));
            }
            try ctx.sleep(.fromMilliseconds(100));
        }
    };
}

/// commonware `certify_persists_equivocated_block`: after an equivocating leader's block A is
/// verified and its block B certified at the same round, both stay retrievable.
pub fn CertifyPersistsEquivocated(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, H, body);
        }

        fn body(ctx: Ctx, fixture: *const H.Fixture) anyerror!void {
            const gpa = ctx.gpa();
            var node: Node(H) = undefined;
            try node.start(ctx.child("validator").with_attribute("index", 0), fixture);
            defer node.crash();
            const validator = node.validator;
            const round = round_at(1);
            const parent = harness.genesis_parent();
            const commitment = H.genesis_parent_commitment(num_validators);
            // Distinct timestamps give the two blocks at one height distinct digests.
            var block_a = try H.make_test_block(gpa, parent, commitment, .new(1), 1, 4);
            defer H.Variant.deinit_block(gpa, &block_a);
            var block_b = try H.make_test_block(gpa, parent, commitment, .new(1), 2, 4);
            defer H.Variant.deinit_block(gpa, &block_b);
            assert(!H.digest(&block_a).eql(H.digest(&block_b)));
            try H.verify(validator, round, &block_a);
            if (!try H.certify(validator, round, &block_b)) return error.CertifyNotAcknowledged;
            // A stays in the verified archive, and B persists despite the same-round verify.
            if (!try has_block(H, validator, H.digest(&block_a))) return error.VerifiedBlockLost;
            if (!try has_block(H, validator, H.digest(&block_b))) return error.CertifiedBlockLost;
        }
    };
}
