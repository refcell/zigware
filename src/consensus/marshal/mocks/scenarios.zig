//! commonware `mocks/harness.rs`'s scenario functions, generic over a harness `H`
//! (`harness.StandardHarness`, or the coding variant's harness).
//!
//! Besides the decls `harness.zig` lists, a scenario harness declares `finalize_timeout_s` and
//! its signing setup: `Fixture`, `fixture(gpa, rng)`, `Provider`, `make_finalization`, and
//! `make_notarization` over its commitment. A harness whose verification needs every validator
//! (commonware's `all_handles`) declares `verify_among(validator, round, block, nodes)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const p2p = @import("p2p");
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

/// A uniform draw from the runtime's randomness (recorded by its auditor).
fn random_u64(ctx: Ctx) u64 {
    var bytes: [8]u8 = undefined;
    ctx.io().random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

/// True with probability `probability`.
fn random_bool(ctx: Ctx, probability: f64) bool {
    assert(probability >= 0 and probability <= 1);
    const unit = @as(f64, @floatFromInt(random_u64(ctx) >> 11)) / (1 << 53);
    return unit < probability;
}

/// Fisher-Yates over the runtime's randomness.
fn shuffle(ctx: Ctx, comptime T: type, items: []T) void {
    var index = items.len;
    while (index > 1) {
        index -= 1;
        const other: usize = @intCast(random_u64(ctx) % (index + 1));
        std.mem.swap(T, &items[index], &items[other]);
    }
}

/// Validators on a simulated network, each with its own application, crashed together.
pub fn Cluster(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const App = Application(H.ApplicationBlock);
        pub const Validator = H.Validator(App);

        validators: H.Fixture,
        network: harness.TestNetwork,
        apps: [num_validators]App,
        nodes: [num_validators]*Validator,
        started: usize,

        /// Starts every validator, then links them all with `link`. Must not move afterwards.
        pub fn start(self: *Self, ctx: Ctx, link: p2p.simulated.Link) !void {
            const gpa = ctx.gpa();
            var rng = utils.rng.test_rng();
            self.validators = try H.fixture(gpa, &rng);
            errdefer self.validators.deinit(gpa);
            const participants = self.validators.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 3, participants, max_size);
            errdefer self.network.stop();
            self.started = 0;
            errdefer self.stop_nodes();
            for (&self.apps, &self.nodes, participants, 0..) |*app, *node, me, index| {
                app.* = try .init(gpa, ctx.io());
                errdefer app.deinit();
                const node_ctx = ctx.child("validator").with_attribute("index", index);
                const provider: H.Provider = .init(&self.validators.schemes[index]);
                const network = self.network.network;
                node.* = try Validator.setup(node_ctx, network, me, provider, 1, app.clone());
                self.started += 1;
            }
            try self.network.link_all(participants, link);
            assert(self.started == num_validators);
        }

        fn stop_nodes(self: *Self) void {
            for (self.nodes[0..self.started], self.apps[0..self.started]) |node, *app| {
                node.crash();
                app.deinit();
            }
            self.started = 0;
        }

        /// Crashes every validator, then stops the network under them.
        pub fn stop(self: *Self, gpa: Allocator) void {
            self.stop_nodes();
            self.network.stop();
            self.validators.deinit(gpa);
            self.* = undefined;
        }

        /// Whether every application holds `count` blocks and a tip at `tip` or above.
        pub fn delivered(self: *const Self, count: usize, tip: u64) bool {
            for (self.apps) |app| {
                if (app.block_count() != count) return false;
                const current = app.tip() orelse return false;
                if (current.height.get() < tip) return false;
            }
            return true;
        }

        /// Verifies `block` at `node` (borrowed), through `verify_among` when `H` has it.
        pub fn verify(
            self: *Self,
            node: *Validator,
            round: Round,
            block: *const H.TestBlock,
        ) !void {
            if (@hasDecl(H, "verify_among")) return H.verify_among(node, round, block, &self.nodes);
            return H.verify(node, round, block);
        }
    };
}

/// Chain heights 1 through `harness.num_blocks` (owned; free with `free_chain`).
fn make_chain(comptime H: type, gpa: Allocator) ![]H.TestBlock {
    const blocks = try gpa.alloc(H.TestBlock, harness.num_blocks);
    errdefer gpa.free(blocks);
    var made: usize = 0;
    errdefer for (blocks[0..made]) |*block| H.Variant.deinit_block(gpa, block);
    var parent = harness.genesis_parent();
    var parent_commitment = H.genesis_parent_commitment(num_validators);
    for (blocks, 1..) |*block, value| {
        const height: Height = .new(value);
        block.* = try H.make_test_block(gpa, parent, parent_commitment, height, value, 4);
        made += 1;
        parent = H.digest(block);
        parent_commitment = H.commitment(block);
    }
    assert(made == blocks.len);
    return blocks;
}

fn free_chain(comptime H: type, gpa: Allocator, blocks: []H.TestBlock) void {
    for (blocks) |*block| H.Variant.deinit_block(gpa, block);
    gpa.free(blocks);
}

/// commonware `finalize`: validators linked by `link` receive every block, proposed and
/// verified at one validator in shuffled order, notarized there, and finalized at a random
/// subset (always at an epoch's last height and the chain's end), until every application
/// holds the whole chain. Returns the runtime's audit state, for determinism checks.
pub fn Finalize(comptime H: type) type {
    return struct {
        const C = Cluster(H);
        const Proposal = simplex_types.Proposal(H.Commitment);
        const Options = struct { link: p2p.simulated.Link, quorum_sees_finalization: bool };

        pub fn run(
            gpa: Allocator,
            seed: u64,
            link: p2p.simulated.Link,
            quorum_sees_finalization: bool,
        ) ![8]u8 {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .seed = seed,
                .timeout_ns = H.finalize_timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            const options: Options = .{
                .link = link,
                .quorum_sees_finalization = quorum_sees_finalization,
            };
            try try runner.start_context(body, .{options});
            return runner.auditor.state();
        }

        fn body(ctx: Ctx, options: Options) anyerror!void {
            const gpa = ctx.gpa();
            var cluster: C = undefined;
            try cluster.start(ctx, options.link);
            defer cluster.stop(gpa);
            const blocks = try make_chain(H, gpa);
            defer free_chain(H, gpa, blocks);
            shuffle(ctx, H.TestBlock, blocks);
            for (blocks) |*block| try drive(ctx, &cluster, block, options);
            while (!cluster.delivered(harness.num_blocks + 1, harness.num_blocks)) {
                try ctx.sleep(.fromSeconds(1));
            }
        }

        /// Proposes, verifies, notarizes, and maybe finalizes `block` (borrowed).
        fn drive(ctx: Ctx, cluster: *C, block: *const H.TestBlock, options: Options) !void {
            const gpa = ctx.gpa();
            const height = H.height(block);
            assert(!height.is_zero()); // Genesis is never proposed.
            const epoch_length = utils.NonZero(u64).init(harness.blocks_per_epoch).?;
            const epocher = types.FixedEpocher.new(epoch_length);
            const bounds = epocher.containing(height).?;
            const round: Round = .new(bounds.epoch, .new(height.get()));
            const proposer = cluster.nodes[height.get() % num_validators];
            try H.propose(proposer, round, block);
            try cluster.verify(proposer, round, block);
            try ctx.sleep(.fromNanoseconds(@intCast(options.link.latency.as_nanos())));

            const proposal = Proposal.init(round, .new(height.get() - 1), H.commitment(block));
            const validators = &cluster.validators;
            var notarization = try H.make_notarization(gpa, validators, proposal, harness.quorum);
            defer notarization.deinit(gpa);
            _ = proposer.mailbox.report(.{ .notarization = notarization });
            var finalization = try H.make_finalization(gpa, validators, proposal, harness.quorum);
            defer finalization.deinit(gpa);
            const always = height.get() == harness.num_blocks or height.get() == bounds.last.get();
            var order: [num_validators]usize = undefined;
            for (&order, 0..) |*slot, index| slot.* = index;
            if (options.quorum_sees_finalization) {
                const do_finalize = random_bool(ctx, 0.2);
                shuffle(ctx, usize, &order);
                for (order, 0..) |index, position| {
                    if (!((do_finalize and position < harness.quorum) or always)) continue;
                    _ = cluster.nodes[index].mailbox.report(.{ .finalization = finalization });
                }
            } else {
                for (order) |index| {
                    if (!(random_bool(ctx, 0.2) or always)) continue;
                    _ = cluster.nodes[index].mailbox.report(.{ .finalization = finalization });
                }
            }
        }
    };
}
