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
const soak = @import("soak.zig");

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

/// A uniform draw from `[low, high]`.
fn random_range(ctx: Ctx, low: u64, high: u64) u64 {
    assert(low <= high);
    return low + random_u64(ctx) % (high - low + 1);
}

/// commonware `hailstorm`: a canonical finalized chain keeps advancing while `shutdowns`
/// rounds each crash up to `max_down` validators (sometimes between a height's verify and its
/// finalization), advance further, and restart them. Every restarted validator recovers the
/// height it had persisted and catches up, and every live one matches the canonical chain.
/// Returns the runtime's audit state, for determinism checks.
pub fn Hailstorm(comptime H: type) type {
    return struct {
        const Self = @This();
        const App = Application(H.ApplicationBlock);
        const Validator = H.Validator(App);
        const Proposal = simplex_types.Proposal(H.Commitment);
        pub const Options = struct {
            shutdowns: u32,
            interval: u64,
            max_down: u32,
            link: p2p.simulated.Link,
        };
        const Live = struct { app: App, node: *Validator };
        const Entry = struct { height: Height, digest: harness.D, finalization: H.Finalization };
        /// A height proposed and verified whose finalization is not yet reported.
        const Pending = struct {
            height: Height,
            digest: harness.D,
            commitment: H.Commitment,
            finalization: H.Finalization,
        };

        ctx: Ctx,
        gpa: Allocator,
        fixture: H.Fixture,
        network: harness.TestNetwork,
        live: [num_validators]?Live,
        canonical: std.ArrayList(Entry),
        parent: harness.D,
        parent_commitment: H.Commitment,

        pub fn run(gpa: Allocator, seed: u64, options: Options) ![8]u8 {
            var runner = try runtime.deterministic.Runner.init(gpa, .{
                .seed = seed,
                .timeout_ns = H.finalize_timeout_s * std.time.ns_per_s,
            });
            defer runner.deinit();
            try try runner.start_context(body, .{options});
            return runner.auditor.state();
        }

        fn body(ctx: Ctx, options: Options) anyerror!void {
            var self: Self = undefined;
            try self.start(ctx, options.link);
            defer self.stop();
            var target: u64 = 0;
            const interval = @max(options.interval, 1);
            for (0..options.shutdowns) |shutdown| {
                const leadup = random_range(ctx, 1, interval);
                target += leadup;
                var down_buffer: [num_validators]usize = undefined;
                const down = self.select_down(&down_buffer, @max(options.max_down, 1));
                const crash_after = random_range(ctx, 0, leadup);
                const persisted = target - leadup + crash_after;
                try self.advance_to(persisted);
                try self.crash_mid_advance(down, persisted, target);
                target += random_range(ctx, 1, interval);
                try self.advance_to(target);
                try self.restart(down, persisted, @intCast(shutdown));
                try self.expect_all_match();
            }
        }

        fn start(self: *Self, ctx: Ctx, link: p2p.simulated.Link) !void {
            const gpa = ctx.gpa();
            self.ctx = ctx;
            self.gpa = gpa;
            var rng = utils.rng.test_rng();
            self.fixture = try H.fixture(gpa, &rng);
            errdefer self.fixture.deinit(gpa);
            const participants = self.fixture.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 3, participants, max_size);
            errdefer self.network.stop();
            try self.network.link_all(participants, link);
            self.live = @splat(null);
            self.canonical = .empty;
            errdefer self.stop_nodes();
            for (0..num_validators) |index| {
                const node_ctx = ctx.child("validator").with_attribute("index", index);
                try self.start_node(node_ctx, index);
            }
            self.parent = harness.genesis_parent();
            self.parent_commitment = H.genesis_parent_commitment(num_validators);
        }

        fn start_node(self: *Self, ctx: Ctx, index: usize) !void {
            assert(self.live[index] == null);
            var app: App = try .init(self.gpa, ctx.io());
            errdefer app.deinit();
            const provider: H.Provider = .init(&self.fixture.schemes[index]);
            const me = self.fixture.participants[index];
            const network = self.network.network;
            const node = try Validator.setup(ctx, network, me, provider, 1, app.clone());
            self.live[index] = .{ .app = app, .node = node };
        }

        fn crash_node(self: *Self, index: usize) void {
            var live = self.live[index].?;
            live.node.crash();
            live.app.deinit();
            self.live[index] = null;
        }

        fn stop_nodes(self: *Self) void {
            for (0..num_validators) |index| if (self.live[index] != null) self.crash_node(index);
            for (self.canonical.items) |*entry| entry.finalization.deinit(self.gpa);
            self.canonical.deinit(self.gpa);
        }

        fn stop(self: *Self) void {
            self.stop_nodes();
            self.network.stop();
            self.fixture.deinit(self.gpa);
            self.* = undefined;
        }

        /// The live validators' indices, ascending.
        fn active(self: *const Self, out: *[num_validators]usize) []usize {
            var count: usize = 0;
            for (self.live, 0..) |live, index| if (live != null) {
                out[count] = index;
                count += 1;
            };
            return out[0..count];
        }

        /// Between one and `max_down` live validators to crash, keeping one up; ascending.
        fn select_down(self: *Self, out: *[num_validators]usize, max_down: u32) []usize {
            const live = self.active(out);
            assert(live.len > 1);
            const limit = @min(max_down, live.len - 1);
            const count: usize = @intCast(random_range(self.ctx, 1, limit));
            shuffle(self.ctx, usize, live);
            std.mem.sort(usize, live[0..count], {}, std.sort.asc(usize));
            return live[0..count];
        }

        /// Proposes `height` at a random live validator, notarizes it there, and verifies it
        /// at up to a quorum of live validators, without finalizing it.
        fn drive_up_to_verify(self: *Self, value: u64) !Pending {
            const gpa = self.gpa;
            const height: Height = .new(value);
            var buffer: [num_validators]usize = undefined;
            const live = self.active(&buffer);
            shuffle(self.ctx, usize, live);
            const parent, const parent_commitment = .{ self.parent, self.parent_commitment };
            var block = try H.make_test_block(gpa, parent, parent_commitment, height, value, 4);
            defer H.Variant.deinit_block(gpa, &block);
            const epoch_length = utils.NonZero(u64).init(harness.blocks_per_epoch).?;
            const epocher = types.FixedEpocher.new(epoch_length);
            const round: Round = .new(epocher.containing(height).?.epoch, .new(value));
            const proposal = Proposal.init(round, .new(value - 1), H.commitment(&block));
            const proposer = self.live[live[0]].?.node;
            try H.propose(proposer, round, &block);
            const quorum = harness.quorum;
            var notarization = try H.make_notarization(gpa, &self.fixture, proposal, quorum);
            defer notarization.deinit(gpa);
            _ = proposer.mailbox.report(.{ .notarization = notarization });
            // The proposer plus quorum - 1 others (commonware's verifier count includes it).
            const verifiers = @min(quorum, live.len);
            for (live[1..verifiers]) |index| try H.verify(self.live[index].?.node, round, &block);
            return .{
                .height = height,
                .digest = H.digest(&block),
                .commitment = H.commitment(&block),
                .finalization = try H.make_finalization(gpa, &self.fixture, proposal, quorum),
            };
        }

        /// Reports `pending` (taken) to every live validator, appends it to the canonical
        /// chain, and waits until each live validator holds it.
        fn finalize_pending(self: *Self, pending: Pending) !void {
            var owned = pending;
            errdefer owned.finalization.deinit(self.gpa);
            for (self.live) |live| if (live) |value| {
                _ = value.node.mailbox.report(.{ .finalization = owned.finalization });
            };
            try self.canonical.append(self.gpa, .{
                .height = owned.height,
                .digest = owned.digest,
                .finalization = owned.finalization,
            });
            self.parent = owned.digest;
            self.parent_commitment = owned.commitment;
            const entry = self.canonical.items[self.canonical.items.len - 1];
            for (self.live) |live| if (live) |value| try self.wait_height(value.node, entry);
        }

        fn advance_to(self: *Self, target: u64) !void {
            var value: u64 = self.canonical.items.len + 1;
            while (value <= target) : (value += 1) {
                try self.finalize_pending(try self.drive_up_to_verify(value));
            }
            try self.expect_all_match();
        }

        /// Crashes `down` after driving the next height through verify (when it is still
        /// below `target`), then finalizes that height at the survivors.
        fn crash_mid_advance(self: *Self, down: []const usize, persisted: u64, target: u64) !void {
            const pending: ?Pending = if (persisted < target)
                try self.drive_up_to_verify(persisted + 1)
            else
                null;
            for (down) |index| self.crash_node(index);
            if (pending) |value| try self.finalize_pending(value);
        }

        /// Restarts `down`: each recovers `persisted`, replays the later finalizations, and
        /// catches up to the whole canonical chain.
        fn restart(self: *Self, down: []const usize, persisted: u64, shutdown: u32) !void {
            for (down) |index| {
                const node_ctx = self.ctx.child("validator")
                    .with_attribute("index", index)
                    .with_attribute("restart", shutdown);
                try self.start_node(node_ctx, index);
                const node = self.live[index].?.node;
                const recovered = node.height orelse return error.HailstormHeightMissing;
                if (recovered.get() != persisted) return error.HailstormRecoveredWrongHeight;
                for (self.canonical.items[@intCast(persisted)..]) |entry| {
                    _ = node.mailbox.report(.{ .finalization = entry.finalization });
                }
            }
            for (down) |index| {
                const node = self.live[index].?.node;
                for (self.canonical.items) |entry| try self.wait_height(node, entry);
            }
        }

        /// Polls `node` until it stores `entry`'s block and finalization, then checks them.
        fn wait_height(self: *Self, node: *Validator, entry: Entry) !void {
            while (true) {
                if (try self.stored_matches(node, entry)) return;
                try self.ctx.sleep(.fromMilliseconds(10));
            }
        }

        /// Whether `node` stores `entry`'s block and finalization (an error when they differ).
        fn stored_matches(self: *Self, node: *Validator, entry: Entry) !bool {
            var block = try node.mailbox.get_block(.{ .height = entry.height }) orelse return false;
            defer H.Variant.deinit_block(self.gpa, &block);
            var finalization = try node.mailbox.get_finalization(entry.height) orelse return false;
            defer finalization.deinit(self.gpa);
            if (!std.meta.eql(block.digest(), entry.digest)) return error.HailstormWrongBlock;
            const expected = &entry.finalization;
            if (!std.meta.eql(finalization.round(), expected.round())) {
                return error.HailstormWrongFinalizationRound;
            }
            if (!std.meta.eql(finalization.proposal.payload, expected.proposal.payload)) {
                return error.HailstormWrongFinalizationPayload;
            }
            return true;
        }

        fn expect_all_match(self: *Self) !void {
            for (self.live) |live| if (live) |value| try self.expect_matches(value);
        }

        /// The application saw only canonical blocks and the canonical tip, and the actor
        /// stores the whole chain with the canonical tip as its latest.
        fn expect_matches(self: *Self, live: Live) !void {
            var genesis = try H.genesis_block(self.gpa, num_validators);
            const genesis_digest = H.digest(&genesis);
            H.Variant.deinit_block(self.gpa, &genesis);
            const delivered = try live.app.blocks(self.gpa);
            defer App.free_blocks(self.gpa, delivered);
            for (delivered) |entry| {
                const expected = self.canonical_digest(entry.height, genesis_digest) orelse
                    return error.HailstormUnexpectedDelivery;
                if (!std.meta.eql(entry.block.digest(), expected)) {
                    return error.HailstormWrongDelivery;
                }
            }
            const tip_height, const tip_digest = if (self.canonical.items.len == 0)
                .{ Height.zero(), genesis_digest }
            else
                .{ self.canonical.getLast().height, self.canonical.getLast().digest };
            if (live.app.tip()) |tip| {
                if (tip.height.get() != tip_height.get()) return error.HailstormWrongTip;
                if (!std.meta.eql(tip.digest, tip_digest)) return error.HailstormWrongTip;
            }
            for (self.canonical.items) |entry| {
                if (!try self.stored_matches(live.node, entry)) return error.HailstormMissing;
            }
            if (self.canonical.items.len == 0) return;
            const latest = try live.node.mailbox.get_info(.latest);
            const info = latest orelse return error.HailstormNoLatest;
            if (info.height.get() != tip_height.get()) return error.HailstormWrongLatest;
            if (!std.meta.eql(info.digest, tip_digest)) return error.HailstormWrongLatest;
        }

        fn canonical_digest(self: *const Self, height: Height, genesis: harness.D) ?harness.D {
            if (height.is_zero()) return genesis;
            const index: usize = @intCast(height.get() - 1);
            if (index >= self.canonical.items.len) return null;
            assert(self.canonical.items[index].height.get() == height.get());
            return self.canonical.items[index].digest;
        }
    };
}

/// commonware `ack_pipeline_backlog` and `ack_pipeline_backlog_persists_on_restart`: one
/// validator with three pending acknowledgements and a manually acknowledging application.
pub fn AckPipeline(comptime H: type) type {
    return struct {
        const Self = @This();
        const App = Application(H.ApplicationBlock);
        const Validator = H.Validator(App);
        const Proposal = simplex_types.Proposal(H.Commitment);
        const max_pending_acks = 3;

        ctx: Ctx,
        gpa: Allocator,
        fixture: H.Fixture,
        network: harness.TestNetwork,
        app: App,
        node: *Validator,

        /// Five finalized blocks fill the pipeline to three before any ack; releasing acks in
        /// FIFO order lets the rest dispatch.
        pub fn backlog(gpa: Allocator) !void {
            try run_seeded(gpa, 0xA11CE, backlog_body);
        }

        /// Three acks released without yielding are drained together and their processed
        /// height survives a restart.
        pub fn persists_on_restart(gpa: Allocator) !void {
            try run_seeded(gpa, 0xA11CF, restart_body);
        }

        fn run_seeded(gpa: Allocator, seed: u64, comptime body: fn (Ctx) anyerror!void) !void {
            try soak.run(gpa, .{
                .seed = seed,
                .timeout_ns = 120 * std.time.ns_per_s,
            }, body, .{});
        }

        fn start(self: *Self, ctx: Ctx) !void {
            const gpa = ctx.gpa();
            self.ctx = ctx;
            self.gpa = gpa;
            var rng = utils.rng.test_rng();
            self.fixture = try H.fixture(gpa, &rng);
            errdefer self.fixture.deinit(gpa);
            const participants = self.fixture.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 1, participants, max_size);
            errdefer self.network.stop();
            self.app = try .manual_ack(gpa, ctx.io());
            errdefer self.app.deinit();
            const node_ctx = ctx.child("validator").with_attribute("index", 0);
            self.node = try self.setup(node_ctx, self.app.clone());
            assert((try self.app.acknowledged()).is_zero());
        }

        fn setup(self: *Self, ctx: Ctx, app: App) !*Validator {
            const provider: H.Provider = .init(&self.fixture.schemes[0]);
            const me = self.fixture.participants[0];
            const network = self.network.network;
            return Validator.setup(ctx, network, me, provider, max_pending_acks, app);
        }

        fn stop(self: *Self) void {
            self.node.crash();
            self.app.deinit();
            self.network.stop();
            self.fixture.deinit(self.gpa);
            self.* = undefined;
        }

        /// Verifies and finalizes the chain's heights 1 through `count` at the validator.
        fn finalize_chain(self: *Self, count: u64) !void {
            const gpa = self.gpa;
            const epoch_length = utils.NonZero(u64).init(harness.blocks_per_epoch).?;
            const epocher = types.FixedEpocher.new(epoch_length);
            var parent = harness.genesis_parent();
            var parent_commitment = H.genesis_parent_commitment(num_validators);
            for (1..count + 1) |value| {
                const height: Height = .new(value);
                var block = try H.make_test_block(gpa, parent, parent_commitment, height, value, 4);
                defer H.Variant.deinit_block(gpa, &block);
                parent = H.digest(&block);
                parent_commitment = H.commitment(&block);
                const round: Round = .new(epocher.containing(height).?.epoch, .new(value));
                try H.verify(self.node, round, &block);
                const proposal = Proposal.init(round, .new(value - 1), parent_commitment);
                const quorum = harness.quorum;
                var finalization = try H.make_finalization(gpa, &self.fixture, proposal, quorum);
                defer finalization.deinit(gpa);
                _ = self.node.mailbox.report(.{ .finalization = finalization });
            }
        }

        fn pending_heights(self: *Self, out: []u64) ![]u64 {
            const pending = try self.app.pending_ack_heights(self.gpa);
            defer self.gpa.free(pending);
            const count = @min(pending.len, out.len);
            for (pending[0..count], out[0..count]) |height, *slot| slot.* = height.get();
            return out[0..pending.len];
        }

        /// Waits until the application holds `blocks` blocks and `pending` pending acks.
        fn wait_for(self: *Self, blocks: usize, pending: usize) !void {
            while (true) {
                var buffer: [8]u64 = undefined;
                const heights = try self.pending_heights(&buffer);
                const done = self.app.block_count() >= blocks and heights.len >= pending;
                if (done and (pending > 0 or heights.len == 0)) return;
                try self.ctx.sleep(.fromMilliseconds(10));
            }
        }

        fn expect_pending_one_to_three(self: *Self) !void {
            var buffer: [8]u64 = undefined;
            const heights = try self.pending_heights(&buffer);
            if (!std.mem.eql(u64, heights, &.{ 1, 2, 3 })) return error.AckPipelineWrongPending;
        }

        fn backlog_body(ctx: Ctx) anyerror!void {
            var self: Self = undefined;
            try self.start(ctx);
            defer self.stop();
            try self.finalize_chain(5);
            // The backlog fills to its capacity before any ack is released.
            try self.wait_for(3, 3);
            try self.expect_pending_one_to_three();
            if (self.app.contains(.new(4))) return error.AckPipelineDispatchedPastCapacity;
            if (self.app.contains(.new(5))) return error.AckPipelineDispatchedPastCapacity;
            // Releasing acks keeps FIFO order and lets further blocks dispatch.
            for (1..6) |expected| {
                while (true) {
                    var buffer: [8]u64 = undefined;
                    const heights = try self.pending_heights(&buffer);
                    if (heights.len > 0 and heights[0] == expected) break;
                    try ctx.sleep(.fromMilliseconds(10));
                }
                const acknowledged = self.app.acknowledge_next() orelse
                    return error.AckPipelineNoPending;
                if (acknowledged.get() != expected) return error.AckPipelineOutOfOrder;
            }
            // Every finalized block is delivered once the backlog drains.
            try self.wait_for(5, 0);
        }

        fn restart_body(ctx: Ctx) anyerror!void {
            var self: Self = undefined;
            try self.start(ctx);
            defer self.stop();
            try self.finalize_chain(3);
            try self.wait_for(0, 3);
            try self.expect_pending_one_to_three();
            // Acknowledge every pending block without yielding, so marshal drains them in one
            // ack event and syncs its metadata once.
            for (1..4) |expected| {
                const acknowledged = self.app.acknowledge_next() orelse
                    return error.AckPipelineNoPending;
                if (acknowledged.get() != expected) return error.AckPipelineOutOfOrder;
            }
            try ctx.sleep(.fromMilliseconds(10));
            const tip = self.app.tip() orelse return error.AckPipelineNoTip;
            if (tip.height.get() != 3) return error.AckPipelineWrongTip;
            // A restart restores the processed height from metadata.
            self.node.crash();
            const restart_ctx = ctx.child("validator_restart").with_attribute("index", 0);
            const app: App = try .manual_ack(self.gpa, ctx.io());
            self.node = try self.setup(restart_ctx, app);
            const restored = self.node.height orelse return error.AckPipelineNoHeight;
            if (restored.get() != 3) return error.AckPipelineWrongRestoredHeight;
        }
    };
}
