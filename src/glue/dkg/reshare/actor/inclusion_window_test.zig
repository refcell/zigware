//! Whole-window tests of commonware's `glue::dkg::reshare::actor::inclusion` (`mod tests`),
//! driven through the actor's mailbox in one-shot DKG mode over a singleton set, as
//! commonware's `InclusionHarness` is.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const dealing_mod = @import("dealing.zig");
const window = @import("inclusion_window.zig");

const Epoch = consensus.Epoch;
const Exact = utils.acknowledgement.Exact;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const Summary = cryptography.transcript.Summary;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Harness = actor_test.Harness;
const TestActor = @import("actor.zig").Actor(mocks.ActorTypes);
const Digested = TestActor.Digested;
const gpa = testing.allocator;
const namespace = "_COMMONWARE_GLUE_DKG_RESHARE_INCLUSION_TEST";

/// A singleton harness switched to one-shot DKG mode, with epoch zero's round.
const Fixture = FixtureOf(mocks.ActorTypes);

/// `Fixture` over an actor of `Types` (`mocks.ActorTypes` with another `Ancestry`).
fn FixtureOf(comptime Types: type) type {
    return struct {
        const Self = @This();
        const H = actor_test.HarnessOf(Types);
        const Block = H.Actor.Digested;
        const Dealing = dealing_mod.Window(Types);
        const Inclusion = window.Window(Types);

        h: H,
        round: fd.Info(V, P),

        fn init(self: *Self, io: Io, partition: []const u8, length: u64) !void {
            try self.h.init(io, partition, length);
            errdefer self.h.deinit();
            const key = self.h.public_key;
            const participants = try Set.from_dedup(gpa, &.{key});
            self.h.actor.mode = .{ .dkg = .{ .participants = participants, .directory = .{} } };
            const mode = .non_zero_counter;
            const dealers = try Set.from_dedup(gpa, &.{key});
            const players = try Set.from_dedup(gpa, &.{key});
            self.round = try .init(N3f1, gpa, namespace, 0, null, mode, .v1, dealers, players);
        }

        /// This node's signed log for `round`, after dealing to itself through the store
        /// (commonware's harness completes self-dealing the same way).
        fn self_log(self: *Self) !fd.SignedDealerLog(V, P) {
            const signer = mocks.TestSigner.from_seed(0);
            const store = &self.h.store;
            const key = self.h.public_key;
            const summary: Summary = .{ .bytes = @splat(2) };
            const S = mocks.TestSigner;
            const round = &self.round;
            const created = try store.create_dealer(N3f1, S, .zero(), signer, round, null, summary);
            var dealer = created orelse return error.ExpectedDealer;
            defer dealer.deinit();
            const joined = try store.create_player(N3f1, S, .zero(), signer, &self.round);
            var player = joined orelse return error.ExpectedPlayer;
            defer player.deinit();
            const item = dealer.shares_to_distribute()[0];
            std.debug.assert(item.player.eql(key));
            const ack = try player.handle(store, .zero(), key, dealer.public, item.msg);
            try testing.expectEqual(.recorded, try dealer.handle(store, .zero(), key, ack));
            try testing.expect(try dealer.finalize(N3f1));
            return dealer.finalized.?.clone(gpa);
        }

        fn deinit(self: *Self) void {
            self.round.deinit(gpa);
            self.h.deinit();
        }

        fn dealing(self: *Self, epoch: u64) !Dealing.Outcome {
            const peers = (&self.h.public_key)[0..1];
            var channel = p2p.utils.mocks.inert_channel(P, gpa, self.h.io, peers);
            const session: Dealing.Session = .{
                .epoch = .new(epoch),
                .store = &self.h.store,
                .dealer = null,
                .player = null,
            };
            return Dealing.dealing(&self.h.actor, session, &channel.sender, &channel.receiver);
        }

        fn inclusion(self: *Self, requests: Inclusion.Requests) !@import("actor.zig").Flow {
            const session: Inclusion.Session = .{
                .epoch = .zero(),
                .info = &self.round,
                .store = &self.h.store,
                .dealer = null,
            };
            return Inclusion.inclusion_window(&self.h.actor, session, requests);
        }

        /// Delivers `blocks[index]` for each index and returns the waiters.
        fn deliver(self: *Self, blocks: []const Block, indices: []const usize) ![4]Exact.Waiter {
            var waiters: [4]Exact.Waiter = undefined;
            for (indices, waiters[0..indices.len]) |index, *waiter| {
                waiter.* = try self.h.deliver(&blocks[index]);
            }
            return waiters;
        }
    };
}

fn expect_acknowledged(waiters: []Exact.Waiter) !void {
    for (waiters) |*waiter| {
        defer waiter.deinit();
        try (waiter.poll() orelse return error.Unacknowledged);
    }
}

fn free_blocks(blocks: []Digested) void {
    for (blocks) |*block| block.deinit();
}

// commonware `redelivered_receipts_survive_phase_changes`: marshal may redeliver blocks the
// actor already applied; every window acknowledges them.
test "inclusion: redelivered receipts survive phase changes" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: Fixture = undefined;
            try f.init(io, "redelivered-receipts", 4);
            defer f.deinit();
            var blocks: [6]Digested = undefined;
            try f.h.chain(&blocks);
            defer free_blocks(&blocks);

            // Dealing completes epoch zero's early phase.
            var early = try f.deliver(&blocks, &.{ 0, 1 });
            var first = try f.dealing(0);
            try testing.expect(first == .proceed);
            first.proceed.deinit(gpa);
            try expect_acknowledged(early[0..2]);

            // Inclusion receives a redelivered early block and a repeated midpoint before the
            // final block completes the epoch.
            var late = try f.deliver(&blocks, &.{ 1, 2, 2, 3 });
            try testing.expectEqual(.proceed, try f.inclusion(.empty));
            try expect_acknowledged(&late);

            // The next epoch's dealing receives redelivered epoch-zero blocks first.
            var next = try f.deliver(&blocks, &.{ 2, 3, 4, 5 });
            var second = try f.dealing(1);
            try testing.expect(second == .proceed);
            second.proceed.deinit(gpa);
            try expect_acknowledged(&next);
        }
    }.body);
}

const Response = TestActor.Mailbox.Response;

fn ask(mailbox: TestActor.Mailbox, blocks: []const Digested) !Response {
    var handles: [2]Digested = undefined;
    for (blocks, &handles) |block, *handle| handle.* = block.clone();
    const ancestry = try consensus.marshal.ancestry.from_iter(mocks.TestBlock, gpa, &handles);
    return mailbox.epoch_info(ancestry);
}

// commonware `pr_5263_regression`: a final-block request made while dealing still applies
// blocks is held through dealing and answered by inclusion on entry, from the request's
// ancestry.
test "inclusion: a request held through dealing is answered on entry (pr 5263)" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: Fixture = undefined;
            try f.init(io, "dealing-holds-requests", 4);
            defer f.deinit();
            var blocks: [4]Digested = undefined;
            try f.h.chain(&blocks);
            defer free_blocks(&blocks);

            // Verification of the final block asks for epoch info before dealing applies
            // any block.
            const ancestry = [_]Digested{ blocks[3], blocks[2] };
            var request = try io.concurrent(ask, .{ f.h.mailbox, &ancestry });
            var waiters = try f.deliver(&blocks, &.{ 0, 1 });
            const outcome = try f.dealing(0);
            try testing.expect(outcome == .proceed);
            try expect_acknowledged(waiters[0..2]);

            // No further message arrives, so inclusion starts the held request on entry.
            var running = try io.concurrent(Fixture.inclusion, .{ &f, outcome.proceed });
            var response = try request.await(io);
            defer response.deinit();
            if (running.cancel(io)) |_| {} else |_| {}
            try testing.expect(response == .available);
            try testing.expect(response.available.payload == null);
        }
    }.body);
}

/// Released and first-read signals shared by a gated ancestry and its clones.
const Gate = struct {
    io: Io,
    started: Io.Event = .unset,
    released: Io.Event = .unset,

    fn release(gate: *Gate) void {
        std.debug.assert(!gate.released.isSet());
        gate.released.set(gate.io);
    }
};

/// A fixed ancestry, newest first, whose reads wait for its gate when it has one (commonware
/// `GatedAncestry`); it peeks nothing until the gate opens.
const Gated = struct {
    pub const Block = mocks.TestBlock;
    const D = TestActor.Digested;

    blocks: [2]D = undefined,
    head: usize = 0,
    len: usize = 0,
    /// Leading blocks read and peeked without the gate (commonware `with_prefix`'s prefix).
    free: usize = 0,
    gate: ?*Gate = null,

    /// Takes new handles to `blocks`.
    fn init(blocks: []const D, gate: ?*Gate) Gated {
        std.debug.assert(blocks.len > 0 and blocks.len <= 2);
        var result: Gated = .{ .len = blocks.len, .gate = gate };
        for (blocks, result.blocks[0..blocks.len]) |block, *copy| copy.* = block.clone();
        return result;
    }

    /// `blocks` (new handles) whose first `free` read without waiting for `gate`.
    fn prefixed(blocks: []const D, free: usize, gate: *Gate) Gated {
        std.debug.assert(free < blocks.len);
        var result = init(blocks, gate);
        result.free = free;
        return result;
    }

    fn opened(self: *const Gated) bool {
        const gate = self.gate orelse return true;
        return gate.released.isSet();
    }

    pub fn peek(self: *const Gated) ?*const D {
        std.debug.assert(self.head <= self.len);
        if (self.head == self.len) return null;
        if (self.head >= self.free and !self.opened()) return null;
        return &self.blocks[self.head];
    }

    pub fn next(self: *Gated) Io.Cancelable!?D {
        std.debug.assert(self.head <= self.len);
        if (self.gate) |gate| if (self.head >= self.free) {
            gate.started.set(gate.io);
            try gate.released.wait(gate.io);
        };
        if (self.head == self.len) return null;
        self.head += 1;
        return self.blocks[self.head - 1];
    }

    pub fn clone(self: *const Gated) std.mem.Allocator.Error!Gated {
        var copy = self.*;
        const live = self.blocks[self.head..self.len];
        for (live, copy.blocks[self.head..self.len]) |block, *handle| handle.* = block.clone();
        return copy;
    }

    pub fn deinit(self: *Gated) void {
        std.debug.assert(self.head <= self.len);
        for (self.blocks[self.head..self.len]) |*block| block.deinit();
        self.* = undefined;
    }
};

const GatedTypes = struct {
    pub const Block = mocks.ActorTypes.Block;
    pub const Ack = mocks.ActorTypes.Ack;
    pub const Ancestry = Gated;
    pub const Signer = mocks.ActorTypes.Signer;
    pub const Manager = mocks.ActorTypes.Manager;
    pub const Blocker = mocks.ActorTypes.Blocker;
    pub const Provider = mocks.ActorTypes.Provider;
    pub const SecretStore = mocks.ActorTypes.SecretStore;
    pub const Registrar = mocks.ActorTypes.Registrar;
    pub const Marshal = mocks.ActorTypes.Marshal;
    pub const Strategy = mocks.ActorTypes.Strategy;
};
const GatedFixture = FixtureOf(GatedTypes);
const GatedResponse = GatedFixture.H.Actor.Mailbox.Response;

/// An `epoch_info` request running in its own task; `done` is set once it answered.
const Asked = struct {
    done: std.atomic.Value(bool) = .init(false),
    task: Io.Future(anyerror!GatedResponse) = undefined,

    fn start(self: *Asked, io: Io, f: *GatedFixture, ancestry: Gated) !void {
        self.done = .init(false);
        self.task = try io.concurrent(run, .{ self, f, ancestry });
    }

    fn run(self: *Asked, f: *GatedFixture, ancestry: Gated) anyerror!GatedResponse {
        defer self.done.store(true, .release);
        return f.h.mailbox.epoch_info(ancestry);
    }

    fn answered(self: *const Asked) bool {
        return self.done.load(.acquire);
    }

    /// Awaits the answer and checks it: `null` expects unavailable, otherwise an available
    /// response whose payload presence is `expected.?`.
    fn expect(self: *Asked, io: Io, expected: ?bool) !void {
        var response = try self.task.await(io);
        defer response.deinit();
        if (expected) |has_payload| {
            try testing.expect(response == .available);
            try testing.expectEqual(has_payload, response.available.payload != null);
        } else {
            try testing.expect(response == .unavailable);
        }
    }
};

fn gated_block(parent: mocks.TestDigest, height: u64, timestamp: u64) mocks.TestBlock {
    const genesis = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key());
    return .init(genesis.context(), parent, .new(height), timestamp);
}

fn ready(raw: mocks.TestBlock) !TestActor.Digested {
    return TestActor.Digested.precomputed(gpa, raw, raw.digest());
}

fn run_inclusion(f: *GatedFixture) anyerror!@import("actor.zig").Flow {
    return f.inclusion(.empty);
}

/// Reports `block` and waits for its acknowledgement.
fn finalize(f: *GatedFixture, block: *const TestActor.Digested) !void {
    var waiter = try f.h.deliver(block);
    defer waiter.deinit();
    try waiter.wait();
}

const Histories = struct {
    canonical: [4]TestActor.Digested,
    detached: [2]TestActor.Digested,

    fn deinit(self: *Histories) void {
        free_blocks(&self.canonical);
        free_blocks(&self.detached);
    }
};

/// The canonical chain's midpoint, fourth, and final blocks (heights 3 to 5 of a six-block
/// epoch, at indices 0 to 2, and the height-2 block at 3), and a detached midpoint carrying
/// `log` with its child.
fn histories(log: fd.SignedDealerLog(V, P)) !Histories {
    const genesis = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key());
    const common = gated_block(genesis.digest(), 1, 1);
    const two = gated_block(common.digest(), 2, 2);
    const mid = gated_block(two.digest(), 3, 3);
    const four = gated_block(mid.digest(), 4, 4);
    const last = gated_block(four.digest(), 5, 5);
    const detached_mid = try gated_block(two.digest(), 3, 6).with_payload(gpa, 16, .{
        .dealer_log = log,
    });
    const detached_four = gated_block(detached_mid.digest(), 4, 7);
    return .{
        .canonical = .{ try ready(mid), try ready(four), try ready(last), try ready(two) },
        .detached = .{ try ready(detached_four), try ready(detached_mid) },
    };
}

// commonware `unanchored_or_delayed_ancestry_does_not_block_finalization`: a request waits
// for an anchor, a gated ancestry never holds up finalized reporting, and a scan the final
// block overtakes answers unavailable.
test "inclusion: unanchored or delayed ancestry does not block finalization" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: GatedFixture = undefined;
            try f.init(io, "inclusion-actor", 6);
            defer f.deinit();
            var log = try f.self_log();
            defer log.deinit(gpa);
            var h = try histories(log);
            defer h.deinit();
            const mid = &h.canonical[0];
            const four = &h.canonical[1];
            const last = &h.canonical[2];

            // The detached request arrives before the window starts and waits for an anchor.
            var detached: Asked = .{};
            try detached.start(io, &f, .init(&h.detached, null));
            var inclusion = try io.concurrent(run_inclusion, .{&f});
            defer _ = inclusion.cancel(io) catch {};
            // A verification candidate without its parent is truncated.
            var malformed: Asked = .{};
            try malformed.start(io, &f, .init(last[0..1], null));
            try io.sleep(.fromMilliseconds(50), .awake);
            try testing.expect(!detached.answered());
            try testing.expect(!malformed.answered());

            // Finalizing the canonical midpoint anchors the scans: the detached history
            // conflicts with it, and the malformed one lacks its parent.
            try finalize(&f, mid);
            try detached.expect(io, null);
            try malformed.expect(io, null);

            // While a scan waits for its parent, finalized reporting continues.
            var gate: Gate = .{ .io = io };
            var canonical: Asked = .{};
            try canonical.start(io, &f, .init(four[0..1], &gate));
            try gate.started.wait(io);
            try finalize(&f, four);
            try testing.expect(!canonical.answered());
            gate.release();
            try canonical.expect(io, false);

            // A scan the final block overtakes stays unresolved, then reads as unavailable.
            var terminal_gate: Gate = .{ .io = io };
            var terminal: Asked = .{};
            try terminal.start(io, &f, .init(four[0..1], &terminal_gate));
            try terminal_gate.started.wait(io);
            try finalize(&f, last);
            try terminal.expect(io, null);
            try testing.expectEqual(.proceed, try inclusion.await(io));
            try testing.expect(f.h.store.current_info() == null);
        }
    }.body);
}

/// Canonical heights 4 to 7 of an eight-block epoch (indices 0 to 3) and a losing history
/// whose height-5 block carries `log` (index 0) with its child (index 1).
const RaceHistories = struct {
    canonical: [4]TestActor.Digested,
    losing: [2]TestActor.Digested,

    fn init(log: fd.SignedDealerLog(V, P)) !RaceHistories {
        const genesis = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key());
        var parent = genesis.digest();
        var raw: [8]mocks.TestBlock = undefined;
        for (raw[1..], 1..) |*block, height| {
            block.* = gated_block(parent, height, height);
            parent = block.digest();
        }
        const five = try gated_block(raw[4].digest(), 5, 8).with_payload(gpa, 16, .{
            .dealer_log = log,
        });
        const six = gated_block(five.digest(), 6, 9);
        return .{
            .canonical = .{
                try ready(raw[4]), try ready(raw[5]), try ready(raw[6]), try ready(raw[7]),
            },
            .losing = .{ try ready(five), try ready(six) },
        };
    }

    fn deinit(self: *RaceHistories) void {
        free_blocks(&self.canonical);
        free_blocks(&self.losing);
    }
};

// commonware `ready_scan_yields_to_admitted_finalization`: a finalized block admitted in the
// same turn a cached losing-view scan finishes invalidates that scan before its result
// escapes.
test "inclusion: a ready scan yields to an admitted finalization" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: GatedFixture = undefined;
            try f.init(io, "ready-scan", 8);
            defer f.deinit();
            var log = try f.self_log();
            defer log.deinit(gpa);
            var h = try RaceHistories.init(log);
            defer h.deinit();
            const losing = [_]TestActor.Digested{ h.losing[1], h.losing[0] };

            // Anchor scans to the canonical midpoint before asking for boundary artifacts.
            var inclusion = try io.concurrent(run_inclusion, .{&f});
            defer _ = inclusion.cancel(io) catch {};
            try finalize(&f, &h.canonical[0]);

            // Prime the losing view's cache: its log makes the artifact available.
            var primed: Asked = .{};
            try primed.start(io, &f, .init(&losing, null));
            try primed.expect(io, true);

            // Hold a second scan of that view at the read past its first block.
            var gate: Gate = .{ .io = io };
            var raced: Asked = .{};
            try raced.start(io, &f, .prefixed(&losing, 1, &gate));
            try gate.started.wait(io);
            try testing.expect(!raced.answered());

            // The canonical block and the stale scan become ready together; the finalization
            // must invalidate the scan before its cached losing-view result escapes.
            var five = try f.h.deliver(&h.canonical[1]);
            defer five.deinit();
            gate.release();
            try five.wait();
            try raced.expect(io, null);

            try finalize(&f, &h.canonical[2]);
            try finalize(&f, &h.canonical[3]);
            try testing.expectEqual(.proceed, try inclusion.await(io));
            try testing.expect(f.h.store.current_info() == null);
        }
    }.body);
}

// commonware `closed_terminal_verification_exits_without_acknowledging`. Commonware closes the
// actor's runtime context, so the final block's spawned verification fails and inclusion
// breaks. Verification runs inline here; the equivalent is the window's task canceled while
// it finishes the final block (in its share write). The final block stays unacknowledged
// and no epoch is committed.
test "inclusion: a canceled final block exits without acknowledging" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var f: GatedFixture = undefined;
            try f.init(io, "closed-verification", 6);
            defer f.deinit();
            var log = try f.self_log();
            defer log.deinit(gpa);
            const genesis = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key());
            const two = gated_block(genesis.digest(), 2, 2);
            var mid = try ready(try gated_block(two.digest(), 3, 3).with_payload(gpa, 16, .{
                .dealer_log = log,
            }));
            defer mid.deinit();
            var four = try ready(gated_block(mid.digest(), 4, 4));
            defer four.deinit();

            var inclusion = try io.concurrent(run_inclusion, .{&f});
            defer _ = inclusion.cancel(io) catch {};
            try finalize(&f, &mid);
            try finalize(&f, &four);

            // The final block carries the epoch info this node's log produces.
            var asked: Asked = .{};
            try asked.start(io, &f, .init((&four)[0..1], null));
            var response = try asked.task.await(io);
            defer response.deinit();
            try testing.expect(response == .available);
            const payload = response.available.payload orelse return error.ExpectedPayload;
            const raw_last = try gated_block(four.digest(), 5, 5).with_payload(gpa, 16, payload);
            var last = try ready(raw_last);
            defer last.deinit();

            f.h.secrets.stall(io);
            var waiter = try f.h.deliver(&last);
            defer waiter.deinit();
            while (!f.h.secrets.has_share(.zero())) try io.sleep(.fromMilliseconds(1), .awake);
            try testing.expectError(error.Canceled, inclusion.cancel(io));
            try testing.expectError(error.AcknowledgementCanceled, waiter.wait());
            try testing.expect(f.h.store.current_info() == null);
        }
    }.body);
}
