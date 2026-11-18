//! Tests of commonware's `glue::dkg::reshare::actor::dealing` (`mod tests`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");
const types = @import("../../types.zig");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const dealing = @import("dealing.zig");

const Epoch = consensus.Epoch;
const Exact = utils.acknowledgement.Exact;
const PrivateKey = mocks.TestSigner;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Harness = actor_test.Harness;
const Digested = @import("actor.zig").Actor(mocks.ActorTypes).Digested;
const Window = dealing.Window(mocks.ActorTypes);
const Wire = types.Message(V, P);
const gpa = testing.allocator;

/// A receiver that yields its queued messages from `peer`, then waits until canceled
/// (commonware `QueuedReceiver`).
const QueuedReceiver = struct {
    pub const PublicKey = P;

    io: Io,
    peer: P,
    payload: []const u8,
    remaining: usize,
    received: usize = 0,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,

    pub fn recv(self: *QueuedReceiver) Io.Cancelable!p2p.Message(P) {
        if (self.remaining > 0) {
            self.remaining -= 1;
            self.received += 1;
            return .{ .peer = self.peer, .payload = self.payload };
        }
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        // Nothing signals the condition, so only cancelation ends the wait.
        while (true) try self.condition.wait(self.io, &self.mutex);
    }

    pub fn capacity(_: *const QueuedReceiver) usize {
        return 16;
    }
};

// commonware `finalized_message_is_acknowledged_before_ready_peer_traffic`: the window
// handles a queued finalized block before ready peer traffic, so the block before the
// midpoint ends it without reading the network.
test "dealing: a finalized block is acknowledged before ready peer traffic" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "dealing-priority", 2);
            defer h.deinit();
            const peer = PrivateKey.from_seed(1).public_key();
            var receiver: QueuedReceiver = .{
                .io = io,
                .peer = peer,
                .payload = &.{0xff},
                .remaining = 8,
            };
            var channel = p2p.utils.mocks.inert_channel(P, gpa, io, &.{peer});
            var blocks: [1]Digested = undefined;
            try h.chain(&blocks);
            defer blocks[0].deinit();
            var waiter = try h.deliver(&blocks[0]);
            defer waiter.deinit();

            const session: Window.Session = .{
                .epoch = .zero(),
                .store = &h.store,
                .dealer = null,
                .player = null,
            };
            var outcome = try Window.dealing(&h.actor, session, &channel.sender, &receiver);
            defer if (outcome == .proceed) outcome.proceed.deinit(gpa);
            try testing.expect(outcome == .proceed);
            try (waiter.poll() orelse return error.Unacknowledged);
            try testing.expectEqual(@as(usize, 0), receiver.received);
            try testing.expectEqual(@as(usize, 0), h.blocker.blocked.items.len);
        }
    }.body);
}

fn encode(message: Wire) ![]u8 {
    return codec.encode(Wire, gpa, message);
}

fn private_for(started: anytype, player: P) !fd.DealerPrivMsg {
    for (started.priv_msgs) |item| if (item.player.eql(player)) return item.msg;
    return error.MissingDealing;
}

fn free_started(started: anytype) void {
    started.dealer.deinit(gpa);
    started.pub_msg.deinit(gpa);
    gpa.free(started.priv_msgs);
}

/// Four signers; the first three are players and all four are dealers of epoch zero.
const Fault = struct {
    keys: [4]PrivateKey,
    public_keys: [4]P,
    info: fd.Info(V, P),

    fn init(self: *Fault) !void {
        for (&self.keys, &self.public_keys, 0..) |*key, *public, seed| {
            key.* = .from_seed(seed);
            public.* = key.public_key();
        }
        self.info = try .init(
            N3f1,
            gpa,
            "_COMMONWARE_GLUE_DKG_RESHARE_AUTHENTICATED_FAULT_TEST",
            0,
            null,
            .non_zero_counter,
            .v1,
            try Set.from_dedup(gpa, &self.public_keys),
            try Set.from_dedup(gpa, self.public_keys[0..3]),
        );
    }

    /// `dealer`'s commitment paired with the share it dealt to `other` (encoded).
    fn misdirected_dealing(self: *const Fault, dealer: PrivateKey, other: P) ![]u8 {
        var rng = utils.rng.TestRng.init(0);
        const Dealer = fd.Dealer(V, PrivateKey);
        var started = try Dealer.start(N3f1, gpa, &rng, &self.info, dealer, null);
        defer free_started(&started);
        const wrong = try private_for(&started, other);
        return encode(.{ .dealer = .{ .pub_msg = started.pub_msg, .priv_msg = wrong } });
    }

    /// `player`'s valid acknowledgement of a transcript `dealer` dealt from seed one
    /// (encoded).
    fn foreign_ack(self: *const Fault, dealer: PrivateKey, player: PrivateKey) ![]u8 {
        var rng = utils.rng.TestRng.init(1);
        const Dealer = fd.Dealer(V, PrivateKey);
        var source = try Dealer.start(N3f1, gpa, &rng, &self.info, dealer, null);
        defer free_started(&source);
        var source_player = try fd.Player(V, PrivateKey).init(&self.info, player);
        defer source_player.deinit(gpa);
        const private = try private_for(&source, player.public_key());
        const key = dealer.public_key();
        const processed = source_player.dealer_message(N3f1, gpa, key, source.pub_msg, private);
        return encode(.{ .ack = (try processed).? });
    }
};

// commonware `authenticated_invalid_messages_block_senders`: a configured dealer sending an
// invalid share, a configured player acknowledging another transcript, and an authenticated
// non-player acknowledging are each blocked.
test "dealing: authenticated invalid messages block their senders" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "authenticated-fault", 8);
            defer h.deinit();
            var fault: Fault = undefined;
            try fault.init();
            defer fault.info.deinit(gpa);
            const target, const dealer, const ack_player, const outsider = fault.keys;
            var channel = p2p.utils.mocks.inert_channel(P, gpa, io, &fault.public_keys);
            const sender = &channel.sender;
            const actor = &h.actor;
            const store = &h.store;
            const epoch = Epoch.zero();
            const info = &fault.info;

            // A configured dealer that sends an invalid private share is blocked.
            var player = (try store.create_player(N3f1, PrivateKey, epoch, target, info)).?;
            defer player.deinit();
            const dealing_bytes = try fault.misdirected_dealing(dealer, ack_player.public_key());
            defer gpa.free(dealing_bytes);
            var session: Window.Session = .{
                .epoch = epoch,
                .store = store,
                .dealer = null,
                .player = &player,
            };
            try Window.handle_message(actor, session, sender, dealer.public_key(), dealing_bytes);

            // The local dealer has one recoverable transcript, so a configured player
            // acknowledging another one is blocked, and so is the same ack from a non-player.
            var seed_rng = utils.rng.TestRng.init(0);
            const seed = try store.seed_or_random(epoch, utils.rng.random(&seed_rng));
            const created = store.create_dealer(N3f1, PrivateKey, epoch, target, info, null, seed);
            var local = (try created).?;
            defer local.deinit();
            const ack_bytes = try fault.foreign_ack(target, ack_player);
            defer gpa.free(ack_bytes);
            session.dealer = &local;
            session.player = null;
            try Window.handle_message(actor, session, sender, ack_player.public_key(), ack_bytes);
            try Window.handle_message(actor, session, sender, outsider.public_key(), ack_bytes);

            const blocked = h.blocker.blocked.items;
            try testing.expectEqual(@as(usize, 3), blocked.len);
            const expected = [_]P{
                dealer.public_key(),
                ack_player.public_key(),
                outsider.public_key(),
            };
            for (expected, blocked) |want, got| try testing.expect(want.eql(got));
        }
    }.body);
}
