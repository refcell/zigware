//! Tests of the reshare actor's one-shot DKG mode (commonware `reshare/actor/dkg.rs`).

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const p2p = @import("p2p");
const utils = @import("utils");
const mocks = @import("../../tests/mocks.zig");
const actor_test = @import("actor_test.zig");
const dkg_mod = @import("dkg.zig");

const Exact = utils.acknowledgement.Exact;
const P = mocks.TestPublicKey;
const Set = utils.ordered.Set(P);
const Harness = actor_test.Harness;
const TestActor = @import("actor.zig").Actor(mocks.ActorTypes);
const Digested = TestActor.Digested;
const Dkg = dkg_mod.Dkg(mocks.ActorTypes);
const mocks_p2p = p2p.utils.mocks;
const Muxer = p2p.utils.mux.Muxer(mocks_p2p.InertSender(P), mocks_p2p.InertReceiver(P));
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;

fn run_dkg(h: *Harness, handle: *Muxer.Handle) anyerror!void {
    return Dkg.run_dkg(&h.actor, &h.store, handle);
}

/// Delivers `block` and waits for its acknowledgement.
fn apply(h: *Harness, block: *const Digested) !void {
    var waiter = try h.deliver(block);
    defer waiter.deinit();
    try waiter.wait();
}

/// The child of `parent` carrying `payload` (borrowed).
fn child_with(parent: *const Digested, payload: anytype) !Digested {
    const raw = try mocks.child(parent.inner()).with_payload(gpa, 16, payload);
    return Digested.precomputed(gpa, raw, raw.digest());
}

// A singleton one-shot DKG run through its mailbox as consensus drives it: dealing applies
// the first half, the proposer takes this node's dealer log for the midpoint block, and the
// final block carries the epoch info the actor derives. The completion then reports epoch
// zero's successful output, and this node holds its share.
test "dkg: a singleton ceremony completes through its mailbox" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var h: Harness = undefined;
            try h.init(io, "dkg-singleton", 4);
            defer h.deinit();
            const pair = try oneshot.channel(TestActor.DkgOutcome, gpa, io);
            var outcome_receiver = pair.receiver;
            defer outcome_receiver.deinit();
            const participants = try Set.from_dedup(gpa, &.{h.public_key});
            h.actor.mode = .{ .dkg = .{
                .participants = participants,
                .directory = .{},
                .completion = pair.sender,
            } };
            const peers = (&h.public_key)[0..1];
            const channel = mocks_p2p.inert_channel(P, gpa, io, peers);
            var mux = try Muxer.init(gpa, io, channel.sender, channel.receiver);
            defer mux.muxer.deinit();
            defer mux.handle.deinit();
            var running = try io.concurrent(run_dkg, .{ &h, &mux.handle });
            defer if (running.cancel(io)) |_| {} else |_| {};

            var blocks: [4]Digested = undefined;
            try h.chain(blocks[0..2]);
            defer for (blocks[0..2]) |*block| block.deinit();
            for (blocks[0..2]) |*block| try apply(&h, block);
            try propose_and_finalize(&h, &blocks);

            var outcome = try outcome_receiver.recv();
            defer outcome.deinit();
            const info = outcome.info orelse return error.ExpectedDkgOutput;
            try testing.expectEqual(@as(u64, 0), info.epoch.get());
            try testing.expectEqual(.success, info.outcome);
            try testing.expect(info.players.eql(h.actor.mode.dkg.participants));
            try testing.expect(try h.store.share(.zero()) != null);
            try testing.expectEqual(@as(u32, 1), h.manager.tracked);
        }
    }.body);
}

/// Builds and finalizes the midpoint block with this node's dealer log, then the final block
/// with the epoch info the actor answers for it (`blocks[2]` and `blocks[3]`, owned here).
fn propose_and_finalize(h: *Harness, blocks: *[4]Digested) !void {
    var reservation = try h.mailbox.next_log(.new(2)) orelse return error.ExpectedDealerLog;
    var log_payload = reservation.take_payload() orelse return error.ExpectedDealerLog;
    defer log_payload.deinit(gpa);
    try testing.expect(log_payload == .dealer_log);
    blocks[2] = try child_with(&blocks[1], log_payload);
    defer blocks[2].deinit();
    reservation.included();
    try apply(h, &blocks[2]);

    var handles = [_]Digested{blocks[2].clone()};
    const ancestry = try consensus.marshal.ancestry.from_iter(mocks.TestBlock, gpa, &handles);
    var response = try h.mailbox.epoch_info(ancestry);
    defer response.deinit();
    try testing.expect(response == .available);
    const info_payload = response.available.payload orelse return error.ExpectedEpochInfo;
    try testing.expect(info_payload == .epoch_info);
    blocks[3] = try child_with(&blocks[2], info_payload);
    defer blocks[3].deinit();
    try apply(h, &blocks[3]);
}
