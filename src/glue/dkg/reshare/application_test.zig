//! Tests of commonware's `glue::dkg::reshare::application` (`mod tests`), against a fake
//! actor that answers the reshare mailbox.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const mocks = @import("../tests/mocks.zig");
const actor_test = @import("actor/actor_test.zig");
const inclusion_test = @import("actor/inclusion_test.zig");
const application = @import("application.zig");

const Height = consensus.Height;
const P = mocks.TestPublicKey;
const V = mocks.TestBlsVariant;
const B = mocks.TestBlock;
const Set = utils.ordered.Set(P);
const N3f1 = utils.N3f1;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Digested = broadcast.Digested(B);
const Types = mocks.ActorTypes;
const gpa = testing.allocator;

comptime {
    // Every `T` over the same block shares one `Input`, named by its payload alone.
    std.debug.assert(application.Input(Types) == application.InputOf(Types.Block.Payload));
}

/// The inner application: records the payload of each proposal and builds a child of the
/// parent carrying it, unless it rejects (commonware `RecordingApp`).
const Recording = struct {
    pub const Block = B;
    const Wrapper = application.Application(*Recording, Types);

    accept: bool = true,
    verify_result: bool = true,
    /// What `prepare` decides.
    handoff: std.meta.Tag(consensus.Handoff(Digested)) = .wait,
    /// When set, `propose` waits on this runtime until it is canceled.
    pending: ?Io = null,
    prepares: u32 = 0,
    proposals: u32 = 0,
    verifies: u32 = 0,
    last_payload: ?Wrapper.Payload = null,

    fn deinit(self: *Recording) void {
        if (self.last_payload) |*payload| payload.deinit(gpa);
    }

    pub fn propose(
        self: *Recording,
        _: void,
        _: void,
        ancestry: anytype,
        input: application.Input(Types),
    ) anyerror!?Digested {
        var owned = ancestry;
        defer owned.deinit();
        var taken = input;
        const payload = taken.take();
        self.proposals += 1;
        if (self.last_payload) |*old| old.deinit(gpa);
        self.last_payload = payload;
        if (self.pending) |io| try io.sleep(.fromSeconds(3600), .awake);
        if (!self.accept) return null;
        const parent = owned.peek().?;
        var raw = mocks.child(parent.inner());
        if (payload) |value| raw = try raw.with_payload(gpa, 16, value);
        return try Digested.precomputed(gpa, raw, raw.digest());
    }

    pub fn prepare(
        self: *Recording,
        _: void,
        _: void,
        ancestry: anytype,
        input: application.Input(Types),
    ) anyerror!consensus.Handoff(Digested) {
        var owned = ancestry;
        defer owned.deinit();
        std.debug.assert(input.payload == null);
        self.prepares += 1;
        if (self.handoff == .wait) return .wait;
        const raw = mocks.child(owned.peek().?.inner());
        const block = try Digested.precomputed(gpa, raw, raw.digest());
        return if (self.handoff == .vote) .{ .vote = block } else .{ .stage = block };
    }

    pub fn verify(self: *Recording, _: void, _: void, ancestry: anytype) anyerror!bool {
        var owned = ancestry;
        owned.deinit();
        self.verifies += 1;
        return self.verify_result;
    }
};

const App = Recording.Wrapper;
const Message = App.Mailbox.M;

/// Answers the reshare mailbox like the actor: serves `log` once until released, answers
/// every epoch-info request with `info` (unavailable when null), and records releases.
const FakeActor = struct {
    receiver: actor.mailbox.Receiver(Message),
    log: ?App.Payload = null,
    info: ?App.Payload = null,
    served_at: ?Height = null,
    released: ?Height = null,
    info_requests: u32 = 0,

    fn run(self: *FakeActor) anyerror!void {
        while (try self.receiver.recv()) |message| try self.handle(message);
    }

    fn handle(self: *FakeActor, message: Message) !void {
        switch (message.body) {
            .next_log => |value| {
                var body = value;
                const serve = self.served_at == null and self.log != null;
                const payload: ?App.Payload = if (serve) try self.log.?.clone(gpa) else null;
                if (serve) self.served_at = body.height;
                body.response.send(payload) catch if (payload) |p| {
                    var dropped = p;
                    dropped.deinit(gpa);
                };
            },
            .release_log => |height| {
                self.released = height;
                if (self.served_at != null and self.served_at.?.get() == height.get()) {
                    self.served_at = null;
                }
            },
            .epoch_info => |value| {
                var body = value;
                body.ancestry.deinit();
                self.info_requests += 1;
                const response: App.Mailbox.Response = if (self.info) |info|
                    .{ .available = .{ .gpa = gpa, .payload = try info.clone(gpa) } }
                else
                    .unavailable;
                body.response.send(response) catch response.discard();
            },
            .finalized => Message.discard(message),
        }
    }
};

/// A wrapper over `inner` and a fake actor, with `blocks_per_epoch`-long epochs.
const Fixture = struct {
    fake: FakeActor,
    app: App,
    task: Io.Future(anyerror!void),
    io: Io,

    fn init(self: *Fixture, io: Io, inner: *Recording, length: u64) !void {
        const pair = try actor.mailbox.new(Message, gpa, io, 4);
        self.io = io;
        self.fake = .{ .receiver = pair.receiver };
        self.app = .init(inner, App.Mailbox.init(gpa, io, pair.sender), length);
        self.task = try io.concurrent(FakeActor.run, .{&self.fake});
    }

    fn deinit(self: *Fixture) void {
        self.app.deinit();
        if (self.task.cancel(self.io)) |_| {} else |_| {}
        self.fake.receiver.deinit();
        if (self.fake.log) |*payload| payload.deinit(gpa);
        if (self.fake.info) |*payload| payload.deinit(gpa);
    }
};

/// `count` chained blocks from genesis; the last may carry `payload` (borrowed).
fn chain(blocks: []Digested, payload: ?App.Payload) !void {
    var raw = mocks.genesis_block(mocks.TestSigner.from_seed(0).public_key());
    for (blocks, 0..) |*block, index| {
        if (index + 1 == blocks.len) if (payload) |value| {
            raw = try raw.with_payload(gpa, 16, value);
        };
        block.* = try Digested.precomputed(gpa, raw, raw.digest());
        raw = mocks.child(block.inner());
    }
}

/// An ancestry headed by `blocks`' last block (copies).
fn ancestry_of(blocks: []const Digested) !Types.Ancestry {
    var handles: [4]Digested = undefined;
    const count = blocks.len;
    for (blocks, 0..) |block, index| handles[count - 1 - index] = block.clone();
    return consensus.marshal.ancestry.from_iter(B, gpa, handles[0..count]);
}

fn free_blocks(blocks: []Digested) void {
    for (blocks) |*block| block.deinit();
}

/// Epoch one's info over seed zero's key alone, dealt from `seed`.
fn epoch_payload(seed: u64) !App.Payload {
    var rng = utils.rng.TestRng.init(seed);
    const key = mocks.TestSigner.from_seed(0).public_key();
    const participants = try Set.from_dedup(gpa, &.{key});
    var dealt = try fd.deal(V, P, N3f1, gpa, &rng, .non_zero_counter, participants);
    for (dealt.shares.values) |*share| share.private.zeroize();
    dealt.shares.deinit(gpa);
    return .{ .epoch_info = .{
        .outcome = .success,
        .epoch = .new(1),
        .output = dealt.output,
        .players = try dealt.output.players.clone(gpa),
        .next_players = try dealt.output.players.clone(gpa),
        .directory = .{},
    } };
}

fn log_payload() !App.Payload {
    return .{ .dealer_log = try inclusion_test.signed_log(0, 2) };
}

// commonware `proposal_skips_unavailable_final_epoch_info` and
// `proposal_includes_available_final_epoch_info`.
test "application: final proposals carry the derived epoch info or none" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var blocks: [1]Digested = undefined;
            try chain(&blocks, null);
            defer free_blocks(&blocks);
            var inner: Recording = .{};
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 2);
            defer f.deinit();
            // Height one is epoch zero's final block.
            try testing.expect(try f.app.propose({}, {}, try ancestry_of(&blocks)) == null);
            try testing.expectEqual(@as(u32, 0), inner.proposals);

            f.fake.info = try epoch_payload(0);
            var proposed = (try f.app.propose({}, {}, try ancestry_of(&blocks))).?;
            defer proposed.deinit();
            try testing.expectEqual(@as(u32, 1), inner.proposals);
            try testing.expect(inner.last_payload.?.eql(f.fake.info.?));
        }
    }.body);
}

// commonware `verification_accepts_equal_final_epoch_info` and
// `verification_rejects_mismatched_final_epoch_info`.
test "application: a final block must carry the derived epoch info" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var carried = try epoch_payload(0);
            defer carried.deinit(gpa);
            var blocks: [2]Digested = undefined;
            try chain(&blocks, carried);
            defer free_blocks(&blocks);
            var inner: Recording = .{};
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 2);
            defer f.deinit();
            f.fake.info = try epoch_payload(1);
            try testing.expect(!try f.app.verify({}, {}, try ancestry_of(&blocks)));
            try testing.expectEqual(@as(u32, 0), inner.verifies);
            f.fake.info.?.deinit(gpa);
            f.fake.info = try carried.clone(gpa);
            try testing.expect(try f.app.verify({}, {}, try ancestry_of(&blocks)));
            try testing.expectEqual(@as(u32, 1), inner.verifies);
        }
    }.body);
}

fn verify_task(app: *App, ancestry: Types.Ancestry) anyerror!bool {
    return app.verify({}, {}, ancestry);
}

// commonware `verification_stays_pending_without_final_epoch_info`, extended by the examples
// lane: a final block whose epoch info the actor cannot derive stays unresolved until consensus
// cancels it, and cancellation releases its ancestry exactly once (a state-synced validator
// hit the double release).
test "application: a canceled pending final verification releases its ancestry once" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var carried = try epoch_payload(0);
            defer carried.deinit(gpa);
            var blocks: [2]Digested = undefined;
            try chain(&blocks, carried);
            defer free_blocks(&blocks);
            var inner: Recording = .{};
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 2);
            defer f.deinit();
            var task = try io.concurrent(verify_task, .{ &f.app, try ancestry_of(&blocks) });
            var waited: u32 = 0;
            while (f.fake.info_requests == 0 and waited < 100) : (waited += 1) try settle(io, &f);
            try testing.expectEqual(@as(u32, 1), f.fake.info_requests);
            try testing.expectError(error.Canceled, task.cancel(io));
            try testing.expectEqual(@as(u32, 0), inner.verifies);
        }
    }.body);
}

/// Whether a block at height `count - 1` carrying `payload` verifies with 4-block epochs.
fn verifies(io: Io, count: usize, payload: App.Payload) !bool {
    var blocks: [4]Digested = undefined;
    try chain(blocks[0..count], payload);
    defer free_blocks(blocks[0..count]);
    var inner: Recording = .{};
    defer inner.deinit();
    var f: Fixture = undefined;
    try f.init(io, &inner, 4);
    defer f.deinit();
    return f.app.verify({}, {}, try ancestry_of(blocks[0..count]));
}

// commonware `verification_rejects_non_final_epoch_info` and
// `verification_gates_dealer_log_by_phase`.
test "application: non-final blocks carry only dealer logs from the midpoint" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var info = try epoch_payload(0);
            defer info.deinit(gpa);
            var dealer_log = try log_payload();
            defer dealer_log.deinit(gpa);
            try testing.expect(!try verifies(io, 3, info));
            try testing.expect(!try verifies(io, 2, dealer_log));
            try testing.expect(try verifies(io, 3, dealer_log));
        }
    }.body);
}

// commonware `proposal_none_releases_dealer_log_reservation` and
// `successful_proposal_keeps_dealer_log_reserved`.
test "application: only an included dealer log stays reserved" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var blocks: [2]Digested = undefined;
            try chain(&blocks, null);
            defer free_blocks(&blocks);
            var inner: Recording = .{ .accept = false };
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 4);
            defer f.deinit();
            f.fake.log = try log_payload();
            // Height two is the midpoint: the declined proposal releases the log.
            try testing.expect(try f.app.propose({}, {}, try ancestry_of(&blocks)) == null);
            try testing.expect(inner.last_payload.? == .dealer_log);
            try settle(io, &f);
            try testing.expectEqual(@as(?u64, 2), height_of(f.fake.released));

            f.fake.released = null;
            inner.accept = true;
            var proposed = (try f.app.propose({}, {}, try ancestry_of(&blocks))).?;
            defer proposed.deinit();
            try settle(io, &f);
            try testing.expect(f.fake.released == null);
            try testing.expect(f.fake.served_at != null);
        }
    }.body);
}

/// Lets the fake actor drain its mailbox.
fn settle(io: Io, f: *Fixture) !void {
    _ = f;
    try io.sleep(.fromMilliseconds(10), .awake);
}

fn height_of(height: ?Height) ?u64 {
    return if (height) |value| value.get() else null;
}

const HandoffTag = std.meta.Tag(consensus.Handoff(Digested));

fn release_handoff(handoff: consensus.Handoff(Digested)) void {
    switch (handoff) {
        .vote, .stage => |block| {
            var owned = block;
            owned.deinit();
        },
        .wait => {},
    }
}

// commonware `prepare_leaves_dealer_log_to_propose`: at the midpoint a prepare that finds this
// node's dealer log declines and releases it for the ordinary proposal; before the midpoint
// the inner application's decision is forwarded.
test "application: prepare leaves a dealer log to propose" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            for ([_]HandoffTag{ .vote, .stage, .wait }) |decision| try check(io, decision);
        }

        fn check(io: Io, decision: HandoffTag) !void {
            var blocks: [2]Digested = undefined;
            try chain(&blocks, null);
            defer free_blocks(&blocks);
            var inner: Recording = .{ .handoff = decision };
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 4);
            defer f.deinit();
            f.fake.log = try log_payload();
            const prepared = try f.app.prepare({}, {}, try ancestry_of(&blocks));
            try testing.expect(prepared.is_wait());
            try testing.expectEqual(@as(u32, 0), inner.prepares);
            try settle(io, &f);
            try testing.expectEqual(@as(?u64, 2), height_of(f.fake.released));
            // The released log is served to the ordinary proposal at the same height.
            var proposed = (try f.app.propose({}, {}, try ancestry_of(&blocks))).?;
            defer proposed.deinit();
            try testing.expect(inner.last_payload.? == .dealer_log);
            // Before the midpoint no dealer log is due, so the decision is forwarded.
            const early = try f.app.prepare({}, {}, try ancestry_of(blocks[0..1]));
            defer release_handoff(early);
            try testing.expectEqual(decision, std.meta.activeTag(early));
            try testing.expectEqual(@as(u32, 1), inner.prepares);
        }
    }.body);
}

// commonware `prepare_leaves_final_block_to_propose`: prepare never builds the epoch's final
// block nor asks for its info; the ordinary proposal does both.
test "application: prepare leaves the final block to propose" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            for ([_]HandoffTag{ .vote, .stage, .wait }) |decision| try check(io, decision);
        }

        fn check(io: Io, decision: HandoffTag) !void {
            var blocks: [1]Digested = undefined;
            try chain(&blocks, null);
            defer free_blocks(&blocks);
            var inner: Recording = .{ .handoff = decision };
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 2);
            defer f.deinit();
            f.fake.info = try epoch_payload(7);
            const prepared = try f.app.prepare({}, {}, try ancestry_of(&blocks));
            try testing.expect(prepared.is_wait());
            try testing.expectEqual(@as(u32, 0), inner.prepares);
            try settle(io, &f);
            try testing.expectEqual(@as(u32, 0), f.fake.info_requests);
            var proposed = (try f.app.propose({}, {}, try ancestry_of(&blocks))).?;
            defer proposed.deinit();
            try testing.expectEqual(@as(u32, 1), f.fake.info_requests);
            try testing.expect(inner.last_payload.? == .epoch_info);
        }
    }.body);
}

fn propose_task(app: *App, ancestry: Types.Ancestry) anyerror!?Digested {
    return app.propose({}, {}, ancestry);
}

// commonware `dropped_proposal_future_releases_dealer_log_reservation`: a proposal canceled
// inside the inner application releases the dealer log it reserved.
test "application: a canceled proposal releases its dealer log" {
    try actor_test.run(struct {
        fn body(io: Io) anyerror!void {
            var blocks: [2]Digested = undefined;
            try chain(&blocks, null);
            defer free_blocks(&blocks);
            var inner: Recording = .{ .pending = io };
            defer inner.deinit();
            var f: Fixture = undefined;
            try f.init(io, &inner, 4);
            defer f.deinit();
            f.fake.log = try log_payload();
            var task = try io.concurrent(propose_task, .{ &f.app, try ancestry_of(&blocks) });
            var waited: u32 = 0;
            while (inner.proposals == 0 and waited < 100) : (waited += 1) try settle(io, &f);
            try testing.expectEqual(@as(u32, 1), inner.proposals);
            try testing.expect(f.fake.released == null);
            try testing.expectError(error.Canceled, task.cancel(io));
            try settle(io, &f);
            try testing.expectEqual(@as(?u64, 2), height_of(f.fake.released));
        }
    }.body);
}
