//! Tests for `gates.zig`, ported from commonware `marshal/application/gates.rs`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const Sha256 = @import("cryptography").Sha256;
const types = @import("../../types.zig");
const gates = @import("gates.zig");
const soak = @import("../mocks/soak.zig");

const Round = types.Round;
const D = Sha256.Digest;
const GateOutcome = gates.GateOutcome;
const Gate = gates.Gate;
const Ack = gates.Ack;
const oneshot = utils.channel.oneshot;
const gpa = testing.allocator;

/// Blocks are plain numbers.
const TestVariant = struct {
    pub const Block = u64;

    pub fn clone_block(block: *const u64) u64 {
        return block.*;
    }

    pub fn deinit_block(_: Allocator, _: *u64) void {}
};
const TestGates = gates.Gates(D, TestVariant);
const StageFuture = Io.Future(anyerror!void);

fn round(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn hash(bytes: []const u8) D {
    return Sha256.hash(&.{bytes});
}

fn run(seed: u64, comptime body: fn (Io) anyerror!void) ![8]u8 {
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = seed });
    defer runner.deinit();
    try (try runner.start(body, .{runner.io()}));
    return runner.auditor.state();
}

/// A gate whose task already dropped its sender.
fn pending_task(io: Io) !Gate {
    var pair = try oneshot.channel(GateOutcome, gpa, io);
    pair.sender.deinit();
    return pair.receiver;
}

/// Sends the published digest once.
const Publisher = struct {
    sender: ?oneshot.Sender(D),

    pub fn call(self: *Publisher, digest: D) void {
        if (self.sender) |*sender| sender.send(digest) catch {};
        self.sender = null;
    }
};

fn stage_task(
    handle: TestGates,
    view: u64,
    digest: D,
    published: oneshot.Sender(D),
) anyerror!void {
    var owned = handle;
    defer owned.deinit();
    var publisher: Publisher = .{ .sender = published };
    defer if (publisher.sender) |*sender| sender.deinit();
    try owned.stage(round(view), digest, 7, &publisher, "test");
}

/// Stages block 7 at `view` in a task and waits until it publishes `digest`.
fn spawn_stage(io: Io, handle: TestGates, view: u64, digest: D) !StageFuture {
    var published = try oneshot.channel(D, gpa, io);
    defer published.receiver.deinit();
    var future = try io.concurrent(stage_task, .{ handle.clone(), view, digest, published.sender });
    errdefer finish(io, &future);
    try testing.expect((try published.receiver.recv()).eql(digest));
    return future;
}

fn finish(io: Io, future: *StageFuture) void {
    future.cancel(io) catch {};
}

/// Acknowledges a claimed proposal as persisted.
const Persist = struct {
    pub fn call(_: Persist, block: u64, ack: Ack) void {
        assert(block == 7);
        var owned = ack;
        owned.send({}) catch {};
    }
};

const NoPersist = struct {
    pub fn call(_: NoPersist, _: u64, _: Ack) void {
        @panic("a claim must not persist a proposal that was never staged");
    }
};

const NoFallback = struct {
    pub fn call(_: NoFallback) !oneshot.Receiver(bool) {
        @panic("certification must not fall back");
    }
};

const Fallback = struct {
    receiver: oneshot.Receiver(bool),

    pub fn call(self: Fallback) !oneshot.Receiver(bool) {
        return self.receiver;
    }
};

const Identity = struct {
    pub fn call(_: Identity, value: bool) ?bool {
        return value;
    }
};

test "retain after releases in deterministic order" {
    const Body = struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("candidate");
            var futures: [16]StageFuture = undefined;
            for (&futures, 1..) |*future, view| {
                future.* = try spawn_stage(io, registry, view, digest);
            }
            registry.retain_after(round(16));
            // Pruning dropped every ack, so each stage returns.
            for (&futures) |*future| try future.await(io);
        }
    };
    for (0..8) |seed| {
        try testing.expectEqualSlices(u8, &try run(seed, Body.body), &try run(seed, Body.body));
    }
}

test "insert and take" {
    const io = testing.io;
    var registry: TestGates = try .init(gpa, io);
    defer registry.deinit();
    const digest = hash("block");
    try registry.insert(round(1), digest, try pending_task(io));
    var taken = registry.take(round(1), digest).?;
    taken.deinit();
    try testing.expectEqual(null, registry.take(round(1), digest));
    try testing.expectEqual(null, registry.take(round(1), hash("missing")));

    // Rounds and digests are distinct keys.
    const digest_b = hash("b");
    try registry.insert(round(1), digest, try pending_task(io));
    try registry.insert(round(2), digest, try pending_task(io));
    try registry.insert(round(1), digest_b, try pending_task(io));
    for ([_]struct { u64, D }{ .{ 1, digest }, .{ 2, digest }, .{ 1, digest_b } }) |key| {
        var gate = registry.take(round(key[0]), key[1]).?;
        gate.deinit();
    }
}

test "retain after drops at and below the boundary, across epochs" {
    const io = testing.io;
    var registry: TestGates = try .init(gpa, io);
    defer registry.deinit();
    const digest = hash("block");
    registry.retain_after(round(5));
    try testing.expectEqual(null, registry.take(round(5), digest));
    for (1..4) |view| try registry.insert(round(view), digest, try pending_task(io));
    registry.retain_after(round(2));
    try testing.expectEqual(null, registry.take(round(1), digest));
    try testing.expectEqual(null, registry.take(round(2), digest));
    var kept = registry.take(round(3), digest).?;
    kept.deinit();

    const early: Round = .new(.zero(), .new(100));
    const late: Round = .new(.new(1), .zero());
    try registry.insert(early, digest, try pending_task(io));
    try registry.insert(late, digest, try pending_task(io));
    registry.retain_after(early);
    try testing.expectEqual(null, registry.take(early, digest));
    var later = registry.take(late, digest).?;
    later.deinit();
}

test "resolve" {
    try testing.expectEqual(null, gates.resolve(null, true));
    try testing.expectEqual(null, gates.resolve(null, false));
    try testing.expectEqual(false, gates.resolve(false, false).?);
    try testing.expectEqual(false, gates.resolve(false, true).?);
    try testing.expectEqual(true, gates.resolve(true, true).?);
    try testing.expectEqual(null, gates.resolve(true, false));
}

test "forward cancels input when output closes" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var input = try oneshot.channel(bool, gpa, io);
            defer input.sender.deinit();
            var output = try oneshot.channel(bool, gpa, io);
            output.receiver.deinit();
            try gates.forward(bool, bool, io, output.sender, input.receiver, Identity{});
            try testing.expect(input.sender.is_closed());
        }
    }.body);
}

fn forward_task(
    io: Io,
    started: oneshot.Sender(void),
    output: oneshot.Sender(bool),
    input: oneshot.Receiver(bool),
) anyerror!void {
    var signal = started;
    signal.send({}) catch {};
    try gates.forward(bool, bool, io, output, input, Identity{});
}

test "forward cancels in flight input when output closes" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var input = try oneshot.channel(bool, gpa, io);
            defer input.sender.deinit();
            var output = try oneshot.channel(bool, gpa, io);
            var started = try oneshot.channel(void, gpa, io);
            defer started.receiver.deinit();
            var forwarder = try io.concurrent(forward_task, .{
                io,
                started.sender,
                output.sender,
                input.receiver,
            });
            try started.receiver.recv();
            try testing.expect(!input.sender.is_closed());
            output.receiver.deinit();
            try forwarder.await(io);
            try testing.expect(input.sender.is_closed());
        }
    }.body);
}

test "a canceled forward stops its waits before returning" {
    // A crash cancels a forward that waits on both channels; its select branches must end
    // before the frame that owns them, or they later touch freed memory.
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var input = try oneshot.channel(bool, gpa, io);
            defer input.sender.deinit();
            var output = try oneshot.channel(bool, gpa, io);
            defer output.receiver.deinit();
            var started = try oneshot.channel(void, gpa, io);
            defer started.receiver.deinit();
            var forwarder = try io.concurrent(forward_task, .{
                io,
                started.sender,
                output.sender,
                input.receiver,
            });
            try started.receiver.recv();
            try io.sleep(.fromMilliseconds(1), .awake);
            try testing.expectError(error.Canceled, forwarder.cancel(io));
            try testing.expect(input.sender.is_closed());
            try testing.expectError(error.Closed, output.receiver.recv());
        }
    }.body);
}

test "drive adopts a ready verdict without fallback" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            for ([_]bool{ true, false }) |verdict| {
                var task = try oneshot.channel(GateOutcome, gpa, io);
                try task.sender.send(.{ .ready = verdict });
                var published = try oneshot.channel(bool, gpa, io);
                defer published.receiver.deinit();
                try gates.drive(io, published.sender, task.receiver, NoFallback{});
                try testing.expectEqual(verdict, try published.receiver.recv());
            }
        }
    }.body);
}

test "drive recovers through the fallback" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            // A recover outcome, then a dropped gate sender, each publish the fallback verdict.
            for ([_]bool{ true, false }) |recover| {
                var task = try oneshot.channel(GateOutcome, gpa, io);
                if (recover) try task.sender.send(.recover) else task.sender.deinit();
                var fallback = try oneshot.channel(bool, gpa, io);
                try fallback.sender.send(recover);
                var published = try oneshot.channel(bool, gpa, io);
                defer published.receiver.deinit();
                const recovery: Fallback = .{ .receiver = fallback.receiver };
                try gates.drive(io, published.sender, task.receiver, recovery);
                try testing.expectEqual(recover, try published.receiver.recv());
            }
        }
    }.body);
}

test "drive abandons when the consensus receiver is dropped" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var task = try oneshot.channel(GateOutcome, gpa, io);
            defer task.sender.deinit();
            var published = try oneshot.channel(bool, gpa, io);
            published.receiver.deinit();
            try gates.drive(io, published.sender, task.receiver, NoFallback{});
            try testing.expect(task.sender.is_closed());
        }
    }.body);
}

test "stage handshake" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            // The digest is published only after the gate and staged block are registered.
            var stage = try spawn_stage(io, registry, 1, digest);
            var gate = registry.take(round(1), digest).?;
            defer gate.deinit();
            const staged, const sent = (try registry.take_staged(round(1), digest)).?;
            try testing.expectEqual(7, staged.block);
            try testing.expect(!sent);
            try testing.expectEqual(null, try registry.take_staged(round(1), digest));
            // Acknowledging the persist resolves the gate.
            var ack = staged.ack;
            try ack.send({});
            try testing.expectEqual(GateOutcome{ .ready = true }, try gate.recv());
            try stage.await(io);
        }
    }.body);
}

/// Persists the claimed proposal after staging the same block again, as a concurrent build
/// would, and keeps that second stage pending.
const RestagePersist = struct {
    io: Io,
    registry: TestGates,
    restage: *?StageFuture,

    pub fn call(self: RestagePersist, block: u64, ack: Ack) void {
        assert(block == 7);
        var owned = ack;
        self.restage.* = spawn_stage(self.io, self.registry, 1, hash("block")) catch null;
        owned.send({}) catch {};
    }
};

test "claim takes the gate with its staged proposal" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            var stage = try spawn_stage(io, registry, 1, digest);
            var restage: ?StageFuture = null;
            var gate = registry.claim(round(1), digest, RestagePersist{
                .io = io,
                .registry = registry,
                .restage = &restage,
            }).?;
            defer gate.deinit();
            try testing.expect(restage != null);
            defer finish(io, &restage.?);
            // The first stage finishes once its proposal is durable, so the claimed gate
            // already holds its outcome.
            try stage.await(io);
            try testing.expectEqual(GateOutcome{ .ready = true }, try gate.try_recv());
        }
    }.body);
}

fn expect_claim_releases_other_gates(certified_has_gate: bool) !void {
    const io = testing.io;
    var registry: TestGates = try .init(gpa, io);
    defer registry.deinit();
    const certified = hash("certified");
    const conflicting = hash("conflicting");
    var channels: [4]oneshot.Pair(GateOutcome) = undefined;
    for (&channels) |*pair| pair.* = try oneshot.channel(GateOutcome, gpa, io);
    defer for (channels[1..]) |*pair| pair.sender.deinit();
    defer channels[0].sender.deinit();
    if (certified_has_gate) {
        try registry.insert(round(2), certified, channels[0].receiver);
    } else {
        channels[0].receiver.deinit();
    }
    try registry.insert(round(2), conflicting, channels[1].receiver);
    try registry.insert(round(1), conflicting, channels[2].receiver);
    try registry.insert(round(3), conflicting, channels[3].receiver);

    // No proposal is staged, so nothing is persisted.
    var gate = registry.claim(round(2), certified, NoPersist{});
    defer if (gate) |*claimed| claimed.deinit();
    try testing.expectEqual(certified_has_gate, gate != null);
    // The round's other gate was dropped; earlier and later rounds keep theirs.
    try testing.expect(channels[1].sender.is_closed());
    try testing.expect(!channels[2].sender.is_closed());
    try testing.expect(!channels[3].sender.is_closed());
}

test "claim releases the other gates of its round" {
    try expect_claim_releases_other_gates(true);
    try expect_claim_releases_other_gates(false);
}

test "send staged marks sent and keeps the entry" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            var first = try spawn_stage(io, registry, 1, digest);
            try testing.expectEqual(null, try registry.send_staged(round(1), hash("other")));
            try testing.expectEqual(7, (try registry.send_staged(round(1), digest)).?);
            // Staging the same block again replaces the first stage's ack, ending it.
            var second = try spawn_stage(io, registry, 1, digest);
            defer finish(io, &second);
            try first.await(io);
            // A sent block is not handed out for another send.
            try testing.expectEqual(null, try registry.send_staged(round(1), digest));
            // The entry survives, so the lock-in broadcast only persists it.
            var staged, const sent = (try registry.take_staged(round(1), digest)).?;
            staged.ack.deinit();
            try testing.expect(sent);
        }
    }.body);
}

test "restaging after a take or a claim stays sent" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            // The lock-in broadcast takes an unsent block and sends it.
            var first = try spawn_stage(io, registry, 1, digest);
            defer finish(io, &first);
            var taken, const unsent = (try registry.take_staged(round(1), digest)).?;
            taken.ack.deinit();
            try testing.expect(!unsent);
            var again = try spawn_stage(io, registry, 1, digest);
            defer finish(io, &again);
            try testing.expectEqual(null, try registry.send_staged(round(1), digest));
            var retaken, const sent = (try registry.take_staged(round(1), digest)).?;
            retaken.ack.deinit();
            try testing.expect(sent);

            // Certification claims a block that a prepare broadcast sent.
            var second = try spawn_stage(io, registry, 2, digest);
            defer finish(io, &second);
            try testing.expect(try registry.send_staged(round(2), digest) != null);
            var gate = registry.claim(round(2), digest, Persist{});
            if (gate) |*claimed| claimed.deinit();
            var restaged = try spawn_stage(io, registry, 2, digest);
            defer finish(io, &restaged);
            try testing.expectEqual(null, try registry.send_staged(round(2), digest));
            var claimed_again, const claimed_sent = (try registry.take_staged(round(2), digest)).?;
            claimed_again.ack.deinit();
            try testing.expect(claimed_sent);
        }
    }.body);
}

test "the retain cutoff suppresses sends" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            // A later, lower prune cannot lower the cutoff.
            registry.retain_after(round(2));
            registry.retain_after(round(1));
            var at_cutoff = try spawn_stage(io, registry, 2, digest);
            defer finish(io, &at_cutoff);
            var above = try spawn_stage(io, registry, 3, digest);
            defer finish(io, &above);
            try testing.expectEqual(null, try registry.send_staged(round(2), digest));
            var staged, const sent = (try registry.take_staged(round(2), digest)).?;
            staged.ack.deinit();
            try testing.expect(sent);
            try testing.expect(try registry.send_staged(round(3), digest) != null);
        }
    }.body);
}

test "retain after drops staged proposals and abandons the handshake" {
    try soak.run_io(gpa, .{ .seed = 0 }, struct {
        fn body(io: Io) anyerror!void {
            var registry: TestGates = try .init(gpa, io);
            defer registry.deinit();
            const digest = hash("block");
            var stage = try spawn_stage(io, registry, 1, digest);
            var gate = registry.take(round(1), digest).?;
            defer gate.deinit();
            try testing.expect(try registry.send_staged(round(1), digest) != null);
            registry.retain_after(round(1));
            try testing.expectEqual(null, try registry.take_staged(round(1), digest));
            try testing.expectEqual(0, registry.sent_count());
            // The dropped ack ends the stage without resolving the gate.
            try stage.await(io);
            try testing.expectError(error.Closed, gate.recv());
        }
    }.body);
}
