//! Engine tests, ported from commonware `collector/src/p2p/mod.rs`, on the simulated network
//! and the deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");

const engine_module = @import("engine.zig");
const mocks = @import("mocks.zig");

const metrics = runtime.telemetry.metrics;
const Key = cryptography.ed25519.PublicKey;
const Net = p2p.simulated.Network(Key);
const Request = mocks.types.Request;
const Response = mocks.types.Response;
const TestEngine = engine_module.Engine(mocks.Handler, mocks.Monitor, Net.Control, Net);
const Config = engine_module.Config(Net.Control, mocks.Monitor, mocks.Handler);
const Mailbox = TestEngine.Mailbox;
const Feedback = p2p.Feedback;
const gpa = testing.allocator;

/// Requests go through a sender that always fails.
const FailingNet = struct {
    pub const Sender = Net.Sender;
    pub const RequestSender = mocks.Failing;
    pub const Receiver = Net.Receiver;
};
const FailingEngine = engine_module.Engine(mocks.Handler, mocks.Monitor, Net.Control, FailingNet);

/// High enough to not interfere with normal operation.
const test_quota = p2p.Quota.per_second(1_000_000);
const mailbox_size = 1024;
const peers_max = 3;

fn link_ms(latency_ms: u64) p2p.simulated.Link {
    return .{
        .latency = utils.Duration.from_millis(latency_ms),
        .jitter = utils.Duration.from_millis(1),
        .success_rate = 1.0,
    };
}
const link = link_ms(10);
const link_slow = link_ms(1_000);

fn sleep_ms(io: Io, ms: u64) !void {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

/// A simulated network whose peers each register a request (0) and a response (1) channel.
const Sim = struct {
    io: Io,
    network: *Net,
    network_task: Io.Future((Io.Cancelable || Allocator.Error)!void),
    registry: *metrics.Registry,
    peers: [peers_max]Key = undefined,
    count: usize,
    requests: [peers_max]?Net.Registered = @splat(null),
    responses: [peers_max]?Net.Registered = @splat(null),
    mailboxes: [peers_max]?Mailbox = @splat(null),
    engines: [peers_max]?Io.Future(TestEngine.Error!void) = @splat(null),

    fn init(io: Io, seeds: []const u64) !*Sim {
        assert(seeds.len <= peers_max);
        const network = try Net.init(gpa, io, .{
            .max_size = 1024 * 1024,
            .max_peers_per_set = seeds.len,
            .disconnect_on_block = true,
            .tracked_peer_sets = 1,
        });
        const registry = try gpa.create(metrics.Registry);
        registry.* = .init(gpa);
        const sim = try gpa.create(Sim);
        sim.* = .{
            .io = io,
            .network = network,
            .network_task = try io.concurrent(Net.run, .{network}),
            .registry = registry,
            .count = seeds.len,
        };
        for (seeds, 0..) |seed, index| {
            const peer = cryptography.ed25519.PrivateKey.from_seed(seed).public_key();
            sim.peers[index] = peer;
            const control = network.oracle().control(peer);
            sim.requests[index] = try control.register(0, test_quota);
            sim.responses[index] = try control.register(1, test_quota);
        }
        var sorted: [peers_max]Key = undefined;
        @memcpy(sorted[0..sim.count], sim.peers[0..sim.count]);
        std.sort.pdq(Key, sorted[0..sim.count], {}, Key.less_than);
        const tracked: p2p.TrackedPeers(Key) = .init_primary(.init(sorted[0..sim.count]));
        try testing.expectEqual(Feedback.ok, network.oracle().manager().track(0, tracked));
        return sim;
    }

    /// Links `from` and `to` both ways.
    fn add_link(sim: *Sim, value: p2p.simulated.Link, from: usize, to: usize) !void {
        const oracle = sim.network.oracle();
        try oracle.add_link(sim.peers[from], sim.peers[to], value);
        try oracle.add_link(sim.peers[to], sim.peers[from], value);
    }

    fn config(sim: *Sim, index: usize, monitor: mocks.Monitor, handler: mocks.Handler) Config {
        return .{
            .blocker = sim.network.oracle().control(sim.peers[index]),
            .monitor = monitor,
            .handler = handler,
            .mailbox_size = mailbox_size,
            .priority_request = false,
            .request_codec = {},
            .priority_response = false,
            .response_codec = {},
        };
    }

    fn scope(sim: *Sim, index: usize) metrics.Scope {
        return metrics.Scope.init(sim.registry).child("engine")
            .with_attribute("public_key", sim.peers[index]);
    }

    fn take(slot: *?Net.Registered) Net.Registered {
        const registered = slot.*.?;
        slot.* = null;
        return registered;
    }

    /// Starts peer `index`'s engine on its channels and returns its mailbox.
    fn spawn(sim: *Sim, index: usize, monitor: mocks.Monitor, handler: mocks.Handler) !Mailbox {
        const engine_scope = sim.scope(index);
        const config_value = sim.config(index, monitor, handler);
        const created = try TestEngine.init(gpa, sim.io, &engine_scope, config_value);
        const requests = take(&sim.requests[index]);
        const responses = take(&sim.responses[index]);
        sim.engines[index] = try created.engine.start(
            requests.sender,
            requests.receiver,
            responses.sender,
            responses.receiver,
        );
        sim.mailboxes[index] = created.mailbox;
        return created.mailbox;
    }

    /// Stops peer `index`'s engine (commonware `Handle::abort`).
    fn abort(sim: *Sim, index: usize) void {
        if (sim.engines[index]) |*future| {
            future.cancel(sim.io) catch |err| std.debug.panic("engine: {t}", .{err});
        }
        sim.engines[index] = null;
    }

    fn deinit(sim: *Sim) void {
        for (0..sim.count) |index| {
            sim.abort(index);
            if (sim.mailboxes[index]) |*value| value.deinit();
            if (sim.requests[index]) |*value| value.deinit();
            if (sim.responses[index]) |*value| value.deinit();
        }
        sim.network.close();
        sim.network_task.await(sim.io) catch |err| std.debug.panic("run: {t}", .{err});
        sim.network.deinit();
        sim.registry.deinit();
        gpa.destroy(sim.registry);
        gpa.destroy(sim);
    }
};

fn run_deterministic(seed: u64, comptime function: fn (Io) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, .{ .seed = seed }, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try (try runner.start(function, .{runner.io()}));
        }
    }.run);
}

/// Asserts that no event arrives within `ms` (commonware's `select!` against a sleep).
fn expect_quiet(io: Io, events: anytype, ms: u64) !void {
    try sleep_ms(io, ms);
    try testing.expectError(error.Empty, events.try_recv());
}

fn expect_send(mailbox: Mailbox, recipients: p2p.Recipients(Key), request: Request) !void {
    try testing.expectEqual(Feedback.ok, try mailbox.send(recipients, request));
}

test "send and collect response" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            var handler = try mocks.Handler.init(gpa, io, true);
            defer handler.events.deinit();
            _ = try sim.spawn(1, .dummy(), handler.handler);

            const request: Request = .{ .id = 1, .data = 1 };
            try expect_send(mailbox, .{ .one = sim.peers[1] }, request);
            const processed = (try handler.events.recv()).?;
            try testing.expect(processed.origin.eql(sim.peers[0]));
            try testing.expectEqual(request, processed.request);
            try testing.expect(processed.responded);
            const collected = (try monitor.events.recv()).?;
            try testing.expect(collected.handler.eql(sim.peers[1]));
            try testing.expectEqual(Response{ .id = 1, .result = 2 }, collected.response);
            try testing.expectEqual(@as(usize, 1), collected.count);
        }
    }.run);
}

test "cancel request" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link_slow, 0, 1);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            var handler = try mocks.Handler.init(gpa, io, true);
            defer handler.events.deinit();
            _ = try sim.spawn(1, .dummy(), handler.handler);

            const request: Request = .{ .id = 1, .data = 1 };
            try expect_send(mailbox, .{ .one = sim.peers[1] }, request);
            try testing.expectEqual(Feedback.ok, try mailbox.cancel(request.commitment()));
            try expect_quiet(io, &monitor.events, 5_000);
        }
    }.run);
}

test "broadcast request" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1, 2 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            try sim.add_link(link, 0, 2);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            _ = try sim.spawn(1, .dummy(), .dummy());
            _ = try sim.spawn(2, .dummy(), .dummy());

            try expect_send(mailbox, .all, .{ .id = 3, .data = 3 });
            var responded = [_]bool{ false, false };
            for (0..2) |collected_count| {
                const collected = (try monitor.events.recv()).?;
                try testing.expectEqual(Response{ .id = 3, .result = 6 }, collected.response);
                try testing.expectEqual(collected_count + 1, collected.count);
                for (1..3) |index| {
                    if (collected.handler.eql(sim.peers[index])) responded[index - 1] = true;
                }
            }
            try testing.expect(responded[0] and responded[1]);
        }
    }.run);
}

test "duplicate response ignored" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            _ = try sim.spawn(1, .dummy(), .dummy());

            const request: Request = .{ .id = 5, .data = 5 };
            for (0..3) |_| try expect_send(mailbox, .{ .one = sim.peers[1] }, request);
            const collected = (try monitor.events.recv()).?;
            try testing.expect(collected.handler.eql(sim.peers[1]));
            try testing.expectEqual(@as(u64, 5), collected.response.id);
            try testing.expectEqual(@as(usize, 1), collected.count);
            try expect_quiet(io, &monitor.events, 5_000);
        }
    }.run);
}

test "concurrent requests" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            var handler = try mocks.Handler.init(gpa, io, false);
            defer handler.events.deinit();
            const responses = [_]Response{
                .{ .id = 10, .result = 20 },
                .{ .id = 20, .result = 40 },
            };
            handler.handler.responses = &responses;
            _ = try sim.spawn(1, .dummy(), handler.handler);

            try expect_send(mailbox, .{ .one = sim.peers[1] }, .{ .id = 10, .data = 10 });
            try expect_send(mailbox, .{ .one = sim.peers[1] }, .{ .id = 20, .data = 20 });
            var received = [_]bool{ false, false };
            for (0..2) |_| {
                const collected = (try monitor.events.recv()).?;
                try testing.expect(collected.handler.eql(sim.peers[1]));
                try testing.expectEqual(@as(usize, 1), collected.count);
                switch (collected.response.id) {
                    10 => received[0] = collected.response.result == 20,
                    20 => received[1] = collected.response.result == 40,
                    else => return error.UnexpectedResponse,
                }
            }
            try testing.expect(received[0] and received[1]);
        }
    }.run);
}

test "handler no response" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            var handler = try mocks.Handler.init(gpa, io, false);
            defer handler.events.deinit();
            _ = try sim.spawn(1, .dummy(), handler.handler);

            const request: Request = .{ .id = 100, .data = 100 };
            try expect_send(mailbox, .{ .one = sim.peers[1] }, request);
            const processed = (try handler.events.recv()).?;
            try testing.expect(processed.origin.eql(sim.peers[0]));
            try testing.expectEqual(request, processed.request);
            try testing.expect(!processed.responded);
            try expect_quiet(io, &monitor.events, 1_000);
        }
    }.run);
}

test "empty recipients" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{0});
            defer sim.deinit();
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            try expect_send(mailbox, .all, .{ .id = 1, .data = 1 });
            try expect_quiet(io, &monitor.events, 1_000);
        }
    }.run);
}

test "send closed does not collect" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            var requests = Sim.take(&sim.requests[0]);
            requests.sender.deinit(); // replaced by the failing sender
            const responses = Sim.take(&sim.responses[0]);
            const engine_scope = sim.scope(0);
            const config = sim.config(0, .dummy(), .dummy());
            const created = try FailingEngine.init(gpa, io, &engine_scope, config);
            var mailbox = created.mailbox;
            defer mailbox.deinit();
            var future = try created.engine.start(
                .{ .gpa = gpa },
                requests.receiver,
                responses.sender,
                responses.receiver,
            );
            try testing.expectEqual(
                Feedback.ok,
                try mailbox.send(.{ .one = sim.peers[1] }, .{ .id = 1, .data = 1 }),
            );
            try sleep_ms(io, 100);
            try future.cancel(io);
        }
    }.run);
}

test "send after shutdown returns closed" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            const mailbox = try sim.spawn(0, .dummy(), .dummy());
            sim.abort(0);
            const feedback = try mailbox.send(.{ .one = sim.peers[1] }, .{ .id = 1, .data = 1 });
            try testing.expectEqual(Feedback.closed, feedback);
        }
    }.run);
}

test "response from unknown peer" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1, 2 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            try sim.add_link(link, 0, 2);
            try sim.add_link(link, 1, 2);
            var monitor = try mocks.Monitor.init(gpa, io);
            defer monitor.events.deinit();
            const mailbox = try sim.spawn(0, monitor.monitor, .dummy());
            _ = try sim.spawn(1, .dummy(), .dummy());

            // Peer 0 asks peer 1; peer 2 answers the same commitment unasked.
            try expect_send(mailbox, .{ .one = sim.peers[1] }, .{ .id = 42, .data = 42 });
            const forged = codec.encode_fixed(Response, .{ .id = 42, .result = 72 });
            const sender = &sim.responses[2].?.sender;
            gpa.free(try sender.send(.{ .one = sim.peers[0] }, &.{&forged}, true));
            try sleep_ms(io, 1_000);

            // Only peer 1's response (42 * 2) is collected.
            const collected = (try monitor.events.recv()).?;
            try testing.expect(collected.handler.eql(sim.peers[1]));
            try testing.expectEqual(Response{ .id = 42, .result = 84 }, collected.response);
            try testing.expectEqual(@as(usize, 1), collected.count);
            try expect_quiet(io, &monitor.events, 1_000);
        }
    }.run);
}

test "operations after shutdown do not panic" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            const mailbox = try sim.spawn(0, .dummy(), .dummy());
            _ = try sim.spawn(1, .dummy(), .dummy());
            sim.abort(0);
            sim.abort(1);
            const request: Request = .{ .id = 1, .data = 1 };
            const sent = try mailbox.send(.{ .one = sim.peers[1] }, request);
            try testing.expectEqual(Feedback.closed, sent);
            try testing.expectEqual(Feedback.closed, try mailbox.cancel(request.commitment()));
        }
    }.run);
}

fn clean_shutdown(seed: u64) !void {
    try run_deterministic(seed, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            try sim.add_link(link, 0, 1);
            const mailbox = try sim.spawn(0, .dummy(), .dummy());
            _ = try sim.spawn(1, .dummy(), .dummy());
            try sleep_ms(io, 100);
            try expect_send(mailbox, .{ .one = sim.peers[1] }, .{ .id = 1, .data = 1 });
            // Aborting frees each engine and everything it owns (the allocator checks).
            sim.abort(0);
            sim.abort(1);
            try sleep_ms(io, 100);
        }
    }.run);
}

test "clean shutdown" {
    for (0..25) |seed| try clean_shutdown(seed);
}

test "engine stops once every mailbox is dropped (pr 5153 regression)" {
    try run_deterministic(0, struct {
        fn run(io: Io) !void {
            const sim = try Sim.init(io, &.{ 0, 1 });
            defer sim.deinit();
            _ = try sim.spawn(0, .dummy(), .dummy());
            sim.mailboxes[0].?.deinit();
            sim.mailboxes[0] = null;
            try sim.engines[0].?.await(io);
            sim.engines[0] = null;
        }
    }.run);
}
