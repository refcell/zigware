//! commonware `deterministic.rs`'s `external` feature tests: a deterministic runner with
//! `Config.external` waits on work outside the runtime, here threads that set an `Io.Event`
//! through a real `std.Io.Threaded`. The real waits are scaled down from commonware's seconds.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const deterministic = @import("deterministic.zig");

const gpa = testing.allocator;

/// A thread that sets `event` through `real` after `delay_ns` of real time.
fn set_later(real: Io, event: *Io.Event, delay_ns: u64) !std.Thread {
    const Setter = struct {
        fn run(io: Io, target: *Io.Event, delay: u64) void {
            io.sleep(.fromNanoseconds(delay), .awake) catch {};
            target.set(io);
        }
    };
    return std.Thread.spawn(.{}, Setter.run, .{ real, event, delay_ns });
}

const Wait = struct {
    fn run(io: Io, event: *Io.Event) !void {
        try event.wait(io);
    }
};

test "an external thread wakes a task (test_external_realtime)" {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    var runner = try deterministic.Runner.init(gpa, .{
        .external = threaded.io(),
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    var event: Io.Event = .unset;
    const thread = try set_later(threaded.io(), &event, 50 * std.time.ns_per_ms);
    defer thread.join();
    try (try runner.start(Wait.run, .{ runner.io(), &event }));
    try testing.expect(event.isSet());
}

test "without external, waiting on an external thread stalls (test_external_simulated)" {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    var runner = try deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    var event: Io.Event = .unset;
    const thread = try set_later(threaded.io(), &event, 50 * std.time.ns_per_ms);
    defer thread.join();
    try testing.expectError(error.Stalled, runner.start(Wait.run, .{ runner.io(), &event }));
}

test "external mode cycles through idle time (test_realtime_no_skip)" {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    // 100 us cycles keep the real sleep short; 50 ms of simulated time is then 500 cycles.
    var runner = try deterministic.Runner.init(gpa, .{
        .external = threaded.io(),
        .cycle_ns = 100 * std.time.ns_per_us,
    });
    defer runner.deinit();
    const Root = struct {
        fn run(io: Io) !void {
            try io.sleep(.fromMilliseconds(50), .awake);
        }
    };
    try (try runner.start(Root.run, .{runner.io()}));
    try testing.expect(runner.iterations >= 450);
}

const real_wait_ns = 200 * std.time.ns_per_ms;

/// Shared by the two paced tasks of the variable-latency test.
const Paced = struct {
    real: Io,
    real_start: Io.Clock.Timestamp,
    sim_start_ns: i96,
    order: [2]u8 = .{ 0, 0 },
    finished: usize = 0,

    fn record(paced: *Paced, io: Io, which: u8, latency_ns: u64, event: *Io.Event) !void {
        try deterministic.pace(io, .fromNanoseconds(latency_ns), event);
        const real_elapsed = paced.real_start.untilNow(paced.real).raw.nanoseconds;
        const sim_elapsed = Io.Clock.awake.now(io).nanoseconds - paced.sim_start_ns;
        if (which == 1) {
            // Sampled before the send: the runtime blocked for it, simulated time did not pass.
            try testing.expect(real_elapsed >= real_wait_ns);
            try testing.expect(sim_elapsed < real_wait_ns);
        } else {
            // Sampled after the send: released only at its simulated deadline.
            try testing.expect(sim_elapsed >= real_wait_ns);
        }
        paced.order[paced.finished] = which;
        paced.finished += 1;
    }
};

test "paced waits surface at their simulated deadline (test_external_realtime_variable)" {
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const real = threaded.io();
    var runner = try deterministic.Runner.init(gpa, .{
        .external = real,
        .timeout_ns = 10 * std.time.ns_per_s,
    });
    defer runner.deinit();
    // Taken before the threads start, so the first one's real wait lands after it.
    var paced: Paced = .{ .real = real, .real_start = .now(real, .awake), .sim_start_ns = 0 };
    var first: Io.Event = .unset;
    var second: Io.Event = .unset;
    const first_thread = try set_later(real, &first, real_wait_ns);
    defer first_thread.join();
    const second_thread = try set_later(real, &second, 0);
    defer second_thread.join();
    const Root = struct {
        fn run(io: Io, shared: *Paced, a: *Io.Event, b: *Io.Event) !void {
            shared.sim_start_ns = Io.Clock.awake.now(io).nanoseconds;
            var one = try io.concurrent(Paced.record, .{ shared, io, 1, 0, a });
            var two = try io.concurrent(Paced.record, .{ shared, io, 2, real_wait_ns, b });
            try two.await(io);
            try one.await(io);
        }
    };
    try (try runner.start(Root.run, .{ runner.io(), &paced, &first, &second }));
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, &paced.order);
}

test "a paced wait in another task keeps its deadline (test_paced_future_moves_between_tasks)" {
    // commonware moves a pending paced future to another task. A Zig wait cannot move, so
    // another task paces an already-set event and must still wait out the latency.
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    var runner = try deterministic.Runner.init(gpa, .{
        .external = threaded.io(),
        .timeout_ns = std.time.ns_per_s,
    });
    defer runner.deinit();
    const Root = struct {
        fn paced(io: Io, event: *Io.Event) !i96 {
            try deterministic.pace(io, .fromMilliseconds(10), event);
            return Io.Clock.awake.now(io).nanoseconds;
        }

        fn run(io: Io, event: *Io.Event) !void {
            const deadline = Io.Clock.awake.now(io).nanoseconds + 10 * std.time.ns_per_ms;
            var task = try io.concurrent(paced, .{ io, event });
            try testing.expect(try task.await(io) >= deadline);
        }
    };
    var event: Io.Event = .is_set;
    try (try runner.start(Root.run, .{ runner.io(), &event }));
}
