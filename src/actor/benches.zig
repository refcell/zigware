//! Mailbox benchmarks, ported from commonware `actor/src/benches/mailbox.rs`, with its names
//! (`mailbox::mailbox::<group>/<params>`, Criterion's group/function ids) and constants.
//!
//! `iter_batched(.., BatchSize::LargeInput)` maps to `before_iter`: the mailbox is built and
//! filled untimed, and the previous one is dropped there too. `recv_waiting` runs on the
//! deterministic runtime, single-threaded like the reference's `block_on`; each message is
//! enqueued only after the receiver has parked. `concurrent_enqueue` builds the mailbox inside
//! the timed loop, like the reference's `iter`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bench = @import("bench");
const actor = @import("actor");
const runtime = @import("runtime");

const mailbox = actor.mailbox;
const Feedback = actor.Feedback;
const U = actor.Unreliable(Feedback);

const capacity_default = 1024;
const messages = 1024;
const producers = 4;
const producer_messages = 16 * 1024;
const replace_capacity = 1024;

/// The reference's bench policy: drop, spill to overflow, or replace the newest pending
/// replace message.
const Message = struct {
    policy: Policy,

    const Policy = enum { drop, spill, replace };

    const drop: Message = .{ .policy = .drop };
    const spill: Message = .{ .policy = .spill };
    const replace: Message = .{ .policy = .replace };

    pub const Overflow = std.Deque(Message);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Message) Allocator.Error!bool {
        switch (message.policy) {
            .drop => return false,
            .spill => try overflow.pushBack(gpa, message),
            .replace => {
                if (newest_replace(overflow)) |pending| {
                    pending.* = message;
                } else {
                    try overflow.pushBack(gpa, message);
                }
            },
        }
        return true;
    }

    /// The newest pending replace message, scanning the deque's two contiguous halves from the
    /// back (the reference's `iter_mut().rev().find`).
    fn newest_replace(overflow: *Overflow) ?*Message {
        const head_len = @min(overflow.len, overflow.buffer.len - overflow.head);
        const halves = [2][]Message{
            overflow.buffer[0 .. overflow.len - head_len],
            overflow.buffer[overflow.head..][0..head_len],
        };
        for (halves) |half| {
            if (last_replace(half)) |index| return &half[index];
        }
        return null;
    }

    /// The index of the last replace message in `half`, scanning its bytes from the back.
    fn last_replace(half: []const Message) ?usize {
        comptime assert(@sizeOf(Message) == 1);
        const bytes: []const u8 = @ptrCast(half);
        const target: u8 = @backingInt(Policy.replace);
        var index = bytes.len;
        // Four bytes per step, as Rust's unrolled slice `rfind` does.
        while (index >= 4) {
            index -= 4;
            inline for (.{ 3, 2, 1, 0 }) |offset| {
                if (bytes[index + offset] == target) return index + offset;
            }
        }
        while (index > 0) {
            index -= 1;
            if (bytes[index] == target) return index;
        }
        return null;
    }
};

const Pair = mailbox.Pair(Message);

fn expect(sender: mailbox.Sender(Message), message: Message, expected: U) !void {
    const result = try sender.enqueue(message);
    assert(result.eql(expected));
    std.mem.doNotOptimizeAway(result);
}

fn fill(sender: mailbox.Sender(Message), count: usize, message: Message, expected: U) !void {
    for (0..count) |_| try expect(sender, message, expected);
}

const Case = enum {
    enqueue_ready,
    try_recv_ready,
    try_recv_overflow,
    round_trip_ready,
    overflow_drop,
    overflow_spill,
    replace_newest,
    replace_oldest,
};

/// A benchmark over one mailbox rebuilt (untimed) before every iteration.
fn Batched(comptime case: Case) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: Io,
        pair: ?Pair = null,

        fn drop_pair(workload: *Self) void {
            if (workload.pair) |*pair| {
                pair.sender.deinit();
                pair.receiver.deinit();
            }
            workload.pair = null;
        }

        pub fn before_iter(workload: *Self) !void {
            workload.drop_pair();
            const capacity: u32 = switch (case) {
                .overflow_drop, .overflow_spill => 1,
                .replace_newest, .replace_oldest => replace_capacity,
                else => capacity_default,
            };
            workload.pair = try mailbox.new(Message, workload.gpa, workload.io, capacity);
            const sender = workload.pair.?.sender;
            switch (case) {
                .enqueue_ready, .round_trip_ready => {},
                .try_recv_ready => try fill(sender, messages, .drop, .new(.ok)),
                .try_recv_overflow => {
                    try fill(sender, capacity_default, .drop, .new(.ok));
                    try fill(sender, messages, .spill, .new(.backoff));
                },
                .overflow_drop, .overflow_spill => try expect(sender, .drop, .new(.ok)),
                .replace_newest, .replace_oldest => {
                    try fill(sender, replace_capacity, .drop, .new(.ok));
                    try expect(sender, .replace, .new(.backoff));
                    if (case == .replace_oldest) {
                        try fill(sender, replace_capacity - 1, .spill, .new(.backoff));
                    }
                },
            }
        }

        pub fn iter(workload: *Self) !void {
            const pair = &workload.pair.?;
            switch (case) {
                .enqueue_ready => try fill(pair.sender, messages, .drop, .new(.ok)),
                .try_recv_ready => try recv_ready(&pair.receiver, messages),
                .try_recv_overflow => try recv_ready(&pair.receiver, capacity_default + messages),
                .round_trip_ready => for (0..messages) |_| {
                    try expect(pair.sender, .drop, .new(.ok));
                    try recv_ready(&pair.receiver, 1);
                },
                .overflow_drop => try fill(pair.sender, messages, .drop, .rejected),
                .overflow_spill => try fill(pair.sender, messages, .spill, .new(.backoff)),
                .replace_newest, .replace_oldest => {
                    try fill(pair.sender, messages, .replace, .new(.backoff));
                },
            }
        }

        pub fn teardown(workload: *Self) void {
            workload.drop_pair();
            assert(workload.pair == null);
        }
    };
}

fn recv_ready(receiver: *mailbox.Receiver(Message), count: usize) !void {
    for (0..count) |_| std.mem.doNotOptimizeAway(try receiver.try_recv());
}

/// `recv_waiting`: every receive parks before its message is enqueued.
const RecvWaiting = struct {
    gpa: Allocator,
    deterministic: ?runtime.deterministic.Runner = null,

    pub fn setup(workload: *RecvWaiting) !void {
        assert(workload.deterministic == null);
        workload.deterministic = try .init(workload.gpa, .{});
    }

    pub fn iter(workload: *RecvWaiting) !void {
        const deterministic = &workload.deterministic.?;
        try (try deterministic.start(round_trips, .{ workload.gpa, deterministic.io() }));
    }

    fn round_trips(gpa: Allocator, io: Io) !void {
        var pair = try mailbox.new(Message, gpa, io, 1);
        defer pair.receiver.deinit();
        defer pair.sender.deinit();
        var parked: u32 = 0;
        var consumer = try io.concurrent(consume, .{ &pair.receiver, &parked });
        errdefer consumer.cancel(io) catch {};
        for (0..messages) |index| {
            // Run the receiver until it parks in `recv` for this message. Single-threaded and
            // cooperative, it only yields once `recv` waits.
            for (0..parked_cycles_max) |_| {
                if (parked > index) break;
                try io.sleep(.fromNanoseconds(1), .awake);
            }
            assert(parked == index + 1);
            try expect(pair.sender, .drop, .new(.ok));
        }
        try consumer.await(io);
        assert(parked == messages);
    }

    /// Scheduler cycles a parked-receiver wait may take (ready tasks run in seeded order).
    const parked_cycles_max = 64;

    fn consume(receiver: *mailbox.Receiver(Message), parked: *u32) Io.Cancelable!void {
        for (0..messages) |_| {
            parked.* += 1;
            const message = try receiver.recv();
            std.mem.doNotOptimizeAway(message.?);
        }
    }

    pub fn teardown(workload: *RecvWaiting) void {
        workload.deterministic.?.deinit();
        workload.deterministic = null;
    }
};

/// `concurrent_enqueue`: `producers` tasks fill one mailbox sized to hold every message.
const ConcurrentEnqueue = struct {
    gpa: Allocator,
    io: Io,

    pub fn iter(workload: *ConcurrentEnqueue) !void {
        const total = producers * producer_messages;
        var pair = try mailbox.new(Message, workload.gpa, workload.io, total);
        defer pair.receiver.deinit();
        defer pair.sender.deinit();
        var group: Io.Group = .init;
        errdefer group.cancel(workload.io);
        for (0..producers) |_| {
            var sender = pair.sender.clone();
            group.concurrent(workload.io, produce, .{sender}) catch |err| {
                sender.deinit();
                return err;
            };
        }
        try group.await(workload.io);
        assert(pair.sender.backoff_total() == 0);
    }

    fn produce(sender: mailbox.Sender(Message)) void {
        var owned = sender;
        defer owned.deinit();
        for (0..producer_messages) |_| {
            // Only the overflow policy allocates, and ready holds every producer's messages.
            const result = owned.enqueue(.drop) catch unreachable;
            assert(result.eql(.new(.ok)));
            std.mem.doNotOptimizeAway(result);
        }
    }
};

fn run_batched(runner: *bench.Runner, comptime case: Case, benchmark: bench.Benchmark) !void {
    var workload: Batched(case) = .{ .gpa = runner.allocator, .io = runner.io };
    try runner.run(benchmark, &workload);
    assert(workload.pair == null);
}

fn benchmark_group(comptime name: []const u8) bench.Benchmark {
    return bench.Benchmark.init("mailbox::mailbox::" ++ name);
}

pub fn run(runner: *bench.Runner) !void {
    const capacity = capacity_default;
    try run_batched(runner, .enqueue_ready, benchmark_group("enqueue_ready")
        .with_param("capacity", capacity));
    try run_batched(runner, .try_recv_ready, benchmark_group("try_recv_ready")
        .with_param("capacity", capacity));
    try run_batched(runner, .try_recv_overflow, benchmark_group("try_recv_overflow")
        .with_param("capacity", capacity).with_param("overflow", messages));
    try run_batched(runner, .round_trip_ready, benchmark_group("round_trip_ready")
        .with_param("capacity", capacity));

    var waiting: RecvWaiting = .{ .gpa = runner.allocator };
    try runner.run(benchmark_group("recv_waiting").with_param("capacity", 1), &waiting);

    try run_batched(runner, .overflow_drop, benchmark_group("overflow_drop")
        .with_param("capacity", 1));
    try run_batched(runner, .overflow_spill, benchmark_group("overflow_spill")
        .with_param("capacity", 1));
    try run_batched(runner, .replace_newest, benchmark_group("overflow_replace")
        .with_param("capacity", replace_capacity).with_param("position", "newest"));
    try run_batched(runner, .replace_oldest, benchmark_group("overflow_replace")
        .with_param("capacity", replace_capacity).with_param("position", "oldest"));

    var concurrent: ConcurrentEnqueue = .{ .gpa = runner.allocator, .io = runner.io };
    try runner.run(benchmark_group("concurrent_enqueue")
        .with_param("producers", producers)
        .with_param("capacity", producers * producer_messages), &concurrent);
}
