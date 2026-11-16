//! Model-based fuzz of the delivery tracker: random insert, remove, retain, deliver,
//! redeliver, accept, discard, verdict, and completion operations, checked against a model of
//! each key's entry and each delivery's lifecycle. A delivery's context is its slot id, and a
//! redelivery carries the context of the response it reuses, so each completion is matched to
//! a ready slot with its context.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const p2p = @import("p2p");
const runtime = @import("runtime");
const resolver = @import("root.zig");
const delivery_mod = @import("delivery.zig");
const MockKey = @import("p2p/mocks/key.zig").Key;

const gpa = testing.allocator;
const oneshot = utils.channel.oneshot;
const keys_count = 4;
const steps_max = 64;
const poll_rounds = 4;

/// A consumer that keeps each delivery's verdict sender, indexed by delivery order (which is
/// the slot id the test passes as context).
const Holding = struct {
    pub const Key = MockKey;
    pub const Value = []const u8;
    pub const Subscriber = void;
    pub const Outcome = bool;

    senders: *[steps_max]?oneshot.Sender(bool),
    count: *usize,
    io: Io,

    pub fn deliver(
        self: Holding,
        _: resolver.Delivery(MockKey, void),
        _: []const u8,
    ) Allocator.Error!oneshot.Receiver(bool) {
        const pair = try oneshot.channel(bool, gpa, self.io);
        assert(self.senders[self.count.*] == null);
        self.senders[self.count.*] = pair.sender;
        self.count.* += 1;
        return pair.receiver;
    }
};

const Tracker = delivery_mod.Tracker(Holding, u32, void);

const Verdict = union(enum) { waiting, sent: bool, dropped, refused };

const Slot = struct {
    key: u8,
    /// The context the completion reports.
    context: u32,
    canceled: bool = false,
    closed: bool = false,
    previously_accepted: bool,
    verdict: Verdict = .waiting,
    done: bool = false,

    /// Whether the verdict wait has ended, so a poll returns this slot.
    fn ready(slot: Slot) bool {
        if (slot.done) return false;
        return switch (slot.verdict) {
            .sent, .dropped => true,
            .waiting, .refused => slot.closed,
        };
    }
};

const Entry = struct {
    tracked: bool = false,
    delivery: ?u32 = null,
    /// The cached response: null when none, else whether it was accepted.
    accepted: ?bool = null,
    /// The cached response's context.
    context: u32 = 0,
};

const Model = struct {
    entries: [keys_count]Entry = @splat(.{}),
    slots: [steps_max]Slot = undefined,
    slot_count: u32 = 0,

    fn release(model: *Model, key: usize) void {
        const entry = &model.entries[key];
        if (entry.delivery) |id| model.slots[id].canceled = true;
        entry.* = .{};
    }

    fn live(model: *const Model) usize {
        var count: usize = 0;
        for (model.slots[0..model.slot_count]) |slot| count += @intFromBool(!slot.done);
        return count;
    }
};

const Env = struct {
    io: Io,
    tracker: *Tracker,
    model: *Model,
    senders: *[steps_max]?oneshot.Sender(bool),
};

const KeepAtMost = struct {
    max: u8,
    pub fn call(keep: KeepAtMost, key: MockKey) bool {
        return key.value <= keep.max;
    }
};

/// Delivers a fresh response to `key` (tracking it first if needed), or redelivers its
/// cached response.
fn start(env: Env, key: u8, redeliver: bool) !void {
    const entry = &env.model.entries[key];
    if (!redeliver and !entry.tracked) {
        try testing.expect(try env.tracker.insert(.init(key)));
        entry.tracked = true;
    }
    if (!entry.tracked or entry.delivery != null) return;
    if (redeliver and entry.accepted == null) return;
    const id = env.model.slot_count;
    const delivery: resolver.Delivery(MockKey, void) = .{
        .key = .init(key),
        .subscribers = &.{{}},
    };
    if (redeliver) {
        try env.tracker.redeliver(delivery);
    } else {
        try env.tracker.deliver(delivery, id, "value");
    }
    env.model.slots[id] = .{
        .key = key,
        .context = if (redeliver) entry.context else id,
        .previously_accepted = redeliver and entry.accepted.?,
    };
    if (!redeliver) {
        entry.accepted = false;
        entry.context = id;
    }
    entry.delivery = id;
    env.model.slot_count += 1;
}

/// Sends, drops, or (for a closed receiver) has refused the verdict of slot `selector`.
fn verdict(env: Env, selector: u8, choice: u8) void {
    // Pick among the deliveries whose verdict is still held.
    var held: [steps_max]u32 = undefined;
    var held_count: usize = 0;
    for (env.senders[0..env.model.slot_count], 0..) |sender, id| {
        if (sender == null) continue;
        held[held_count] = @intCast(id);
        held_count += 1;
    }
    if (held_count == 0) return;
    const id = held[selector % held_count];
    var sender = env.senders[id].?;
    env.senders[id] = null;
    const slot = &env.model.slots[id];
    if (choice % 3 == 2) {
        sender.deinit();
        slot.verdict = .dropped;
        return;
    }
    const valid = choice % 3 == 0;
    if (sender.send(valid)) {
        assert(!slot.closed);
        slot.verdict = .{ .sent = valid };
    } else |_| {
        assert(slot.closed);
        slot.verdict = .refused;
    }
}

/// Closes canceled receivers, lets every verdict wait run, then reads every completion and
/// checks it finishes exactly the ready slots, with the model's fields.
fn poll(env: Env) !void {
    const model = env.model;
    env.tracker.close_canceled();
    for (model.slots[0..model.slot_count]) |*slot| {
        if (slot.canceled) slot.closed = true;
    }
    var expected: usize = 0;
    for (model.slots[0..model.slot_count]) |slot| expected += @intFromBool(slot.ready());
    // A verdict task may take more than one scheduling round to queue its slot, so yield a
    // few rounds and read completions as they arrive; slots that are not ready never do.
    var finished: usize = 0;
    for (0..poll_rounds) |_| {
        try env.io.sleep(.fromMilliseconds(1), .real);
        finished += try read_completions(model, env.tracker);
    }
    try testing.expectEqual(expected, finished);
}

/// Reads every completion queued now and matches each to the model; returns the count.
fn read_completions(model: *Model, tracker: *Tracker) !usize {
    var finished: usize = 0;
    // Bounded by the live deliveries.
    while (finished <= steps_max) : (finished += 1) {
        const completion = tracker.try_next_completion() catch |err| {
            try testing.expectEqual(error.Aborted, err);
            // An abort carries no context; it is a canceled slot without a verdict.
            try finish_aborted(model);
            continue;
        } orelse break;
        var done = completion;
        defer done.deinit(gpa);
        try finish(model, done);
    }
    return finished;
}

fn finish(model: *Model, done: Tracker.Done) !void {
    const slot = find_slot(model, done) orelse return error.NoMatchingSlot;
    try testing.expect(slot.ready());
    try testing.expectEqual(slot.key, done.key.value);
    try testing.expectEqual(slot.canceled, done.canceled);
    try testing.expectEqual(slot.previously_accepted, done.previously_accepted);
    switch (slot.verdict) {
        .sent => |valid| try testing.expect(done.outcome.?.eql(.from_bool(valid))),
        else => {
            try testing.expect(done.outcome == null);
            try testing.expect(!slot.canceled); // a canceled slot without a verdict aborts
        },
    }
    slot.done = true;
    if (!slot.canceled) model.entries[slot.key].delivery = null;
}

/// The oldest ready slot with the completion's context, cancellation, and verdict.
fn find_slot(model: *Model, done: Tracker.Done) ?*Slot {
    for (model.slots[0..model.slot_count]) |*slot| {
        if (!slot.ready() or slot.context != done.context) continue;
        if (slot.canceled != done.canceled) continue;
        const sent = slot.verdict == .sent;
        if (sent != (done.outcome != null)) continue;
        if (sent and !done.outcome.?.eql(.from_bool(slot.verdict.sent))) continue;
        return slot;
    }
    return null;
}

/// Marks the oldest ready canceled slot without a verdict done.
fn finish_aborted(model: *Model) !void {
    for (model.slots[0..model.slot_count]) |*slot| {
        if (!slot.ready() or !slot.canceled or slot.verdict == .sent) continue;
        slot.done = true;
        return;
    }
    return error.UnexpectedAbort;
}

fn step(env: Env, op: [3]u8) !void {
    const model = env.model;
    const key: u8 = op[1] % keys_count;
    const entry = &model.entries[key];
    switch (op[0] % 16) {
        0 => {
            try testing.expectEqual(!entry.tracked, try env.tracker.insert(.init(key)));
            entry.tracked = true;
        },
        1 => {
            try testing.expectEqual(entry.tracked, env.tracker.remove(.init(key)));
            model.release(key);
        },
        2 => {
            var removed: usize = 0;
            for (key + 1..keys_count) |value| {
                removed += @intFromBool(model.entries[value].tracked);
                model.release(value);
            }
            try testing.expectEqual(removed, env.tracker.retain(KeepAtMost{ .max = key }));
        },
        3, 4 => try start(env, key, false),
        5, 6 => try start(env, key, true),
        7, 8 => if (entry.accepted != null) {
            env.tracker.accept_response(.init(key));
            entry.accepted = true;
        },
        9 => {
            env.tracker.discard_response(.init(key));
            if (entry.tracked) entry.accepted = null;
        },
        10, 11, 12 => verdict(env, op[1], op[2]),
        else => try poll(env),
    }
}

fn expect_matches(env: Env) !void {
    for (env.model.entries, 0..) |entry, key| {
        try testing.expectEqual(entry.tracked, env.tracker.contains(.init(@intCast(key))));
        const accepted = entry.accepted orelse false;
        try testing.expectEqual(accepted, env.tracker.response_accepted(.init(@intCast(key))));
    }
    try testing.expectEqual(env.model.live(), env.tracker.pending());
}

fn run_ops(io: Io, ops: *const [steps_max][3]u8) !void {
    var senders: [steps_max]?oneshot.Sender(bool) = @splat(null);
    var count: usize = 0;
    defer for (&senders) |*slot| if (slot.*) |*sender| sender.deinit();
    const consumer: Holding = .{ .senders = &senders, .count = &count, .io = io };
    var tracker = try Tracker.init(gpa, io, consumer);
    defer tracker.deinit();
    var model: Model = .{};
    const env: Env = .{ .io = io, .tracker = &tracker, .model = &model, .senders = &senders };
    for (ops) |op| {
        try step(env, op);
        try expect_matches(env);
    }
    try poll(env);
}

fn tracker_model(_: void, smith: *testing.Smith) anyerror!void {
    // Operations come from raw bytes: `Smith.value` maps random words outside small ranges
    // to their minimum, so the seeded driver would otherwise replay one operation.
    var ops: [steps_max][3]u8 = undefined;
    smith.bytes(std.mem.asBytes(&ops));
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = ops[0][0] });
    defer runner.deinit();
    try try runner.start(run_ops, .{ runner.io(), &ops });
}

test "fuzz: delivery tracker matches a model" {
    try p2p.fuzz.run({}, tracker_model, 0x64656c6976657221, 300);
}
