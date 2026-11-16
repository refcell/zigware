//! The `queue_operations` fuzz target (commonware `storage/fuzz`): random enqueues, appends,
//! commits, dequeues, acks, resets, and syncs on one queue, checked after every operation
//! against a reference model of positions, publication, acks, and the read position.
//!
//! commonware draws an unbounded operation list; here at most `operations_max` are drawn.
//! One `Queue` holds both commonware's queue and its reader.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const queue_mod = @import("mod.zig");

const gpa = testing.allocator;
const Bytes = []const u8;
const Queue = queue_mod.Queue(Bytes);
const Draws = codec.fuzz.Draws;
const CacheRef = runtime.buffer.paged.CacheRef;

const operations_max = 128;

const Operation = enum { enqueue, append, commit, dequeue, ack, ack_up_to, reset, sync };

/// commonware's `ReferenceQueue`.
const Reference = struct {
    items: [operations_max]u8 = undefined,
    size: u64 = 0,
    /// Items published by a successful commit or sync.
    published: u64 = 0,
    acked: [operations_max]bool = @splat(false),
    read_position: u64 = 0,

    fn append(self: *Reference, value: u8) u64 {
        assert(self.size < operations_max);
        self.items[@intCast(self.size)] = value;
        self.size += 1;
        return self.size - 1;
    }

    fn is_acked(self: *const Reference, position: u64) bool {
        return position < operations_max and self.acked[@intCast(position)];
    }

    fn ack_floor(self: *const Reference) u64 {
        var position: u64 = 0;
        while (position < self.published and self.is_acked(position)) position += 1;
        assert(position <= self.published);
        return position;
    }

    fn dequeue(self: *Reference) ?u64 {
        while (self.read_position < self.published) {
            const position = self.read_position;
            self.read_position += 1;
            if (!self.is_acked(position)) return position;
        }
        return null;
    }

    fn ack(self: *Reference, position: u64) bool {
        if (position >= self.published) return false;
        self.acked[@intCast(position)] = true;
        return true;
    }

    fn ack_up_to(self: *Reference, up_to: u64) bool {
        if (up_to > self.published) return false;
        @memset(self.acked[0..@intCast(up_to)], true);
        return true;
    }
};

const State = struct {
    queue: Queue,
    reference: Reference = .{},

    fn run(self: *State, operation: Operation, value: u8) !void {
        const queue = &self.queue;
        const reference = &self.reference;
        switch (operation) {
            .enqueue => {
                const position = try queue.enqueue(&.{value});
                try testing.expectEqual(reference.append(value), position);
                reference.published = reference.size;
            },
            .append => {
                const position = try queue.append(&.{value});
                try testing.expectEqual(reference.append(value), position);
            },
            .commit => {
                try queue.commit();
                reference.published = reference.size;
            },
            .sync => {
                try queue.sync();
                reference.published = reference.size;
            },
            .dequeue => try self.dequeue(),
            .ack => try self.ack(value % (reference.size + reference.size / 4 + 1), false),
            .ack_up_to => try self.ack(value % (reference.size + reference.size / 4 + 2), true),
            .reset => {
                queue.reset();
                reference.read_position = reference.ack_floor();
            },
        }
    }

    fn dequeue(self: *State) !void {
        const received = try self.queue.try_recv();
        defer if (received) |r| codec.free(Bytes, gpa, r.item);
        const expected = self.reference.dequeue();
        try testing.expectEqual(expected != null, received != null);
        const position = expected orelse return;
        try testing.expectEqual(position, received.?.position);
        const value = self.reference.items[@intCast(position)];
        try testing.expectEqualSlices(u8, &.{value}, received.?.item);
    }

    /// An ack (or `ack_up_to`) either matches the model or fails with `PositionOutOfRange`
    /// without changing the ack state.
    fn ack(self: *State, position: u64, up_to: bool) !void {
        const floor_before = self.queue.floor();
        const read_before = self.queue.read_position();
        const result = if (up_to) self.queue.ack_up_to(position) else self.queue.ack(position);
        const accepted = if (up_to)
            self.reference.ack_up_to(position)
        else
            self.reference.ack(position);
        if (accepted) return result;
        try testing.expectError(error.PositionOutOfRange, result);
        try testing.expectEqual(floor_before, self.queue.floor());
        try testing.expectEqual(read_before, self.queue.read_position());
        if (!up_to) try testing.expect(!self.queue.is_acked(position));
    }

    fn check(self: *const State) !void {
        const reference = &self.reference;
        try testing.expectEqual(reference.size, self.queue.size());
        try testing.expectEqual(reference.ack_floor(), self.queue.floor());
        try testing.expectEqual(reference.read_position, self.queue.read_position());
        const empty = reference.ack_floor() >= reference.published;
        try testing.expectEqual(empty, self.queue.is_empty());
        for (0..@min(reference.size, 20)) |position| {
            try testing.expectEqual(reference.is_acked(position), self.queue.is_acked(position));
        }
    }
};

fn fuzz_operations(_: void, smith: *std.testing.Smith) anyerror!void {
    const draws: Draws = .init(smith);
    const page_size = draws.range_at_most(u16, 1, 256);
    const page_cache_size = draws.range_at_most(u32, 1, 16);
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var storage = runtime.buffer.mocks.Storage.init(gpa);
    defer storage.deinit();
    var state: State = .{
        .queue = try Queue.init(gpa, storage.interface(), .{
            .partition = "queue-operations-fuzz-test",
            .items_per_section = draws.range_at_most(u64, 1, 64),
            .codec_config = .{ .range = .full(), .item = {} },
            .cache_ref = &cache_ref,
            .write_buffer = draws.range_at_most(usize, 1, 2048),
            // Never reopened, so replay never reads: fuzzing this adds no coverage.
            .replay_buffer = 1024,
        }, null),
    };
    defer state.queue.deinit();
    const steps = draws.range_at_most(usize, 0, operations_max);
    for (0..steps) |_| {
        const operation = draws.value(Operation);
        try state.run(operation, draws.value(u8));
        try state.check();
    }
    assert(state.reference.size <= steps);
}

// Seeded inputs in `zig build test`, then `std.testing.fuzz` under `--fuzz`.
test "fuzz queue operations (seeded)" {
    try codec.fuzz.run({}, fuzz_operations, 0x7175657565_6f7073, 100);
}
