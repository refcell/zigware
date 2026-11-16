//! Tests of the queue, ported from commonware's `queue/storage.rs` (ten items per section,
//! 1024-byte pages, a 10-page cache, 4096-byte buffers).
//!
//! commonware's reader is a separate handle; here the queue is both, so reader tests call the
//! queue. Tests of `recv` waiting, `select!`, and dropping an in-flight mutation have no
//! counterpart, since nothing runs concurrently with the journal.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const mocks = runtime.buffer.mocks;
const paged = runtime.buffer.paged;
const queue_mod = @import("mod.zig");

const gpa = testing.allocator;
const Bytes = []const u8;
const Queue = queue_mod.Queue(Bytes);
const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full(), .item = {} };

const Harness = struct {
    storage: mocks.Storage,
    cache_ref: paged.CacheRef,
    partition: []const u8,

    fn init(partition: []const u8) !Harness {
        return .{
            .storage = mocks.Storage.init(gpa),
            .cache_ref = try paged.CacheRef.init(gpa, 1024, 10),
            .partition = partition,
        };
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn cfg(self: *Harness) queue_mod.Config(Bytes) {
        return .{
            .partition = self.partition,
            .items_per_section = 10,
            .codec_config = bytes_cfg,
            .cache_ref = &self.cache_ref,
            .write_buffer = 4096,
            .replay_buffer = 4096,
        };
    }

    fn open(self: *Harness) !Queue {
        return Queue.init(gpa, self.storage.interface(), self.cfg(), null);
    }
};

/// Enqueue `[i]` for each `i` in `[start, end)`.
fn enqueue_range(queue: *Queue, start: u8, end: u8) !void {
    for (start..end) |value| {
        const item = [_]u8{@intCast(value)};
        try testing.expectEqual(value, try queue.enqueue(&item));
    }
}

/// Receive the next item, check its position and single-byte contents, and free it.
fn expect_recv(queue: *Queue, position: u64, value: u8) !void {
    const received = (try queue.try_recv()).?;
    defer codec.free(Bytes, gpa, received.item);
    try testing.expectEqual(position, received.position);
    try testing.expectEqualSlices(u8, &.{value}, received.item);
}

/// Receive and free the next item, returning its position.
fn recv_position(queue: *Queue) !u64 {
    const received = (try queue.try_recv()).?;
    codec.free(Bytes, gpa, received.item);
    return received.position;
}

test "queue: basic enqueue and dequeue" {
    var h = try Harness.init("test_basic");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try testing.expect(queue.is_empty());
    try testing.expectEqual(0, queue.pending());
    try testing.expectEqual(0, queue.size());
    const names = [_]Bytes{ "item0", "item1", "item2" };
    for (names, 0..) |name, position| try testing.expectEqual(position, try queue.enqueue(name));
    try testing.expectEqual(3, queue.size());
    try testing.expectEqual(3, queue.pending());
    try testing.expect(!queue.is_empty());
    for (names, 0..) |name, position| {
        const received = (try queue.try_recv()).?;
        defer codec.free(Bytes, gpa, received.item);
        try testing.expectEqual(position, received.position);
        try testing.expectEqualSlices(u8, name, received.item);
        try testing.expectEqual(2 - position, queue.pending());
    }
    // Delivered but unacknowledged items keep the queue non-empty.
    try testing.expect(!queue.is_empty());
    try testing.expectEqual(null, try queue.try_recv());
}

test "queue: append then commit a batch" {
    var h = try Harness.init("test_batch");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    for (0..5) |value| _ = try queue.append(&.{@intCast(value)});
    // Appended items are invisible until committed.
    try testing.expectEqual(null, try queue.try_recv());
    try queue.commit();
    try testing.expectEqual(5, queue.size());
    for (0..5) |value| try expect_recv(&queue, value, @intCast(value));
    for (5..8) |value| _ = try queue.append(&.{@intCast(value)});
    try queue.commit();
    try testing.expectEqual(8, try queue.enqueue(&.{8}));
    try testing.expectEqual(9, queue.size());
    try queue.ack_up_to(9);
    try testing.expect(queue.is_empty());
}

test "queue: committed batch persists" {
    var h = try Harness.init("test_batch_persist");
    defer h.deinit();
    var queue = try h.open();
    for (0..4) |value| _ = try queue.append(&.{@intCast(value)});
    try queue.commit();
    try queue.sync();
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(4, queue.size());
    for (0..4) |value| try expect_recv(&queue, value, @intCast(value));
}

test "queue: commit after sync recovers without a second sync" {
    var h = try Harness.init("test_commit_after_sync_recovery");
    defer h.deinit();
    var queue = try h.open();
    // A synced baseline leaves the recovery watermark behind the next commit.
    _ = try queue.append("synced");
    try queue.commit();
    try queue.sync();
    _ = try queue.append("committed-a");
    _ = try queue.append("committed-b");
    try queue.commit();
    queue.deinit();
    h.storage.crash();
    queue = try h.open();
    try testing.expectEqual(3, queue.size());
    for ([_]Bytes{ "synced", "committed-a", "committed-b" }, 0..) |expected, position| {
        const received = (try queue.try_recv()).?;
        defer codec.free(Bytes, gpa, received.item);
        try testing.expectEqual(position, received.position);
        try testing.expectEqualSlices(u8, expected, received.item);
    }
    try queue.destroy();
}

test "queue: sequential ack" {
    var h = try Harness.init("test_seq_ack");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 5);
    for (0..5) |position| {
        try testing.expectEqual(position, try recv_position(&queue));
        try queue.ack(position);
        try testing.expectEqual(position + 1, queue.floor());
    }
    try testing.expect(queue.is_empty());
    try testing.expectEqual(5, queue.floor());
}

test "queue: out-of-order ack" {
    var h = try Harness.init("test_ooo_ack");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 5);
    for (0..5) |_| _ = try recv_position(&queue);
    for ([_]u64{ 2, 4, 1, 3 }) |position| {
        try queue.ack(position);
        try testing.expectEqual(0, queue.floor());
        try testing.expect(queue.is_acked(position));
    }
    // Acking 0 consumes 1 through 4.
    try queue.ack(0);
    try testing.expectEqual(5, queue.floor());
    try testing.expect(queue.is_empty());
}

test "queue: ack up to" {
    var h = try Harness.init("test_ack_up_to");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    try queue.ack_up_to(5);
    try testing.expectEqual(5, queue.floor());
    for (0..5) |position| try testing.expect(queue.is_acked(position));
    for (5..10) |position| try testing.expect(!queue.is_acked(position));
    try testing.expectEqual(5, try recv_position(&queue));
}

test "queue: ack up to with existing acks" {
    var h = try Harness.init("test_ack_up_to_existing");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    try queue.ack(7);
    try queue.ack(8);
    try testing.expectEqual(2, queue.cursor.acked_above_count());
    try queue.ack_up_to(5);
    try testing.expectEqual(5, queue.floor());
    try testing.expectEqual(2, queue.cursor.acked_above_count());
    // Advancing through the acknowledged run consumes it.
    try queue.ack_up_to(9);
    try testing.expectEqual(9, queue.floor());
    try testing.expectEqual(0, queue.cursor.acked_above_count());
}

test "queue: ack up to coalesces with acknowledged items above" {
    var h = try Harness.init("test_ack_up_to_coalesce");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    for ([_]u64{ 5, 6, 7 }) |position| try queue.ack(position);
    try testing.expectEqual(0, queue.floor());
    try queue.ack_up_to(5);
    try testing.expectEqual(8, queue.floor());
}

test "queue: ack up to errors" {
    var h = try Harness.init("test_ack_up_to_errors");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    _ = try queue.enqueue("item0");
    _ = try queue.enqueue("item1");
    try testing.expectError(error.PositionOutOfRange, queue.ack_up_to(5));
    try queue.ack_up_to(2);
    try testing.expectEqual(2, queue.floor());
    // At or below the floor is a no-op.
    try queue.ack_up_to(1);
    try testing.expectEqual(2, queue.floor());
}

test "queue: dequeue skips acknowledged items" {
    var h = try Harness.init("test_skip_acked");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 5);
    try queue.ack(1);
    try queue.ack(3);
    try expect_recv(&queue, 0, 0);
    try expect_recv(&queue, 2, 2);
    try expect_recv(&queue, 4, 4);
    try testing.expectEqual(null, try queue.try_recv());
}

test "queue: ack errors" {
    var h = try Harness.init("test_ack_errors");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    _ = try queue.enqueue("item0");
    _ = try queue.enqueue("item1");
    try testing.expectError(error.PositionOutOfRange, queue.ack(5));
    // Unread items can be acknowledged, twice.
    try queue.ack(1);
    try testing.expect(queue.is_acked(1));
    try queue.ack(1);
    // An appended but uncommitted item is not yet published.
    _ = try queue.append("item2");
    try testing.expectError(error.PositionOutOfRange, queue.ack(2));
}

test "queue: prune keeps unacknowledged items readable" {
    var h = try Harness.init("test_prune");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 25);
    try queue.sync();
    for (0..15) |position| {
        _ = try recv_position(&queue);
        try queue.ack(position);
    }
    try testing.expectEqual(15, queue.floor());
    try queue.sync();
    try testing.expectEqual(10, queue.journal.pruning_boundary());
    try expect_recv(&queue, 15, 15);
}

test "queue: ack across sections" {
    var h = try Harness.init("test_multi_prune");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 50);
    try queue.sync();
    const batches = [_][2]u64{ .{ 0, 15 }, .{ 15, 30 }, .{ 30, 50 } };
    for (batches) |batch| {
        for (batch[0]..batch[1]) |position| {
            // The first item of a later batch was already received by the previous check.
            if (position != batch[0] or batch[0] == 0) _ = try recv_position(&queue);
            try queue.ack(position);
        }
        try testing.expectEqual(batch[1], queue.floor());
        try queue.sync();
        if (batch[1] < 50) try expect_recv(&queue, batch[1], @intCast(batch[1]));
    }
    try testing.expect(queue.is_empty());
    try testing.expectEqual(null, try queue.try_recv());
}

test "queue: crash recovery replays from the pruning boundary" {
    var h = try Harness.init("test_recovery_replay");
    defer h.deinit();
    var queue = try h.open();
    try enqueue_range(&queue, 0, 5);
    // Acknowledged items within one section are not pruned.
    for (0..3) |position| try queue.ack(position);
    try testing.expectEqual(3, queue.floor());
    try queue.sync();
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(0, queue.floor());
    for (0..5) |position| try testing.expectEqual(position, try recv_position(&queue));
}

test "queue: crash recovery after pruning" {
    var h = try Harness.init("test_recovery_pruned");
    defer h.deinit();
    var queue = try h.open();
    try enqueue_range(&queue, 0, 25);
    for (0..15) |position| try queue.ack(position);
    try testing.expectEqual(15, queue.floor());
    try queue.sync();
    const boundary = queue.journal.pruning_boundary();
    try testing.expect(boundary > 0);
    queue.deinit();
    h.storage.crash();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(boundary, queue.journal.pruning_boundary());
    try testing.expectEqual(boundary, queue.floor());
    for (boundary..25) |position| try expect_recv(&queue, position, @intCast(position));
    try testing.expectEqual(null, try queue.try_recv());
}

test "queue: reset" {
    var h = try Harness.init("test_reset");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 5);
    for (0..3) |_| _ = try recv_position(&queue);
    try testing.expectEqual(3, queue.read_position());
    queue.reset();
    try testing.expectEqual(0, queue.read_position());
    try expect_recv(&queue, 0, 0);
}

test "queue: reset with ack" {
    var h = try Harness.init("test_reset_ack");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    for (0..5) |position| {
        _ = try recv_position(&queue);
        try queue.ack(position);
    }
    try testing.expectEqual(5, queue.floor());
    try testing.expectEqual(5, queue.read_position());
    _ = try recv_position(&queue);
    _ = try recv_position(&queue);
    try testing.expectEqual(7, queue.read_position());
    queue.reset();
    try testing.expectEqual(5, queue.read_position());
    try expect_recv(&queue, 5, 5);
}

test "queue: empty queue operations" {
    var h = try Harness.init("test_empty");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try testing.expect(queue.is_empty());
    try testing.expectEqual(null, try queue.try_recv());
    try queue.sync();
    queue.reset();
    try testing.expectEqual(0, queue.read_position());
}

test "queue: persistence" {
    var h = try Harness.init("test_persist");
    defer h.deinit();
    var queue = try h.open();
    _ = try queue.enqueue("item0");
    _ = try queue.enqueue("item1");
    try queue.sync();
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(2, queue.size());
    for ([_]Bytes{ "item0", "item1" }) |expected| {
        const received = (try queue.try_recv()).?;
        defer codec.free(Bytes, gpa, received.item);
        try testing.expectEqualSlices(u8, expected, received.item);
    }
}

test "queue: large queue with sparse acks" {
    var h = try Harness.init("test_sparse");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 100);
    var position: u64 = 0;
    while (position < 100) : (position += 3) try queue.ack(position);
    // Every position not divisible by 3 arrives, in order.
    var expected: u64 = 1;
    var received_count: u64 = 0;
    while (try queue.try_recv()) |received| {
        codec.free(Bytes, gpa, received.item);
        if (expected % 3 == 0) expected += 1;
        try testing.expectEqual(expected, received.position);
        expected += 1;
        received_count += 1;
    }
    try testing.expectEqual(66, received_count);
}

test "queue: acknowledged runs coalesce into the floor" {
    var h = try Harness.init("test_coalesce");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    for (1..9) |position| try queue.ack(position);
    try testing.expectEqual(0, queue.floor());
    try testing.expectEqual(8, queue.cursor.acked_above_count());
    try queue.ack(0);
    try testing.expectEqual(9, queue.floor());
    try testing.expectEqual(0, queue.cursor.acked_above_count());
}

test "queue: ack up to past the read position" {
    var h = try Harness.init("test_ack_up_to_past_read_pos");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 10);
    for (0..3) |_| _ = try recv_position(&queue);
    try testing.expectEqual(3, queue.read_position());
    try queue.ack_up_to(7);
    try testing.expectEqual(7, queue.floor());
    try expect_recv(&queue, 7, 7);
}

test "queue: metrics" {
    var h = try Harness.init("test-metrics");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(0, queue.tip.metric().get());
    try testing.expectEqual(0, queue.floor());
    try testing.expectEqual(0, queue.next.metric().get());
    // Append updates the tip without a commit.
    _ = try queue.append(&.{0});
    try testing.expectEqual(1, queue.tip.metric().get());
    try queue.commit();
    try enqueue_range(&queue, 1, 10);
    try testing.expectEqual(10, queue.tip.metric().get());
    _ = try recv_position(&queue);
    _ = try recv_position(&queue);
    try testing.expectEqual(2, queue.next.metric().get());
    try queue.ack(0);
    try queue.ack(1);
    try testing.expectEqual(2, queue.floor());
    // The floor stays until the gap fills.
    try queue.ack(4);
    try queue.ack(6);
    try testing.expectEqual(2, queue.floor());
    try queue.ack(2);
    try queue.ack(3);
    try testing.expectEqual(5, queue.floor());
    try queue.ack_up_to(8);
    try testing.expectEqual(8, queue.floor());
    try queue.ack(8);
    try queue.ack(9);
    try testing.expectEqual(10, queue.floor());
    try testing.expectEqual(10, queue.ack_floor.metric().get());
    queue.reset();
    try testing.expectEqual(10, queue.next.metric().get());
}

test "queue: metrics register under the scope" {
    const metrics = runtime.telemetry.metrics;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    var h = try Harness.init("test-metrics-scope");
    defer h.deinit();
    const scope = metrics.Scope.init(&registry).child("queue");
    var queue = try Queue.init(gpa, h.storage.interface(), h.cfg(), scope);
    defer queue.deinit();
    try enqueue_range(&queue, 0, 3);
    try queue.ack(try recv_position(&queue));
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expect(metrics.has_metric_value(text, "queue_tip", "3"));
    try testing.expect(metrics.has_metric_value(text, "queue_floor", "1"));
    try testing.expect(metrics.has_metric_value(text, "queue_next", "1"));
}

test "queue: next metric updates on fast-forward" {
    var h = try Harness.init("test-ff");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    try enqueue_range(&queue, 0, 3);
    try queue.ack(try recv_position(&queue));
    try testing.expectEqual(1, queue.next.metric().get());
    try queue.ack(2);
    try queue.ack(1);
    try testing.expectEqual(3, queue.floor());
    try testing.expectEqual(1, queue.next.metric().get());
    // A dequeue that finds nothing still fast-forwards to the floor.
    try testing.expectEqual(null, try queue.try_recv());
    try testing.expectEqual(3, queue.next.metric().get());
}

test "queue: sync publishes appended items" {
    var h = try Harness.init("test_reader_sync_publishes");
    defer h.deinit();
    var queue = try h.open();
    defer queue.deinit();
    _ = try queue.append(&.{7});
    try testing.expectEqual(null, try queue.try_recv());
    try queue.sync();
    try expect_recv(&queue, 0, 7);
}

test "queue: enqueue bulk and ack up to prune on sync" {
    var h = try Harness.init("test_reader_ack_up_to");
    defer h.deinit();
    var queue = try h.open();
    var items: [25]Bytes = undefined;
    var values: [25]u8 = undefined;
    for (&items, &values, 0..) |*item, *value, index| {
        value.* = @intCast(index);
        item.* = value[0..1];
    }
    const range = try queue.enqueue_bulk(&items);
    try testing.expectEqual(queue_mod.Range{ .start = 0, .end = 25 }, range);
    // An empty batch commits nothing.
    const empty = try queue.enqueue_bulk(&.{});
    try testing.expectEqual(queue_mod.Range{ .start = 25, .end = 25 }, empty);
    try queue.ack_up_to(15);
    try queue.sync();
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(10, queue.floor());
    try expect_recv(&queue, 10, 10);
}

test "queue: sync prunes below the ack floor and delivery continues" {
    var h = try Harness.init("test_reader_sync_prunes");
    defer h.deinit();
    var queue = try h.open();
    try enqueue_range(&queue, 0, 25);
    for (0..15) |position| {
        try testing.expectEqual(position, try recv_position(&queue));
        try queue.ack(position);
    }
    try queue.sync();
    try testing.expectEqual(25, queue.size());
    try testing.expectEqual(10, queue.journal.pruning_boundary());
    for (15..25) |position| try expect_recv(&queue, position, @intCast(position));
    try testing.expectEqual(null, try queue.try_recv());
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    try testing.expectEqual(10, queue.floor());
    try expect_recv(&queue, 10, 10);
}

// commonware's `QueueWorkload`, driven by `TestRng` instead of the deterministic runtime: the
// queue round-trips random items across a reopen after acknowledging half of them.
test "queue: random workload round-trips across a reopen" {
    const utils = @import("utils");
    var h = try Harness.init("queue-workload");
    defer h.deinit();
    var rng = utils.rng.TestRng.init(42);
    const count = utils.rng.range_at_most(&rng, usize, 1, 64 * 4 - 1);
    var data: std.ArrayList([]u8) = .empty;
    defer {
        for (data.items) |item| gpa.free(item);
        data.deinit(gpa);
    }
    var queue = try h.open();
    for (0..count) |_| {
        const item = try gpa.alloc(u8, utils.rng.range_at_most(&rng, usize, 0, 255));
        errdefer gpa.free(item);
        rng.fill_bytes(item);
        try data.append(gpa, item);
        _ = try queue.enqueue(item);
    }
    for (0..count / 2) |_| try queue.ack(try recv_position(&queue));
    try queue.sync();
    queue.deinit();
    queue = try h.open();
    defer queue.deinit();
    var delivered: u64 = 0;
    while (try queue.try_recv()) |received| {
        defer codec.free(Bytes, gpa, received.item);
        try testing.expectEqualSlices(u8, data.items[received.position], received.item);
        try queue.ack(received.position);
        delivered += 1;
    }
    try testing.expectEqual(count - queue.journal.pruning_boundary(), delivered);
    try queue.sync();
}
