//! The `queue_recovery` fuzz target (commonware `storage/fuzz`): queue crash recovery and
//! durability on `runtime.storage.faulty`.
//!
//! Operations run under write and sync faults; remove faults are armed only around each
//! `sync`, whose prune may then fail after removing some sections. After the crash, a chain
//! of faulted recovery attempts reopens the queue under fresh faults, then a clean recovery is
//! checked against a model: committed items survive, recovered positions hold tracked content,
//! the ack floor is the last synced boundary, unacknowledged items are re-delivered, and the
//! recovered queue accepts and publishes new items.
//!
//! One `Queue` holds both sides here (commonware has a separate `Reader`), and a failed
//! mutation leaves only `deinit`, so the reader's drain after the queue is dropped is checked
//! only on runs without a failed operation.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const queue_mod = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const Faults = @import("../archive/faults.zig").Faults;

const gpa = testing.allocator;
const Item = []const u8;
const Queue = queue_mod.Queue(Item);
const CacheRef = runtime.buffer.paged.CacheRef;
const Probability = utils.Probability;
const faulty = runtime.storage.faulty;

const item_size = 32;
/// Positions are bounded by the operations an input can hold.
const max_operations = 128;

const Operation = union(enum) {
    enqueue: u8,
    append: u8,
    commit,
    dequeue_and_ack,
    dequeue_no_ack,
    ack_offset: u8,
    ack_up_to_offset: u8,
    sync,
    reset,
};

const Input = struct {
    page_size: u16,
    page_cache_size: u32,
    items_per_section: u64,
    write_buffer: usize,
    replay_buffer: usize,
    sync_failure_rate: Probability,
    write_config: faulty.WriteConfig,
    remove_rate: Probability,
    seed: u64,
    operations: [max_operations]Operation,
    operations_len: usize,

    fn decode(bytes: []const u8) Input {
        var reader = fuzz_bytes.Reader.init(bytes);
        var input: Input = .{
            .page_size = @intCast(1 + reader.int(u8)),
            .page_cache_size = 1 + reader.int(u8) % 16,
            .items_per_section = 1 + reader.int(u8) % 64,
            .write_buffer = 1 + reader.int(u16) % 2048,
            .replay_buffer = 1 + reader.int(u16) % 2048,
            .sync_failure_rate = rate(&reader, 1),
            .write_config = .{
                .failure_rate = rate(&reader, 0),
                .retention_rate = Probability.init(reader.int(u8) % 101, 100).?,
                .mode = if (reader.boolean()) .prefix else .subset,
            },
            .remove_rate = rate(&reader, 0),
            .seed = reader.int(u64),
            .operations = undefined,
            .operations_len = 0,
        };
        while (!reader.done() and input.operations_len < max_operations) {
            input.operations[input.operations_len] = operation(&reader);
            input.operations_len += 1;
        }
        assert(input.operations_len <= max_operations);
        return input;
    }

    /// A failure rate of `from..=100` percent, biased toward low rates (cubically) so
    /// random inputs also reach deep states; every rate stays reachable.
    fn rate(reader: *fuzz_bytes.Reader, from: u64) Probability {
        assert(from <= 1);
        const draw: u64 = reader.int(u8) % 101;
        const biased = draw * draw * draw / 10_000;
        assert(biased <= 100);
        return Probability.init(@max(from, biased), 100).?;
    }

    fn operation(reader: *fuzz_bytes.Reader) Operation {
        const kind = reader.int(u8) % 9;
        const value = reader.int(u8);
        return switch (kind) {
            0 => .{ .enqueue = value },
            1 => .{ .append = value },
            2 => .commit,
            3 => .dequeue_and_ack,
            4 => .dequeue_no_ack,
            5 => .{ .ack_offset = value },
            6 => .{ .ack_up_to_offset = value },
            7 => .sync,
            8 => .reset,
            else => unreachable, // Proof: `kind` is below 9.
        };
    }
};

/// What recovery may find at each position.
const Status = enum { none, committed, uncommitted, pending };

/// The model of the operation phase (commonware's `RecoveryState`). Reader acks are not
/// persisted: on restart the ack floor is the journal's pruning boundary.
const Model = struct {
    status: [max_operations]Status = @splat(.none),
    values: [max_operations]u8 = undefined,
    /// Committed positions are exactly `[0, published)`.
    published: u64 = 0,
    current_ack_floor: u64 = 0,
    /// The blob-aligned boundary pruned by the last successful sync.
    synced_boundary: u64 = 0,
    saw_mutable_error: bool = false,

    fn track(self: *Model, position: u64, value: u8, status: Status) void {
        const index: usize = @intCast(position);
        assert(self.status[index] == .none);
        self.status[index] = status;
        self.values[index] = value;
    }

    /// Every uncommitted item is durable now.
    fn commit_succeeded(self: *Model) void {
        for (&self.status) |*status| {
            if (status.* == .uncommitted) status.* = .committed;
        }
        self.published = self.count(.committed);
    }

    /// Uncommitted items may or may not be durable.
    fn commit_failed(self: *Model) void {
        for (&self.status) |*status| {
            if (status.* == .uncommitted) status.* = .pending;
        }
        self.saw_mutable_error = true;
    }

    /// Mirrors the journal's clamp: the target blob is capped to the tail blob, boundaries
    /// are blob-aligned, and the boundary never regresses.
    fn sync_succeeded(self: *Model, ack_floor: u64, size: u64, items_per_section: u64) void {
        const min_blob = @min(ack_floor / items_per_section, size / items_per_section);
        self.synced_boundary = @max(self.synced_boundary, min_blob * items_per_section);
    }

    fn count(self: *const Model, status: Status) u64 {
        var total: u64 = 0;
        for (self.status) |entry| {
            if (entry == status) total += 1;
        }
        return total;
    }

    fn expected_item(self: *const Model, position: u64) ?u8 {
        if (position >= max_operations) return null;
        const index: usize = @intCast(position);
        if (self.status[index] == .none) return null;
        return self.values[index];
    }

    fn max_recovered_size(self: *const Model) u64 {
        return max_operations - self.count(.none);
    }
};

fn make_item(value: u8) [item_size]u8 {
    return @splat(value);
}

fn expect_item(value: u8, item: Item) !void {
    try testing.expectEqualSlices(u8, &make_item(value), item);
}

/// An item the reader delivered was published and holds its committed content.
fn check_delivery(model: *const Model, received: Queue.Received) !void {
    try testing.expect(received.position < model.published);
    try expect_item(model.values[@intCast(received.position)], received.item);
}

const Harness = struct {
    faults: Faults,
    cache_ref: CacheRef,
    input: *const Input,

    fn init(self: *Harness, input: *const Input) !void {
        self.input = input;
        self.faults.init(gpa, input.seed);
        self.cache_ref = try CacheRef.init(gpa, input.page_size, input.page_cache_size);
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.faults.deinit();
    }

    fn open(self: *Harness) !Queue {
        return Queue.init(gpa, self.faults.interface(), .{
            .partition = "queue-crash-recovery",
            .items_per_section = self.input.items_per_section,
            .codec_config = .{ .range = .full(), .item = {} },
            .cache_ref = &self.cache_ref,
            .write_buffer = self.input.write_buffer,
            .replay_buffer = self.input.replay_buffer,
        });
    }

    fn op_faults(self: *const Harness) faulty.Config {
        return .{
            .sync_rate = self.input.sync_failure_rate,
            .write_rate = self.input.write_config,
        };
    }
};

/// A faulted recovery attempt; its result is discarded.
fn recover(harness: *Harness) !void {
    var queue = try harness.open();
    queue.deinit();
}

/// Applies a mutation, tracking it; returns false once one fails.
fn apply_mutation(harness: *Harness, queue: *Queue, model: *Model, op: Operation) !bool {
    const position = queue.size();
    switch (op) {
        .enqueue => |value| {
            const item = make_item(value);
            if (queue.enqueue(&item)) |landed| {
                try testing.expectEqual(position, landed);
                model.track(position, value, .uncommitted);
                model.commit_succeeded();
            } else |_| {
                model.track(position, value, .pending);
                model.commit_failed();
                return false;
            }
        },
        .append => |value| {
            const item = make_item(value);
            if (queue.append(&item)) |_| {
                model.track(position, value, .uncommitted);
            } else |_| {
                model.track(position, value, .pending);
                model.commit_failed();
                return false;
            }
        },
        .commit => if (queue.commit()) |_| model.commit_succeeded() else |_| {
            model.commit_failed();
            return false;
        },
        .sync => return sync(harness, queue, model),
        else => unreachable, // Proof: the caller passes only mutations.
    }
    return true;
}

/// Remove faults are armed only around `sync`: its prune is the only remove site.
fn sync(harness: *Harness, queue: *Queue, model: *Model) bool {
    var faults = harness.op_faults();
    faults.remove_rate = harness.input.remove_rate;
    harness.faults.layer.config = faults;
    const result = queue.sync();
    harness.faults.layer.config = harness.op_faults();
    if (result) |_| {
        model.commit_succeeded();
        model.current_ack_floor = queue.floor();
        model.sync_succeeded(queue.floor(), queue.size(), harness.input.items_per_section);
        return true;
    } else |_| {
        // A partial prune may land the recovered floor anywhere between the last synced
        // boundary and the blob-aligned ack floor, so `synced_boundary` stays.
        model.commit_failed();
        return false;
    }
}

/// Dequeues one item, acknowledging it if `ack`. Reads are never faulted.
fn dequeue(queue: *Queue, model: *Model, ack: bool) !void {
    const received = try queue.try_recv() orelse {
        try testing.expectEqual(model.published, queue.read_position());
        return;
    };
    defer codec.free(Item, gpa, received.item);
    try check_delivery(model, received);
    if (!ack) return;
    try queue.ack(received.position);
    try testing.expect(queue.is_acked(received.position));
    model.current_ack_floor = queue.floor();
}

fn ack_offset(queue: *Queue, model: *Model, offset: u8) !void {
    const size = queue.size();
    const floor = queue.floor();
    if (size <= floor) return;
    const position = floor + offset % (size - floor);
    if (position < model.published) {
        try queue.ack(position);
        try testing.expect(queue.is_acked(position));
        model.current_ack_floor = queue.floor();
        return;
    }
    // Appended items stay out of range until a commit or sync publishes them.
    try testing.expectError(error.PositionOutOfRange, queue.ack(position));
    try testing.expectEqual(floor, queue.floor());
    try testing.expect(!queue.is_acked(position));
}

fn ack_up_to_offset(queue: *Queue, model: *Model, offset: u8) !void {
    const up_to = offset % (queue.size() + 1);
    const floor = queue.floor();
    if (up_to <= model.published) {
        try queue.ack_up_to(up_to);
        try testing.expect(queue.floor() >= up_to);
        model.current_ack_floor = queue.floor();
        return;
    }
    try testing.expectError(error.PositionOutOfRange, queue.ack_up_to(up_to));
    try testing.expectEqual(floor, queue.floor());
}

/// Applies operations until one fails.
fn apply_operations(harness: *Harness, queue: *Queue, model: *Model) !void {
    for (harness.input.operations[0..harness.input.operations_len]) |op| {
        switch (op) {
            .dequeue_and_ack => try dequeue(queue, model, true),
            .dequeue_no_ack => try dequeue(queue, model, false),
            .ack_offset => |offset| try ack_offset(queue, model, offset),
            .ack_up_to_offset => |offset| try ack_up_to_offset(queue, model, offset),
            .reset => queue.reset(),
            else => if (!try apply_mutation(harness, queue, model, op)) return,
        }
    }
}

/// The reader delivers exactly the unacknowledged published items, then nothing.
fn drain(queue: *Queue, model: *const Model) !void {
    queue.reset();
    const floor = queue.floor();
    var delivered: [max_operations]bool = @splat(false);
    while (try queue.try_recv()) |received| {
        defer codec.free(Item, gpa, received.item);
        try check_delivery(model, received);
        try testing.expect(!queue.is_acked(received.position));
        const index: usize = @intCast(received.position);
        try testing.expect(!delivered[index]);
        delivered[index] = true;
    }
    for (floor..model.published) |position| {
        try testing.expect(queue.is_acked(position) != delivered[position]);
    }
}

/// Re-delivers every unacknowledged recovered item, each holding tracked content.
fn verify_recovered_items(queue: *Queue, model: *const Model) !void {
    queue.reset();
    var count: u64 = 0;
    while (try queue.try_recv()) |received| {
        defer codec.free(Item, gpa, received.item);
        count += 1;
        const value = model.expected_item(received.position) orelse return error.Untracked;
        try expect_item(value, received.item);
    }
    try testing.expectEqual(queue.size() - queue.floor(), count);
}

/// A new item lands at the recovered size and is published to the drained reader.
fn verify_enqueue(queue: *Queue) !void {
    const size = queue.size();
    const item = make_item(0xFF);
    try testing.expectEqual(size, try queue.enqueue(&item));
    const received = (try queue.try_recv()).?;
    defer codec.free(Item, gpa, received.item);
    try testing.expectEqual(size, received.position);
    try expect_item(0xFF, received.item);
}

fn verify_recovery(queue: *Queue, model: *const Model) !void {
    const size = queue.size();
    const floor = queue.floor();
    // Committed items survive; recovery fabricates nothing.
    try testing.expect(size >= model.published);
    try testing.expect(size <= model.max_recovered_size());
    if (model.saw_mutable_error) {
        // Successful prunes are durable; a failed sync's partial prune only advances the
        // floor, at most to the requested ack floor.
        try testing.expect(floor <= model.current_ack_floor);
        try testing.expect(floor >= model.synced_boundary);
    } else {
        try testing.expectEqual(model.synced_boundary, floor);
    }
    try verify_recovered_items(queue, model);
    try verify_enqueue(queue);
    if (model.saw_mutable_error) try queue.sync();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    const input = Input.decode(bytes);
    var harness: Harness = undefined;
    try harness.init(&input);
    defer harness.deinit();
    var model: Model = .{};
    var queue = try harness.open();
    harness.faults.layer.config = harness.op_faults();
    {
        defer queue.deinit();
        try apply_operations(&harness, &queue, &model);
        harness.faults.disarm();
        if (!model.saw_mutable_error) try drain(&queue, &model);
    }
    try harness.faults.crash();
    try harness.faults.faulted_recovery(&harness, recover);
    queue = try harness.open();
    verify_recovery(&queue, &model) catch |err| {
        queue.deinit();
        return err;
    };
    try queue.destroy();
}

test "fuzz queue_recovery (seeded)" {
    try fuzz_bytes.seeded(320, 0x71756575, 64, recovery_run);
}

test "fuzz queue_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(320, recovery_run), .{});
}
