//! Model fuzz for the tracked channel (commonware `utils/fuzz/fuzz_targets/channel.rs`, extended
//! with a model of the watermark and per-batch pending counts).

const std = @import("std");
const tracked = @import("tracked.zig");
const fuzz = @import("../fuzz.zig");
const rng = @import("../rng.zig");
const testing = std.testing;
const gpa = testing.allocator;

const batch_count = 4;
const Message = tracked.Message(u64, u32);

const Model = struct {
    /// `delivered[i]` is sequence `i + 1`.
    delivered: std.ArrayList(bool) = .empty,
    batch: std.ArrayList(?u32) = .empty,

    fn deinit(model: *Model) void {
        model.delivered.deinit(gpa);
        model.batch.deinit(gpa);
    }

    fn watermark(model: *const Model) u64 {
        var count: u64 = 0;
        for (model.delivered.items) |done| {
            if (!done) break;
            count += 1;
        }
        return count;
    }

    fn pending(model: *const Model, id: u32) usize {
        var count: usize = 0;
        for (model.delivered.items, model.batch.items) |done, batch| {
            if (!done and batch != null and batch.? == id) count += 1;
        }
        return count;
    }
};

const Held = struct { message: Message, clones: std.ArrayList(tracked.Guard(u32)) };

fn release(model: *Model, held: *Held) void {
    for (held.clones.items) |*guard| guard.deinit();
    held.clones.deinit(gpa);
    model.delivered.items[@intCast(held.message.guard.sequence - 1)] = true;
    held.message.guard.deinit();
}

fn check(model: *const Model, sender: tracked.Sender(u64, u32)) !void {
    try testing.expectEqual(model.watermark(), sender.watermark());
    for (0..batch_count) |id| {
        try testing.expectEqual(model.pending(@intCast(id)), sender.pending(@intCast(id)));
    }
}

fn step(
    generator: *rng.FuzzRng,
    pair: *tracked.Pair(u64, u32),
    model: *Model,
    held: *std.ArrayList(Held),
) !void {
    switch (rng.range_less_than(generator, u8, 0, 4)) {
        0 => {
            const batch: ?u32 = if (rng.boolean(generator))
                rng.range_less_than(generator, u32, 0, batch_count)
            else
                null;
            const sequence = pair.sender.try_send(batch, model.delivered.items.len) catch |err| {
                try testing.expectEqual(error.Full, err);
                // The refused message took a sequence and is delivered at once.
                try model.delivered.append(gpa, true);
                try model.batch.append(gpa, batch);
                return;
            };
            try model.delivered.append(gpa, false);
            try model.batch.append(gpa, batch);
            try testing.expectEqual(model.delivered.items.len, sequence);
        },
        1 => {
            const message = pair.receiver.try_recv() catch |err| {
                return testing.expectEqual(error.Empty, err);
            };
            try testing.expectEqual(message.guard.sequence - 1, message.data);
            try held.append(gpa, .{ .message = message, .clones = .empty });
        },
        2 => if (held.items.len > 0) {
            const index = rng.range_less_than(generator, usize, 0, held.items.len);
            const entry = &held.items[index];
            try entry.clones.append(gpa, entry.message.guard.clone());
        },
        3 => if (held.items.len > 0) {
            const index = rng.range_less_than(generator, usize, 0, held.items.len);
            var entry = held.swapRemove(index);
            release(model, &entry);
        },
        else => unreachable,
    }
}

fn fuzz_tracked(_: void, generator: *rng.FuzzRng) !void {
    const capacity = rng.range_at_most(generator, usize, 1, 4);
    var pair = try tracked.bounded(u64, u32, gpa, testing.io, capacity);
    var model: Model = .{};
    defer model.deinit();
    var held: std.ArrayList(Held) = .empty;
    defer held.deinit(gpa);
    for (0..rng.range_at_most(generator, u32, 0, 64)) |_| {
        try step(generator, &pair, &model, &held);
        try check(&model, pair.sender);
    }
    // Dropping the receiver delivers every unread message.
    pair.receiver.deinit();
    for (model.delivered.items) |*done| {
        if (!done.*) done.* = true;
    }
    // Held messages are still undelivered until released.
    for (held.items) |entry| model.delivered.items[@intCast(entry.message.guard.sequence - 1)] =
        false;
    try check(&model, pair.sender);
    pair.sender.deinit();
    for (held.items) |*entry| release(&model, entry);
}

test "fuzz tracked" {
    try fuzz.run({}, fuzz_tracked, 0x7472_6163, 300);
}
