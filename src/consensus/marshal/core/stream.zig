//! Application delivery progress and the processed round floor, with their durable metadata
//! (commonware `marshal/core/stream.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const storage = @import("storage");
const types = @import("../../types.zig");
const Cutoff = @import("floor.zig").Cutoff;

const Height = types.Height;
const Round = types.Round;

/// The key of the last processed height in the metadata store.
const latest_key: u64 = 0xFF;
/// The key of the processed round floor's epoch. With `cutoff_view_key` present, the round
/// floor is `.round` at that epoch and view; alone, it is `.epoch` of that epoch.
const cutoff_epoch_key: u64 = 0xFE;
/// The key of the processed round floor's view when it is a `.round`.
const cutoff_view_key: u64 = 0xFD;

/// Every value is a varint `u64`, under a big-endian `u64` key (commonware's `U64`).
const Value = codec.UInt(u64);
const Metadata = storage.metadata.Metadata(u64, Value);

/// Application delivery stream progress, the processed round floor, and their durable
/// metadata. The processed height and the round floor sit under fixed keys of one store, so one
/// sync persists them together; a missing round floor reads as `Cutoff.zero()`.
pub const Stream = struct {
    pub const Error = Metadata.Error;

    metadata: Metadata,
    /// Mirrors the processed height entry in `metadata`; null before the first block.
    processed: ?Height,
    /// Whether every buffered value has been synced.
    synced: bool,

    /// Loads the processed height and round floor from the metadata store in `partition`.
    pub fn init(
        gpa: Allocator,
        store: runtime.storage.Storage,
        partition: []const u8,
    ) Error!Stream {
        const metadata: Metadata = try .init(gpa, store, .{
            .partition = partition,
            .codec_config = {},
        });
        const processed: ?Height = if (metadata.get(latest_key)) |height|
            .new(height.value)
        else
            null;
        return .{ .metadata = metadata, .processed = processed, .synced = true };
    }

    pub fn deinit(self: *Stream) void {
        self.metadata.deinit();
        self.* = undefined;
    }

    /// Whether every buffered value has been synced.
    pub fn is_synced(self: *const Stream) bool {
        return self.synced;
    }

    pub fn processed_height(self: *const Stream) ?Height {
        return self.processed;
    }

    /// The next height to deliver: genesis before any block is processed.
    pub fn next_height(self: *const Stream) Height {
        const processed = self.processed orelse return .zero();
        return processed.next();
    }

    /// The processed round floor, or `Cutoff.zero()` if none has been set. A value buffered by
    /// `set_cutoff` is returned before it is synced.
    pub fn cutoff(self: *const Stream) Cutoff {
        const epoch = self.metadata.get(cutoff_epoch_key) orelse return .zero();
        const view = self.metadata.get(cutoff_view_key) orelse
            return .{ .epoch = .new(epoch.value) };
        return .{ .round = .new(.new(epoch.value), .new(view.value)) };
    }

    /// Buffers `height` as the last processed height. The next `sync` makes it durable.
    pub fn acknowledge(self: *Stream, height: Height) Allocator.Error!void {
        _ = try self.metadata.put(latest_key, .{ .value = height.get() });
        self.processed = height;
        self.synced = false;
    }

    /// Buffers `value` as the processed round floor. The next `sync` makes it durable.
    pub fn set_cutoff(self: *Stream, value: Cutoff) Allocator.Error!void {
        switch (value) {
            .round => |round| {
                _ = try self.metadata.put(cutoff_epoch_key, .{ .value = round.epoch.get() });
                _ = try self.metadata.put(cutoff_view_key, .{ .value = round.view.get() });
            },
            .epoch => |epoch| {
                _ = try self.metadata.put(cutoff_epoch_key, .{ .value = epoch.get() });
                _ = self.metadata.remove(cutoff_view_key);
            },
        }
        assert(self.cutoff().eql(value));
        self.synced = false;
    }

    /// Makes every buffered value durable, skipping the metadata sync when nothing is
    /// buffered. After an error only `deinit` may follow.
    pub fn sync(self: *Stream) Error!void {
        if (self.synced) return;
        try self.metadata.sync();
        self.synced = true;
    }
};

const testing = std.testing;
const Storage = runtime.buffer.mocks.Storage;
const test_partition = "stream-metadata";

/// Writes a store whose only entry is `height`, encoded as a `Height` under the processed
/// height key.
fn seed_processed_height(store: runtime.storage.Storage, height: Height) !void {
    const Seed = storage.metadata.Metadata(u64, Height);
    var metadata: Seed = try .init(testing.allocator, store, .{
        .partition = test_partition,
        .codec_config = {},
    });
    defer metadata.deinit();
    _ = try metadata.put(latest_key, height);
    try metadata.sync();
}

test "round floor round trips beside processed height" {
    const gpa = testing.allocator;
    var backing = Storage.init(gpa);
    defer backing.deinit();
    try seed_processed_height(backing.interface(), .new(7));

    var stream: Stream = try .init(gpa, backing.interface(), test_partition);
    try testing.expectEqual(7, stream.processed_height().?.get());
    try testing.expect(stream.cutoff().eql(.zero()));

    const at_round: Cutoff = .{ .round = .new(.new(2), .new(40)) };
    try stream.set_cutoff(at_round);
    try stream.acknowledge(.new(8));
    try stream.sync();
    stream.deinit();

    var reopened: Stream = try .init(gpa, backing.interface(), test_partition);
    defer reopened.deinit();
    try testing.expectEqual(8, reopened.processed_height().?.get());
    try testing.expect(reopened.cutoff().eql(at_round));
}

test "round floor kind survives reopen across transitions" {
    const gpa = testing.allocator;
    var backing = Storage.init(gpa);
    defer backing.deinit();

    const cutoffs = [_]Cutoff{
        .{ .round = .new(.new(2), .new(40)) },
        .{ .epoch = .new(2) },
        .{ .round = .new(.new(3), .new(5)) },
    };
    var previous: Cutoff = .zero();
    for (cutoffs) |value| {
        var stream: Stream = try .init(gpa, backing.interface(), test_partition);
        defer stream.deinit();
        try testing.expect(stream.cutoff().eql(previous));
        try testing.expectEqual(null, stream.processed_height());
        try testing.expectEqual(0, stream.next_height().get());
        try stream.set_cutoff(value);
        try testing.expect(stream.cutoff().eql(value));
        try testing.expect(!stream.is_synced());
        try stream.sync();
        try testing.expect(stream.is_synced());
        previous = value;
    }
    var stream: Stream = try .init(gpa, backing.interface(), test_partition);
    defer stream.deinit();
    try testing.expect(stream.cutoff().eql(previous));
}
