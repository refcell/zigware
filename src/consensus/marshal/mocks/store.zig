//! A finalized-block store that records its `put` and `get` calls in order (commonware
//! `marshal/mocks/store.rs`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");
const store = @import("../store.zig");

const Height = types.Height;

/// A store operation `Recording` observed (commonware `Op`).
pub const Op = union(enum) {
    /// A `put` of the block at `height`, with the payload address passed to storage.
    put: struct { height: Height, payload_address: usize },
    /// A `get` by height, or by digest (null).
    get: ?Height,

    pub fn eql(a: Op, b: Op) bool {
        return std.meta.eql(a, b);
    }
};

/// The shared operation log, owned by the test.
pub const Log = struct {
    gpa: Allocator,
    ops: std.ArrayList(Op) = .empty,

    pub fn init(gpa: Allocator) Log {
        return .{ .gpa = gpa };
    }

    pub fn deinit(log: *Log) void {
        log.ops.deinit(log.gpa);
        log.* = undefined;
    }
};

/// Wraps the block store `T` (a `store.Blocks` of `Block`), recording into `log` with
/// `payload_address` for each put (commonware `Recording`). Unlocked: the mocks run on the
/// single-threaded deterministic runtime.
pub fn Recording(comptime T: type, comptime Block: type) type {
    return struct {
        const Self = @This();
        pub const Digest = T.Digest;
        pub const Error = T.Error || Allocator.Error;

        inner: T,
        log: *Log,
        payload_address: *const fn (*const Block) usize,

        pub fn init(inner: T, log: *Log, payload_address: *const fn (*const Block) usize) Self {
            return .{ .inner = inner, .log = log, .payload_address = payload_address };
        }

        pub fn put(self: Self, digest: Digest, block: *const Block) Error!void {
            const op: Op = .{ .put = .{
                .height = block.height(),
                .payload_address = self.payload_address(block),
            } };
            try self.log.ops.append(self.log.gpa, op);
            try self.inner.put(digest, block);
        }

        pub fn sync(self: Self) Error!void {
            try self.inner.sync();
        }

        pub fn start_sync(self: Self) Error!void {
            try self.inner.start_sync();
        }

        pub fn get(self: Self, id: store.Identifier(Digest)) Error!?Block {
            const height: ?Height = switch (id) {
                .index => |index| index,
                .key => null,
            };
            try self.log.ops.append(self.log.gpa, .{ .get = height });
            return self.inner.get(id);
        }

        pub fn prune(self: Self, min: Height) Error!void {
            try self.inner.prune(min);
        }

        pub fn missing_items(self: Self, start: Height, out: []u64) []u64 {
            return self.inner.missing_items(start, out);
        }

        pub fn next_gap(self: Self, value: Height) struct { ?Height, ?Height } {
            return self.inner.next_gap(value);
        }

        pub fn last_index(self: Self) ?Height {
            return self.inner.last_index();
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const block_mod = @import("block.zig");

const Sha256 = cryptography.Sha256;
const TestBlock = block_mod.EmptyBlock(Sha256);

/// One block in memory, by height or digest.
const SingleStore = struct {
    pub const Digest = Sha256.Digest;
    pub const Error = error{};

    block: *?TestBlock,

    pub fn put(self: SingleStore, _: Digest, block: *const TestBlock) Error!void {
        self.block.* = block.*;
    }

    pub fn sync(_: SingleStore) Error!void {}

    pub fn start_sync(_: SingleStore) Error!void {}

    pub fn get(self: SingleStore, id: store.Identifier(Digest)) Error!?TestBlock {
        const block = self.block.* orelse return null;
        const found = switch (id) {
            .index => |height| height.get() == block.height().get(),
            .key => |digest| digest.eql(block.digest()),
        };
        return if (found) block else null;
    }

    pub fn prune(_: SingleStore, _: Height) Error!void {}

    pub fn missing_items(_: SingleStore, _: Height, out: []u64) []u64 {
        return out[0..0];
    }

    pub fn next_gap(_: SingleStore, _: Height) struct { ?Height, ?Height } {
        return .{ null, null };
    }

    pub fn last_index(self: SingleStore) ?Height {
        const block = self.block.* orelse return null;
        return block.height();
    }
};

fn timestamp_address(block: *const TestBlock) usize {
    return @intCast(block.timestamp);
}

test "recording logs puts and gets in order and forwards them" {
    var log = Log.init(testing.allocator);
    defer log.deinit();
    var slot: ?TestBlock = null;
    const Store = Recording(SingleStore, TestBlock);
    const recording = Store.init(.{ .block = &slot }, &log, &timestamp_address);
    const block = TestBlock.init(Sha256.Digest.empty, .new(4), 77);
    try recording.put(block.digest(), &block);
    try testing.expect((try recording.get(.{ .index = .new(4) })).?.eql(block));
    try testing.expect((try recording.get(.{ .key = block.digest() })).?.eql(block));
    try testing.expectEqual(@as(?Height, .new(4)), recording.last_index());
    const expected = [_]Op{
        .{ .put = .{ .height = .new(4), .payload_address = 77 } },
        .{ .get = .new(4) },
        .{ .get = null },
    };
    try testing.expectEqual(expected.len, log.ops.items.len);
    for (expected, log.ops.items) |want, got| try testing.expect(want.eql(got));
}
