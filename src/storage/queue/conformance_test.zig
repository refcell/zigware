//! Queue conformance (commonware's `queue/conformance.rs`). See
//! `cache/conformance_test.zig` for how storage workloads are committed.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const runtime = @import("runtime");
const utils = @import("utils");
const queue_mod = @import("mod.zig");

const conformance_file = @embedFile("../conformance.toml");
const Bytes = []const u8;
const Queue = queue_mod.Queue(Bytes);
const Rng = utils.rng.TestRng;
const items_per_section = 64;

const QueueWorkload = struct {
    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = Rng.init(seed);
        var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
        defer cache_ref.deinit();
        var buffer: [64]u8 = undefined;
        const config: queue_mod.Config(Bytes) = .{
            .partition = try std.fmt.bufPrint(&buffer, "queue-conformance-{d}", .{seed}),
            .items_per_section = items_per_section,
            .codec_config = .{ .range = .range(0, 256), .item = {} },
            .cache_ref = &cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
        const count = utils.rng.range_less_than(&rng, usize, 1, items_per_section * 4);
        const data = try gpa.alloc([]u8, count);
        var drawn: usize = 0;
        defer {
            for (data[0..drawn]) |item| gpa.free(item);
            gpa.free(data);
        }
        while (drawn < count) : (drawn += 1) {
            data[drawn] = try gpa.alloc(u8, utils.rng.range_less_than(&rng, usize, 0, 256));
            rng.fill_bytes(data[drawn]);
        }
        {
            var queue = try Queue.init(gpa, storage, config, null);
            defer queue.deinit();
            for (data) |item| _ = try queue.enqueue(item);
            for (0..count / 2) |_| {
                const received = (try queue.try_recv()).?;
                codec.free(Bytes, gpa, received.item);
                try queue.ack(received.position);
            }
            try queue.sync();
        }
        var queue = try Queue.init(gpa, storage, config, null);
        defer queue.deinit();
        while (try queue.try_recv()) |received| {
            defer codec.free(Bytes, gpa, received.item);
            try std.testing.expectEqualSlices(u8, data[@intCast(received.position)], received.item);
            try queue.ack(received.position);
        }
        try queue.sync();
        assert(queue.is_empty());
    }

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        try run(gpa, memory.storage(), seed);
        const audit = memory.audit();
        return gpa.dupe(u8, &audit);
    }
};

test "conformance StorageConformance<QueueWorkload>" {
    try conformance.verify(
        QueueWorkload,
        std.testing.allocator,
        "commonware_storage::queue::conformance::StorageConformance<QueueWorkload>",
        512,
        conformance_file,
    );
}
