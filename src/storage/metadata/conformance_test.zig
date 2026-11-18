//! Metadata conformance (commonware's `metadata/conformance.rs`). See
//! `cache/conformance_test.zig` for how storage workloads are committed.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const runtime = @import("runtime");
const utils = @import("utils");
const metadata_mod = @import("mod.zig");

const conformance_file = @embedFile("../conformance.toml");
const Bytes = []const u8;
const Metadata = metadata_mod.Metadata(u64, Bytes);
const Rng = utils.rng.TestRng;

const MetadataWorkload = struct {
    /// Puts a random value of up to 511 bytes at `key`.
    fn put_random(gpa: Allocator, metadata: *Metadata, rng: *Rng, key: u64) !void {
        const value = try gpa.alloc(u8, utils.rng.range_less_than(rng, usize, 0, 512));
        rng.fill_bytes(value);
        const previous = metadata.put(key, value) catch |err| {
            gpa.free(value);
            return err;
        };
        if (previous) |old| codec.free(Bytes, gpa, old);
        assert(metadata.get(key) != null);
    }

    fn write(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = Rng.init(seed);
        var buffer: [64]u8 = undefined;
        const partition = try std.fmt.bufPrint(&buffer, "metadata-conformance-{d}", .{seed});
        var metadata = try Metadata.init(gpa, storage, .{
            .partition = partition,
            .codec_config = .{ .range = .range(0, 512), .item = {} },
        });
        defer metadata.deinit();
        const items = utils.rng.range_less_than(&rng, u64, 16, 64);
        for (0..items) |key| try put_random(gpa, &metadata, &rng, key);
        try metadata.sync();
        var key: u64 = 0;
        while (key < items) : (key += 3) try put_random(gpa, &metadata, &rng, key);
        try metadata.sync();
    }

    /// Runs on `runtime.conformance.StorageConformance`'s deterministic runner, which commits
    /// its storage audit.
    pub fn run(ctx: runtime.deterministic.Context, seed: u64) !void {
        return write(ctx.gpa(), ctx.storage, seed);
    }
};

test "conformance StorageConformance<MetadataWorkload>" {
    try conformance.verify(
        runtime.conformance.StorageConformance(MetadataWorkload),
        std.testing.allocator,
        "commonware_storage::metadata::conformance::StorageConformance<MetadataWorkload>",
        256,
        conformance_file,
    );
}
