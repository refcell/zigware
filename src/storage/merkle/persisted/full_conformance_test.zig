//! Storage conformance of the persisted Merkle structures (commonware's
//! `merkle::conformance::tests::StorageConformance<MmrFullWorkload>` and `<MmbFullWorkload>`).
//!
//! Each case runs commonware's workload on the deterministic runner seeded with the case seed
//! and commits the storage audit (a CRC32C of every durable blob), so a match means the journal
//! and metadata blobs are byte-identical to commonware's. The workload draws from the runtime
//! RNG only after `init`, which draws nothing, so a `TestRng` seeded with the case seed makes
//! the same draws.

const std = @import("std");
const assert = std.debug.assert;
const conformance = @import("conformance");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../mod.zig");
const support = @import("full_test.zig");

const conformance_file = @embedFile("../../conformance.toml");
const prefix = "commonware_storage::merkle::conformance::tests::";

/// Commonware's `run_full_merkle`: `16..96` leaves in one batch, synced, then pruned to a
/// third of them and synced again when there are more than 32.
fn FullWorkload(comptime F: type, comptime name: []const u8) type {
    return struct {
        pub fn run(ctx: runtime.deterministic.Context, seed: u64) !void {
            const gpa = ctx.gpa();
            var rng = utils.rng.TestRng.init(seed);
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10);
            defer cache_ref.deinit();
            var journal_buffer: [96]u8 = undefined;
            var metadata_buffer: [96]u8 = undefined;
            const cfg: @import("full.zig").Config = .{
                .journal_partition = try std.fmt.bufPrint(
                    &journal_buffer,
                    name ++ "-{d}-journal",
                    .{seed},
                ),
                .metadata_partition = try std.fmt.bufPrint(
                    &metadata_buffer,
                    name ++ "-{d}-metadata",
                    .{seed},
                ),
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &cache_ref,
            };
            var structure = try support.Merkle(F).init(gpa, ctx.storage, &support.hasher, cfg);
            defer structure.deinit();
            // Rust infers nothing for `random_range(16..96)`, so it samples an `i32`.
            const items: u64 = utils.rng.range_less_than(&rng, u32, 16, 96);
            try add_items(&structure, gpa, seed, items);
            try structure.sync();
            if (items > 32) {
                try structure.prune(items / 3);
                try structure.sync();
            }
            assert(structure.leaves() == items);
        }

        /// Adds leaf `i` as `hasher.digest((seed + i) as 8 big-endian bytes)`, in one batch.
        fn add_items(
            structure: *support.Merkle(F),
            gpa: std.mem.Allocator,
            seed: u64,
            items: u64,
        ) !void {
            var batch = try structure.new_batch();
            for (0..items) |i| {
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, seed +% i, .big);
                const element = support.hasher.digest(&bytes);
                batch.add(gpa, &support.hasher, &element.bytes) catch |err| {
                    batch.deinit(gpa);
                    return err;
                };
            }
            const merkleized = try batch.merkleize(structure, &support.hasher);
            defer merkleized.release(gpa);
            try structure.apply_batch(merkleized);
            assert(structure.leaves() == items);
        }
    };
}

const MmrFullWorkload = FullWorkload(merkle.mmr.Family, "mmr-full-conformance");
const MmbFullWorkload = FullWorkload(merkle.mmb.Family, "mmb-full-conformance");

test "conformance StorageConformance<MmrFullWorkload>" {
    // commonware `StorageConformance<MmrFullWorkload>`.
    try conformance.verify(
        runtime.conformance.StorageConformance(MmrFullWorkload),
        std.testing.allocator,
        prefix ++ "StorageConformance<MmrFullWorkload>",
        256,
        conformance_file,
    );
}

test "conformance StorageConformance<MmbFullWorkload>" {
    // commonware `StorageConformance<MmbFullWorkload>`.
    try conformance.verify(
        runtime.conformance.StorageConformance(MmbFullWorkload),
        std.testing.allocator,
        prefix ++ "StorageConformance<MmbFullWorkload>",
        256,
        conformance_file,
    );
}
