//! Journal conformance (commonware's `journal/conformance.rs`). See
//! `cache/conformance_test.zig` for how storage workloads are committed: each runs on
//! the deterministic runner of `runtime.conformance.StorageConformance`, with the RNG seeded by
//! the case seed, and commits its storage audit, so a
//! match means the journal writes byte-identical blobs.
//!
//! The contiguous and segmented workloads write up to 16k items per case (about a minute each
//! in Debug), so Debug builds run them only with `-Dslow-tests`.
//!
//! The compressed workloads (`<true>`) write zstd level-3 frames, so their hashes also check
//! that `zstd.compress_into` writes exactly what libzstd's level 3 does.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../merkle/mod.zig");
const contiguous = @import("contiguous/mod.zig");
const oversized = @import("segmented/oversized.zig");
const glob = @import("segmented/glob.zig");
const segmented_fixed = @import("segmented/fixed.zig");
const segmented_variable = @import("segmented/variable.zig");
const authenticated_journal = @import("authenticated_journal.zig");

const conformance_file = @embedFile("../conformance.toml");
const CacheRef = runtime.buffer.paged.CacheRef;
const Rng = utils.rng.TestRng;
const Bytes = []const u8;

const write_buffer = 1024;
const replay_buffer = 1024;
const items_per_blob = 4096;
const page_size = 1024;
const page_cache_size = 10;
const bytes_config: codec.Cfg(Bytes) = .{ .range = .range(0, 256), .item = {} };

/// Commits a workload's storage audit for one seed.
/// Runs `write` on `runtime.conformance.StorageConformance`'s deterministic runner, which
/// commits its storage audit.
fn Workload(
    comptime write: fn (Allocator, runtime.storage.Storage, *Rng, u64) anyerror!void,
) type {
    const W = struct {
        pub fn run(ctx: runtime.deterministic.Context, seed: u64) !void {
            var rng = Rng.init(seed);
            try write(ctx.gpa(), ctx.storage, &rng, seed);
        }
    };
    return runtime.conformance.StorageConformance(W);
}

/// A variable workload with `compressed` bound (commonware's `const COMPRESSED: bool`).
fn Variant(
    comptime write: fn (Allocator, runtime.storage.Storage, *Rng, u64, bool) anyerror!void,
    comptime compressed: bool,
) fn (Allocator, runtime.storage.Storage, *Rng, u64) anyerror!void {
    return struct {
        fn run(gpa: Allocator, storage: runtime.storage.Storage, rng: *Rng, seed: u64) !void {
            return write(gpa, storage, rng, seed, compressed);
        }
    }.run;
}

/// commonware's `fill_variable_item`: when compressed, even items are 192 bytes repeating
/// `0..16` (compressible); otherwise items are random bytes of a random length below 256.
fn fill_item(rng: *Rng, buffer: *[256]u8, index: usize, compressed: bool) []u8 {
    if (compressed and index % 2 == 0) {
        for (buffer[0..192], 0..) |*byte, offset| byte.* = @intCast(offset % 16);
        return buffer[0..192];
    }
    const len = utils.rng.range_less_than(rng, usize, 0, 256);
    rng.fill_bytes(buffer[0..len]);
    assert(len < 256);
    return buffer[0..len];
}

/// The number of items a segmented or contiguous workload writes.
fn item_count(rng: *Rng) usize {
    return utils.rng.range_less_than(rng, usize, 0, items_per_blob * 4);
}

fn partition_name(buffer: []u8, comptime prefix: []const u8, seed: u64) ![]u8 {
    return std.fmt.bufPrint(buffer, prefix ++ "-{d}", .{seed});
}

fn contiguous_fixed(gpa: Allocator, storage: runtime.storage.Storage, rng: *Rng, seed: u64) !void {
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var buffer: [64]u8 = undefined;
    var journal = try contiguous.fixed.Journal(u64).init(gpa, storage, .{
        .partition = try partition_name(&buffer, "contiguous-fixed-conformance", seed),
        .items_per_blob = items_per_blob,
        .cache_ref = &cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
    defer journal.deinit();
    // `context.fill(&mut [u64])` fills the bytes, then reads each word little-endian.
    const items = try gpa.alloc(u64, item_count(rng));
    defer gpa.free(items);
    rng.fill_bytes(std.mem.sliceAsBytes(items));
    for (items) |*item| item.* = std.mem.littleToNative(u64, item.*);
    for (items) |item| _ = try journal.append(item);
    try journal.sync();
}

fn contiguous_variable(
    gpa: Allocator,
    storage: runtime.storage.Storage,
    rng: *Rng,
    seed: u64,
    compressed: bool,
) !void {
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var buffer: [64]u8 = undefined;
    var journal = try contiguous.variable.Journal(Bytes).init(gpa, storage, .{
        .partition = try partition_name(&buffer, "contiguous-variable-conformance", seed),
        .items_per_section = items_per_blob,
        .compression = if (compressed) 3 else null,
        .codec_config = bytes_config,
        .cache_ref = &cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
    defer journal.deinit();
    // Every item is drawn before the first append, as commonware fills its vector first.
    const items = try draw_items(gpa, rng, compressed);
    defer free_items(gpa, items);
    for (items) |item| _ = try journal.append(item);
    try journal.sync();
}

fn draw_items(gpa: Allocator, rng: *Rng, compressed: bool) ![][]u8 {
    const items = try gpa.alloc([]u8, item_count(rng));
    var drawn: usize = 0;
    errdefer {
        for (items[0..drawn]) |item| gpa.free(item);
        gpa.free(items);
    }
    var buffer: [256]u8 = undefined;
    while (drawn < items.len) : (drawn += 1) {
        items[drawn] = try gpa.dupe(u8, fill_item(rng, &buffer, drawn, compressed));
    }
    return items;
}

fn free_items(gpa: Allocator, items: [][]u8) void {
    for (items) |item| gpa.free(item);
    gpa.free(items);
}

/// Item `i` goes to section `i % 3`.
fn section_of(index: usize) u64 {
    return index % 3;
}

fn segmented_fixed_run(
    gpa: Allocator,
    storage: runtime.storage.Storage,
    rng: *Rng,
    seed: u64,
) !void {
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var buffer: [64]u8 = undefined;
    var journal = try segmented_fixed.Journal(u64).init(gpa, storage, .{
        .partition = try partition_name(&buffer, "segmented-fixed-conformance", seed),
        .cache_ref = &cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
    defer journal.deinit();
    const items = try gpa.alloc(u64, item_count(rng));
    defer gpa.free(items);
    rng.fill_bytes(std.mem.sliceAsBytes(items));
    for (items, 0..) |item, index| {
        _ = try journal.append(section_of(index), std.mem.littleToNative(u64, item));
    }
    try journal.sync(&.{ 0, 1, 2 });
}

fn segmented_glob(
    gpa: Allocator,
    storage: runtime.storage.Storage,
    rng: *Rng,
    seed: u64,
    compressed: bool,
) !void {
    var buffer: [64]u8 = undefined;
    var recovery = try glob.Recovery(Bytes).init(gpa, storage, .{
        .partition = try partition_name(&buffer, "segmented-glob-conformance", seed),
        .compression = if (compressed) 3 else null,
        .codec_config = bytes_config,
        .write_buffer = write_buffer,
    });
    var journal = recovery.finish();
    defer journal.deinit();
    const items = try draw_items(gpa, rng, compressed);
    defer free_items(gpa, items);
    for (items, 0..) |item, index| _ = try journal.append(section_of(index), item);
    try journal.sync(&.{ 0, 1, 2 });
}

fn segmented_variable_run(
    gpa: Allocator,
    storage: runtime.storage.Storage,
    rng: *Rng,
    seed: u64,
    compressed: bool,
) !void {
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var buffer: [64]u8 = undefined;
    var recovery = try segmented_variable.Journal(Bytes).init(gpa, storage, .{
        .partition = try partition_name(&buffer, "segmented-variable-conformance", seed),
        .compression = if (compressed) 3 else null,
        .codec_config = bytes_config,
        .cache_ref = &cache_ref,
        .write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
    });
    try recovery.drain();
    var journal = try recovery.finish();
    defer journal.deinit();
    const items = try draw_items(gpa, rng, compressed);
    defer free_items(gpa, items);
    for (items, 0..) |item, index| _ = try journal.append(section_of(index), item);
    try journal.sync(&.{ 0, 1, 2 });
}

/// commonware's oversized conformance `TestEntry`.
const TestEntry = struct {
    id: u64,
    value_offset: u64 = 0,
    value_size: u32 = 0,

    pub const fixed_size: usize = 8 + 8 + 4;

    pub fn value_location(self: TestEntry) oversized.Location {
        return .{ .offset = self.value_offset, .size = self.value_size };
    }

    pub fn with_location(self: TestEntry, offset: u64, size: u32) TestEntry {
        return .{ .id = self.id, .value_offset = offset, .value_size = size };
    }

    pub fn encode_size(_: TestEntry) usize {
        return fixed_size;
    }

    pub fn write(self: TestEntry, writer: *codec.Writer) void {
        writer.write_int(u64, self.id);
        writer.write_int(u64, self.value_offset);
        writer.write_int(u32, self.value_size);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!TestEntry {
        return .{
            .id = try reader.read_int(u64),
            .value_offset = try reader.read_int(u64),
            .value_size = try reader.read_int(u32),
        };
    }
};

fn segmented_oversized(
    gpa: Allocator,
    storage: runtime.storage.Storage,
    rng: *Rng,
    seed: u64,
    compressed: bool,
) !void {
    var cache_ref = try CacheRef.init(gpa, page_size, page_cache_size);
    defer cache_ref.deinit();
    var index_buffer: [64]u8 = undefined;
    var value_buffer: [64]u8 = undefined;
    const Journal = oversized.Oversized(TestEntry, Bytes);
    var journal = try Journal.init_with_checkpoint(gpa, storage, .{
        .index_partition = try partition_name(
            &index_buffer,
            "segmented-oversized-index-conformance",
            seed,
        ),
        .value_partition = try partition_name(
            &value_buffer,
            "segmented-oversized-value-conformance",
            seed,
        ),
        .index_cache_ref = &cache_ref,
        .index_write_buffer = write_buffer,
        .value_write_buffer = write_buffer,
        .replay_buffer = replay_buffer,
        .compression = if (compressed) 3 else null,
        .codec_config = bytes_config,
    }, .{ .section = 0, .size = 0 });
    defer journal.deinit();
    const items = try draw_items(gpa, rng, compressed);
    defer free_items(gpa, items);
    for (items, 0..) |item, index| {
        _ = try journal.append(section_of(index), .{ .id = index }, item);
    }
    try journal.sync(&.{ 0, 1, 2 });
}

fn always(_: u64) bool {
    return true;
}

fn Authenticated(comptime F: type, comptime prefix: []const u8) type {
    return struct {
        const Journal = authenticated_journal.Journal(
            F,
            contiguous.fixed.Journal(u64),
            cryptography.Sha256,
        );

        fn run(gpa: Allocator, storage: runtime.storage.Storage, rng: *Rng, seed: u64) !void {
            var merkle_cache = try CacheRef.init(gpa, page_size, page_cache_size);
            defer merkle_cache.deinit();
            var journal_cache = try CacheRef.init(gpa, page_size, page_cache_size);
            defer journal_cache.deinit();
            var names: [3][96]u8 = undefined;
            const merkle_cfg: merkle.full.Config = .{
                .journal_partition = try std.fmt.bufPrint(
                    &names[0],
                    prefix ++ "-{d}-merkle-journal",
                    .{seed},
                ),
                .metadata_partition = try std.fmt.bufPrint(
                    &names[1],
                    prefix ++ "-{d}-merkle-metadata",
                    .{seed},
                ),
                .items_per_blob = 11,
                .write_buffer = write_buffer,
                .replay_buffer = replay_buffer,
                .cache_ref = &merkle_cache,
            };
            const journal_cfg: contiguous.fixed.Config = .{
                .partition = try std.fmt.bufPrint(&names[2], prefix ++ "-{d}-journal", .{seed}),
                .items_per_blob = 11,
                .cache_ref = &journal_cache,
                .write_buffer = write_buffer,
                .replay_buffer = replay_buffer,
            };
            var journal =
                try Journal.init(gpa, storage, merkle_cfg, journal_cfg, always, .forward_fold);
            defer journal.deinit();
            const items = utils.rng.range_less_than(rng, usize, 16, 96);
            for (0..items) |index| _ = try journal.append(seed +% index);
            try journal.sync();
            if (items > 32) {
                _ = try journal.prune(items / 3);
                try journal.sync();
            }
        }
    };
}

const cases = 512;
const conformance_prefix = "commonware_storage::journal::conformance::StorageConformance<";

/// Skips a large workload in Debug unless slow tests are enabled.
fn skip_large() !void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

/// The compressed workloads spend about 40 s each in zstd even in ReleaseSafe, so they run only
/// with -Dslow-tests in every mode (nightly runs ReleaseSafe with it).
fn skip_compressed() !void {
    if (!build_options.slow_tests) return error.SkipZigTest;
}

test "conformance StorageConformance<ContiguousFixedWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(contiguous_fixed),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<ContiguousFixedWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<ContiguousVariableWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(Variant(contiguous_variable, false)),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<ContiguousVariableWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<ContiguousVariableWorkload<true>>" {
    try skip_compressed();
    try conformance.verify(
        Workload(Variant(contiguous_variable, true)),
        std.testing.allocator,
        conformance_prefix ++ "ContiguousVariableWorkload<true>>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedFixedWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(segmented_fixed_run),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<SegmentedFixedWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedGlobWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(Variant(segmented_glob, false)),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<SegmentedGlobWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedGlobWorkload<true>>" {
    try skip_compressed();
    try conformance.verify(
        Workload(Variant(segmented_glob, true)),
        std.testing.allocator,
        conformance_prefix ++ "SegmentedGlobWorkload<true>>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedVariableWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(Variant(segmented_variable_run, false)),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<SegmentedVariableWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedVariableWorkload<true>>" {
    try skip_compressed();
    try conformance.verify(
        Workload(Variant(segmented_variable_run, true)),
        std.testing.allocator,
        conformance_prefix ++ "SegmentedVariableWorkload<true>>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedOversizedWorkload>" {
    try skip_large();
    try conformance.verify(
        Workload(Variant(segmented_oversized, false)),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<SegmentedOversizedWorkload>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<SegmentedOversizedWorkload<true>>" {
    try skip_compressed();
    try conformance.verify(
        Workload(Variant(segmented_oversized, true)),
        std.testing.allocator,
        conformance_prefix ++ "SegmentedOversizedWorkload<true>>",
        cases,
        conformance_file,
    );
}

test "conformance StorageConformance<AuthenticatedMmrWorkload>" {
    const W = Authenticated(merkle.mmr.Family, "authenticated-mmr-conformance");
    try conformance.verify(
        Workload(W.run),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<AuthenticatedMmrWorkload>",
        256,
        conformance_file,
    );
}

test "conformance StorageConformance<AuthenticatedMmbWorkload>" {
    const W = Authenticated(merkle.mmb.Family, "authenticated-mmb-conformance");
    try conformance.verify(
        Workload(W.run),
        std.testing.allocator,
        "commonware_storage::journal::conformance::StorageConformance<AuthenticatedMmbWorkload>",
        256,
        conformance_file,
    );
}
