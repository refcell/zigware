//! Ordinal conformance (commonware's `ordinal/conformance.rs` and the `Record<u32>` codec
//! hash). See `cache/conformance_test.zig` for how storage workloads are committed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const ordinal = @import("mod.zig");

const conformance_file = @embedFile("../conformance.toml");
/// `FixedBytes<32>`: 32 raw bytes on the wire.
const Value = [32]u8;

const OrdinalWorkload = struct {
    fn run(gpa: Allocator, storage: runtime.storage.Storage, seed: u64) !void {
        var rng = utils.rng.TestRng.init(seed);
        var registry = metrics.Registry.init(gpa);
        defer registry.deinit();
        var partition_buffer: [64]u8 = undefined;
        const partition =
            try std.fmt.bufPrint(&partition_buffer, "ordinal-conformance-{d}", .{seed});
        const config: ordinal.Config = .{
            .partition = partition,
            .items_per_blob = 16,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
        const scope = metrics.Scope.init(&registry).child("ordinal");
        var store = try ordinal.Ordinal(Value).init(gpa, storage, scope, config, null);
        defer store.deinit();
        const items = utils.rng.range_less_than(&rng, usize, 16, 80);
        for (0..items) |i| {
            const index = @as(u64, i) * 3 + seed % 3;
            var value: Value = undefined;
            rng.fill_bytes(&value);
            try store.put(index, value);
        }
        try store.sync();
        if (items > 32) {
            try store.prune(32);
            try store.sync();
        }
    }

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var memory = runtime.storage.memory.Storage.init(gpa);
        defer memory.deinit();
        try run(gpa, memory.storage(), seed);
        const audit = memory.audit();
        return gpa.dupe(u8, &audit);
    }
};

/// `Record::arbitrary`: an arbitrary value and the CRC of its bytes.
const RecordConformance = struct {
    const Record = ordinal.Record(u32);

    pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const value = try codec.arbitrary.generate(
            u32,
            codec.arbitrary.default_generator(u32),
            arena.allocator(),
            seed,
        );
        const bytes = Record.encode(value);
        return gpa.dupe(u8, &bytes);
    }
};

test "conformance StorageConformance<OrdinalWorkload>" {
    try conformance.verify(
        OrdinalWorkload,
        std.testing.allocator,
        "commonware_storage::ordinal::conformance::StorageConformance<OrdinalWorkload>",
        256,
        conformance_file,
    );
}

test "conformance CodecConformance<Record<u32>>" {
    try conformance.verify(
        RecordConformance,
        std.heap.smp_allocator,
        "commonware_storage::ordinal::storage::conformance::CodecConformance<Record<u32>>",
        conformance.default_cases,
        conformance_file,
    );
}
