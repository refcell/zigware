//! Storage conformance helper (commonware `runtime/src/conformance.rs`).
//!
//! `StorageConformance(Workload)` runs `Workload.run(ctx.child("workload"), seed)` on a
//! deterministic runner seeded with `seed` and commits the runner's storage audit (a CRC32C of
//! every durable blob). It has the `commit(gpa, seed) ![]u8` shape `conformance.verify`
//! takes, so a crate's workload hash can be checked against commonware's conformance.toml.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const deterministic = @import("deterministic.zig");

/// `Workload` declares `run(ctx: deterministic.Context, seed: u64) !void`.
pub fn StorageConformance(comptime Workload: type) type {
    comptime assert(@hasDecl(Workload, "run"));
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var runner = try deterministic.Runner.init(gpa, .{ .seed = seed });
            defer runner.deinit();
            const Root = struct {
                fn body(ctx: deterministic.Context, workload_seed: u64) !void {
                    try Workload.run(ctx.child("workload"), workload_seed);
                }
            };
            try (try runner.start_context(Root.body, .{seed}));
            const audit = runner.storage_audit();
            const result = try gpa.dupe(u8, &audit);
            assert(result.len == audit.len);
            return result;
        }
    };
}

const testing = std.testing;

/// Writes `seed`'s low byte and then `tail`, durably, to a blob named by `seed`.
fn Write(comptime tail: [3]u8) type {
    return struct {
        pub fn run(ctx: deterministic.Context, seed: u64) !void {
            const name = std.mem.toBytes(std.mem.nativeToBig(u64, seed));
            const opened = try ctx.storage.open("storage-conformance", &name);
            defer opened.blob.close();
            const bytes = [_]u8{@truncate(seed)} ++ tail;
            try opened.blob.write_at(0, &bytes, .{});
            try opened.blob.sync();
        }
    };
}

const SyncedWrite = Write(.{ 1, 2, 3 });
const DifferentWrite = Write(.{ 4, 5, 6 });

const EmptyWorkload = struct {
    pub fn run(ctx: deterministic.Context, seed: u64) !void {
        _ = .{ ctx, seed };
    }
};

fn commit(comptime Workload: type, seed: u64) ![]u8 {
    return StorageConformance(Workload).commit(testing.allocator, seed);
}

test "synced writes affect audit (synced_writes_affect_audit)" {
    const empty = try commit(EmptyWorkload, 0);
    defer testing.allocator.free(empty);
    const written = try commit(SyncedWrite, 0);
    defer testing.allocator.free(written);
    try testing.expect(!std.mem.eql(u8, empty, written));
}

test "identical workloads produce identical audits" {
    const first = try commit(SyncedWrite, 7);
    defer testing.allocator.free(first);
    const second = try commit(SyncedWrite, 7);
    defer testing.allocator.free(second);
    try testing.expectEqualSlices(u8, first, second);
}

test "different storage contents produce different audits" {
    const first = try commit(SyncedWrite, 7);
    defer testing.allocator.free(first);
    const second = try commit(DifferentWrite, 7);
    defer testing.allocator.free(second);
    try testing.expect(!std.mem.eql(u8, first, second));
}
