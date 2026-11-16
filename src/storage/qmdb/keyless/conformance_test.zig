//! Root conformance of the keyless database (commonware's `qmdb/conformance.rs`
//! `Keyless{Mmr,Mmb}FixedConf`): the root after a three-batch append workload, over 200 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const value = @import("../value.zig");
const test_support = @import("../test_support.zig");
const keyless = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const Encoding = value.Fixed(U64);

fn Db(comptime F: type) type {
    return keyless.Db(F, Encoding, fixed.Journal(keyless.Operation(F, Encoding)), Sha256);
}

/// Appends `count` values `U64(first + i)` (wrapping) in one batch at the database's floor.
fn apply_appends(comptime F: type, db: *Db(F), first: u64, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| try batch.append(U64.init(first +% i));
        batch.with_inactivity_floor(db.inactivity_floor());
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn KeylessConformance(comptime F: type) type {
    return struct {
        /// The root after commonware's `keyless_root!` workload for `seed`.
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var storage = runtime.buffer.mocks.Storage.init(gpa);
            defer storage.deinit();
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
            defer cache_ref.deinit();
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            const cfg: Db(F).Cfg = .{
                .merkle = .{
                    .journal_partition = "cf-mj",
                    .metadata_partition = "cf-mm",
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &cache_ref,
                },
                .log = .{
                    .partition = "cf-log",
                    .items_per_blob = 7,
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
            };
            const scope = metrics.Scope.init(&registry).child("db");
            var db = try Db(F).init(gpa, storage.interface(), scope, cfg, null);
            errdefer db.deinit();
            const n = seed % 30 + 5;
            try apply_appends(F, &db, seed, n);
            try apply_appends(F, &db, seed +% n, n);
            try apply_appends(F, &db, ~seed, n / 2);
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const prefix = "commonware_storage::qmdb::conformance::tests::";

test "keyless root conformance (MMR fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmr.Family);
    const name = prefix ++ "KeylessMmrFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "keyless root conformance (MMB fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmb.Family);
    const name = prefix ++ "KeylessMmbFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}
