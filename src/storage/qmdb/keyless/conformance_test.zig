//! Root conformance of the keyless database (commonware's `qmdb/conformance.rs`
//! `Keyless{Mmr,Mmb}{Fixed,Variable}Conf`): the root after a three-batch append workload, over
//! 200 seeds. Fixed values are `U64(x)`; variable ones are `x`'s 8 big-endian bytes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const conformance = @import("conformance");
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const value = @import("../value.zig");
const test_support = @import("../test_support.zig");
const keyless = @import("mod.zig");

const Sha256 = cryptography.Sha256;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const Bytes = []const u8;

fn Encoding(comptime is_variable: bool) type {
    return if (is_variable) value.Variable(Bytes) else value.Fixed(U64);
}

pub fn Db(comptime F: type, comptime is_variable: bool) type {
    const E = Encoding(is_variable);
    const Op = keyless.Operation(F, E);
    const J = if (is_variable) variable.Journal(Op) else fixed.Journal(Op);
    return keyless.Db(F, E, J, Sha256);
}

/// The workload's value for `x`, owned by the caller.
fn make_value(comptime is_variable: bool, gpa: Allocator, x: u64) !Encoding(is_variable).Value {
    if (!is_variable) return U64.init(x);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, x, .big);
    return gpa.dupe(u8, &bytes);
}

/// Appends `count` values made from `first + i` (wrapping) in one batch at the floor.
fn apply_appends(comptime F: type, comptime V: bool, db: *Db(F, V), first: u64, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| {
            const made = try make_value(V, db.gpa, first +% i);
            errdefer codec.free(@TypeOf(made), db.gpa, made);
            try batch.append(made);
        }
        batch.with_inactivity_floor(db.inactivity_floor());
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

/// Commonware's `keyless_root!` workload for `seed`: n values, n more, then n / 2 from `!seed`.
pub fn workload(comptime F: type, comptime V: bool, db: *Db(F, V), seed: u64) !void {
    const n = seed % 30 + 5;
    try apply_appends(F, V, db, seed, n);
    try apply_appends(F, V, db, seed +% n, n);
    try apply_appends(F, V, db, ~seed, n / 2);
}

fn KeylessConformance(comptime F: type, comptime V: bool) type {
    return struct {
        /// The root after commonware's `keyless_root!` workload for `seed`.
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var storage = runtime.buffer.mocks.Storage.init(gpa);
            defer storage.deinit();
            var cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 101, 11);
            defer cache_ref.deinit();
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            const cfg: Db(F, V).Cfg = .{
                .merkle = .{
                    .journal_partition = "cf-mj",
                    .metadata_partition = "cf-mm",
                    .items_per_blob = 11,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                    .cache_ref = &cache_ref,
                },
                .log = if (V) .{
                    .partition = "cf-log",
                    .items_per_section = 7,
                    .codec_config = .{ .range = .inclusive(0, 10000) },
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                } else .{
                    .partition = "cf-log",
                    .items_per_blob = 7,
                    .cache_ref = &cache_ref,
                    .write_buffer = 1024,
                    .replay_buffer = 1024,
                },
            };
            const scope = metrics.Scope.init(&registry).child("db");
            var db = try Db(F, V).init(gpa, storage.interface(), scope, cfg, null);
            errdefer db.deinit();
            try workload(F, V, &db, seed);
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const prefix = "commonware_storage::qmdb::conformance::tests::";

test "keyless root conformance (MMR fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmr.Family, false);
    const name = prefix ++ "KeylessMmrFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "keyless root conformance (MMB fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmb.Family, false);
    const name = prefix ++ "KeylessMmbFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "keyless root conformance (MMR variable)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmr.Family, true);
    const name = prefix ++ "KeylessMmrVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "keyless root conformance (MMB variable)" {
    const gpa = std.heap.smp_allocator;
    const C = KeylessConformance(merkle.mmb.Family, true);
    const name = prefix ++ "KeylessMmbVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}
