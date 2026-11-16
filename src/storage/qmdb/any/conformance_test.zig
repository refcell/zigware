//! Root conformance of the `any` database (commonware's `qmdb/conformance.rs`
//! `Any{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}Conf`): the root after a four-batch keyed
//! workload exercising creates, updates, deletes, recreates, and translator collisions, over
//! 200 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const test_support = @import("../test_support.zig");
const support = @import("test_support.zig");

const Write = support.Write;
const to_digest = support.to_digest;
const to_val = support.to_val;
const colliding_digest = support.colliding_digest;

/// Commonware's `is_deleted`: about a fifth of the keys, varying with the seed.
fn is_deleted(seed: u64, i: u64) bool {
    return (seed ^ i) % 5 == 0;
}

/// Commonware's `keyed_batches(seed)`, as four write lists. The caller frees each.
pub fn keyed_batches(gpa: Allocator, seed: u64) ![4][]Write {
    const n = seed % 50 + 5;
    const prefix: u8 = @intCast(seed % 256);
    var lists: [4]std.ArrayList(Write) = @splat(.empty);
    errdefer for (&lists) |*list| list.deinit(gpa);
    for (0..n) |i| try lists[0].append(gpa, .{ .key = to_digest(i), .value = to_val(i, 1) });
    for (0..n) |i| {
        const value: ?support.Digest = if (is_deleted(seed, i)) null else to_val(i, 2);
        try lists[1].append(gpa, .{ .key = to_digest(i), .value = value });
    }
    for (0..n) |i| {
        if (!is_deleted(seed, i)) continue;
        try lists[2].append(gpa, .{ .key = to_digest(i), .value = to_val(i, 3) });
    }
    for (0..n / 2) |i| {
        const key = colliding_digest(prefix, 10000 + i);
        try lists[2].append(gpa, .{ .key = key, .value = to_val(i, 4) });
    }
    for (0..n) |i| try lists[3].append(gpa, .{ .key = to_digest(i), .value = to_val(i, 5) });
    for (0..n / 2) |i| {
        const key = colliding_digest(prefix, 10000 + i);
        const value: ?support.Digest = if (i % 2 == 1) null else to_val(i, 6);
        try lists[3].append(gpa, .{ .key = key, .value = value });
    }
    var out: [4][]Write = undefined;
    var done: usize = 0;
    errdefer for (out[0..done]) |list| gpa.free(list);
    for (&lists, &out) |*list, *slot| {
        slot.* = try list.toOwnedSlice(gpa);
        done += 1;
    }
    return out;
}

fn AnyConformance(comptime Db: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open(Db, null);
            errdefer db.deinit();
            const batches = try keyed_batches(gpa, seed);
            defer for (batches) |list| gpa.free(list);
            for (batches) |writes| try support.apply_writes(Db, &db, writes);
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const name_prefix = "commonware_storage::qmdb::conformance::tests::";

test "any root conformance (MMR unordered fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.UnorderedFixed(merkle.mmr.Family));
    const name = name_prefix ++ "AnyMmrUnorderedFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMB unordered fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.UnorderedFixed(merkle.mmb.Family));
    const name = name_prefix ++ "AnyMmbUnorderedFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMR ordered fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.OrderedFixed(merkle.mmr.Family));
    const name = name_prefix ++ "AnyMmrOrderedFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMB ordered fixed)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.OrderedFixed(merkle.mmb.Family));
    const name = name_prefix ++ "AnyMmbOrderedFixedConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMR unordered variable)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.UnorderedVariable(merkle.mmr.Family));
    const name = name_prefix ++ "AnyMmrUnorderedVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMR ordered variable)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.OrderedVariable(merkle.mmr.Family));
    const name = name_prefix ++ "AnyMmrOrderedVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMB unordered variable)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.UnorderedVariable(merkle.mmb.Family));
    const name = name_prefix ++ "AnyMmbUnorderedVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}

test "any root conformance (MMB ordered variable)" {
    const gpa = std.heap.smp_allocator;
    const C = AnyConformance(support.OrderedVariable(merkle.mmb.Family));
    const name = name_prefix ++ "AnyMmbOrderedVariableConf";
    try conformance.verify(C, gpa, name, 200, test_support.conformance_file);
}
