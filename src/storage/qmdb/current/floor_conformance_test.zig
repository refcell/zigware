//! Floor-policy root conformance of the `current` database (commonware's `qmdb/conformance.rs`
//! `Current{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}FloorConf`): the canonical root after
//! the `any` floor workload (`floor_batches`), whose batches advance their floors under
//! `Proportional`, `Hold`, `Bounded`, and a seeded keep, evict, replace, or stop policy, over
//! 200 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const qmdb_support = @import("../test_support.zig");
const any_floor = @import("../any/floor_conformance_test.zig");
const support = @import("test_support.zig");

fn FloorConformance(comptime Db: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open(Db, null);
            errdefer db.deinit();
            var plan = try any_floor.floor_batches(gpa, seed);
            defer plan.deinit();
            assert(plan.batches.items.len > 0);
            for (plan.batches.items) |*b| {
                var batch = try db.new_batch();
                const merkleized = merkleized: {
                    errdefer batch.deinit();
                    for (b.writes) |w| try batch.write(w.key, w.value);
                    break :merkleized try batch.merkleize_with(&db, &b.rule);
                };
                defer merkleized.release();
                try db.apply_batch(merkleized);
            }
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }
    };
}

const name_prefix = "commonware_storage::qmdb::conformance::tests::";

fn verify(comptime Db: type, comptime name: []const u8) !void {
    const gpa = std.heap.smp_allocator;
    const file = qmdb_support.conformance_file;
    try conformance.verify(FloorConformance(Db), gpa, name_prefix ++ name, 200, file);
}

test "current floor conformance (MMR unordered fixed)" {
    try verify(support.UnorderedFixed(merkle.mmr.Family), "CurrentMmrUnorderedFixedFloorConf");
}

test "current floor conformance (MMB unordered fixed)" {
    try verify(support.UnorderedFixed(merkle.mmb.Family), "CurrentMmbUnorderedFixedFloorConf");
}

test "current floor conformance (MMR unordered variable)" {
    const name = "CurrentMmrUnorderedVariableFloorConf";
    try verify(support.UnorderedVariable(merkle.mmr.Family), name);
}

test "current floor conformance (MMB unordered variable)" {
    const name = "CurrentMmbUnorderedVariableFloorConf";
    try verify(support.UnorderedVariable(merkle.mmb.Family), name);
}

test "current floor conformance (MMR ordered fixed)" {
    try verify(support.OrderedFixed(merkle.mmr.Family), "CurrentMmrOrderedFixedFloorConf");
}

test "current floor conformance (MMB ordered fixed)" {
    try verify(support.OrderedFixed(merkle.mmb.Family), "CurrentMmbOrderedFixedFloorConf");
}

test "current floor conformance (MMR ordered variable)" {
    try verify(support.OrderedVariable(merkle.mmr.Family), "CurrentMmrOrderedVariableFloorConf");
}

test "current floor conformance (MMB ordered variable)" {
    try verify(support.OrderedVariable(merkle.mmb.Family), "CurrentMmbOrderedVariableFloorConf");
}
