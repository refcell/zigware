//! Floor-policy root conformance of the `any` database (commonware's `qmdb/conformance.rs`
//! `Any{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}FloorConf`): the root after commonware's
//! `floor_batches` workload, whose batches advance their floors under `Proportional`, `Hold`,
//! `Bounded`, and a seeded policy that keeps, evicts, replaces, or stops, over 200 seeds.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const conformance = @import("conformance");
const merkle = @import("../../merkle/mod.zig");
const floor_mod = @import("../floor.zig");
const test_support = @import("../test_support.zig");
const support = @import("test_support.zig");

const Digest = support.Digest;
const Sha256 = support.Sha256;
const Write = support.Write;

/// The policy a batch of the workload advances its floor with (commonware's `Rule`).
const Rule = union(enum) {
    proportional,
    hold,
    bounded: floor_mod.Bounded,
    seeded: struct { seed: u64, entries: usize, skips: u64 },

    pub fn evicts(self: *const Rule) bool {
        return self.* == .seeded;
    }

    pub fn limits(self: *const Rule, made_inactive: usize) floor_mod.Limits {
        return switch (self.*) {
            .proportional => (floor_mod.Proportional{}).limits(made_inactive),
            .hold => (floor_mod.Hold{}).limits(made_inactive),
            .bounded => |*b| b.limits(made_inactive),
            .seeded => |s| .{ .entries = s.entries, .skips = s.skips },
        };
    }

    pub fn decide(
        self: *Rule,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        comptime assert(K == Digest and V == Digest);
        switch (self.*) {
            .hold => return entry.stop(),
            .proportional, .bounded => return entry.keep(),
            .seeded => |s| {
                const mix = entry.location ^ s.seed ^ @as(u64, entry.key.bytes[31]);
                switch (mix % 8) {
                    0 => {
                        const decision, _ = entry.evict(); // Digests own no memory.
                        return decision;
                    },
                    1 => return entry.replace(Sha256.hash(&.{&entry.value.bytes})),
                    2 => return entry.stop(),
                    else => return entry.keep(),
                }
            },
        }
    }
};

/// The first id of the keys that share a translator bucket.
const colliding = 10_000;

const Batch = struct { writes: []Write, rule: Rule };

/// Builds the batches of `floor_batches` over key ids (commonware's `Plan`).
const Plan = struct {
    gpa: Allocator,
    seed: u64,
    prefix: u8,
    /// Sorted ids.
    live: std.ArrayList(u64) = .empty,
    dead: std.ArrayList(u64) = .empty,
    /// The open batch's writes, sorted by key.
    writes: std.ArrayList(Write) = .empty,
    batches: std.ArrayList(Batch) = .empty,

    pub fn deinit(self: *Plan) void {
        self.live.deinit(self.gpa);
        self.dead.deinit(self.gpa);
        self.writes.deinit(self.gpa);
        for (self.batches.items) |b| self.gpa.free(b.writes);
        self.batches.deinit(self.gpa);
        self.* = undefined;
    }

    fn key(self: *const Plan, id: u64) Digest {
        if (id >= colliding) return support.colliding_digest(self.prefix, id);
        return support.to_digest(id);
    }

    fn contains(ids: []const u64, id: u64) bool {
        return std.sort.binarySearch(u64, ids, id, order_u64) != null;
    }

    fn order_u64(context: u64, item: u64) std.math.Order {
        return std.math.order(context, item);
    }

    fn insert_id(self: *Plan, ids: *std.ArrayList(u64), id: u64) !void {
        const at = std.sort.lowerBound(u64, ids.items, id, order_u64);
        if (at < ids.items.len and ids.items[at] == id) return;
        try ids.insert(self.gpa, at, id);
    }

    fn remove_id(ids: *std.ArrayList(u64), id: u64) bool {
        const at = std.sort.binarySearch(u64, ids.items, id, order_u64) orelse return false;
        _ = ids.orderedRemove(at);
        return true;
    }

    fn write_index(self: *const Plan, k: *const Digest) struct { usize, bool } {
        var low: usize = 0;
        var high: usize = self.writes.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            switch (std.mem.order(u8, &self.writes.items[mid].key.bytes, &k.bytes)) {
                .lt => low = mid + 1,
                .gt => high = mid,
                .eq => return .{ mid, true },
            }
        }
        return .{ low, false };
    }

    fn put(self: *Plan, k: Digest, value: ?Digest) !void {
        const at, const found = self.write_index(&k);
        if (found) {
            self.writes.items[at].value = value;
        } else {
            try self.writes.insert(self.gpa, at, .{ .key = k, .value = value });
        }
    }

    fn set(self: *Plan, id: u64) !void {
        const value = support.to_val(id, self.batches.items.len);
        try self.put(self.key(id), value);
        _ = remove_id(&self.dead, id);
        try self.insert_id(&self.live, id);
    }

    fn delete(self: *Plan, id: u64) !void {
        try self.put(self.key(id), null);
        if (remove_id(&self.live, id)) try self.insert_id(&self.dead, id);
    }

    /// The `j`th seeded pick from `ids` the open batch does not write yet.
    fn pick(self: *const Plan, ids: []const u64, j: u64) !?u64 {
        var open: std.ArrayList(u64) = .empty;
        defer open.deinit(self.gpa);
        for (ids) |id| {
            _, const written = self.write_index(&self.key(id));
            if (!written) try open.append(self.gpa, id);
        }
        if (open.items.len == 0) return null;
        var bytes: [3][8]u8 = undefined;
        std.mem.writeInt(u64, &bytes[0], self.seed, .big);
        std.mem.writeInt(u64, &bytes[1], self.batches.items.len, .big);
        std.mem.writeInt(u64, &bytes[2], j, .big);
        const digest = Sha256.hash(&.{ &bytes[0], &bytes[1], &bytes[2] });
        const mix = std.mem.readInt(u64, digest.bytes[0..8], .big);
        return open.items[@intCast(mix % open.items.len)];
    }

    fn live_pick(self: *const Plan, j: u64) !u64 {
        return (try self.pick(self.live.items, j)).?;
    }

    fn close(self: *Plan, rule: Rule) !void {
        try self.batches.ensureUnusedCapacity(self.gpa, 1);
        const writes = try self.writes.toOwnedSlice(self.gpa);
        self.batches.appendAssumeCapacity(.{ .writes = writes, .rule = rule });
    }

    fn push(self: *Plan) !void {
        const round: u64 = self.batches.items.len;
        const rule: Rule = switch (round % 8) {
            2 => .hold,
            4 => .{ .bounded = .{ .entries = @intCast(1 + self.seed % 3), .skips = round % 5 } },
            6 => .{ .seeded = .{
                .seed = self.seed,
                .entries = @intCast(2 + self.seed % 4),
                .skips = round % 7,
            } },
            else => .proportional,
        };
        try self.close(rule);
    }
};

/// Commonware's `floor_batches(seed)`. The caller deinits the plan holding them.
pub fn floor_batches(gpa: Allocator, seed: u64) !Plan {
    const n = seed % 48 + 40;
    var plan: Plan = .{ .gpa = gpa, .seed = seed, .prefix = @intCast(seed % 256) };
    errdefer plan.deinit();
    // 1. Create n keys and eight colliding keys.
    for (0..n) |id| try plan.set(id);
    for (colliding..colliding + 8) |id| try plan.set(id);
    try plan.close(.proportional);
    // 2. Update three live keys per batch.
    for (0..12) |_| {
        for (0..3) |j| try plan.set(try plan.live_pick(j));
        try plan.push();
    }
    // 3. Delete two live keys, update one, and delete a missing key per batch.
    for (0..12) |round| {
        for (0..2) |j| try plan.delete(try plan.live_pick(j));
        try plan.set(try plan.live_pick(2));
        const missing: u64 = if (round % 2 == 0) 5_000 else colliding + 5_000;
        try plan.delete(missing + round);
        try plan.push();
    }
    try later_batches(&plan, seed, n);
    return plan;
}

/// Steps 4 to 8 of `floor_batches`.
fn later_batches(plan: *Plan, seed: u64, n: u64) !void {
    // 4. Recreate two deleted keys and update one live key per batch.
    for (0..8) |_| {
        for (0..2) |j| {
            if (try plan.pick(plan.dead.items, j)) |id| try plan.set(id);
        }
        try plan.set(try plan.live_pick(2));
        try plan.push();
    }
    // 5. Toggle one colliding key and update another per batch.
    for (0..6) |round| {
        const toggled = colliding + (3 * round) % 8;
        if (Plan.contains(plan.live.items, toggled)) {
            try plan.delete(toggled);
        } else {
            try plan.set(toggled);
        }
        const updated = colliding + (3 * round + 1) % 8;
        if (Plan.contains(plan.live.items, updated)) try plan.set(updated);
        try plan.push();
    }
    // 6. Apply two batches without writes.
    try plan.close(.proportional);
    try plan.close(.{ .seeded = .{ .seed = seed, .entries = 4, .skips = 4 } });
    // 7. Delete four live keys per batch until four remain.
    while (plan.live.items.len > 4) {
        for (0..4) |j| {
            if (plan.live.items.len > 4) try plan.delete(try plan.live_pick(j));
        }
        try plan.push();
    }
    // 8. Create 16 keys, then update two live keys per batch.
    for (n..n + 16) |id| try plan.set(id);
    try plan.push();
    for (0..4) |_| {
        for (0..2) |j| try plan.set(try plan.live_pick(j));
        try plan.push();
    }
}

fn FloorConformance(comptime Db: type) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var harness = try support.Harness.init(gpa);
            defer harness.deinit();
            var db = try harness.open(Db, null);
            errdefer db.deinit();
            var plan = try floor_batches(gpa, seed);
            defer plan.deinit();
            for (plan.batches.items) |*b| try apply(&db, b.writes, &b.rule);
            const root = db.root();
            try db.destroy();
            return gpa.dupe(u8, &root.bytes);
        }

        fn apply(db: *Db, writes: []const Write, rule: *Rule) !void {
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                for (writes) |w| try batch.write(w.key, w.value);
                break :merkleized try batch.merkleize_with(db, rule);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }
    };
}

const name_prefix = "commonware_storage::qmdb::conformance::tests::";

fn verify(comptime Db: type, comptime name: []const u8) !void {
    const gpa = std.heap.smp_allocator;
    const file = test_support.conformance_file;
    try conformance.verify(FloorConformance(Db), gpa, name_prefix ++ name, 200, file);
}

test "any floor conformance (MMR unordered fixed)" {
    try verify(support.UnorderedFixed(merkle.mmr.Family), "AnyMmrUnorderedFixedFloorConf");
}

test "any floor conformance (MMB unordered fixed)" {
    try verify(support.UnorderedFixed(merkle.mmb.Family), "AnyMmbUnorderedFixedFloorConf");
}

test "any floor conformance (MMR unordered variable)" {
    try verify(support.UnorderedVariable(merkle.mmr.Family), "AnyMmrUnorderedVariableFloorConf");
}

test "any floor conformance (MMB unordered variable)" {
    try verify(support.UnorderedVariable(merkle.mmb.Family), "AnyMmbUnorderedVariableFloorConf");
}

test "any floor conformance (MMR ordered fixed)" {
    try verify(support.OrderedFixed(merkle.mmr.Family), "AnyMmrOrderedFixedFloorConf");
}

test "any floor conformance (MMB ordered fixed)" {
    try verify(support.OrderedFixed(merkle.mmb.Family), "AnyMmbOrderedFixedFloorConf");
}

test "any floor conformance (MMR ordered variable)" {
    try verify(support.OrderedVariable(merkle.mmr.Family), "AnyMmrOrderedVariableFloorConf");
}

test "any floor conformance (MMB ordered variable)" {
    try verify(support.OrderedVariable(merkle.mmb.Family), "AnyMmbOrderedVariableFloorConf");
}
