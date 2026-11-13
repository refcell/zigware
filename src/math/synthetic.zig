//! Synthetic linear combinations of free generators and concrete points (commonware
//! `math::synthetic`).
//!
//! A `Synthetic(F, G)` is `sum_i w_i * G_i + sum_j v_j * P_j`, where the `G_i` are abstract
//! generators identified by `u32` index and bound later by `eval`, and the `P_j` are concrete
//! points. Scaling multiplies every weight; addition merges free terms by index and
//! concatenates concrete terms.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const algebra = @import("algebra.zig");
const fuzz = @import("fuzz.zig");
const Unstructured = fuzz.Unstructured;

pub fn Synthetic(comptime F: type, comptime G: type) type {
    algebra.assert_additive(F);
    algebra.assert_space(G, F);
    return struct {
        const Self = @This();

        pub const FreeTerm = struct { index: u32, weight: F };
        pub const ConcreteTerm = struct { weight: F, point: G };

        /// Sorted by strictly increasing index.
        free: std.ArrayList(FreeTerm) = .empty,
        concrete: std.ArrayList(ConcreteTerm) = .empty,

        pub const zero: Self = .{};

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.free.deinit(allocator);
            self.concrete.deinit(allocator);
            self.* = undefined;
        }

        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            var out: Self = .{ .free = try self.free.clone(allocator) };
            errdefer out.free.deinit(allocator);
            out.concrete = try self.concrete.clone(allocator);
            return out;
        }

        /// The generator G_index with unit weight.
        pub fn generator(allocator: Allocator, index: u32) Allocator.Error!Self {
            comptime algebra.assert_ring(F);
            var out: Self = .{};
            try out.free.append(allocator, .{ .index = index, .weight = F.one });
            return out;
        }

        /// From known weighted points.
        pub fn init_concrete(allocator: Allocator, terms: []const ConcreteTerm) !Self {
            var out: Self = .{};
            try out.concrete.appendSlice(allocator, terms);
            return out;
        }

        /// The largest free generator index, or null without free terms.
        pub fn max_free_index(self: Self) ?u32 {
            if (self.free.items.len == 0) return null;
            return self.free.items[self.free.items.len - 1].index;
        }

        fn merge_free(self: *Self, allocator: Allocator, term: FreeTerm, negate: bool) !void {
            const weight = if (negate) term.weight.neg() else term.weight;
            var position: usize = 0;
            while (position < self.free.items.len) : (position += 1) {
                const existing = &self.free.items[position];
                if (existing.index == term.index) {
                    existing.weight = existing.weight.add(weight);
                    return;
                }
                if (existing.index > term.index) break;
            }
            try self.free.insert(allocator, position, .{ .index = term.index, .weight = weight });
        }

        fn merge(self: *Self, allocator: Allocator, rhs: Self, negate: bool) !void {
            for (rhs.free.items) |term| try self.merge_free(allocator, term, negate);
            try self.concrete.ensureUnusedCapacity(allocator, rhs.concrete.items.len);
            for (rhs.concrete.items) |term| {
                const weight = if (negate) term.weight.neg() else term.weight;
                self.concrete.appendAssumeCapacity(.{ .weight = weight, .point = term.point });
            }
        }

        pub fn add_assign(self: *Self, allocator: Allocator, rhs: Self) !void {
            try self.merge(allocator, rhs, false);
        }

        pub fn sub_assign(self: *Self, allocator: Allocator, rhs: Self) !void {
            try self.merge(allocator, rhs, true);
        }

        pub fn neg_assign(self: *Self) void {
            for (self.free.items) |*term| term.weight = term.weight.neg();
            for (self.concrete.items) |*term| term.weight = term.weight.neg();
        }

        /// Multiply every weight by `scalar`.
        pub fn mul_assign(self: *Self, scalar: F) void {
            for (self.free.items) |*term| term.weight = term.weight.mul(scalar);
            for (self.concrete.items) |*term| term.weight = term.weight.mul(scalar);
        }

        /// Substitute `generators[i]` for each free index `i` and sum.
        pub fn eval(self: Self, allocator: Allocator, generators: []const G) !G {
            const total = self.free.items.len + self.concrete.items.len;
            const points = try allocator.alloc(G, total);
            defer allocator.free(points);
            const weights = try allocator.alloc(F, total);
            defer allocator.free(weights);
            for (self.free.items, 0..) |term, i| {
                assert(term.index < generators.len);
                points[i] = generators[term.index];
                weights[i] = term.weight;
            }
            const offset = self.free.items.len;
            for (self.concrete.items, 0..) |term, i| {
                points[offset + i] = term.point;
                weights[offset + i] = term.weight;
            }
            return algebra.msm(G, F, points, weights);
        }

        /// Equal free weights (missing ones count as zero), and equal concrete sums.
        pub fn eql(a: Self, b: Self, allocator: Allocator) !bool {
            var i: usize = 0;
            var j: usize = 0;
            while (i < a.free.items.len or j < b.free.items.len) {
                const left: ?FreeTerm = if (i < a.free.items.len) a.free.items[i] else null;
                const right: ?FreeTerm = if (j < b.free.items.len) b.free.items[j] else null;
                var lw = F.zero;
                var rw = F.zero;
                if (left != null and (right == null or left.?.index <= right.?.index)) {
                    lw = left.?.weight;
                    i += 1;
                }
                if (right != null and (left == null or right.?.index <= left.?.index)) {
                    rw = right.?.weight;
                    j += 1;
                }
                if (!lw.eql(rw)) return false;
            }
            var difference: Self = .{};
            defer difference.deinit(allocator);
            try difference.concrete.appendSlice(allocator, a.concrete.items);
            for (b.concrete.items) |term| {
                try difference.concrete.append(allocator, .{
                    .weight = term.weight.neg(),
                    .point = term.point,
                });
            }
            return (try difference.eval(allocator, &.{})).eql(G.zero);
        }

        pub fn arbitrary(allocator: Allocator, u: *Unstructured) !Self {
            var out: Self = .{};
            errdefer out.deinit(allocator);
            const free_count = u.int_in_range(u8, 0, 8);
            for (0..free_count) |_| {
                const index = u.int_in_range(u32, 0, 32);
                const weight = F.arbitrary(u);
                // Like a BTreeMap collect: a later duplicate index replaces the earlier one.
                var position: usize = 0;
                while (position < out.free.items.len and out.free.items[position].index < index) {
                    position += 1;
                }
                const items = out.free.items;
                if (position < items.len and items[position].index == index) {
                    items[position].weight = weight;
                } else {
                    try out.free.insert(allocator, position, .{ .index = index, .weight = weight });
                }
            }
            const concrete_count = u.length(8);
            for (0..concrete_count) |_| {
                try out.concrete.append(allocator, .{
                    .weight = F.arbitrary(u),
                    .point = G.arbitrary(u),
                });
            }
            return out;
        }
    };
}

const testing_types = @import("testing.zig");
const TF = testing_types.F;
const TG = testing_types.G;
const S = Synthetic(TF, TG);

fn expect(ok: bool) !void {
    if (!ok) return error.LawViolated;
}

fn eval_matches_msm(allocator: Allocator, u: *Unstructured) !void {
    var free_weights: [8]TF = undefined;
    const free_count = u.length(free_weights.len);
    var expression: S = .{};
    defer expression.deinit(allocator);
    for (free_weights[0..free_count], 0..) |*w, i| {
        w.* = TF.arbitrary(u);
        var term = try S.generator(allocator, @intCast(i));
        defer term.deinit(allocator);
        term.mul_assign(w.*);
        try expression.add_assign(allocator, term);
    }
    var concrete: [8]S.ConcreteTerm = undefined;
    const concrete_count = u.length(concrete.len);
    for (concrete[0..concrete_count]) |*c| {
        c.* = .{ .weight = TF.arbitrary(u), .point = TG.arbitrary(u) };
    }
    var concrete_part = try S.init_concrete(allocator, concrete[0..concrete_count]);
    defer concrete_part.deinit(allocator);
    try expression.add_assign(allocator, concrete_part);
    var points: [16]TG = undefined;
    var weights: [16]TF = undefined;
    for (0..free_count) |i| {
        points[i] = TG.arbitrary(u);
        weights[i] = free_weights[i];
    }
    for (concrete[0..concrete_count], 0..) |c, i| {
        points[free_count + i] = c.point;
        weights[free_count + i] = c.weight;
    }
    const count = free_count + concrete_count;
    const expected = algebra.msm(TG, TF, points[0..count], weights[0..count]);
    try expect((try expression.eval(allocator, points[0..free_count])).eql(expected));
}

fn eval_is_linear(allocator: Allocator, u: *Unstructured) !void {
    var lhs = try S.arbitrary(allocator, u);
    defer lhs.deinit(allocator);
    var rhs = try S.arbitrary(allocator, u);
    defer rhs.deinit(allocator);
    var generators: [33]TG = undefined;
    for (&generators) |*g| g.* = TG.arbitrary(u);
    const lhs_eval = try lhs.eval(allocator, &generators);
    const rhs_eval = try rhs.eval(allocator, &generators);
    try lhs.add_assign(allocator, rhs);
    try expect((try lhs.eval(allocator, &generators)).eql(lhs_eval.add(rhs_eval)));
}

fn fuzz_additive(allocator: Allocator, u: *Unstructured) !void {
    var a = try S.arbitrary(allocator, u);
    defer a.deinit(allocator);
    var b = try S.arbitrary(allocator, u);
    defer b.deinit(allocator);
    var ab = try a.clone(allocator);
    defer ab.deinit(allocator);
    try ab.add_assign(allocator, b);
    var ba = try b.clone(allocator);
    defer ba.deinit(allocator);
    try ba.add_assign(allocator, a);
    try expect(try ab.eql(ba, allocator));
    var difference = try a.clone(allocator);
    defer difference.deinit(allocator);
    try difference.sub_assign(allocator, a);
    try expect(try difference.eql(S.zero, allocator));
    var negated = try a.clone(allocator);
    defer negated.deinit(allocator);
    negated.neg_assign();
    try negated.add_assign(allocator, a);
    try expect(try negated.eql(S.zero, allocator));
}

fn fuzz_space_ring(allocator: Allocator, u: *Unstructured) !void {
    var a = try S.arbitrary(allocator, u);
    defer a.deinit(allocator);
    var b = try S.arbitrary(allocator, u);
    defer b.deinit(allocator);
    const x = TF.arbitrary(u);
    const y = TF.arbitrary(u);
    // (a + b) * x == a * x + b * x
    var left = try a.clone(allocator);
    defer left.deinit(allocator);
    try left.add_assign(allocator, b);
    left.mul_assign(x);
    var right = try a.clone(allocator);
    defer right.deinit(allocator);
    right.mul_assign(x);
    var bx = try b.clone(allocator);
    defer bx.deinit(allocator);
    bx.mul_assign(x);
    try right.add_assign(allocator, bx);
    try expect(try left.eql(right, allocator));
    // (a * x) * y == a * (x * y), a * 1 == a, a * 0 == 0.
    var axy = try a.clone(allocator);
    defer axy.deinit(allocator);
    axy.mul_assign(x);
    axy.mul_assign(y);
    var a_xy = try a.clone(allocator);
    defer a_xy.deinit(allocator);
    a_xy.mul_assign(x.mul(y));
    try expect(try axy.eql(a_xy, allocator));
    var scaled = try a.clone(allocator);
    defer scaled.deinit(allocator);
    scaled.mul_assign(TF.one);
    try expect(try scaled.eql(a, allocator));
    scaled.mul_assign(TF.zero);
    try expect(try scaled.eql(S.zero, allocator));
}

/// The synthetic fuzz plan (commonware `synthetic::fuzz::Plan`).
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const allocator = std.testing.allocator;
    switch (u.choose(enum { eval_matches_msm, eval_is_linear, fuzz_additive, fuzz_space_ring })) {
        .eval_matches_msm => try eval_matches_msm(allocator, u),
        .eval_is_linear => try eval_is_linear(allocator, u),
        .fuzz_additive => try fuzz_additive(allocator, u),
        .fuzz_space_ring => try fuzz_space_ring(allocator, u),
    }
}

const testing = std.testing;

test "synthetic fuzz plan (seeded)" {
    try fuzz.run_seeded(0x5e7, 500, {}, fuzz_plan);
}

test "synthetic fuzz plan (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            try fuzz.run_smith({}, smith, fuzz_plan);
        }
    }.one, .{});
}

test "generators track indices" {
    const allocator = testing.allocator;
    try testing.expectEqual(@as(?u32, null), S.zero.max_free_index());
    for (0..3) |i| {
        var g = try S.generator(allocator, @intCast(i));
        defer g.deinit(allocator);
        try testing.expectEqual(@as(?u32, @intCast(i)), g.max_free_index());
    }
}

test "equality handles zero free weights and concrete terms" {
    const allocator = testing.allocator;
    var g0 = try S.generator(allocator, 0);
    defer g0.deinit(allocator);
    g0.mul_assign(TF.zero);
    try testing.expect(try S.zero.eql(g0, allocator));
    var concrete = try S.init_concrete(allocator, &.{.{
        .weight = TF.from_u64(3),
        .point = TG.generator,
    }});
    defer concrete.deinit(allocator);
    try testing.expect(try concrete.eql(concrete, allocator));
    try testing.expect(!try concrete.eql(S.zero, allocator));
}

test "documented example: 2 G0 + 3 G1" {
    const allocator = testing.allocator;
    var expression = try S.generator(allocator, 0);
    defer expression.deinit(allocator);
    expression.mul_assign(TF.from_u64(2));
    var g1 = try S.generator(allocator, 1);
    defer g1.deinit(allocator);
    g1.mul_assign(TF.from_u64(3));
    try expression.add_assign(allocator, g1);
    const a = TG.generator;
    const b = a.mul(TF.from_u64(5));
    const expected = a.mul(TF.from_u64(2)).add(b.mul(TF.from_u64(3)));
    try testing.expect((try expression.eval(allocator, &.{ a, b })).eql(expected));
}
