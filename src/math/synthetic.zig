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
const minifuzz = @import("invariants").minifuzz;
const Unstructured = minifuzz.Unstructured;

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

        /// Merges `rhs`'s free terms (both sorted by index) in one linear pass, as
        /// commonware's `BTreeMap` merge does in `O(n log n)`: a per-term scan and insert
        /// would be quadratic in the generator count.
        fn merge_free(
            self: *Self,
            allocator: Allocator,
            rhs: []const FreeTerm,
            negate: bool,
        ) !void {
            if (rhs.len == 0) return;
            const left = self.free.items;
            // Terms added in index order (a synthetic MSM over generators) append in place.
            if (left.len == 0 or left[left.len - 1].index < rhs[0].index) {
                try self.free.ensureUnusedCapacity(allocator, rhs.len);
                for (rhs) |term| {
                    const weight = if (negate) term.weight.neg() else term.weight;
                    self.free.appendAssumeCapacity(.{ .index = term.index, .weight = weight });
                }
                return;
            }
            var merged = try std.ArrayList(FreeTerm).initCapacity(allocator, left.len + rhs.len);
            var i: usize = 0;
            var j: usize = 0;
            while (i < left.len or j < rhs.len) {
                const take_left = j == rhs.len or (i < left.len and left[i].index <= rhs[j].index);
                const take_right = i == left.len or (j < rhs.len and rhs[j].index <= left[i].index);
                assert(take_left or take_right);
                var term: FreeTerm = undefined;
                if (take_left) term = left[i];
                if (take_right) {
                    const weight = if (negate) rhs[j].weight.neg() else rhs[j].weight;
                    term = if (take_left)
                        .{ .index = term.index, .weight = term.weight.add(weight) }
                    else
                        .{ .index = rhs[j].index, .weight = weight };
                }
                const items = merged.items;
                assert(items.len == 0 or items[items.len - 1].index < term.index);
                merged.appendAssumeCapacity(term);
                if (take_left) i += 1;
                if (take_right) j += 1;
            }
            assert(merged.items.len >= @max(left.len, rhs.len));
            self.free.deinit(allocator);
            self.free = merged;
        }

        fn merge(self: *Self, allocator: Allocator, rhs: Self, negate: bool) !void {
            try self.merge_free(allocator, rhs.free.items, negate);
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

        /// commonware's `Arbitrary`: up to eight free terms (index in 0..=32, then weight;
        /// a later duplicate index replaces the earlier one, as a BTreeMap collect), then
        /// arbitrary's `Vec<(F, G)>` of concrete terms.
        pub fn arbitrary(allocator: Allocator, u: *Unstructured) !Self {
            var out: Self = .{};
            errdefer out.deinit(allocator);
            const free_count = u.int_in_range(usize, 0, 8);
            for (0..free_count) |_| {
                const index = u.int_in_range(u32, 0, 32);
                const weight = try u.arbitrary(F);
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
            try arbitrary_concrete(allocator, u, &out.concrete);
            return out;
        }

        /// arbitrary's `Vec<(F, G)>`: a continue flag before each term.
        pub fn arbitrary_concrete(
            allocator: Allocator,
            u: *Unstructured,
            terms: *std.ArrayList(ConcreteTerm),
        ) !void {
            const flags_max = u.len() + 1;
            var flags: usize = 0;
            while (flags < flags_max and try u.arbitrary(bool)) : (flags += 1) {
                const weight = try u.arbitrary(F);
                try terms.append(allocator, .{ .weight = weight, .point = try u.arbitrary(G) });
            }
        }
    };
}

const testing_types = @import("testing.zig");
const build_options = @import("build_options");
const TF = testing_types.F;
const TG = testing_types.G;
const S = Synthetic(TF, TG);

fn expect(ok: bool) !void {
    if (!ok) return error.LawViolated;
}

/// arbitrary's `Vec<T>` for value types: a continue flag before each element.
fn arbitrary_list(comptime T: type, allocator: Allocator, u: *Unstructured) !std.ArrayList(T) {
    var out: std.ArrayList(T) = .empty;
    errdefer out.deinit(allocator);
    const flags_max = u.len() + 1;
    while (out.items.len < flags_max and try u.arbitrary(bool)) {
        try out.append(allocator, try u.arbitrary(T));
    }
    return out;
}

fn eval_matches_msm(allocator: Allocator, u: *Unstructured) !void {
    var free_weights = try arbitrary_list(TF, allocator, u);
    defer free_weights.deinit(allocator);
    var concrete: std.ArrayList(S.ConcreteTerm) = .empty;
    defer concrete.deinit(allocator);
    try S.arbitrary_concrete(allocator, u, &concrete);
    var expression: S = .{};
    defer expression.deinit(allocator);
    for (free_weights.items, 0..) |weight, index| {
        var term = try S.generator(allocator, @intCast(index));
        defer term.deinit(allocator);
        term.mul_assign(weight);
        try expression.add_assign(allocator, term);
    }
    var concrete_part = try S.init_concrete(allocator, concrete.items);
    defer concrete_part.deinit(allocator);
    try expression.add_assign(allocator, concrete_part);
    const count = free_weights.items.len + concrete.items.len;
    const points = try allocator.alloc(TG, count);
    defer allocator.free(points);
    const weights = try allocator.alloc(TF, count);
    defer allocator.free(weights);
    const free_count = free_weights.items.len;
    for (points[0..free_count], weights[0..free_count], free_weights.items) |*p, *w, weight| {
        p.* = try u.arbitrary(TG);
        w.* = weight;
    }
    for (points[free_count..], weights[free_count..], concrete.items) |*p, *w, term| {
        p.* = term.point;
        w.* = term.weight;
    }
    const expected = algebra.msm(TG, TF, points, weights);
    try expect((try expression.eval(allocator, points[0..free_count])).eql(expected));
}

fn eval_is_linear(allocator: Allocator, u: *Unstructured) !void {
    var lhs = try S.arbitrary(allocator, u);
    defer lhs.deinit(allocator);
    var rhs = try S.arbitrary(allocator, u);
    defer rhs.deinit(allocator);
    var generators = try arbitrary_list(TG, allocator, u);
    defer generators.deinit(allocator);
    // cover_generators: draw more until every free index has one.
    const lhs_needed = if (lhs.max_free_index()) |m| m + 1 else 0;
    const rhs_needed = if (rhs.max_free_index()) |m| m + 1 else 0;
    const needed = @max(lhs_needed, rhs_needed);
    while (generators.items.len < needed) try generators.append(allocator, try u.arbitrary(TG));
    const lhs_eval = try lhs.eval(allocator, generators.items);
    const rhs_eval = try rhs.eval(allocator, generators.items);
    try lhs.add_assign(allocator, rhs);
    try expect((try lhs.eval(allocator, generators.items)).eql(lhs_eval.add(rhs_eval)));
}

fn sum(allocator: Allocator, a: S, b: S) !S {
    var out = try a.clone(allocator);
    errdefer out.deinit(allocator);
    try out.add_assign(allocator, b);
    return out;
}

fn scaled(allocator: Allocator, a: S, x: TF) !S {
    var out = try a.clone(allocator);
    out.mul_assign(x);
    return out;
}

/// `test_suites::fuzz_additive::<Synthetic<F, G>>` with allocating values.
fn fuzz_additive(allocator: Allocator, u: *Unstructured) !void {
    var a = try S.arbitrary(allocator, u);
    defer a.deinit(allocator);
    var b = try S.arbitrary(allocator, u);
    defer b.deinit(allocator);
    var c = try S.arbitrary(allocator, u);
    defer c.deinit(allocator);
    var ab = try sum(allocator, a, b);
    defer ab.deinit(allocator);
    var ba = try sum(allocator, b, a);
    defer ba.deinit(allocator);
    try expect(try ab.eql(ba, allocator));
    var ab_c = try sum(allocator, ab, c);
    defer ab_c.deinit(allocator);
    var bc = try sum(allocator, b, c);
    defer bc.deinit(allocator);
    var a_bc = try sum(allocator, a, bc);
    defer a_bc.deinit(allocator);
    try expect(try ab_c.eql(a_bc, allocator));
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

/// `test_suites::fuzz_space_ring::<F, Synthetic<F, G>>`, drawing in the same order.
fn fuzz_space_ring(allocator: Allocator, u: *Unstructured) !void {
    {
        var a = try S.arbitrary(allocator, u);
        defer a.deinit(allocator);
        var b = try S.arbitrary(allocator, u);
        defer b.deinit(allocator);
        const x = try u.arbitrary(TF);
        var ab = try sum(allocator, a, b);
        defer ab.deinit(allocator);
        var left = try scaled(allocator, ab, x);
        defer left.deinit(allocator);
        var ax = try scaled(allocator, a, x);
        defer ax.deinit(allocator);
        var bx = try scaled(allocator, b, x);
        defer bx.deinit(allocator);
        var right = try sum(allocator, ax, bx);
        defer right.deinit(allocator);
        try expect(try left.eql(right, allocator));
        _ = try u.arbitrary(TF); // `a *= c` against `a * c`: the same call here.
    }
    try check_msm(allocator, u);
    {
        var a = try S.arbitrary(allocator, u);
        defer a.deinit(allocator);
        const x = try u.arbitrary(TF);
        const y = try u.arbitrary(TF);
        var axy = try scaled(allocator, a, x);
        defer axy.deinit(allocator);
        axy.mul_assign(y);
        var a_xy = try scaled(allocator, a, x.mul(y));
        defer a_xy.deinit(allocator);
        try expect(try axy.eql(a_xy, allocator));
    }
    var a = try S.arbitrary(allocator, u);
    defer a.deinit(allocator);
    var one = try scaled(allocator, a, TF.one);
    defer one.deinit(allocator);
    try expect(try one.eql(a, allocator));
    var zero = try scaled(allocator, a, TF.zero);
    defer zero.deinit(allocator);
    try expect(try zero.eql(S.zero, allocator));
}

/// The msm law of `fuzz_space`. Synthetic has no faster msm, so commonware's check
/// compares the default sum with itself; this compares sums taken in both orders.
fn check_msm(allocator: Allocator, u: *Unstructured) !void {
    const count = u.int_in_range(usize, 0, 16);
    var values: [16]S = undefined;
    var built: usize = 0;
    defer for (values[0..built]) |*v| v.deinit(allocator);
    while (built < count) : (built += 1) values[built] = try S.arbitrary(allocator, u);
    var scalars: [16]TF = undefined;
    for (scalars[0..count]) |*scalar| scalar.* = try u.arbitrary(TF);
    var forward: S = .{};
    defer forward.deinit(allocator);
    var backward: S = .{};
    defer backward.deinit(allocator);
    for (0..count) |index| {
        var term = try scaled(allocator, values[index], scalars[index]);
        defer term.deinit(allocator);
        try forward.add_assign(allocator, term);
        const back = count - 1 - index;
        var back_term = try scaled(allocator, values[back], scalars[back]);
        defer back_term.deinit(allocator);
        try backward.add_assign(allocator, back_term);
    }
    try expect(try forward.eql(backward, allocator));
}

/// The synthetic fuzz plan (commonware `synthetic::fuzz::Plan`).
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    const allocator = std.testing.allocator;
    const Plan = enum { eval_matches_msm, eval_is_linear, fuzz_additive, fuzz_space_ring };
    switch (try u.arbitrary(Plan)) {
        .eval_matches_msm => try eval_matches_msm(allocator, u),
        .eval_is_linear => try eval_is_linear(allocator, u),
        .fuzz_additive => try fuzz_additive(allocator, u),
        .fuzz_space_ring => try fuzz_space_ring(allocator, u),
    }
}

const testing = std.testing;

test "synthetic fuzz plan" {
    try (minifuzz.Builder{}).with_search_limit(2000 * build_options.fuzz_soak)
        .run(testing.allocator, {}, fuzz_plan);
}

test "synthetic fuzz plan (coverage-guided)" {
    try testing.fuzz({}, testing_types.smith_body(void, fuzz_plan), .{});
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

test "merging interleaved free terms matches evaluating each side" {
    const allocator = testing.allocator;
    var generators: [8]TG = undefined;
    for (&generators, 0..) |*point, i| point.* = TG.generator.mul(TF.from_u64(i * 7 + 3));
    // `a` holds the even indices and 5, `b` the odd ones: overlaps at 5, and both orders.
    const a_indices = [_]u32{ 0, 2, 4, 5, 6 };
    const b_indices = [_]u32{ 1, 3, 5, 7 };
    var a: S = .zero;
    defer a.deinit(allocator);
    for (a_indices, 1..) |index, weight| {
        var term = try S.generator(allocator, index);
        defer term.deinit(allocator);
        term.mul_assign(TF.from_u64(weight));
        try a.add_assign(allocator, term);
    }
    var b: S = .zero;
    defer b.deinit(allocator);
    for (b_indices, 10..) |index, weight| {
        var term = try S.generator(allocator, index);
        defer term.deinit(allocator);
        term.mul_assign(TF.from_u64(weight));
        try b.add_assign(allocator, term);
    }
    const a_value = try a.eval(allocator, &generators);
    const b_value = try b.eval(allocator, &generators);
    var total = try a.clone(allocator);
    defer total.deinit(allocator);
    try total.add_assign(allocator, b);
    try testing.expectEqual(@as(usize, 8), total.free.items.len);
    try testing.expect((try total.eval(allocator, &generators)).eql(a_value.add(b_value)));
    var difference = try b.clone(allocator);
    defer difference.deinit(allocator);
    try difference.sub_assign(allocator, a);
    const expected = b_value.add(a_value.neg());
    try testing.expect((try difference.eval(allocator, &generators)).eql(expected));
    for (total.free.items[1..], total.free.items[0 .. total.free.items.len - 1]) |later, earlier| {
        try testing.expect(earlier.index < later.index);
    }
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
