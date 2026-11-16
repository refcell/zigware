//! Tests for `zk/circuit.zig` (commonware `zk/circuit.rs`), including its minifuzz plan:
//! a circuit is satisfied exactly when the natively computed values say it should be.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const circuit = @import("circuit.zig");

const F = math.testing.F;
const V = circuit.Var(F);
const B = circuit.BoolVar(F);
const Ctx = circuit.Context(F);
const gpa = testing.allocator;

fn prover() !Ctx {
    return Ctx.init(gpa, .uniform(256), .prover);
}

/// Finishes a prover context with no outputs and reports satisfaction.
fn satisfied(ctx: *Ctx) !bool {
    var valued, const indices = try ctx.finish_valued(gpa, &.{});
    defer valued.deinit(gpa);
    defer gpa.free(indices);
    return valued.is_satisfied();
}

fn f(value: u64) F {
    return F.from_u64(value);
}

const ops_max = 32;

const Op = union(enum) {
    witness: F,
    constant: F,
    zero,
    one,
    add: [2]usize,
    sub: [2]usize,
    mul: [2]usize,
    neg: usize,
    inv: usize,
    assert_eq: [2]usize,
};

/// commonware's `fuzz::Plan`: random operations, and whether the circuit they build should
/// be satisfied. Values come from a small range so assertions often hold.
pub const Plan = struct {
    ops: [ops_max]Op = undefined,
    op_count: usize = 0,
    satisfied: bool = true,

    fn push(plan: *Plan, op: Op) void {
        assert(plan.op_count < ops_max);
        plan.ops[plan.op_count] = op;
        plan.op_count += 1;
    }

    pub fn arbitrary(u: *minifuzz.Unstructured) Plan {
        var plan: Plan = .{};
        var values: [ops_max]F = undefined;
        var native: [ops_max]bool = undefined;
        var count: usize = 0;
        const rounds = u.int_in_range(u32, 1, ops_max);
        for (0..rounds) |_| {
            const kind = u.int_in_range(u32, 0, if (count == 0) 3 else 9);
            if (kind <= 3) {
                const v = f(u.int_in_range(u8, 0, 4));
                const op: Op, values[count], native[count] = switch (kind) {
                    0 => .{ .{ .witness = v }, v, false },
                    1 => .{ .{ .constant = v }, v, false },
                    2 => .{ .zero, F.zero, true },
                    else => .{ .one, F.one, true },
                };
                plan.push(op);
                count += 1;
                continue;
            }
            const a = u.int_in_range(usize, 0, count - 1);
            const b = u.int_in_range(usize, 0, count - 1);
            const merged = native[a] and native[b];
            const op: Op, values[count], native[count] = switch (kind) {
                4 => .{ .{ .add = .{ a, b } }, values[a].add(values[b]), merged },
                5 => .{ .{ .sub = .{ a, b } }, values[a].sub(values[b]), merged },
                6 => .{ .{ .mul = .{ a, b } }, values[a].mul(values[b]), merged },
                7 => .{ .{ .neg = a }, values[a].neg(), native[a] },
                8 => blk: {
                    // Inverting a circuit-backed zero constrains `z * 0 = 1`.
                    if (!native[a] and values[a].eql(F.zero)) plan.satisfied = false;
                    break :blk .{ .{ .inv = a }, values[a].inv(), native[a] };
                },
                else => {
                    // Asserting two unequal natives equal panics by design.
                    const equal = values[a].eql(values[b]);
                    if (merged and !equal) continue;
                    plan.push(.{ .assert_eq = .{ a, b } });
                    plan.satisfied = plan.satisfied and equal;
                    continue;
                },
            };
            plan.push(op);
            count += 1;
        }
        return plan;
    }

    pub fn build(plan: *const Plan, ctx: *Ctx) void {
        var vars: [ops_max]V = undefined;
        var count: usize = 0;
        for (plan.ops[0..plan.op_count]) |op| {
            vars[count] = switch (op) {
                .witness => |v| V.witness_value(ctx, v),
                .constant => |v| V.constant(ctx, v),
                .zero => V.zero,
                .one => V.one,
                .add => |pair| vars[pair[0]].add(vars[pair[1]]),
                .sub => |pair| vars[pair[0]].sub(vars[pair[1]]),
                .mul => |pair| vars[pair[0]].mul(vars[pair[1]]),
                .neg => |a| vars[a].neg(),
                .inv => |a| vars[a].inv(),
                .assert_eq => |pair| {
                    vars[pair[0]].assert_eq(vars[pair[1]]);
                    continue;
                },
            };
            count += 1;
        }
    }
};

pub fn circuit_plan(_: void, u: *minifuzz.Unstructured) !void {
    const plan = Plan.arbitrary(u);
    var ctx = try prover();
    plan.build(&ctx);
    try testing.expectEqual(plan.satisfied, try satisfied(&ctx));
}

test "circuit is satisfied matches native evaluation (minifuzz)" {
    try minifuzz.run(gpa, {}, circuit_plan);
}

test "circuit is satisfied matches native evaluation (coverage-guided)" {
    try testing.fuzz({}, math.testing.smith_body(void, circuit_plan), .{});
}

fn cubic(x_value: u64) !bool {
    // Constrain a witness `x` to satisfy `x^3 + x + 5 = 35`.
    var ctx = try prover();
    const x = V.witness_value(&ctx, f(x_value));
    const out = x.mul(x).mul(x).add(x).add(V.constant(&ctx, f(5)));
    out.assert_eq(V.constant(&ctx, f(35)));
    return satisfied(&ctx);
}

test "circuit is satisfied cubic" {
    try testing.expect(try cubic(3));
    try testing.expect(!try cubic(4));
}

test "circuit verifier records the same structure as the prover" {
    var verifier = try Ctx.init(gpa, .uniform(16), .verifier);
    const x = V.witness_value(&verifier, f(3));
    x.mul(x).add(V.constant(&verifier, f(1))).assert_eq(V.constant(&verifier, f(10)));
    var structure, const indices = try verifier.finish(gpa, &.{x});
    defer structure.deinit(gpa);
    defer gpa.free(indices);
    try testing.expectEqual(1, structure.witnesses);
    try testing.expectEqual(2, structure.nodes.len);
    try testing.expectEqual(2, structure.constants.len);
    try testing.expectEqual(1, structure.assertions.len);
    try testing.expect(indices[0].eql(.{ .witness = 0 }));
}

test "circuit folds constants and natives without gates" {
    var ctx = try prover();
    const sum = V.constant(&ctx, f(2)).add(V.constant(&ctx, f(3)));
    try testing.expect(sum.inner.circuit.idx == .constant);
    try testing.expect(V.native(f(2)).mul(V.native(f(4))).eql(V.native(f(8))));
    try testing.expect(V.native(f(8)).div(V.native(f(2))).eql(V.native(f(4))));
    try testing.expectEqual(0, ctx.nodes.items.len);
    const x = V.witness_value(&ctx, f(12));
    x.div(V.constant(&ctx, f(4))).assert_eq(V.constant(&ctx, f(3)));
    try testing.expect(try satisfied(&ctx));
}

test "circuit bool witness enforces booleanity" {
    // A boolean witness from a `bool` is always satisfiable.
    for ([_]bool{ false, true }) |b| {
        var ctx = try prover();
        _ = B.witness_value(&ctx, b);
        try testing.expect(try satisfied(&ctx));
    }
    // A var that is not 0 or 1 fails the booleanity constraint; 0 and 1 pass.
    for ([_]u64{ 2, 0, 1 }) |v| {
        var ctx = try prover();
        _ = B.from_var(V.witness_value(&ctx, f(v)));
        try testing.expectEqual(v != 2, try satisfied(&ctx));
    }
}

test "circuit bool select, combinators, and constants" {
    for ([_]bool{ false, true }) |a| {
        for ([_]bool{ false, true }) |b| {
            var ctx = try prover();
            const a_var = B.witness_value(&ctx, a);
            const b_var = B.witness_value(&ctx, b);
            a_var.not().assert_eq(B.constant(!a));
            a_var.@"and"(b_var).assert_eq(B.constant(a and b));
            a_var.@"or"(b_var).assert_eq(B.constant(a or b));
            const selected = a_var.select(V.witness_value(&ctx, f(7)), V.witness_value(&ctx, f(9)));
            selected.assert_eq(V.constant(&ctx, f(if (a) 7 else 9)));
            const x = V.witness_value(&ctx, f(5));
            B.constant(true).select(x, V.zero).assert_eq(V.constant(&ctx, f(5)));
            B.constant(false).select(x, V.zero).assert_eq(V.zero);
            try testing.expect(try satisfied(&ctx));
        }
    }
}

test "circuit selector picks the indexed constant" {
    const constants = [_]F{ f(11), f(22), f(33), f(44) };
    for (0..4) |index| {
        var ctx = try prover();
        const bits = [_]B{
            B.witness_value(&ctx, index & 1 == 1),
            B.witness_value(&ctx, index & 2 == 2),
        };
        var selector = try circuit.Selector(F).init(gpa, &bits);
        defer selector.deinit(gpa);
        const chosen = try selector.select_constant(gpa, &constants);
        chosen.assert_eq(V.constant(&ctx, constants[index]));
        try testing.expect(try satisfied(&ctx));
    }
}
