//! Arithmetic circuits over a ring (commonware `cryptography/src/zk/circuit.rs`).
//!
//! A `Var(F)` is either a native value or a reference into a circuit being built by a
//! `Context(F)`. Arithmetic on vars records `add`/`mul` nodes, constants, witnesses, and
//! equality assertions, so code written against the math lane's `Ring`/`Field` interfaces
//! (`zero`, `one`, `add`, `sub`, `neg`, `mul`, `inv`, `eql`) builds a circuit when run over
//! `Var(F)`. Natives fold together without touching the circuit.
//!
//! commonware's `build(f)` and `build_with_values(f)` closures become an explicit context:
//! `Context(F).init(gpa, capacity, .verifier)` records only the structure, `.prover` also
//! records the assignment, and `finish`/`finish_valued` return the circuit. The context
//! allocates its buffers up front from `capacity`, so var arithmetic never fails; exceeding
//! the capacity panics. A witness's value comes from `init.call(values)` (Rust's
//! `FnOnce(Values) -> F`), which must not use the context. Every operation allocates in the
//! same order as commonware's, so circuits match node for node. A context is used from one
//! thread (Rust's mutex only makes `Context: Sync`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const math = @import("math");

/// Where a circuit value lives.
pub const CircuitIdx = union(enum) {
    constant: u32,
    witness: u32,
    node: u32,

    pub fn eql(a: CircuitIdx, b: CircuitIdx) bool {
        return std.meta.eql(a, b);
    }
};

/// A gate: the sum or product of two values.
pub const CircuitNode = union(enum) {
    add: [2]CircuitIdx,
    mul: [2]CircuitIdx,
};

/// The most entries of each kind a context may record.
pub const Capacity = struct {
    constants: u32,
    witnesses: u32,
    nodes: u32,
    assertions: u32,

    /// The same bound for every kind.
    pub fn uniform(count: u32) Capacity {
        return .{ .constants = count, .witnesses = count, .nodes = count, .assertions = count };
    }
};

/// A circuit's structure: constants, a witness count, gates, and equality assertions.
pub fn Circuit(comptime F: type) type {
    return struct {
        const Self = @This();

        witnesses: u32,
        constants: []F,
        nodes: []CircuitNode,
        assertions: [][2]CircuitIdx,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.constants);
            gpa.free(self.nodes);
            gpa.free(self.assertions);
            self.* = undefined;
        }
    };
}

/// The values a witness initializer may read: everything allocated before it.
pub fn Values(comptime F: type) type {
    return struct {
        constants: []const F,
        witnesses: []const F,
        nodes: []const F,

        pub fn get(self: @This(), index: CircuitIdx) F {
            return switch (index) {
                .constant => |i| self.constants[i],
                .witness => |i| self.witnesses[i],
                .node => |i| self.nodes[i],
            };
        }
    };
}

/// A circuit with the prover's assignment to every witness and node.
pub fn ValuedCircuit(comptime F: type) type {
    return struct {
        const Self = @This();

        circuit: Circuit(F),
        witnesses: []F,
        nodes: []F,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.circuit.deinit(gpa);
            gpa.free(self.witnesses);
            gpa.free(self.nodes);
            self.* = undefined;
        }

        pub fn get(self: *const Self, index: CircuitIdx) F {
            return self.values().get(index);
        }

        fn values(self: *const Self) Values(F) {
            return .{
                .constants = self.circuit.constants,
                .witnesses = self.witnesses,
                .nodes = self.nodes,
            };
        }

        /// Whether every assertion holds under the assignment.
        pub fn is_satisfied(self: *const Self) bool {
            for (self.circuit.assertions) |pair| {
                if (!self.get(pair[0]).eql(self.get(pair[1]))) return false;
            }
            return true;
        }
    };
}

pub const Mode = enum { verifier, prover };

/// Records a circuit (and, for a prover, its assignment). Vars point at it, so it must stay
/// in place while they are used.
pub fn Context(comptime F: type) type {
    math.algebra.assert_ring(F);
    return struct {
        const Self = @This();

        mode: Mode,
        witness_count: u32 = 0,
        constants: std.ArrayList(F),
        nodes: std.ArrayList(CircuitNode),
        assertions: std.ArrayList([2]CircuitIdx),
        witness_values: std.ArrayList(F),
        node_values: std.ArrayList(F),
        capacity: Capacity,

        pub fn init(gpa: Allocator, capacity: Capacity, mode: Mode) Allocator.Error!Self {
            var self: Self = .{
                .mode = mode,
                .constants = try .initCapacity(gpa, capacity.constants),
                .nodes = .empty,
                .assertions = .empty,
                .witness_values = .empty,
                .node_values = .empty,
                .capacity = capacity,
            };
            errdefer self.deinit(gpa);
            self.nodes = try .initCapacity(gpa, capacity.nodes);
            self.assertions = try .initCapacity(gpa, capacity.assertions);
            if (mode == .prover) {
                self.witness_values = try .initCapacity(gpa, capacity.witnesses);
                self.node_values = try .initCapacity(gpa, capacity.nodes);
            }
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.constants.deinit(gpa);
            self.nodes.deinit(gpa);
            self.assertions.deinit(gpa);
            self.witness_values.deinit(gpa);
            self.node_values.deinit(gpa);
            self.* = undefined;
        }

        /// The values allocated so far, or null for a verifier.
        pub fn values(self: *const Self) ?Values(F) {
            if (self.mode == .verifier) return null;
            return .{
                .constants = self.constants.items,
                .witnesses = self.witness_values.items,
                .nodes = self.node_values.items,
            };
        }

        fn reserve(list: anytype, limit: u32) void {
            if (list.items.len >= limit) @panic("circuit capacity exceeded");
            assert(list.items.len < list.capacity);
        }

        fn constant(self: *Self, value: F) CircuitIdx {
            reserve(&self.constants, self.capacity.constants);
            const index: u32 = @intCast(self.constants.items.len);
            self.constants.appendAssumeCapacity(value);
            return .{ .constant = index };
        }

        fn witness(self: *Self, value: ?F) CircuitIdx {
            if (self.witness_count >= self.capacity.witnesses) {
                @panic("circuit capacity exceeded");
            }
            assert((value != null) == (self.mode == .prover));
            if (value) |known| self.witness_values.appendAssumeCapacity(known);
            const index = self.witness_count;
            self.witness_count += 1;
            return .{ .witness = index };
        }

        fn node(self: *Self, gate: CircuitNode, value: ?F) CircuitIdx {
            reserve(&self.nodes, self.capacity.nodes);
            assert((value != null) == (self.mode == .prover));
            const index: u32 = @intCast(self.nodes.items.len);
            self.nodes.appendAssumeCapacity(gate);
            if (value) |known| self.node_values.appendAssumeCapacity(known);
            return .{ .node = index };
        }

        fn assert_eq(self: *Self, a: CircuitIdx, b: CircuitIdx) void {
            reserve(&self.assertions, self.capacity.assertions);
            self.assertions.appendAssumeCapacity(.{ a, b });
        }

        /// The circuit and the indices of `outputs` (commonware `build`). Every output must
        /// be circuit-backed. Consumes the context.
        pub fn finish(
            self: *Self,
            gpa: Allocator,
            outputs: []const Var(F),
        ) Allocator.Error!struct { Circuit(F), []CircuitIdx } {
            const indices = try gpa.alloc(CircuitIdx, outputs.len);
            errdefer gpa.free(indices);
            for (outputs, indices) |output, *index| index.* = output.circuit_idx();
            var circuit: Circuit(F) = .{
                .witnesses = self.witness_count,
                .constants = &.{},
                .nodes = &.{},
                .assertions = &.{},
            };
            circuit.constants = try self.constants.toOwnedSlice(gpa);
            errdefer gpa.free(circuit.constants);
            circuit.nodes = try self.nodes.toOwnedSlice(gpa);
            errdefer gpa.free(circuit.nodes);
            circuit.assertions = try self.assertions.toOwnedSlice(gpa);
            self.deinit(gpa);
            return .{ circuit, indices };
        }

        /// The circuit with its assignment and the indices of `outputs` (commonware
        /// `build_with_values`). Consumes a prover context.
        pub fn finish_valued(
            self: *Self,
            gpa: Allocator,
            outputs: []const Var(F),
        ) Allocator.Error!struct { ValuedCircuit(F), []CircuitIdx } {
            assert(self.mode == .prover);
            const witnesses = try self.witness_values.toOwnedSlice(gpa);
            errdefer gpa.free(witnesses);
            const nodes = try self.node_values.toOwnedSlice(gpa);
            errdefer gpa.free(nodes);
            assert(witnesses.len == self.witness_count);
            const circuit, const indices = try self.finish(gpa, outputs);
            return .{ .{ .circuit = circuit, .witnesses = witnesses, .nodes = nodes }, indices };
        }
    };
}

/// A native value or a value in a circuit.
pub fn Var(comptime F: type) type {
    return struct {
        const Self = @This();
        const Ctx = Context(F);

        inner: Inner,

        const Inner = union(enum) {
            native: F,
            circuit: struct { ctx: *Ctx, idx: CircuitIdx },
        };

        pub const zero: Self = .{ .inner = .{ .native = F.zero } };
        pub const one: Self = .{ .inner = .{ .native = F.one } };

        pub fn native(known: F) Self {
            return .{ .inner = .{ .native = known } };
        }

        fn at(ctx: *Ctx, idx: CircuitIdx) Self {
            return .{ .inner = .{ .circuit = .{ .ctx = ctx, .idx = idx } } };
        }

        /// A witness whose value is `init.call(values)` for a prover.
        pub fn witness(ctx: *Ctx, init: anytype) Self {
            const assigned: ?F = if (ctx.values()) |known| init.call(known) else null;
            return at(ctx, ctx.witness(assigned));
        }

        /// A witness with a known value (Rust's `Var::witness(ctx, move |_| value)`).
        pub fn witness_value(ctx: *Ctx, known: F) Self {
            return at(ctx, ctx.witness(if (ctx.mode == .prover) known else null));
        }

        /// A constant recorded in the circuit.
        pub fn constant(ctx: *Ctx, known: F) Self {
            return at(ctx, ctx.constant(known));
        }

        /// The value under `values` (the prover's assignment).
        pub fn value(self: Self, values: Values(F)) F {
            return switch (self.inner) {
                .native => |known| known,
                .circuit => |circuit| values.get(circuit.idx),
            };
        }

        fn circuit_idx(self: Self) CircuitIdx {
            return switch (self.inner) {
                .circuit => |circuit| circuit.idx,
                .native => @panic("expected circuit-backed var"),
            };
        }

        /// Natives compare by value, circuit vars by index.
        pub fn eql(a: Self, b: Self) bool {
            return switch (a.inner) {
                .native => |left| switch (b.inner) {
                    .native => |right| left.eql(right),
                    .circuit => false,
                },
                .circuit => |left| switch (b.inner) {
                    .native => false,
                    .circuit => |right| left.idx.eql(right.idx),
                },
            };
        }

        /// Constrains `self == other`; two natives must already be equal.
        pub fn assert_eq(self: Self, other: Self) void {
            switch (self.inner) {
                .native => |left| switch (other.inner) {
                    .native => |right| if (!left.eql(right)) {
                        @panic("asserted equality between distinct native vars");
                    },
                    .circuit => |right| right.ctx.assert_eq(right.ctx.constant(left), right.idx),
                },
                .circuit => |left| switch (other.inner) {
                    .native => |right| left.ctx.assert_eq(left.ctx.constant(right), left.idx),
                    .circuit => |right| left.ctx.assert_eq(left.idx, right.idx),
                },
            }
        }

        const Op = enum { add, mul };

        fn combine(comptime op: Op, a: F, b: F) F {
            return switch (op) {
                .add => a.add(b),
                .mul => a.mul(b),
            };
        }

        fn merge(self: Self, other: Self, comptime op: Op) Self {
            var ctx: *Ctx = undefined;
            var a_idx: CircuitIdx = undefined;
            var b_idx: CircuitIdx = undefined;
            switch (self.inner) {
                .native => |left| switch (other.inner) {
                    .native => |right| return native(combine(op, left, right)),
                    .circuit => |right| {
                        ctx = right.ctx;
                        a_idx = ctx.constant(left);
                        b_idx = right.idx;
                    },
                },
                .circuit => |left| {
                    ctx = left.ctx;
                    switch (other.inner) {
                        .native => |right| {
                            a_idx = ctx.constant(right);
                            b_idx = left.idx;
                        },
                        .circuit => |right| {
                            a_idx = left.idx;
                            b_idx = right.idx;
                        },
                    }
                },
            }
            if (a_idx == .constant and b_idx == .constant) {
                const constants = ctx.constants.items;
                const folded = combine(op, constants[a_idx.constant], constants[b_idx.constant]);
                return at(ctx, ctx.constant(folded));
            }
            const gate: CircuitNode = switch (op) {
                .add => .{ .add = .{ a_idx, b_idx } },
                .mul => .{ .mul = .{ a_idx, b_idx } },
            };
            const known: ?F = if (ctx.values()) |values|
                combine(op, values.get(a_idx), values.get(b_idx))
            else
                null;
            return at(ctx, ctx.node(gate, known));
        }

        pub fn add(self: Self, other: Self) Self {
            return self.merge(other, .add);
        }

        pub fn mul(self: Self, other: Self) Self {
            return self.merge(other, .mul);
        }

        pub fn neg(self: Self) Self {
            const circuit = switch (self.inner) {
                .native => |known| return native(known.neg()),
                .circuit => |circuit| circuit,
            };
            const ctx = circuit.ctx;
            if (circuit.idx == .constant) {
                return at(ctx, ctx.constant(ctx.constants.items[circuit.idx.constant].neg()));
            }
            const minus_one = ctx.constant(F.one.neg());
            const known: ?F = if (ctx.values()) |values| values.get(circuit.idx).neg() else null;
            return at(ctx, ctx.node(.{ .mul = .{ minus_one, circuit.idx } }, known));
        }

        pub fn sub(self: Self, other: Self) Self {
            return self.add(other.neg());
        }

        fn context_of(a: Self, b: Self) ?*Ctx {
            if (a.inner == .circuit) return a.inner.circuit.ctx;
            if (b.inner == .circuit) return b.inner.circuit.ctx;
            return null;
        }

        /// `self / other`: a witness `q` constrained by `q * other == self`.
        pub fn div(self: Self, other: Self) Self {
            comptime math.algebra.assert_field(F);
            const ctx = context_of(self, other) orelse
                return native(self.inner.native.mul(other.inner.native.inv()));
            const Quotient = struct {
                numerator: Self,
                denominator: Self,
                pub fn call(q: @This(), values: Values(F)) F {
                    return q.numerator.value(values).mul(q.denominator.value(values).inv());
                }
            };
            const q = witness(ctx, Quotient{ .numerator = self, .denominator = other });
            q.mul(other).assert_eq(self);
            return q;
        }

        /// The inverse: a witness constrained by `inv * self == 1` (unsatisfiable for 0).
        pub fn inv(self: Self) Self {
            comptime math.algebra.assert_field(F);
            const circuit = switch (self.inner) {
                .native => |known| return native(known.inv()),
                .circuit => |circuit| circuit,
            };
            const Inverse = struct {
                var_value: Self,
                pub fn call(i: @This(), values: Values(F)) F {
                    return i.var_value.value(values).inv();
                }
            };
            const result = witness(circuit.ctx, Inverse{ .var_value = self });
            result.mul(self).assert_eq(one);
            return result;
        }

        comptime {
            math.algebra.assert_ring(Self);
        }
    };
}

/// A var constrained to 0 or 1.
pub fn BoolVar(comptime F: type) type {
    return struct {
        const Self = @This();
        const V = Var(F);

        inner: V,

        pub fn var_value(self: Self) V {
            return self.inner;
        }

        /// A native boolean.
        pub fn constant(value: bool) Self {
            return .{ .inner = if (value) V.one else V.zero };
        }

        pub fn assert_eq(self: Self, other: Self) void {
            self.inner.assert_eq(other.inner);
        }

        /// `on_true` when set, else `on_false`: `on_false + self * (on_true - on_false)`.
        pub fn select(self: Self, on_true: V, on_false: V) V {
            return on_false.add(self.inner.mul(on_true.sub(on_false)));
        }

        /// A boolean witness from `init.call(values) bool`, constrained to 0 or 1.
        pub fn witness(ctx: *Context(F), init: anytype) Self {
            const Lift = struct {
                inner: @TypeOf(init),
                pub fn call(lift: @This(), values: Values(F)) F {
                    return if (lift.inner.call(values)) F.one else F.zero;
                }
            };
            const result = V.witness(ctx, Lift{ .inner = init });
            enforce(result);
            return .{ .inner = result };
        }

        /// A boolean witness with a known value.
        pub fn witness_value(ctx: *Context(F), value: bool) Self {
            const result = V.witness_value(ctx, if (value) F.one else F.zero);
            enforce(result);
            return .{ .inner = result };
        }

        /// Constrains `value` to 0 or 1 (commonware `BoolVar::assert`).
        pub fn from_var(value: V) Self {
            enforce(value);
            return .{ .inner = value };
        }

        fn enforce(value: V) void {
            value.mul(value).assert_eq(value);
        }

        pub fn not(self: Self) Self {
            return .{ .inner = V.one.sub(self.inner) };
        }

        pub fn @"and"(self: Self, other: Self) Self {
            return .{ .inner = self.inner.mul(other.inner) };
        }

        /// `a + b - a * b`.
        pub fn @"or"(self: Self, other: Self) Self {
            const sum = self.inner.add(other.inner);
            return .{ .inner = sum.sub(self.inner.mul(other.inner)) };
        }
    };
}

/// Selects among `2^k` constants with `k` boolean vars (commonware `Selector`): the
/// constants become multilinear coefficients over the monomials of the bits.
pub fn Selector(comptime F: type) type {
    return struct {
        const Self = @This();
        const V = Var(F);

        monomials: []V,

        pub fn init(gpa: Allocator, bits: []const BoolVar(F)) Allocator.Error!Self {
            assert(bits.len < @bitSizeOf(usize));
            const monomials = try gpa.alloc(V, @as(usize, 1) << @intCast(bits.len));
            monomials[0] = V.one;
            for (1..monomials.len) |mask| {
                const bit: usize = @ctz(mask);
                const previous = mask ^ (@as(usize, 1) << @intCast(bit));
                monomials[mask] = if (previous == 0)
                    bits[bit].inner
                else
                    monomials[previous].mul(bits[bit].inner);
            }
            return .{ .monomials = monomials };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.monomials);
            self.* = undefined;
        }

        /// The constant the bits select; `constants.len` must equal the monomial count.
        pub fn select_constant(self: Self, gpa: Allocator, constants: []const F) !V {
            if (constants.len != self.monomials.len) {
                @panic("constants len must match selectors len");
            }
            const values = try gpa.dupe(F, constants);
            defer gpa.free(values);
            const bit_count: usize = @ctz(values.len);
            for (0..bit_count) |bit| {
                const flag = @as(usize, 1) << @intCast(bit);
                for (0..values.len) |mask| {
                    if (mask & flag != 0) values[mask] = values[mask].sub(values[mask ^ flag]);
                }
            }
            var result = V.native(values[0]).mul(self.monomials[0]);
            for (values[1..], self.monomials[1..]) |coefficient, monomial| {
                result = result.add(V.native(coefficient).mul(monomial));
            }
            return result;
        }
    };
}

test {
    _ = @import("circuit_test.zig");
}
