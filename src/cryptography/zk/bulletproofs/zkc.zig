//! Converts `zk.circuit` circuits into bulletproofs circuits (commonware `circuit.rs` `zkc`).
//!
//! Every circuit value becomes a linear combination of weight-matrix columns. Additions and
//! multiplications by constants combine linearly; each product of two non-constant values
//! becomes a multiplication gate whose output wire is a new column. Each assertion `(l, r)`
//! becomes a row `l - r = 0`. Witnesses are pinned to gate wires (unused ones are paired into
//! padding gates), and committed witnesses are bound to their committed columns.
//!
//! The conversion visits values in commonware's order, with an explicit stack, so circuits
//! (and hence transcripts and proofs) match commonware's column for column.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zk = @import("../circuit.zig");
const bp = @import("circuit.zig");

const CircuitIdx = zk.CircuitIdx;

/// A matrix column, before it is resolved: `witness` is a provisional location for a witness
/// not yet pinned to a column. Ordered by kind, then index, as commonware's derived `Ord`.
const Location = union(enum) {
    one,
    witness: usize,
    left: usize,
    right: usize,
    output: usize,
    committed: usize,

    fn index(location: Location) usize {
        return switch (location) {
            .one => 0,
            inline else => |value| value,
        };
    }

    fn less_than(a: Location, b: Location) bool {
        const tag_a = @backingInt(std.meta.activeTag(a));
        const tag_b = @backingInt(std.meta.activeTag(b));
        if (tag_a != tag_b) return tag_a < tag_b;
        return a.index() < b.index();
    }

    fn eql(a: Location, b: Location) bool {
        return std.meta.eql(a, b);
    }
};

/// A gate: the values feeding its left and right wires, and the value of its output wire.
/// Padding gates for leftover witnesses leave the right wire, then the output, unset.
const Gate = struct { left: CircuitIdx, right: ?CircuitIdx, output: ?CircuitIdx };

fn Converter(comptime F: type) type {
    return struct {
        const Self = @This();

        const Weighted = struct { location: Location, weight: F };

        /// A circuit value as a linear combination of locations: a single location (weight
        /// one), a multiple of the constant column, or general terms sorted by location with
        /// no duplicates.
        const LinComb = union(enum) {
            location: Location,
            constant: F,
            general: []const Weighted,

            fn terms(comb: *const LinComb, single: *[1]Weighted) []const Weighted {
                switch (comb.*) {
                    .location => |location| single[0] = .{ .location = location, .weight = F.one },
                    .constant => |weight| single[0] = .{ .location = .one, .weight = weight },
                    .general => |general| return general,
                }
                return single;
            }

            fn witness(comb: LinComb) ?usize {
                return switch (comb) {
                    .location => |location| switch (location) {
                        .witness => |w| w,
                        else => null,
                    },
                    else => null,
                };
            }
        };

        arena: Allocator,
        zkc: *const zk.Circuit(F),
        committed: []const CircuitIdx,
        queue: std.ArrayList(CircuitIdx) = .empty,
        cache_constants: []?LinComb,
        cache_witnesses: []?LinComb,
        cache_nodes: []?LinComb,
        witness_locations: []?Location,
        extra_assertions: std.ArrayList(struct { CircuitIdx, Location }) = .empty,
        gates: std.ArrayList(Gate) = .empty,

        fn init(arena: Allocator, zkc: *const zk.Circuit(F), committed: []const CircuitIdx) !Self {
            const self: Self = .{
                .arena = arena,
                .zkc = zkc,
                .committed = committed,
                .cache_constants = try arena.alloc(?LinComb, zkc.constants.len),
                .cache_witnesses = try arena.alloc(?LinComb, zkc.witnesses),
                .cache_nodes = try arena.alloc(?LinComb, zkc.nodes.len),
                .witness_locations = try arena.alloc(?Location, zkc.witnesses),
            };
            @memset(self.cache_constants, null);
            @memset(self.cache_witnesses, null);
            @memset(self.cache_nodes, null);
            @memset(self.witness_locations, null);
            return self;
        }

        fn cached(self: *const Self, index: CircuitIdx) *?LinComb {
            return switch (index) {
                .constant => |i| &self.cache_constants[i],
                .witness => |i| &self.cache_witnesses[i],
                .node => |i| &self.cache_nodes[i],
            };
        }

        /// The first committed slot of `index`, so duplicates share one column.
        fn committed_position(self: *const Self, index: CircuitIdx) ?usize {
            for (self.committed, 0..) |committed, position| {
                if (committed.eql(index)) return position;
            }
            return null;
        }

        /// Assigns `location` to `witness` unless it has a non-provisional one; returns the
        /// location in effect.
        fn assign_witness_location(self: *Self, witness: usize, location: Location) Location {
            const slot = &self.witness_locations[witness];
            if (slot.*) |current| {
                if (current != .witness) return current;
            }
            slot.* = location;
            return location;
        }

        /// Linearizes every assertion, pairs unpinned witnesses into padding gates, and binds
        /// each committed index to its column.
        fn populate(self: *Self) !void {
            for (self.zkc.assertions) |pair| {
                try self.linearize(pair[0]);
                try self.linearize(pair[1]);
            }
            var left = true;
            for (self.witness_locations, 0..) |*slot, w| {
                const location = slot.* orelse continue;
                if (location != .witness) continue;
                assert(location.witness == w);
                const index: CircuitIdx = .{ .witness = @intCast(w) };
                if (left) {
                    slot.* = .{ .left = self.gates.items.len };
                    try self.gates.append(
                        self.arena,
                        .{ .left = index, .right = null, .output = null },
                    );
                } else {
                    const gate = self.gates.items.len - 1;
                    slot.* = .{ .right = gate };
                    self.gates.items[gate].right = index;
                }
                left = !left;
            }
            for (self.committed, 0..) |index, i| {
                try self.linearize(index);
                // A committed witness that still resolves to its own column is constrained by
                // nothing, so its binding row would read `Committed(i) - Committed(i) = 0` and
                // leave the commitment free. Anchor it to a fresh padding wire instead.
                const slot = self.cached(index);
                if (slot.*.? == .location and slot.*.?.location == .committed) {
                    const gate = self.gates.items.len;
                    try self.gates.append(
                        self.arena,
                        .{ .left = index, .right = null, .output = null },
                    );
                    slot.* = .{ .location = .{ .left = gate } };
                }
                try self.extra_assertions.append(self.arena, .{ index, .{ .committed = i } });
            }
        }

        /// Computes and caches the combination of `start` and everything it depends on, with
        /// an explicit stack.
        fn linearize(self: *Self, start: CircuitIdx) !void {
            self.queue.clearRetainingCapacity();
            try self.queue.append(self.arena, start);
            while (self.queue.pop()) |index| {
                if (self.cached(index).* != null) continue;
                const comb: LinComb = switch (index) {
                    .constant => |i| .{ .constant = self.zkc.constants[i] },
                    .witness => |i| witness: {
                        const provisional: Location = if (self.committed_position(index)) |p|
                            .{ .committed = p }
                        else
                            .{ .witness = i };
                        break :witness .{
                            .location = self.assign_witness_location(i, provisional),
                        };
                    },
                    .node => |i| (try self.linearize_node(
                        index,
                        self.zkc.nodes[i],
                    )) orelse continue,
                };
                self.cached(index).* = comb;
            }
        }

        /// The combination of a gate node, or null after queueing its missing operands.
        fn linearize_node(self: *Self, index: CircuitIdx, node: zk.CircuitNode) !?LinComb {
            const l, const r = switch (node) {
                inline else => |operands| operands,
            };
            const l_comb = self.cached(l).*;
            const r_comb = self.cached(r).*;
            if (l_comb == null or r_comb == null) {
                try self.queue.append(self.arena, index);
                if (r_comb == null) try self.queue.append(self.arena, r);
                if (l_comb == null) try self.queue.append(self.arena, l);
                return null;
            }
            if (node == .add) return try self.sum(l_comb.?, r_comb.?);
            if (try self.product(l_comb.?, r_comb.?)) |out| return out;
            const gate = self.gates.items.len;
            try self.gates.append(self.arena, .{ .left = l, .right = r, .output = index });
            try self.extra_assertions.append(self.arena, .{ l, .{ .left = gate } });
            try self.extra_assertions.append(self.arena, .{ r, .{ .right = gate } });
            if (l_comb.?.witness()) |w| _ = self.assign_witness_location(w, .{ .left = gate });
            if (r_comb.?.witness()) |w| _ = self.assign_witness_location(w, .{ .right = gate });
            return .{ .location = .{ .output = gate } };
        }

        /// The product when one side is a constant; null when it needs a gate.
        fn product(self: *Self, a: LinComb, b: LinComb) !?LinComb {
            const constant: F, const other = if (a == .constant)
                .{ a.constant, b }
            else if (b == .constant)
                .{ b.constant, a }
            else
                return null;
            switch (other) {
                .location => |location| {
                    const terms = try self.arena.alloc(Weighted, 1);
                    terms[0] = .{ .location = location, .weight = constant };
                    return .{ .general = terms };
                },
                .constant => |other_constant| return .{ .constant = constant.mul(other_constant) },
                .general => |general| {
                    const terms = try self.arena.dupe(Weighted, general);
                    for (terms) |*term| term.weight = term.weight.mul(constant);
                    return .{ .general = terms };
                },
            }
        }

        /// The sum, merging duplicate locations (in location order, stably).
        fn sum(self: *Self, a: LinComb, b: LinComb) !LinComb {
            var single_a: [1]Weighted = undefined;
            var single_b: [1]Weighted = undefined;
            const terms_a = a.terms(&single_a);
            const terms_b = b.terms(&single_b);
            const terms = try self.arena.alloc(Weighted, terms_a.len + terms_b.len);
            @memcpy(terms[0..terms_a.len], terms_a);
            @memcpy(terms[terms_a.len..], terms_b);
            std.sort.insertion(Weighted, terms, {}, weighted_less_than);
            var merged: usize = 0;
            for (terms) |term| {
                if (merged > 0 and terms[merged - 1].location.eql(term.location)) {
                    terms[merged - 1].weight = terms[merged - 1].weight.add(term.weight);
                } else {
                    terms[merged] = term;
                    merged += 1;
                }
            }
            assert(merged >= 1 and merged <= terms.len);
            return .{ .general = terms[0..merged] };
        }

        fn weighted_less_than(_: void, a: Weighted, b: Weighted) bool {
            return a.location.less_than(b.location);
        }

        /// The matrix column of a resolved location.
        fn column(self: *const Self, location: Location) usize {
            const committed = self.committed.len;
            const internal = self.gates.items.len;
            const resolved = switch (location) {
                .witness => |w| self.witness_locations[w].?,
                else => location,
            };
            return switch (resolved) {
                .one => 0,
                .committed => |i| 1 + i,
                .left => |i| 1 + committed + i,
                .right => |i| 1 + committed + internal + i,
                .output => |i| 1 + committed + 2 * internal + i,
                .witness => unreachable, // Proof: `populate` pins every witness location.
            };
        }

        /// Adds row `row`: `+` each term of `l`, `-` each term of `r`.
        fn add_row(
            self: *const Self,
            gpa: Allocator,
            weights: *bp.SparseMatrix(F),
            row: usize,
            l: LinComb,
            r: LinComb,
        ) !void {
            var single: [1]Weighted = undefined;
            for (l.terms(&single)) |term| {
                const entry = try weights.entry(gpa, row, self.column(term.location));
                entry.* = entry.add(term.weight);
            }
            for (r.terms(&single)) |term| {
                const entry = try weights.entry(gpa, row, self.column(term.location));
                entry.* = entry.sub(term.weight);
            }
        }

        /// One row per assertion, then one per extra assertion.
        fn reckon_circuit(self: *const Self, gpa: Allocator) !bp.Circuit(F) {
            var weights: bp.SparseMatrix(F) = .{};
            errdefer weights.deinit(gpa);
            var row: usize = 0;
            for (self.zkc.assertions) |pair| {
                try self.add_row(
                    gpa,
                    &weights,
                    row,
                    self.cached(pair[0]).*.?,
                    self.cached(pair[1]).*.?,
                );
                row += 1;
            }
            for (self.extra_assertions.items) |extra| {
                const r: LinComb = .{ .location = extra[1] };
                try self.add_row(gpa, &weights, row, self.cached(extra[0]).*.?, r);
                row += 1;
            }
            return .{
                .committed_vars = self.committed.len,
                .internal_vars = self.gates.items.len,
                .weights = weights,
            };
        }
    };
}

/// The bulletproofs circuit for `zkc` (verifier side), committing the values at
/// `committed_indices` in order. A duplicate index makes a separate commitment constrained to
/// match. Every index must name a witness of the circuit. It must match the prover's indices.
pub fn zkc_to_circuit(
    comptime F: type,
    gpa: Allocator,
    zkc: *const zk.Circuit(F),
    committed_indices: []const CircuitIdx,
) !bp.Circuit(F) {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var converter = try Converter(F).init(arena_state.allocator(), zkc, committed_indices);
    try converter.populate();
    return converter.reckon_circuit(gpa);
}

/// The bulletproofs circuit and witness for an assigned `zk` circuit (prover side). Blindings
/// come from `blinding_rng`, or are zero when it is `null`.
pub fn zkc_to_circuit_and_witness(
    comptime F: type,
    gpa: Allocator,
    blinding_rng: anytype,
    valued: *const zk.ValuedCircuit(F),
    committed_indices: []const CircuitIdx,
) !struct { bp.Circuit(F), bp.Witness(F) } {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var converter = try Converter(F).init(
        arena_state.allocator(),
        &valued.circuit,
        committed_indices,
    );
    try converter.populate();
    const committed = committed_indices.len;
    const internal = converter.gates.items.len;
    var witness: bp.Witness(F) = .{
        .values = &.{},
        .blinding = &.{},
        .left = &.{},
        .right = &.{},
        .out = &.{},
    };
    errdefer witness.deinit(gpa);
    witness.blinding = try gpa.alloc(F, committed);
    for (witness.blinding) |*blind| {
        blind.* = if (@TypeOf(blinding_rng) == @TypeOf(null)) F.zero else F.random(blinding_rng);
    }
    witness.values = try gpa.alloc(F, committed);
    for (witness.values, committed_indices) |*value, index| value.* = valued.get(index);
    witness.left = try gpa.alloc(F, internal);
    witness.right = try gpa.alloc(F, internal);
    witness.out = try gpa.alloc(F, internal);
    for (converter.gates.items, witness.left, witness.right, witness.out) |gate, *l, *r, *o| {
        l.* = valued.get(gate.left);
        r.* = if (gate.right) |right| valued.get(right) else F.zero;
        o.* = if (gate.output) |output|
            valued.get(output)
        else if (gate.right != null)
            l.*.mul(r.*)
        else
            F.zero;
    }
    const circuit = try converter.reckon_circuit(gpa);
    return .{ circuit, witness };
}
