//! A Bulletproofs circuit proof built on the inner product argument (commonware
//! `zk/bulletproofs/circuit.rs`).
//!
//! Committed values `v_i` are Pedersen commitments `V_i = v_i B + v~_i B~`. A `Circuit`
//! constrains them with multiplication gates `l_i r_i = o_i` and linear constraints: each row
//! of a sparse weight matrix is a linear relation over the column layout
//! `1 | committed values | left wires | right wires | output wires`.
//!
//! - `Setup(G)` wraps an `ipa.Setup` with the value and blinding generators.
//! - `Witness(F)` is the prover's assignment; `claim` derives the public `Claim(G)`.
//! - `prove` builds a `Proof(F, G)` bound to the transcript; `verify` replays it and returns a
//!   `Synthetic` equation over a virtual setup that is zero for a valid proof (evaluate it
//!   with `Setup.eval`, or batch many with `Setup.eval_check_batched`).
//! - `zkc.zig` converts a `zk.circuit` circuit (and its assignment) into this form.
//!
//! Encodings and transcript messages match commonware byte for byte, so proofs interoperate.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const parallel = @import("parallel");
const ipa = @import("ipa.zig");
const Transcript = @import("../../transcript.zig").Transcript;

const algebra = math.algebra;
const Synthetic = math.synthetic.Synthetic;

/// A sparse matrix indexed by `(row, col)`; missing entries are zero. Its dimensions are set by
/// the entries touched through `entry` (which inserts a zero) and by `pad`.
pub fn SparseMatrix(comptime F: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct { row: usize, col: usize, weight: F };

        width: usize = 0,
        height: usize = 0,
        /// Sorted by `(row, col)`, unique.
        entries: std.ArrayList(Entry) = .empty,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        /// Grows the dimensions to at least `width` by `height`.
        pub fn pad(self: *Self, width: usize, height: usize) void {
            self.width = @max(self.width, width);
            self.height = @max(self.height, height);
        }

        fn position(self: *const Self, row: usize, col: usize) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = self.entries.items.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                const at = self.entries.items[mid];
                if (at.row < row or (at.row == row and at.col < col)) low = mid + 1 else high = mid;
            }
            assert(low <= self.entries.items.len);
            const items = self.entries.items;
            const found = low < items.len and items[low].row == row and items[low].col == col;
            return .{ low, found };
        }

        /// The weight at `(row, col)`, zero when absent.
        pub fn get(self: *const Self, row: usize, col: usize) F {
            const index, const found = self.position(row, col);
            return if (found) self.entries.items[index].weight else F.zero;
        }

        /// The weight at `(row, col)`, inserting a zero (and growing the dimensions) when
        /// absent (Rust's `IndexMut`).
        pub fn entry(self: *Self, gpa: Allocator, row: usize, col: usize) !*F {
            self.pad(col + 1, row + 1);
            const index, const found = self.position(row, col);
            if (!found) {
                try self.entries.insert(gpa, index, .{ .row = row, .col = col, .weight = F.zero });
            }
            assert(self.entries.items[index].row == row and self.entries.items[index].col == col);
            return &self.entries.items[index].weight;
        }

        /// Sets `(row, col)` to `weight`.
        pub fn set(self: *Self, gpa: Allocator, row: usize, col: usize, weight: F) !void {
            (try self.entry(gpa, row, col)).* = weight;
        }

        /// `self * rhs`, one value per row; columns beyond `rhs` count as zero.
        pub fn mul_vector(self: *const Self, gpa: Allocator, rhs: []const F) ![]F {
            const out = try gpa.alloc(F, self.height);
            @memset(out, F.zero);
            for (self.entries.items) |item| {
                if (item.col >= rhs.len) continue;
                out[item.row] = out[item.row].add(item.weight.mul(rhs[item.col]));
            }
            return out;
        }

        pub fn encode_size(self: Self) usize {
            var size = codec.encode_size(usize, self.width) + codec.encode_size(usize, self.height);
            size += codec.encode_size(usize, self.entries.items.len);
            for (self.entries.items) |item| {
                size += codec.encode_size(usize, item.row) + codec.encode_size(usize, item.col);
                size += codec.encode_size(F, item.weight);
            }
            return size;
        }

        /// The width, the height, then the entries as a `BTreeMap<(usize, usize), F>`.
        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(usize, self.width, writer);
            codec.write(usize, self.height, writer);
            codec.write(usize, self.entries.items.len, writer);
            for (self.entries.items) |item| {
                codec.write(usize, item.row, writer);
                codec.write(usize, item.col, writer);
                codec.write(F, item.weight, writer);
            }
        }
    };
}

/// The constraints a prover must satisfy: `committed_vars` committed values, `internal_vars`
/// multiplication gates, and one linear constraint per row of `weights`.
pub fn Circuit(comptime F: type) type {
    return struct {
        const Self = @This();

        committed_vars: usize,
        internal_vars: usize,
        weights: SparseMatrix(F),

        /// Takes ownership of `weights`; null (releasing them) when the width does not fit
        /// `1 + committed_vars + 3 * internal_vars` columns.
        pub fn init(gpa: Allocator, committed_vars: usize, weights: SparseMatrix(F)) ?Self {
            var matrix = weights;
            const fixed = std.math.add(usize, committed_vars, 1) catch {
                matrix.deinit(gpa);
                return null;
            };
            if (matrix.width < fixed or (matrix.width - fixed) % 3 != 0) {
                matrix.deinit(gpa);
                return null;
            }
            const internal_vars = (matrix.width - fixed) / 3;
            assert(1 + committed_vars + 3 * internal_vars == matrix.width);
            return .{
                .committed_vars = committed_vars,
                .internal_vars = internal_vars,
                .weights = matrix,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.weights.deinit(gpa);
            self.* = undefined;
        }

        /// The value of column `col` under an assignment (outputs are `left * right`).
        fn column(
            self: *const Self,
            col: usize,
            committed: []const F,
            left: []const F,
            right: []const F,
        ) F {
            if (col == 0) return F.one;
            var offset = col - 1;
            if (offset < self.committed_vars) return committed[offset];
            offset -= self.committed_vars;
            if (offset < self.internal_vars) return left[offset];
            offset -= self.internal_vars;
            if (offset < self.internal_vars) return right[offset];
            offset -= self.internal_vars;
            assert(offset < self.internal_vars);
            return left[offset].mul(right[offset]);
        }

        /// Whether an assignment satisfies every constraint; false for wrong lengths.
        pub fn is_satisfied(
            self: *const Self,
            committed: []const F,
            left: []const F,
            right: []const F,
        ) bool {
            if (committed.len != self.committed_vars) return false;
            if (left.len != self.internal_vars or right.len != self.internal_vars) return false;
            const entries = self.weights.entries.items;
            var index: usize = 0;
            while (index < entries.len) {
                const row = entries[index].row;
                var sum = F.zero;
                while (index < entries.len and entries[index].row == row) : (index += 1) {
                    const value = self.column(entries[index].col, committed, left, right);
                    sum = sum.add(value.mul(entries[index].weight));
                }
                if (!sum.eql(F.zero)) return false;
            }
            assert(index == entries.len);
            return true;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(usize, self.committed_vars) +
                codec.encode_size(usize, self.internal_vars) + self.weights.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(usize, self.committed_vars, writer);
            codec.write(usize, self.internal_vars, writer);
            self.weights.write(writer);
        }
    };
}

/// The IPA generators plus the Pedersen value generator `B` and blinding generator `B~`.
pub fn Setup(comptime G: type) type {
    return struct {
        const Self = @This();

        ipa: ipa.Setup(G),
        value_generator: G,
        blinding_generator: G,

        pub const Cfg = ipa.Setup(G).Cfg;

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.ipa.deinit(gpa);
            if (comptime @hasDecl(G, "deinit")) {
                self.value_generator.deinit(gpa);
                self.blinding_generator.deinit(gpa);
            }
            self.* = undefined;
        }

        pub fn supports(self: Self, lg_len: u8) bool {
            return self.ipa.supports(lg_len);
        }

        pub fn encode_size(self: Self) usize {
            return self.ipa.encode_size() + codec.encode_size(G, self.value_generator) +
                codec.encode_size(G, self.blinding_generator);
        }

        /// The IPA setup, then `B` and `B~`.
        pub fn write(self: Self, writer: *codec.Writer) void {
            self.ipa.write(writer);
            codec.write(G, self.value_generator, writer);
            codec.write(G, self.blinding_generator, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G));
            var setup_ipa = try ipa.Setup(G).read(gpa, reader, cfg);
            errdefer setup_ipa.deinit(gpa);
            const value_generator = try codec.read_cfg(G, gpa, reader, cfg[1]);
            return .{
                .ipa = setup_ipa,
                .value_generator = value_generator,
                .blinding_generator = try codec.read_cfg(G, gpa, reader, cfg[1]),
            };
        }

        /// A setup of `2^lg_len` pairs whose IPA, product, and blinding generators are hashed
        /// to the group from `domain_separator` under distinct labels; the caller supplies the
        /// value generator.
        pub fn hashed(
            gpa: Allocator,
            domain_separator: []const u8,
            lg_len: u8,
            value_generator: G,
        ) !Self {
            assert(lg_len < @bitSizeOf(usize));
            const n = @as(usize, 1) << @intCast(lg_len);
            const g = try gpa.alloc(G, n);
            errdefer gpa.free(g);
            const h = try gpa.alloc(G, n);
            errdefer gpa.free(h);
            for (g, h, 0..) |*g_i, *h_i, i| {
                var message: [10]u8 = undefined;
                std.mem.writeInt(u64, message[2..10], i, .little);
                @memcpy(message[0..2], "g/");
                g_i.* = G.hash_to_group(domain_separator, &message);
                @memcpy(message[0..2], "h/");
                h_i.* = G.hash_to_group(domain_separator, &message);
            }
            return .{
                .ipa = .{
                    .g = g,
                    .h = h,
                    .product_generator = G.hash_to_group(domain_separator, "product"),
                },
                .value_generator = value_generator,
                .blinding_generator = G.hash_to_group(domain_separator, "blinding"),
            };
        }

        /// The virtual setup: the IPA's (indices `0..2n+1`), then `B` at `2n+1` and `B~` at
        /// `2n+2`.
        pub fn virtual_setup(self: Self, gpa: Allocator, comptime F: type) !Setup(Synthetic(F, G)) {
            const S = Synthetic(F, G);
            var virtual_ipa = try self.ipa.virtual_setup(gpa, F);
            errdefer virtual_ipa.deinit(gpa);
            const n: u32 = @intCast(self.ipa.g.len);
            var value = try S.generator(gpa, 2 * n + 1);
            errdefer value.deinit(gpa);
            const blinding = try S.generator(gpa, 2 * n + 2);
            return .{
                .ipa = virtual_ipa,
                .value_generator = value,
                .blinding_generator = blinding,
            };
        }

        /// The concrete generators in virtual-index order.
        pub fn flatten(self: Self, gpa: Allocator) ![]G {
            const n = self.ipa.g.len;
            const flat = try gpa.alloc(G, 2 * n + 3);
            @memcpy(flat[0..n], self.ipa.g);
            @memcpy(flat[n .. 2 * n], self.ipa.h);
            flat[2 * n] = self.ipa.product_generator;
            flat[2 * n + 1] = self.value_generator;
            flat[2 * n + 2] = self.blinding_generator;
            return flat;
        }

        /// Builds the virtual setup, calls `f(context, gpa, &virtual)`, and evaluates the
        /// equation it returns; null when `f` returns null. Zero means the proof verified.
        pub fn eval(
            self: Self,
            gpa: Allocator,
            comptime F: type,
            context: anytype,
            comptime f: anytype,
        ) !?G {
            var virtual = try self.virtual_setup(gpa, F);
            defer virtual.deinit(gpa);
            var equation = (try f(context, gpa, &virtual)) orelse return null;
            defer equation.deinit(gpa);
            const flat = try self.flatten(gpa);
            defer gpa.free(flat);
            return try equation.eval(gpa, flat);
        }

        /// Checks many equations with as few MSMs as possible. `f(context, gpa, &virtual,
        /// rng)` returns one optional equation per item (null for the whole batch when it is
        /// malformed). Each present equation is scaled by an independent random scalar; the
        /// sum over a range of items is evaluated once, and a failing range splits in half
        /// until single items remain. Absent equations are invalid. Returns one verdict per
        /// item (caller frees), or null.
        pub fn eval_check_batched(
            self: Self,
            gpa: Allocator,
            comptime F: type,
            rng: anytype,
            context: anytype,
            comptime f: anytype,
        ) !?[]bool {
            const S = Synthetic(F, G);
            var virtual = try self.virtual_setup(gpa, F);
            defer virtual.deinit(gpa);
            const equations: []?S = (try f(context, gpa, &virtual, rng)) orelse return null;
            defer {
                for (equations) |*equation| if (equation.*) |*present| present.deinit(gpa);
                gpa.free(equations);
            }
            for (equations) |*equation| {
                if (equation.*) |*present| present.mul_assign(F.random(rng));
            }
            const flat = try self.flatten(gpa);
            defer gpa.free(flat);
            return try check_ranges(S, gpa, equations, flat);
        }
    };
}

/// The halving search behind `eval_check_batched`, with an explicit stack of index ranges.
fn check_ranges(comptime S: type, gpa: Allocator, equations: []const ?S, flat: anytype) ![]bool {
    const valid = try gpa.alloc(bool, equations.len);
    errdefer gpa.free(valid);
    @memset(valid, false);
    var active: std.ArrayList(usize) = .empty;
    defer active.deinit(gpa);
    for (equations, 0..) |equation, i| if (equation != null) try active.append(gpa, i);
    var stack: std.ArrayList(parallel.Range) = .empty;
    defer stack.deinit(gpa);
    if (active.items.len > 0) try stack.append(gpa, .init(0, active.items.len));
    while (stack.pop()) |range| {
        assert(range.start < range.end);
        const items = active.items[range.start..range.end];
        var sum: S = .zero;
        defer sum.deinit(gpa);
        for (items) |i| try sum.add_assign(gpa, equations[i].?);
        if ((try sum.eval(gpa, flat)).eql(@TypeOf(flat[0]).zero)) {
            for (items) |i| valid[i] = true;
        } else if (items.len > 1) {
            const mid = range.start + items.len / 2;
            try stack.append(gpa, .init(mid, range.end));
            try stack.append(gpa, .init(range.start, mid));
        }
    }
    return valid;
}

/// The prover's assignment: committed values and their blindings, and the left, right, and
/// output wires.
pub fn Witness(comptime F: type) type {
    return struct {
        const Self = @This();

        values: []F,
        blinding: []F,
        left: []F,
        right: []F,
        out: []F,

        /// Copies the vectors; null unless `values` and `blinding` match in length and the
        /// wires do too. Nothing checks that they satisfy a circuit.
        pub fn init(
            gpa: Allocator,
            values: []const F,
            blinding: []const F,
            left: []const F,
            right: []const F,
            out: []const F,
        ) !?Self {
            if (values.len != blinding.len) return null;
            if (left.len != right.len or right.len != out.len) return null;
            var self: Self = .{
                .values = &.{},
                .blinding = &.{},
                .left = &.{},
                .right = &.{},
                .out = &.{},
            };
            errdefer self.deinit(gpa);
            self.values = try gpa.dupe(F, values);
            self.blinding = try gpa.dupe(F, blinding);
            self.left = try gpa.dupe(F, left);
            self.right = try gpa.dupe(F, right);
            self.out = try gpa.dupe(F, out);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.values);
            gpa.free(self.blinding);
            gpa.free(self.left);
            gpa.free(self.right);
            gpa.free(self.out);
            self.* = undefined;
        }

        /// Whether the wires satisfy `circuit` (a debugging aid for provers).
        pub fn is_satisfied(self: *const Self, circuit: *const Circuit(F)) bool {
            return circuit.is_satisfied(self.values, self.left, self.right);
        }

        /// The Pedersen commitments `v_i B + v~_i B~` to the committed values.
        pub fn claim(
            self: *const Self,
            comptime G: type,
            gpa: Allocator,
            setup: *const Setup(G),
        ) !Claim(G) {
            assert(self.values.len == self.blinding.len);
            const commitments = try gpa.alloc(G, self.values.len);
            for (commitments, self.values, self.blinding) |*commitment, value, blind| {
                commitment.* = setup.value_generator.mul(value).add(
                    setup.blinding_generator.mul(blind),
                );
            }
            return .{ .commitments = commitments };
        }
    };
}

/// The public claim: commitments to values the prover says satisfy a circuit. The circuit is
/// not part of it, so the verifier chooses the properties to check.
pub fn Claim(comptime G: type) type {
    return struct {
        const Self = @This();

        commitments: []G,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.commitments);
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const G, self.commitments);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const G, self.commitments, writer);
        }
    };
}

/// A proof that the prover knows a witness satisfying a circuit for a claim.
pub fn Proof(comptime F: type, comptime G: type) type {
    return struct {
        const Self = @This();

        m_big: G,
        o_big: G,
        m_big_tilde: G,
        t_big: [5]G,
        s_tilde: F,
        t_x: F,
        t_tilde_x: F,
        p_big: G,
        ipa_proof: ipa.Proof(F, G),

        /// `(max_len, (g_cfg, f_cfg))`, where `max_len` bounds the IPA rounds.
        pub const Cfg = ipa.Proof(F, G).Cfg;

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.ipa_proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            var size = codec.encode_size(G, self.m_big) + codec.encode_size(G, self.o_big);
            size += codec.encode_size(G, self.m_big_tilde);
            for (self.t_big) |t| size += codec.encode_size(G, t);
            size += codec.encode_size(F, self.s_tilde) + codec.encode_size(F, self.t_x);
            size += codec.encode_size(F, self.t_tilde_x) + codec.encode_size(G, self.p_big);
            return size + self.ipa_proof.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(G, self.m_big, writer);
            codec.write(G, self.o_big, writer);
            codec.write(G, self.m_big_tilde, writer);
            for (self.t_big) |t| codec.write(G, t, writer);
            codec.write(F, self.s_tilde, writer);
            codec.write(F, self.t_x, writer);
            codec.write(F, self.t_tilde_x, writer);
            codec.write(G, self.p_big, writer);
            self.ipa_proof.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G) and !codec.owns_memory(F));
            const g_cfg, const f_cfg = cfg[1];
            var self: Self = undefined;
            self.m_big = try codec.read_cfg(G, gpa, reader, g_cfg);
            self.o_big = try codec.read_cfg(G, gpa, reader, g_cfg);
            self.m_big_tilde = try codec.read_cfg(G, gpa, reader, g_cfg);
            for (&self.t_big) |*t| t.* = try codec.read_cfg(G, gpa, reader, g_cfg);
            self.s_tilde = try codec.read_cfg(F, gpa, reader, f_cfg);
            self.t_x = try codec.read_cfg(F, gpa, reader, f_cfg);
            self.t_tilde_x = try codec.read_cfg(F, gpa, reader, f_cfg);
            self.p_big = try codec.read_cfg(G, gpa, reader, g_cfg);
            self.ipa_proof = try ipa.Proof(F, G).read(gpa, reader, cfg);
            return self;
        }
    };
}

/// Encodes a write-only value (commonware gives `SparseMatrix`, `Circuit`, and `Claim` only
/// `Write`, while zigware's codec functions also require `read`).
pub fn encode_write_only(gpa: Allocator, value: anytype) ![]u8 {
    const size = value.encode_size();
    const bytes = try gpa.alloc(u8, size);
    var writer = codec.Writer.init(bytes);
    value.write(&writer);
    assert(writer.written().len == size);
    return bytes;
}

fn commit_written(gpa: Allocator, transcript: *Transcript, value: anytype) !void {
    const bytes = try encode_write_only(gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

/// Commits the encoding of `value` to `transcript`.
fn commit_encoded(comptime T: type, gpa: Allocator, transcript: *Transcript, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

fn challenge(comptime F: type, transcript: *const Transcript, label: []const u8) F {
    var noise = transcript.noise(label);
    return F.random(&noise);
}

/// The challenges `y` and `z`, and the circuit's weights folded with them, which the prover
/// and verifier compute identically. `z^(i+1)` folds row `i` into per-column weights: `kappa`
/// (the constant column), `theta` (committed), `lambda` (left), `rho` (right), and `omega`
/// (output). Vectors of the padded length run to `internal_vars` rounded up to a power of two.
fn Folded(comptime F: type) type {
    return struct {
        const Self = @This();

        padded_vars: usize,
        y_inv: F,
        kappa: F,
        /// `<y^-i rho_i, lambda_i>`.
        delta_y_z: F,
        /// `y^i`, padded length.
        y_powers: []F,
        theta: []F,
        lambda: []F,
        /// `omega_i - y^i`, then `-y^i` up to the padded length.
        omega_minus_y: []F,
        y_inv_rho: []F,
        y_inv_lambda: []F,
        /// `y^-i (omega_i - y^i)`, padded length.
        y_inv_omega_minus_y: []F,

        /// Draws `y` then `z` from the transcript and folds the weights. Allocates from
        /// `arena`, which owns the result.
        fn init(arena: Allocator, transcript: *const Transcript, circuit: *const Circuit(F)) !Self {
            const internal = circuit.internal_vars;
            const padded = try std.math.ceilPowerOfTwo(usize, @max(internal, 1));
            const y = challenge(F, transcript, "y");
            const z = challenge(F, transcript, "z");
            var self: Self = .{
                .padded_vars = padded,
                .y_inv = y.inv(),
                .kappa = F.zero,
                .delta_y_z = undefined,
                .y_powers = try power_list(F, arena, y, padded),
                .theta = try zeroes(F, arena, circuit.committed_vars),
                .lambda = try zeroes(F, arena, internal),
                .omega_minus_y = try arena.alloc(F, padded),
                .y_inv_rho = try arena.alloc(F, internal),
                .y_inv_lambda = try arena.alloc(F, internal),
                .y_inv_omega_minus_y = try arena.alloc(F, padded),
            };
            const rho = try zeroes(F, arena, internal);
            const omega = try zeroes(F, arena, internal);
            try self.fold_rows(arena, circuit, z, rho, omega);
            const y_inv_powers = try power_list(F, arena, self.y_inv, padded);
            for (self.omega_minus_y, self.y_powers, 0..) |*out, y_i, i| {
                out.* = if (i < internal) omega[i].sub(y_i) else y_i.neg();
            }
            for (self.y_inv_rho, self.y_inv_lambda, rho, self.lambda, 0..) |*a, *b, r, l, i| {
                a.* = y_inv_powers[i].mul(r);
                b.* = y_inv_powers[i].mul(l);
            }
            for (self.y_inv_omega_minus_y, y_inv_powers, self.omega_minus_y) |*out, a, b| {
                out.* = a.mul(b);
            }
            self.delta_y_z = algebra.msm(F, F, self.y_inv_rho, self.lambda);
            return self;
        }

        /// Adds `z^(row+1) w` for every weight `w` to its column's bucket.
        fn fold_rows(
            self: *Self,
            arena: Allocator,
            circuit: *const Circuit(F),
            z: F,
            rho: []F,
            omega: []F,
        ) !void {
            const z_powers = try power_list(F, arena, z, circuit.weights.height);
            for (z_powers) |*z_i| z_i.* = z_i.mul(z);
            const lambda_start = 1 + circuit.committed_vars;
            const rho_start = lambda_start + circuit.internal_vars;
            const omega_start = rho_start + circuit.internal_vars;
            for (circuit.weights.entries.items) |item| {
                const weighted = item.weight.mul(z_powers[item.row]);
                const col = item.col;
                const bucket = if (col >= omega_start)
                    &omega[col - omega_start]
                else if (col >= rho_start)
                    &rho[col - rho_start]
                else if (col >= lambda_start)
                    &self.lambda[col - lambda_start]
                else if (col >= 1)
                    &self.theta[col - 1]
                else
                    &self.kappa;
                bucket.* = bucket.add(weighted);
            }
        }
    };
}

fn zeroes(comptime F: type, gpa: Allocator, len: usize) ![]F {
    const out = try gpa.alloc(F, len);
    @memset(out, F.zero);
    return out;
}

/// `1, base, base^2, ...` (`len` values).
fn power_list(comptime F: type, gpa: Allocator, base: F, len: usize) ![]F {
    const out = try gpa.alloc(F, len);
    var powers = algebra.powers(F, F.one, base);
    for (out) |*power| power.* = powers.next();
    return out;
}

/// The prover's blinding factors, drawn in commonware's order: `l~`, `r~`, `m`, `o~`, `m~`.
fn Blinds(comptime F: type) type {
    return struct {
        l_tilde: []F,
        r_tilde: []F,
        m: F,
        o_tilde: F,
        m_tilde: F,

        fn draw(arena: Allocator, rng: anytype, internal: usize) !@This() {
            const l_tilde = try arena.alloc(F, internal);
            for (l_tilde) |*value| value.* = F.random(rng);
            const r_tilde = try arena.alloc(F, internal);
            for (r_tilde) |*value| value.* = F.random(rng);
            const m = F.random(rng);
            const o_tilde = F.random(rng);
            return .{
                .l_tilde = l_tilde,
                .r_tilde = r_tilde,
                .m = m,
                .o_tilde = o_tilde,
                .m_tilde = F.random(rng),
            };
        }
    };
}

/// The prover's polynomial coefficients `t_1..t_6` and their blindings, plus `y^i r_i` and
/// `y^i r~_i`, which the IPA witness reuses.
fn Polynomial(comptime F: type) type {
    return struct {
        t: [6]F,
        t_tilde: [6]F,
        y_r: []F,
        y_r_tilde: []F,

        fn init(
            arena: Allocator,
            rng: anytype,
            folded: *const Folded(F),
            witness: *const Witness(F),
            blinds: Blinds(F),
        ) !@This() {
            const internal = witness.left.len;
            const y_r = try arena.alloc(F, internal);
            const y_r_tilde = try arena.alloc(F, internal);
            var t: [6]F = @splat(F.zero);
            for (y_r, y_r_tilde, 0..) |*y_r_i, *y_r_tilde_i, i| {
                y_r_i.* = folded.y_powers[i].mul(witness.right[i]);
                y_r_tilde_i.* = folded.y_powers[i].mul(blinds.r_tilde[i]);
                const left = witness.left[i].add(folded.y_inv_rho[i]);
                const right = y_r_i.*.add(folded.lambda[i]);
                const l_tilde = blinds.l_tilde[i];
                t[0] = t[0].add(left.mul(folded.omega_minus_y[i]));
                t[2] = t[2].add(l_tilde.mul(folded.omega_minus_y[i]));
                t[2] = t[2].add(witness.out[i].mul(right));
                t[3] = t[3].add(l_tilde.mul(right));
                t[3] = t[3].add(left.mul(y_r_tilde_i.*));
            }
            t[1] = folded.delta_y_z.sub(folded.kappa)
                .sub(algebra.msm(F, F, folded.theta, witness.values));
            t[4] = algebra.msm(F, F, witness.out, y_r_tilde);
            t[5] = algebra.msm(F, F, blinds.l_tilde, y_r_tilde);
            var t_tilde: [6]F = undefined;
            for (&t_tilde, 0..) |*value, i| {
                value.* = if (i == 1)
                    algebra.msm(F, F, folded.theta, witness.blinding).neg()
                else
                    F.random(rng);
            }
            return .{ .t = t, .t_tilde = t_tilde, .y_r = y_r, .y_r_tilde = y_r_tilde };
        }

        /// `T_i = t_i B + t~_i B~` for every coefficient but `t_2`, which the verifier
        /// reconstructs from the claim.
        fn commitments(self: @This(), comptime G: type, b: G, b_tilde: G) [5]G {
            comptime assert(G.Scalar == F);
            var t_big: [5]G = undefined;
            for (&t_big, 0..) |*t_big_i, j| {
                const i = if (j >= 1) j + 1 else j;
                assert(i != 1 and i < 6);
                t_big_i.* = b.mul(self.t[i]).add(b_tilde.mul(self.t_tilde[i]));
            }
            return t_big;
        }
    };
}

/// `x, x^2, ..., x^6` for the challenge drawn under "x".
fn x_powers(comptime F: type, transcript: *const Transcript) [6]F {
    const x = challenge(F, transcript, "x");
    var out: [6]F = undefined;
    var powers = algebra.powers(F, x, x);
    for (&out) |*power| power.* = powers.next();
    return out;
}

/// Commits the circuit, the claim, and `M`, `O`, `M~`, in commonware's order.
fn commit_statement(
    comptime G: type,
    gpa: Allocator,
    transcript: *Transcript,
    circuit: *const Circuit(G.Scalar),
    claim: Claim(G),
    wires: [3]G,
) !void {
    try commit_written(gpa, transcript, circuit.*);
    try commit_written(gpa, transcript, claim);
    for (wires) |wire| try commit_encoded(G, gpa, transcript, wire);
}

/// The padded gate count, or null when the setup cannot hold it.
fn padded_vars(internal_vars: usize, generator_count: usize) ?usize {
    const padded = std.math.ceilPowerOfTwo(usize, @max(internal_vars, 1)) catch return null;
    if (generator_count < padded) return null;
    assert(std.math.isPowerOfTwo(padded) and padded >= internal_vars);
    return padded;
}

/// Proves that `witness` satisfies `circuit` and opens `claim`, bound to the transcript. `rng`
/// supplies the blindings. Null when the setup is too small for the circuit or the witness
/// lengths do not match it (commonware panics on short wires); a witness that does not
/// satisfy the circuit or claim yields a proof that does not verify.
pub fn prove(
    comptime G: type,
    gpa: Allocator,
    rng: anytype,
    transcript: *Transcript,
    setup: *const Setup(G),
    circuit: *const Circuit(G.Scalar),
    claim: Claim(G),
    witness: *const Witness(G.Scalar),
    strategy: anytype,
) !?Proof(G.Scalar, G) {
    const F = G.Scalar;
    comptime algebra.assert_crypto_group(G);
    const internal = circuit.internal_vars;
    if (witness.left.len != internal or witness.values.len != circuit.committed_vars) return null;
    assert(witness.right.len == internal and witness.out.len == internal);
    const padded = padded_vars(internal, setup.ipa.g.len) orelse return null;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const blinds = try Blinds(F).draw(arena, rng, internal);
    const g_internal = setup.ipa.g[0..internal];
    const h_internal = setup.ipa.h[0..internal];
    const b_tilde = setup.blinding_generator;
    const m_big, const o_big, const m_big_tilde = wire_commitments(G, setup, witness, blinds);
    try commit_statement(G, gpa, transcript, circuit, claim, .{ m_big, o_big, m_big_tilde });
    const folded = try Folded(F).init(arena, transcript, circuit);
    assert(folded.padded_vars == padded);
    const poly = try Polynomial(F).init(arena, rng, &folded, witness, blinds);
    const t_big = poly.commitments(G, setup.value_generator, b_tilde);
    const p_0 = algebra.msm(G, F, setup.ipa.h[0..padded], folded.y_inv_omega_minus_y);
    const p_1 = algebra.msm(G, F, g_internal, folded.y_inv_rho)
        .add(algebra.msm(G, F, h_internal, folded.y_inv_lambda));
    for (t_big) |t_big_i| try commit_encoded(G, gpa, transcript, t_big_i);
    const x = x_powers(F, transcript);
    const s_tilde = blinds.m.mul(x[0]).add(blinds.o_tilde.mul(x[1])).add(blinds.m_tilde.mul(x[2]));
    const p = b_tilde.mul(s_tilde.neg()).add(p_0).add(p_1.add(m_big).mul(x[0]))
        .add(o_big.mul(x[1])).add(m_big_tilde.mul(x[2]));
    const t_x = algebra.msm(F, F, &poly.t, &x);
    const ipa_claim: ipa.Claim(F, G) = .{
        .commitment = p,
        .product = t_x,
        .y = folded.y_inv,
        .log_len = @intCast(std.math.log2_int(usize, padded)),
    };
    const ipa_witness = try ipa_vectors(F, arena, &folded, witness, blinds, poly, x);
    const ipa_proof = (try ipa.prove(
        G,
        gpa,
        transcript,
        &setup.ipa,
        ipa_claim,
        &ipa_witness,
        strategy,
    )) orelse
        return null;
    return .{
        .m_big = m_big,
        .o_big = o_big,
        .m_big_tilde = m_big_tilde,
        .t_big = t_big,
        .s_tilde = s_tilde,
        .t_x = t_x,
        .t_tilde_x = algebra.msm(F, F, &poly.t_tilde, &x),
        .p_big = p,
        .ipa_proof = ipa_proof,
    };
}

/// `M = <l, G> + <r, H> + m B~`, `O = <o, G> + o~ B~`, and `M~ = <l~, G> + <r~, H> + m~ B~`.
fn wire_commitments(
    comptime G: type,
    setup: *const Setup(G),
    witness: *const Witness(G.Scalar),
    blinds: Blinds(G.Scalar),
) [3]G {
    const F = G.Scalar;
    const internal = witness.left.len;
    assert(internal <= setup.ipa.g.len and blinds.l_tilde.len == internal);
    const g_internal = setup.ipa.g[0..internal];
    const h_internal = setup.ipa.h[0..internal];
    const b_tilde = setup.blinding_generator;
    const m_big = algebra.msm(G, F, g_internal, witness.left)
        .add(algebra.msm(G, F, h_internal, witness.right)).add(b_tilde.mul(blinds.m));
    const o_big = algebra.msm(G, F, g_internal, witness.out).add(b_tilde.mul(blinds.o_tilde));
    const m_big_tilde = algebra.msm(G, F, g_internal, blinds.l_tilde)
        .add(algebra.msm(G, F, h_internal, blinds.r_tilde)).add(b_tilde.mul(blinds.m_tilde));
    return .{ m_big, o_big, m_big_tilde };
}

/// The IPA vectors `f(x)` and `g(x)` of the padded length.
fn ipa_vectors(
    comptime F: type,
    arena: Allocator,
    folded: *const Folded(F),
    witness: *const Witness(F),
    blinds: Blinds(F),
    poly: Polynomial(F),
    x: [6]F,
) !ipa.Witness(F) {
    const padded = folded.padded_vars;
    const internal = witness.left.len;
    const f_x = try zeroes(F, arena, padded);
    const g_x = try arena.dupe(F, folded.omega_minus_y);
    assert(g_x.len == padded);
    for (f_x[0..internal], g_x[0..internal], 0..) |*f_i, *g_i, i| {
        f_i.* = witness.left[i].add(folded.y_inv_rho[i]).mul(x[0])
            .add(witness.out[i].mul(x[1])).add(blinds.l_tilde[i].mul(x[2]));
        g_i.* = poly.y_r[i].add(folded.lambda[i]).mul(x[0]).add(folded.omega_minus_y[i])
            .add(poly.y_r_tilde[i].mul(x[2]));
    }
    return .{ .a = f_x, .b = g_x };
}

/// Builds the equation for `proof` against `circuit`, `claim`, and a virtual `setup` (see
/// `Setup.eval`), replaying the transcript. `rng` draws the weights combining the circuit
/// checks with the IPA's. Null for a malformed proof or a claim whose arity differs from the
/// circuit's (or, where commonware would panic, a setup too small for the circuit).
pub fn verify(
    comptime G: type,
    gpa: Allocator,
    rng: anytype,
    transcript: *Transcript,
    setup: *const Setup(Synthetic(G.Scalar, G)),
    circuit: *const Circuit(G.Scalar),
    claim: Claim(G),
    proof: Proof(G.Scalar, G),
) !?Synthetic(G.Scalar, G) {
    const F = G.Scalar;
    comptime algebra.assert_crypto_group(G);
    if (claim.commitments.len != circuit.committed_vars) return null;
    const padded = padded_vars(circuit.internal_vars, setup.ipa.g.len) orelse return null;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const wires: [3]G = .{ proof.m_big, proof.o_big, proof.m_big_tilde };
    try commit_statement(G, gpa, transcript, circuit, claim, wires);
    const folded = try Folded(F).init(arena, transcript, circuit);
    assert(folded.padded_vars == padded);
    for (proof.t_big) |t_big_i| try commit_encoded(G, gpa, transcript, t_big_i);
    const x = x_powers(F, transcript);
    var t_check = try polynomial_check(G, arena, setup, claim, proof, &folded, x);
    var p_check = try commitment_check(G, arena, setup, circuit, proof, &folded, x);
    const ipa_claim: ipa.Claim(F, G) = .{
        .commitment = proof.p_big,
        .product = proof.t_x,
        .y = folded.y_inv,
        .log_len = @intCast(std.math.log2_int(usize, padded)),
    };
    var out = (try ipa.verify(G, gpa, transcript, &setup.ipa, ipa_claim, proof.ipa_proof)) orelse
        return null;
    errdefer out.deinit(gpa);
    p_check.mul_assign(F.random(rng));
    try out.add_assign(gpa, p_check);
    t_check.mul_assign(F.random(rng));
    try out.add_assign(gpa, t_check);
    return out;
}

/// `t_x B + t~_x B~ - (delta - kappa) x^2 B + x^2 <theta_i, V_i> - sum_{i != 2} x^i T_i`, zero
/// when `t(x)` is the committed polynomial.
fn polynomial_check(
    comptime G: type,
    arena: Allocator,
    setup: *const Setup(Synthetic(G.Scalar, G)),
    claim: Claim(G),
    proof: Proof(G.Scalar, G),
    folded: *const Folded(G.Scalar),
    x: [6]G.Scalar,
) !Synthetic(G.Scalar, G) {
    const S = Synthetic(G.Scalar, G);
    var out: S = .zero;
    try ipa.add_scaled(S, arena, &out, setup.value_generator, proof.t_x, .add);
    try ipa.add_scaled(S, arena, &out, setup.blinding_generator, proof.t_tilde_x, .add);
    const constant = folded.kappa.neg().add(folded.delta_y_z).mul(x[1]);
    try ipa.add_scaled(S, arena, &out, setup.value_generator, constant, .sub);
    for (folded.theta, claim.commitments) |theta_i, commitment| {
        try out.concrete.append(arena, .{ .weight = theta_i.mul(x[1]), .point = commitment });
    }
    const t_weights: [5]G.Scalar = .{ x[0], x[2], x[3], x[4], x[5] };
    for (t_weights, proof.t_big) |weight, t_big_i| {
        try out.concrete.append(arena, .{ .weight = weight.neg(), .point = t_big_i });
    }
    return out;
}

/// `P - x M - x^2 O - x^3 M~ - P_0 - x P_1 + s~ B~`, zero when `P` is the honest IPA
/// commitment.
fn commitment_check(
    comptime G: type,
    arena: Allocator,
    setup: *const Setup(Synthetic(G.Scalar, G)),
    circuit: *const Circuit(G.Scalar),
    proof: Proof(G.Scalar, G),
    folded: *const Folded(G.Scalar),
    x: [6]G.Scalar,
) !Synthetic(G.Scalar, G) {
    const F = G.Scalar;
    const S = Synthetic(F, G);
    const internal = circuit.internal_vars;
    var out = try S.init_concrete(arena, &.{
        .{ .weight = F.one, .point = proof.p_big },
        .{ .weight = x[0].neg(), .point = proof.m_big },
        .{ .weight = x[1].neg(), .point = proof.o_big },
        .{ .weight = x[2].neg(), .point = proof.m_big_tilde },
    });
    const h = setup.ipa.h;
    const p_0 = try ipa.synthetic_msm(
        S,
        arena,
        h[0..folded.padded_vars],
        folded.y_inv_omega_minus_y,
    );
    try out.sub_assign(arena, p_0);
    var p_1 = try ipa.synthetic_msm(S, arena, setup.ipa.g[0..internal], folded.y_inv_rho);
    try p_1.add_assign(arena, try ipa.synthetic_msm(S, arena, h[0..internal], folded.y_inv_lambda));
    p_1.mul_assign(x[0]);
    try out.sub_assign(arena, p_1);
    try ipa.add_scaled(S, arena, &out, setup.blinding_generator, proof.s_tilde, .add);
    return out;
}
