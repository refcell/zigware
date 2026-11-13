//! The public output of a polynomial secret sharing (commonware
//! `bls12381::primitives::sharing`): the committed polynomial, how participants map to
//! evaluation points (`Mode`), and the number of participants.
//!
//! Wire format: the mode byte, the total as a big-endian u32, then the committed polynomial
//! (a varint coefficient count and the compressed points).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const group = @import("group.zig");
const variant = @import("variant.zig");

const Allocator = std.mem.Allocator;
const Participant = utils.Participant;
const Scalar = group.Scalar;
const Error = variant.Error;

/// A polynomial over `T`.
pub const Poly = math.poly.Poly;
/// Lagrange interpolation at zero over participant indices.
pub const Interpolator = math.poly.Interpolator(Participant, Scalar);

/// How participants are assigned evaluation points of the shared polynomial.
pub const Mode = enum(u8) {
    /// Participant i evaluates at i + 1 (f(0) holds the secret).
    non_zero_counter = 0,
    /// Participant i evaluates at w^i for a root of unity w of order
    /// `next_power_of_two(total)`, which allows O(n log n) interpolation.
    roots_of_unity = 1,

    pub const fixed_size: usize = 1;
    pub const Cfg = ModeVersion;

    /// The root of unity for a domain of `total` participants, or null when the domain is
    /// too large.
    fn domain_root(total: u32) ?Scalar {
        assert(total > 0);
        const size = std.math.ceilPowerOfTwoAssert(u64, total);
        const lg_size: u8 = @intCast(std.math.log2_int(u64, size));
        return Scalar.root_of_unity(lg_size);
    }

    /// The evaluation point of participant `i`, or null when `i >= total`.
    pub fn scalar(mode: Mode, total: u32, i: Participant) ?Scalar {
        assert(total > 0);
        if (i.get() >= total) return null;
        return switch (mode) {
            .non_zero_counter => Scalar.from_u64(@as(u64, i.get()) + 1),
            .roots_of_unity => {
                const w = domain_root(total) orelse @panic("domain too large for NTT");
                return math.algebra.exp(Scalar, w, &.{i.get()});
            },
        };
    }

    /// The evaluation points of every participant, in index order; the caller frees them.
    pub fn all_scalars(mode: Mode, gpa: Allocator, total: u32) Allocator.Error![]Scalar {
        assert(total > 0);
        const out = try gpa.alloc(Scalar, total);
        switch (mode) {
            .non_zero_counter => for (out, 0..) |*s, i| {
                s.* = Scalar.from_u64(@as(u64, i) + 1);
            },
            .roots_of_unity => {
                const w = domain_root(total) orelse @panic("domain too large for NTT");
                var state = Scalar.one;
                for (out) |*s| {
                    s.* = state;
                    state = state.mul(w);
                }
            },
        }
        return out;
    }

    /// An interpolator over `indices` (sorted and unique), or `InvalidIndex` when any
    /// index is >= `total` or the roots-of-unity domain exceeds u32.
    pub fn interpolator(
        mode: Mode,
        gpa: Allocator,
        total: u32,
        indices: []const Participant,
    ) (Error || Allocator.Error)!Interpolator {
        assert(total > 0);
        for (indices) |index| if (index.get() >= total) return error.InvalidIndex;
        switch (mode) {
            .non_zero_counter => {
                const points = try gpa.alloc(Scalar, indices.len);
                defer gpa.free(points);
                for (points, indices) |*point, index| point.* = mode.scalar(total, index).?;
                return Interpolator.init(gpa, indices, points);
            },
            .roots_of_unity => {
                const size = std.math.ceilPowerOfTwoAssert(u64, total);
                const ntt_total = std.math.cast(u32, size) orelse return error.InvalidIndex;
                const exponents = try gpa.alloc(u32, indices.len);
                defer gpa.free(exponents);
                for (exponents, indices) |*e, index| e.* = index.get();
                return Interpolator.init_roots_of_unity(gpa, ntt_total, indices, exponents);
            },
        }
    }

    /// An interpolator for `subset`, where each element's participant index is its position
    /// in `set` (both sorted and unique). Null when `subset` has elements not in `set`.
    pub fn subset_interpolator(
        mode: Mode,
        comptime I: type,
        gpa: Allocator,
        set: []const I,
        subset: []const I,
    ) Allocator.Error!?math.poly.Interpolator(I, Scalar) {
        const Result = math.poly.Interpolator(I, Scalar);
        if (set.len == 0) return try Result.init(gpa, &.{}, &.{});
        const total: u32 = @intCast(set.len);
        const positions = try gpa.alloc(u32, subset.len);
        defer gpa.free(positions);
        for (positions, subset) |*position, item| {
            const found = position_of(I, set, item) orelse return null;
            position.* = @intCast(found);
        }
        switch (mode) {
            .non_zero_counter => {
                const points = try gpa.alloc(Scalar, subset.len);
                defer gpa.free(points);
                for (points, positions) |*point, p| {
                    point.* = mode.scalar(total, Participant.init(p)).?;
                }
                return try Result.init(gpa, subset, points);
            },
            .roots_of_unity => {
                const size = std.math.ceilPowerOfTwoAssert(u64, total);
                const ntt_total = std.math.cast(u32, size) orelse return null;
                return try Result.init_roots_of_unity(gpa, ntt_total, subset, positions);
            },
        }
    }

    fn position_of(comptime I: type, set: []const I, item: I) ?usize {
        var low: usize = 0;
        var high: usize = set.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            switch (math.poly.index_order(I, set[mid], item)) {
                .eq => return mid,
                .lt => low = mid + 1,
                .gt => high = mid,
            }
        }
        return null;
    }

    pub fn write(mode: Mode, writer: *codec.Writer) void {
        writer.write_byte(@backingInt(mode));
    }

    pub fn read(_: Allocator, reader: *codec.Reader, version: ModeVersion) codec.Error!Mode {
        const tag = try reader.read_byte();
        const mode: Mode = switch (tag) {
            0 => .non_zero_counter,
            1 => .roots_of_unity,
            else => return reader.fail(error.InvalidEnum, tag),
        };
        if (!version.supports(mode)) {
            return reader.invalid("Mode", "unsupported mode for version");
        }
        return mode;
    }

    /// commonware's `Arbitrary`: `int_in_range(0..=1)`.
    pub fn arbitrary(u: *minifuzz.Unstructured) minifuzz.Error!Mode {
        return if (u.int_in_range(u8, 0, 1) == 0) .non_zero_counter else .roots_of_unity;
    }
};

/// Which modes a decoder accepts, so newer modes can be rolled out gradually.
pub const ModeVersion = enum(u8) {
    /// `non_zero_counter` only.
    v0 = 0,
    /// v0 and `roots_of_unity`.
    v1 = 1,

    pub fn supports(version: ModeVersion, mode: Mode) bool {
        return switch (mode) {
            .non_zero_counter => true,
            .roots_of_unity => @backingInt(version) >= 1,
        };
    }
};

/// The public output of a sharing for variant `V`: the polynomial committed in `V.Public`.
/// Owns its polynomial and a cache of partial public keys; `deinit` frees both.
pub fn Sharing(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const PublicPoly = Poly(V.Public);

        mode: Mode,
        total: u32,
        poly: PublicPoly,
        /// Lazily computed partial public keys, one per participant.
        evals: []?V.Public,

        pub const Cfg = struct { max_participants: u32, max_supported_mode: ModeVersion };

        /// Takes ownership of `poly`.
        pub fn init(gpa: Allocator, mode: Mode, total: u32, poly: PublicPoly) !Self {
            assert(total > 0);
            const evals = try gpa.alloc(?V.Public, total);
            @memset(evals, null);
            return .{ .mode = mode, .total = total, .poly = poly, .evals = evals };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.poly.deinit(gpa);
            gpa.free(self.evals);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var poly = try self.poly.clone(gpa);
            errdefer poly.deinit(gpa);
            const evals = try gpa.dupe(?V.Public, self.evals);
            return .{ .mode = self.mode, .total = self.total, .poly = poly, .evals = evals };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.mode == b.mode and a.total == b.total and a.poly.eql(b.poly);
        }

        /// The evaluation point of participant `i`, or null when `i >= total`.
        pub fn scalar(self: Self, i: Participant) ?Scalar {
            return self.mode.scalar(self.total, i);
        }

        /// The number of participants needed to recover the secret: one more than the
        /// polynomial's exact degree.
        pub fn required(self: Self) u32 {
            return self.poly.degree_exact() + 1;
        }

        /// The group public key (the commitment to the secret).
        pub fn public(self: Self) V.Public {
            return self.poly.constant();
        }

        /// An interpolator over `indices` (sorted and unique).
        pub fn interpolator(
            self: Self,
            gpa: Allocator,
            indices: []const Participant,
        ) (Error || Allocator.Error)!Interpolator {
            return self.mode.interpolator(gpa, self.total, indices);
        }

        /// Computes every partial public key once (for verifying many partials).
        pub fn precompute_partial_publics(self: Self) void {
            for (0..self.total) |i| _ = self.partial_public(Participant.from_usize(i)) catch
                unreachable; // i < total.
        }

        /// The public key of participant `i`'s share, or `InvalidIndex` when `i >= total`.
        /// Computed on first use and cached (the cache is not thread-safe).
        pub fn partial_public(self: Self, i: Participant) Error!V.Public {
            if (i.get() >= self.total) return error.InvalidIndex;
            const slot = &self.evals[i.get()];
            if (slot.*) |cached| return cached;
            const value = self.poly.eval(Scalar, self.scalar(i).?);
            slot.* = value;
            return value;
        }

        /// An upper bound on the encoded size for at most `max_participants` participants.
        pub fn max_encode_size_with(max_participants: u32) usize {
            return PublicPoly.max_encode_size_with(max_participants) + Mode.fixed_size + 4;
        }

        pub fn encode_size(self: Self) usize {
            return Mode.fixed_size + 4 + self.poly.encode_size();
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.mode.write(writer);
            codec.write(u32, self.total, writer);
            self.poly.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            assert(cfg.max_participants > 0);
            const mode = try Mode.read(gpa, reader, cfg.max_supported_mode);
            // Bounding the total bounds the work of precomputing partial public keys.
            const total = try codec.read(u32, gpa, reader);
            if (total == 0 or total > cfg.max_participants) {
                return reader.invalid("Sharing", "total not in range");
            }
            const poly_cfg: PublicPoly.Cfg = .{ .range = .inclusive(1, cfg.max_participants) };
            var poly = try PublicPoly.read(gpa, reader, poly_cfg);
            errdefer poly.deinit(gpa);
            return init(gpa, mode, total, poly);
        }
    };
}

test {
    _ = @import("sharing_tests.zig");
}
