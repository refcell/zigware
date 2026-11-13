//! Small algebraic types for tests (commonware `math::test`): a prime field `F` and a prime
//! order group `G` (the order-p subgroup of the units mod q = 2p + 1), both 8 bytes on the
//! wire. Other packages use them to test generic code cheaply.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const codec = @import("codec");
const algebra = @import("algebra.zig");
const fuzz = @import("fuzz.zig");
const Unstructured = fuzz.Unstructured;

const P: u64 = 4_611_686_018_427_389_243;
const Q: u64 = 9_223_372_036_854_778_487;

comptime {
    assert(Q == 2 * P + 1);
}

fn mul_mod(a: u64, b: u64, modulus: u64) u64 {
    assert(modulus > 1);
    return @intCast((@as(u128, a) * b) % modulus);
}

/// The prime field F_p.
pub const F = struct {
    value: u64,

    pub const max: u64 = P - 1;
    pub const fixed_size = 8;
    pub const zero: F = .{ .value = 0 };
    pub const one: F = .{ .value = 1 };

    pub fn from_u64(x: u64) F {
        return .{ .value = x % P };
    }

    pub fn add(a: F, b: F) F {
        assert(a.value < P and b.value < P);
        const sum = a.value + b.value;
        return .{ .value = if (sum >= P) sum - P else sum };
    }

    pub fn neg(a: F) F {
        assert(a.value < P);
        return .{ .value = if (a.value == 0) 0 else P - a.value };
    }

    pub fn sub(a: F, b: F) F {
        return a.add(b.neg());
    }

    pub fn mul(a: F, b: F) F {
        assert(a.value < P and b.value < P);
        return .{ .value = mul_mod(a.value, b.value, P) };
    }

    pub fn inv(a: F) F {
        return algebra.exp(F, a, &.{P - 2});
    }

    pub fn eql(a: F, b: F) bool {
        return a.value == b.value;
    }

    pub fn random(rng: anytype) F {
        var bytes: [8]u8 = undefined;
        rng.fill_bytes(&bytes);
        return .{ .value = std.mem.readInt(u64, &bytes, .little) % P };
    }

    pub fn arbitrary(u: *Unstructured) F {
        return .{ .value = u.int(u64) % P };
    }

    pub fn write(a: F, writer: *codec.Writer) void {
        writer.write_int(u64, a.value);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!F {
        const value = try reader.read_int(u64);
        if (value >= P) return reader.invalid("F", "out of range");
        return .{ .value = value };
    }
};

/// A prime-order group of order p, written additively: the identity is 1, "addition" is
/// multiplication mod q, and scalar multiplication is exponentiation.
pub const G = struct {
    value: u64,

    pub const Scalar = F;
    pub const fixed_size = 8;
    pub const zero: G = .{ .value = 1 };
    /// 4 = 2^2 is a non-trivial quadratic residue, so it generates the subgroup of order p.
    pub const generator: G = .{ .value = 4 };

    pub fn add(a: G, b: G) G {
        assert(a.value < Q and b.value < Q);
        return .{ .value = mul_mod(a.value, b.value, Q) };
    }

    pub fn double(a: G) G {
        return a.add(a);
    }

    pub fn neg(a: G) G {
        return algebra.scale(G, a, &.{Q - 2});
    }

    pub fn sub(a: G, b: G) G {
        return a.add(b.neg());
    }

    pub fn mul(a: G, scalar: F) G {
        return algebra.scale(G, a, &.{scalar.value});
    }

    pub fn eql(a: G, b: G) bool {
        return a.value == b.value;
    }

    pub fn arbitrary(u: *Unstructured) G {
        return generator.mul(F.arbitrary(u));
    }

    pub fn write(a: G, writer: *codec.Writer) void {
        writer.write_int(u64, a.value);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!G {
        const value = try reader.read_int(u64);
        if (value >= Q) return reader.invalid("G", "out of range");
        const out: G = .{ .value = value };
        if (value == 0 or algebra.scale(G, out, &.{P}).value != 1) {
            return reader.invalid("G", "not in subgroup");
        }
        return out;
    }
};

comptime {
    algebra.assert_field(F);
    algebra.assert_crypto_group(G);
}

/// The test-types fuzz plan (commonware `math::test::fuzz::Plan`).
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    switch (u.choose(enum { f_codec, g_codec, fuzz_field, fuzz_space })) {
        .f_codec => {
            const x = F.arbitrary(u);
            const bytes = codec.encode_fixed(F, x);
            if (!(try codec.decode_fixed(F, &bytes)).eql(x)) return error.RoundTrip;
        },
        .g_codec => {
            const x = G.arbitrary(u);
            const bytes = codec.encode_fixed(G, x);
            if (!(try codec.decode_fixed(G, &bytes)).eql(x)) return error.RoundTrip;
        },
        .fuzz_field => try algebra.test_suites.fuzz_field(F, u),
        .fuzz_space => try algebra.test_suites.fuzz_space(F, G, u),
    }
}

const testing = std.testing;

test "test types fuzz plan (seeded)" {
    try fuzz.run_seeded(0x7e57, 500, {}, fuzz_plan);
}

test "test types fuzz plan (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            try fuzz.run_smith({}, smith, fuzz_plan);
        }
    }.one, .{});
}

test "field and group guards" {
    var rng = utils.rng.test_rng();
    const x = F.random(&rng);
    try testing.expect(x.eql(F.zero) or x.inv().mul(x).eql(F.one));
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, P, .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(F, &bytes));
    std.mem.writeInt(u64, &bytes, Q, .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(G, &bytes));
    std.mem.writeInt(u64, &bytes, 0, .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(G, &bytes));
    // q = 3 (mod 4), so -1 is a non-residue and lies outside the order-p subgroup.
    std.mem.writeInt(u64, &bytes, Q - 1, .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(G, &bytes));
}
