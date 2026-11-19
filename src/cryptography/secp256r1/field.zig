//! P-256 field arithmetic for verify.zig. Multiplication on x86_64 with BMI2 and ADX runs as
//! aws-lc's `ecp_nistz256_mul_mont` does it: Montgomery multiplication (R = 2^256) that
//! interleaves `mulx` with two carry chains (`adcx`, `adox`) and reduces each limb with
//! shifts, since `-p^-1 = 1 mod 2^64` and `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. The limbs
//! are std's (fiat-crypto's) Montgomery limbs, fully reduced, so `mul` returns exactly std's
//! `Fe.mul`; other builds call std. Addition and subtraction are plain u256 arithmetic, about
//! twice as fast as std's, with the same limbs.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Fe = std.crypto.ecc.P256.Fe;

/// The self-hosted backend (Debug on x86_64) does not accept the memory operands.
const accelerated = builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .x86_64 and
    builtin.cpu.has(.x86, .bmi2) and builtin.cpu.has(.x86, .adx);

/// `a b` in the field: the same limbs as `a.mul(b)`.
pub inline fn mul(a: Fe, b: Fe) Fe {
    if (!accelerated) return a.mul(b);
    var l0: u64 = undefined;
    var l1: u64 = undefined;
    var l2: u64 = undefined;
    var l3: u64 = undefined;
    asm volatile (mul_text
        : [l0] "=&{rax}" (l0),
          [l1] "=&{rcx}" (l1),
          [l2] "=&{r14}" (l2),
          [l3] "=&{r11}" (l3),
        : [a] "r" (&a.limbs),
          [b] "r" (&b.limbs),
          // The asm reads `a` and `b` through their pointers.
        : .{
          .rdx = true,
          .r8 = true,
          .r9 = true,
          .r10 = true,
          .r12 = true,
          .r13 = true,
          .cc = true,
          .memory = true,
        });
    return .{ .limbs = .{ l0, l1, l2, l3 } };
}

/// `a^2` in the field: the same limbs as `a.sq()`. A dedicated squaring (aws-lc's
/// `sqr_mont`) measured no faster here: the four serial reductions bound both.
pub inline fn sq(a: Fe) Fe {
    return mul(a, a);
}

/// `a + b`: the same limbs as `a.add(b)` (both fully reduced).
pub inline fn add(a: Fe, b: Fe) Fe {
    if (!little_endian) return a.add(b);
    const sum = @addWithOverflow(wide(a), wide(b));
    const diff = @subWithOverflow(sum[0], Fe.field_order);
    // The sum is below p exactly when it did not carry out and subtracting p borrows.
    return narrow(if (sum[1] == 0 and diff[1] == 1) sum[0] else diff[0]);
}

/// `a - b`: the same limbs as `a.sub(b)`.
pub inline fn sub(a: Fe, b: Fe) Fe {
    if (!little_endian) return a.sub(b);
    const diff = @subWithOverflow(wide(a), wide(b));
    return narrow(if (diff[1] == 1) diff[0] +% Fe.field_order else diff[0]);
}

/// `2 a`: the same limbs as `a.dbl()`.
pub inline fn dbl(a: Fe) Fe {
    return add(a, a);
}

/// `-a`: the same limbs as `a.neg()` (zero stays zero).
pub inline fn neg(a: Fe) Fe {
    return sub(Fe.zero, a);
}

/// std's limbs are least significant first, so they are a native u256 on little-endian hosts.
const little_endian = builtin.cpu.arch.endian() == .little;

inline fn wide(a: Fe) u256 {
    return @bitCast(a.limbs);
}

inline fn narrow(value: u256) Fe {
    assert(value < Fe.field_order);
    return .{ .limbs = @bitCast(value) };
}

/// The six accumulator registers; round `i` treats `accumulator[(i + k) % 6]` as limb `k`, so
/// dropping the reduced low limb renames registers instead of moving them.
const accumulator = [6][]const u8{ "%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13" };

fn limb(comptime round: usize, comptime k: usize) []const u8 {
    comptime assert(k < 6);
    return accumulator[(round + k) % 6];
}

const mul_text = product(0) ++ reduce(0) ++ product(1) ++ reduce(1) ++
    product(2) ++ reduce(2) ++ product(3) ++ reduce(3) ++ subtract_modulus(4);

/// Limbs 0 to 5 += `a b[round]`; limb 5 starts at zero. `r14` holds zero for the carries.
fn product(comptime round: usize) []const u8 {
    const b = std.fmt.comptimePrint("{d}(%[b])", .{round * 8});
    if (round == 0) return "movq " ++ b ++ ", %%rdx\n" ++
        "mulxq 0(%[a]), " ++ limb(0, 0) ++ ", " ++ limb(0, 1) ++ "\n" ++
        "mulxq 8(%[a]), %%rax, " ++ limb(0, 2) ++ "\n" ++
        "mulxq 16(%[a]), %%rcx, " ++ limb(0, 3) ++ "\n" ++
        "addq %%rax, " ++ limb(0, 1) ++ "\n" ++
        "mulxq 24(%[a]), %%rax, " ++ limb(0, 4) ++ "\n" ++
        "adcq %%rcx, " ++ limb(0, 2) ++ "\n" ++
        "adcq %%rax, " ++ limb(0, 3) ++ "\n" ++
        "adcq $0, " ++ limb(0, 4) ++ "\n" ++
        "xorl %%r14d, %%r14d\n" ++
        "movq %%r14, " ++ limb(0, 5) ++ "\n";
    var text: []const u8 = "movq " ++ b ++ ", %%rdx\n" ++
        "xorl %%r14d, %%r14d\n" ++
        "movq %%r14, " ++ limb(round, 5) ++ "\n";
    for (0..4) |k| {
        text = text ++ std.fmt.comptimePrint("mulxq {d}(%[a]), %%rax, %%rcx\n", .{k * 8}) ++
            "adcxq %%rax, " ++ limb(round, k) ++ "\n" ++
            "adoxq %%rcx, " ++ limb(round, k + 1) ++ "\n";
    }
    return text ++ "adcxq %%r14, " ++ limb(round, 4) ++ "\n" ++
        "adoxq %%r14, " ++ limb(round, 5) ++ "\n" ++
        "adcxq %%r14, " ++ limb(round, 5) ++ "\n";
}

/// Limbs += `m p` for `m` = limb 0, which zeroes limb 0: `m (p mod 2^128) + m = m 2^96`
/// lands on limbs 1 and 2, and `m p_3` on limbs 3 and 4.
fn reduce(comptime round: usize) []const u8 {
    const m = limb(round, 0);
    return "movabsq $0xffffffff00000001, %%rdx\n" ++
        "mulxq " ++ m ++ ", %%rax, %%rcx\n" ++
        "movq " ++ m ++ ", %%r14\n" ++
        "shlq $32, %%r14\n" ++
        "movq " ++ m ++ ", %%rdx\n" ++
        "shrq $32, %%rdx\n" ++
        "addq %%r14, " ++ limb(round, 1) ++ "\n" ++
        "adcq %%rdx, " ++ limb(round, 2) ++ "\n" ++
        "adcq %%rax, " ++ limb(round, 3) ++ "\n" ++
        "adcq %%rcx, " ++ limb(round, 4) ++ "\n" ++
        "adcq $0, " ++ limb(round, 5) ++ "\n";
}

/// Stores limbs 0 to 3 less `p` when limbs 0 to 4 (below `2 p`) are at least `p`. Limb 5 is
/// free by now and holds the top difference.
fn subtract_modulus(comptime round: usize) []const u8 {
    const top = limb(round, 5);
    return "movq " ++ limb(round, 0) ++ ", %%rax\n" ++
        "movq " ++ limb(round, 1) ++ ", %%rcx\n" ++
        "movq " ++ limb(round, 2) ++ ", %%r14\n" ++
        "movq " ++ limb(round, 3) ++ ", " ++ top ++ "\n" ++
        "movl $0xffffffff, %%edx\n" ++
        "subq $-1, %%rax\n" ++
        "sbbq %%rdx, %%rcx\n" ++
        "movabsq $0xffffffff00000001, %%rdx\n" ++
        "sbbq $0, %%r14\n" ++
        "sbbq %%rdx, " ++ top ++ "\n" ++
        "sbbq $0, " ++ limb(round, 4) ++ "\n" ++
        "cmovcq " ++ limb(round, 0) ++ ", %%rax\n" ++
        "cmovcq " ++ limb(round, 1) ++ ", %%rcx\n" ++
        "cmovcq " ++ limb(round, 2) ++ ", %%r14\n" ++
        "cmovcq " ++ limb(round, 3) ++ ", " ++ top ++ "\n";
}

const testing = std.testing;

fn field_element(value: u256) !Fe {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return Fe.fromBytes(bytes, .big);
}

test "secp256r1 field arithmetic equals std's at the edges" {
    const p: u256 = Fe.field_order;
    const values = [_]u256{
        0, 1, 2, p - 1, p - 2, p >> 1, 1 << 255, 0xffffffff, 1 << 224, p - (1 << 64), 1 << 96,
    };
    for (values) |x| {
        const a = try field_element(x);
        try testing.expectEqualSlices(u64, &a.sq().limbs, &sq(a).limbs);
        try testing.expectEqualSlices(u64, &a.dbl().limbs, &dbl(a).limbs);
        try testing.expectEqualSlices(u64, &a.neg().limbs, &neg(a).limbs);
        for (values) |y| {
            const b = try field_element(y);
            try testing.expectEqualSlices(u64, &a.mul(b).limbs, &mul(a, b).limbs);
            try testing.expectEqualSlices(u64, &a.add(b).limbs, &add(a, b).limbs);
            try testing.expectEqualSlices(u64, &a.sub(b).limbs, &sub(a, b).limbs);
        }
    }
}

test "secp256r1 field arithmetic equals std's on random elements" {
    var rng = std.Random.DefaultPrng.init(0x256);
    for (0..20_000) |_| {
        const a = try field_element(rng.random().int(u256) % Fe.field_order);
        const b = try field_element(rng.random().int(u256) % Fe.field_order);
        try testing.expectEqualSlices(u64, &a.mul(b).limbs, &mul(a, b).limbs);
        try testing.expectEqualSlices(u64, &a.add(b).limbs, &add(a, b).limbs);
        try testing.expectEqualSlices(u64, &a.sub(b).limbs, &sub(a, b).limbs);
    }
}
