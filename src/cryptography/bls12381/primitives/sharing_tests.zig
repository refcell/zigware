//! Tests for `sharing.zig` (commonware `primitives::sharing` tests).

const std = @import("std");
const testing = std.testing;
const build_options = @import("build_options");
const codec = @import("codec");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const group = @import("group.zig");
const variant = @import("variant.zig");
const sharing = @import("sharing.zig");

const Participant = utils.Participant;
const Scalar = group.Scalar;
const Mode = sharing.Mode;
const Poly = sharing.Poly;
const Sharing = sharing.Sharing;
const MinSig = variant.MinSig;
const gpa = testing.allocator;

test "sharing: roots-of-unity interpolator rejects a domain above u32" {
    const indices = [_]Participant{Participant.init(0)};
    const result = Mode.roots_of_unity.interpolator(gpa, std.math.maxInt(u32), &indices);
    try testing.expectError(error.InvalidIndex, result);
}

test "sharing: mode read rejects a mode above the supported version" {
    try testing.expectError(error.Invalid, codec.decode_cfg(Mode, gpa, &.{1}, .v0));
    try testing.expectEqual(Mode.roots_of_unity, try codec.decode_cfg(Mode, gpa, &.{1}, .v1));
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(Mode, gpa, &.{2}, .v1));
}

fn all_scalars_matches_scalar(_: void, u: *minifuzz.Unstructured) !void {
    const mode = try u.arbitrary(Mode);
    const total = u.int_in_range(u32, 1, 512);
    const index = Participant.init(u.int_in_range(u32, 0, total - 1));
    const scalars = try mode.all_scalars(gpa, total);
    defer gpa.free(scalars);
    try testing.expect(scalars[index.get()].eql(mode.scalar(total, index).?));
}

test "sharing: all_scalars matches scalar" {
    try minifuzz.run(gpa, {}, all_scalars_matches_scalar);
}

test "sharing: required uses the exact degree" {
    var seeded = utils.rng.TestRng.init(0);
    var polynomial = try Poly(Scalar).random(gpa, &seeded, 2);
    defer polynomial.deinit(gpa);
    // Subtraction keeps the three coefficient slots while zeroing every coefficient.
    var padded_zero = try polynomial.clone(gpa);
    defer padded_zero.deinit(gpa);
    try padded_zero.sub_assign(gpa, polynomial);
    try testing.expectEqual(@as(u32, 3), padded_zero.required());

    const committed = try @import("math").poly.commit(gpa, MinSig.Public, padded_zero);
    var shared = try Sharing(MinSig).init(gpa, .non_zero_counter, 4, committed);
    defer shared.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), shared.required());
}

fn subset_interpolation_recovers_constant(_: void, u: *minifuzz.Unstructured) !void {
    const mode = try u.arbitrary(Mode);
    const total = u.int_in_range(u32, 1, 64);
    var subset_buffer: [64]Participant = undefined;
    var subset_len: usize = 0;
    for (0..total) |i| {
        if (try u.arbitrary(bool)) {
            subset_buffer[subset_len] = Participant.from_usize(i);
            subset_len += 1;
        }
    }
    if (subset_len == 0) {
        subset_buffer[0] = Participant.init(u.int_in_range(u32, 0, total - 1));
        subset_len = 1;
    }
    const subset = subset_buffer[0..subset_len];
    const degree = u.int_in_range(u32, 0, @intCast(subset_len - 1));
    const seed = try u.arbitrary(u64);
    var seeded = utils.rng.TestRng.init(seed);
    var poly = try Poly(Scalar).random(gpa, &seeded, degree);
    defer poly.deinit(gpa);

    var evals: [64]Scalar = undefined;
    for (evals[0..subset_len], subset) |*eval, participant| {
        eval.* = poly.eval(Scalar, mode.scalar(total, participant).?);
    }
    var interpolator = try mode.interpolator(gpa, total, subset);
    defer interpolator.deinit(gpa);
    const recovered = interpolator.interpolate(Scalar, subset, evals[0..subset_len]).?;
    try testing.expect(recovered.eql(poly.constant()));
}

test "sharing: subset interpolation recovers the constant" {
    try (minifuzz.Builder{}).with_search_limit(200 * build_options.fuzz_soak)
        .run(gpa, {}, subset_interpolation_recovers_constant);
}

test "sharing: subset interpolator maps positions in the set" {
    const set = [_]u32{ 10, 20, 30, 40 };
    const subset = [_]u32{ 20, 40 };
    var seeded = utils.rng.TestRng.init(7);
    var poly = try Poly(Scalar).random(gpa, &seeded, 1);
    defer poly.deinit(gpa);
    inline for (.{ Mode.non_zero_counter, Mode.roots_of_unity }) |mode| {
        var interpolator = (try mode.subset_interpolator(u32, gpa, &set, &subset)).?;
        defer interpolator.deinit(gpa);
        const evals = [_]Scalar{
            poly.eval(Scalar, mode.scalar(4, Participant.init(1)).?),
            poly.eval(Scalar, mode.scalar(4, Participant.init(3)).?),
        };
        const recovered = interpolator.interpolate(Scalar, &subset, &evals).?;
        try testing.expect(recovered.eql(poly.constant()));
        try testing.expect((try mode.subset_interpolator(u32, gpa, &set, &.{15})) == null);
    }
}

test "sharing: codec round trip and partial publics" {
    var rng = utils.test_rng();
    var poly = try Poly(Scalar).random(gpa, &rng, 2);
    defer poly.deinit(gpa);
    const committed = try @import("math").poly.commit(gpa, MinSig.Public, poly);
    var shared = try Sharing(MinSig).init(gpa, .roots_of_unity, 5, committed);
    defer shared.deinit(gpa);

    const bytes = try codec.encode(Sharing(MinSig), gpa, shared);
    defer gpa.free(bytes);
    try testing.expectEqual(shared.encode_size(), bytes.len);
    try testing.expect(bytes.len <= Sharing(MinSig).max_encode_size_with(5));
    const cfg: Sharing(MinSig).Cfg = .{ .max_participants = 5, .max_supported_mode = .v1 };
    var decoded = try codec.decode_cfg(Sharing(MinSig), gpa, bytes, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(shared));

    const v0: Sharing(MinSig).Cfg = .{ .max_participants = 5, .max_supported_mode = .v0 };
    try testing.expectError(error.Invalid, codec.decode_cfg(Sharing(MinSig), gpa, bytes, v0));
    const small: Sharing(MinSig).Cfg = .{ .max_participants = 4, .max_supported_mode = .v1 };
    try testing.expectError(error.Invalid, codec.decode_cfg(Sharing(MinSig), gpa, bytes, small));

    for (0..5) |i| {
        const participant = Participant.from_usize(i);
        const point = shared.scalar(participant).?;
        const expected = MinSig.Public.generator.mul(poly.eval(Scalar, point));
        try testing.expect((try shared.partial_public(participant)).eql(expected));
    }
    try testing.expectError(error.InvalidIndex, shared.partial_public(Participant.init(5)));
}
