//! Helpers shared by the BLS12-381 benchmarks.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const utils = @import("utils");

const Mode = cryptography.bls12381.primitives.sharing.Mode;

pub const Message = [32]u8;

/// The cases for this run: the first under `zig build test`, else all of them.
pub fn cases(runner: *const bench.Runner, comptime T: type, all: []const T) []const T {
    assert(all.len > 0);
    return runner.inputs.pick([]const T, all[0..1], all, all);
}

const Unused = struct {
    pub fn iter(_: *Unused) void {}
};

/// Whether to skip building `benchmark`'s inputs: when the filters do not select it, and
/// when listing, which only prints its name (done here).
pub fn skip(runner: *bench.Runner, benchmark: bench.Benchmark) !bool {
    if (!runner.matches(benchmark.name())) return true;
    if (!runner.list) return false;
    var unused: Unused = .{};
    try runner.run(benchmark, &unused);
    return true;
}

pub fn random_messages(gpa: Allocator, rng: *utils.TestRng, count: usize) ![]Message {
    const messages = try gpa.alloc(Message, count);
    for (messages) |*message| rng.fill_bytes(message);
    return messages;
}

/// Fisher-Yates, as rand's `SliceRandom::shuffle`.
pub fn shuffle(comptime T: type, rng: *utils.TestRng, items: []T) void {
    var index = items.len;
    while (index > 1) {
        index -= 1;
        const other = utils.rng.range_at_most(rng, usize, 0, index);
        std.mem.swap(T, &items[index], &items[other]);
    }
}

/// commonware's `{mode:?}`.
pub fn mode_name(mode: Mode) []const u8 {
    return switch (mode) {
        .non_zero_counter => "NonZeroCounter",
        .roots_of_unity => "RootsOfUnity",
    };
}
