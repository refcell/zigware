//! The `zk` fuzz target (commonware `cryptography/fuzz/fuzz_targets/zk.rs`, over
//! `zk::fuzz::Plan`): a bulletproofs plan (inner product or circuit argument), the
//! pedersen_to_plain plan, or the circuit satisfaction plan.

const std = @import("std");
const testing = std.testing;
const math = @import("math");
const minifuzz = @import("invariants").minifuzz;
const ipa = @import("bulletproofs/ipa.zig");
const bp = @import("bulletproofs/circuit.zig");
const ipa_test = @import("bulletproofs/ipa_test.zig");
const circuit_test = @import("bulletproofs/circuit_test.zig");
const pedersen_test = @import("pedersen_to_plain_test.zig");
const zk_circuit_test = @import("circuit_test.zig");

const G = math.testing.G;
const gpa = testing.allocator;

/// The setups the bulletproofs plans share across inputs (commonware's `OnceLock`s).
const Setups = struct {
    ipa: *const ipa.Setup(G),
    circuit: *const bp.Setup(G),
};

fn plan_body(setups: *const Setups, u: *minifuzz.Unstructured) anyerror!void {
    switch (u.int_in_range(u8, 0, 2)) {
        0 => switch (u.int_in_range(u8, 0, 1)) {
            0 => try ipa_test.plan_body(setups.ipa, u),
            else => try circuit_test.plan_body(setups.circuit, u),
        },
        1 => try pedersen_test.plan_body({}, u),
        else => try zk_circuit_test.circuit_plan({}, u),
    }
}

fn with_setups(comptime body: fn (*const Setups) anyerror!void) !void {
    var ipa_setup = try ipa_test.test_setup();
    defer ipa_setup.deinit(gpa);
    var circuit_setup = try circuit_test.test_setup();
    defer circuit_setup.deinit(gpa);
    const setups: Setups = .{ .ipa = &ipa_setup, .circuit = &circuit_setup };
    try body(&setups);
}

test "zk fuzz target (minifuzz)" {
    try with_setups(struct {
        fn run(setups: *const Setups) anyerror!void {
            try (minifuzz.Builder{}).with_search_limit(64).run(gpa, setups, plan_body);
        }
    }.run);
}

test "zk fuzz target (std fuzz)" {
    try with_setups(struct {
        fn run(setups: *const Setups) anyerror!void {
            const body = math.testing.smith_body(*const Setups, plan_body);
            try testing.fuzz(setups, body, .{});
        }
    }.run);
}
