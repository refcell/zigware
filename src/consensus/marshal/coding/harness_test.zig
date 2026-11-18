//! Checks of the coding harness's blocks.

const std = @import("std");
const testing = std.testing;
const harness = @import("harness.zig");
const types = @import("types.zig");
const core_variant = @import("../core/variant.zig");

const gpa = testing.allocator;
const H = harness.CodingHarness;

comptime {
    core_variant.assert_variant(H.Variant);
    core_variant.assert_buffer(H.Buffer);
}

test "coding harness genesis commits to its block under the genesis config" {
    var genesis = try H.genesis_block(gpa, 4);
    defer genesis.deinit(gpa);
    const value = H.commitment(&genesis);
    try testing.expect(value.block().eql(H.digest(&genesis)));
    try testing.expect(value.root().eql(H.digest(&genesis)));
    try testing.expect(value.config().eql(harness.genesis_coding_config));
    const context_digest = try types.hash_context(harness.Sha256, gpa, genesis.context());
    try testing.expect(value.context().eql(context_digest));
    try testing.expectEqual(0, H.height(&genesis).get());
}

test "coding harness test blocks chain over their parents' commitments" {
    var genesis = try H.genesis_block(gpa, 4);
    defer genesis.deinit(gpa);
    const parent = H.commitment(&genesis);
    var block = try H.make_test_block(gpa, H.digest(&genesis), parent, .new(1), 7, 4);
    defer block.deinit(gpa);
    try testing.expectEqual(1, H.height(&block).get());
    try testing.expect(block.parent().eql(H.digest(&genesis)));
    try testing.expect(block.context().parent[1].eql(parent));
    try testing.expectEqual(0, block.context().parent[0].get());
    const config = types.coding_config_for_participants(4);
    try testing.expect(H.commitment(&block).config().eql(config));
}
