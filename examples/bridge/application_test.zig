//! The bridge application against an in-process indexer (the indexer's store): proposals
//! reach the indexer before consensus, verification accepts only blocks the indexer holds
//! that carry random data or the other network's finalization, and finalizations are posted.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const types = @import("types.zig");
const store_mod = @import("store.zig");
const store_test = @import("store_test.zig");
const application = @import("application.zig");

const Store = store_mod.Store;
const traces = zigware.runtime.telemetry.traces;

/// The indexer as a direct call into its store.
const Local = struct {
    store: *Store,

    pub fn request(self: *Local, io: Io, inbound: types.Inbound) Io.Cancelable!types.Outbound {
        _ = io;
        var rng = zigware.utils.rng.test_rng();
        return self.store.handle(testing.allocator, &rng, inbound) catch @panic("out of memory");
    }
};

const App = application.Application(Local);

const Bridge = struct {
    one: store_test.Fixture,
    two: store_test.Fixture,
    store: Store,
    local: Local,
    collector: traces.Collector,

    /// Two networks of 4 and an indexer serving both. Must not move after `init`.
    fn init(bridge: *Bridge) !void {
        const gpa = testing.allocator;
        bridge.one = try store_test.network_fixture(gpa, 1, 4);
        errdefer bridge.one.deinit(gpa);
        bridge.two = try store_test.network_fixture(gpa, 2, 4);
        errdefer bridge.two.deinit(gpa);
        const publics = [_]types.Public{ bridge.public(1), bridge.public(2) };
        bridge.store = try .init(gpa, &publics, .none);
        bridge.local = .{ .store = &bridge.store };
        bridge.collector = .init(gpa, .{});
    }

    fn deinit(bridge: *Bridge) void {
        const gpa = testing.allocator;
        bridge.collector.deinit();
        bridge.store.deinit(gpa);
        bridge.two.deinit(gpa);
        bridge.one.deinit(gpa);
    }

    fn public(bridge: *const Bridge, network: u8) types.Public {
        return switch (network) {
            1 => bridge.one.verifier.identity(),
            2 => bridge.two.verifier.identity(),
            else => unreachable,
        };
    }

    /// The application of network `network` (1 or 2).
    fn app(bridge: *Bridge, network: u8) !App {
        const other = if (network == 1) &bridge.two.verifier else &bridge.one.verifier;
        const tracer = bridge.collector.tracer(application.target);
        const identity = bridge.public(network);
        return .init(testing.allocator, testing.io, &bridge.local, identity, other, tracer, 8);
    }
};

fn context(view: u64) App.Context {
    const leader = zigware.cryptography.ed25519.PrivateKey.from_seed(1).public_key();
    return .{
        .round = .new(.new(0), .new(view)),
        .leader = leader,
        .parent = .{ .new(view - 1), application.genesis() },
    };
}

fn block_of(bridge: *Bridge, network: u8, digest: lib.Digest) ?types.BlockFormat {
    var rng = zigware.utils.rng.test_rng();
    const get: types.Inbound = .{
        .get_block = .{ .network = bridge.public(network), .digest = digest },
    };
    const response = bridge.store.handle(testing.allocator, &rng, get) catch unreachable;
    return switch (response) {
        .block => |block| block,
        else => null,
    };
}

test "bridge: genesis is the hash of commonware's genesis message" {
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&application.genesis().bytes});
    const expected = "f0dc29ffb8d66b4c8d3b74a77b070c5006a46ff2b7e36e848acf2c4fc232a037";
    try testing.expectEqualStrings(expected, &hex);
}

test "bridge: proposals are published before consensus sees them and verify" {
    var bridge: Bridge = undefined;
    try bridge.init();
    defer bridge.deinit();
    var one = try bridge.app(1);
    defer one.deinit();
    const io = testing.io;

    // With no finalization of network 2 yet, a coin asking for one proposes nothing.
    var proposed: u32 = 0;
    var skipped: u32 = 0;
    for (1..65) |view| {
        const digest = (try one.propose(io, context(view))) orelse {
            skipped += 1;
            continue;
        };
        proposed += 1;
        const block = block_of(&bridge, 1, digest).?;
        try testing.expect(block == .random);
        try testing.expect(store_mod.block_digest(block).eql(digest));
        try testing.expectEqual(true, try one.verify(io, context(view), digest));
    }
    try testing.expect(proposed > 0 and skipped > 0);
    try bridge.collector.get_by_level(.debug).expect_message_exact("no finalization found");
    try bridge.collector.get_by_level(.info).expect_message_exact("proposed");

    // A digest the indexer does not hold, or holds for the other network, is rejected.
    try testing.expectEqual(false, try one.verify(io, context(1), .fill(1)));
    try bridge.collector.get_by_level(.debug).expect_message_exact("block not found");
}

test "bridge: finalizations cross from one network into the other's blocks" {
    var bridge: Bridge = undefined;
    try bridge.init();
    defer bridge.deinit();
    const gpa = testing.allocator;
    const io = testing.io;
    var one = try bridge.app(1);
    defer one.deinit();
    var two = try bridge.app(2);
    defer two.deinit();

    // Network 2 finalizes and posts the finalization.
    const finalization = try store_test.finalize(gpa, &bridge.two, 3, .fill(3));
    try testing.expectEqual(.ok, two.report(.{ .finalization = finalization }));
    two.close();
    try two.run(io);
    try bridge.collector.get_by_level(.debug).expect_message_exact("finalization posted");

    // Network 1 proposes it once its coin asks for a finalization.
    var bridged: ?lib.Digest = null;
    for (1..65) |view| {
        const digest = (try one.propose(io, context(view))).?;
        if (block_of(&bridge, 1, digest).? == .bridge) {
            bridged = digest;
            break;
        }
    }
    const block = block_of(&bridge, 1, bridged.?).?;
    try testing.expect(block.bridge.eql(finalization));
    try testing.expectEqual(true, try one.verify(io, context(70), bridged.?));

    // A block carrying network 1's own finalization does not verify as network 2's.
    var rng = zigware.utils.rng.test_rng();
    const own = try store_test.finalize(gpa, &bridge.one, 4, .fill(4));
    const put: types.Inbound = .{
        .put_block = .{ .network = bridge.public(1), .block = .{ .bridge = own } },
    };
    try testing.expect((try bridge.store.handle(gpa, &rng, put)).success);
    const digest = store_mod.block_digest(.{ .bridge = own });
    try testing.expectEqual(false, try one.verify(io, context(71), digest));
}

test "bridge: blocks print as Rust's Debug" {
    var buffer: [512]u8 = undefined;
    const random = try std.fmt.bufPrint(&buffer, "{f}", .{application.Debug{
        .block = .{ .random = 12345678901234567890 },
    }});
    try testing.expectEqualStrings("Random(12345678901234567890)", random);
    const round: zigware.consensus.types.Round = .new(.new(333), .new(12345));
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{application.RoundDebug{ .round = round }});
    try testing.expectEqualStrings("Round { epoch: Epoch(333), view: View(12345) }", text);
}
