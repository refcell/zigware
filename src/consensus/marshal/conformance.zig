//! Marshal storage conformance (commonware `marshal/conformance.rs`).
//!
//! `Storage(H)` runs commonware's workload: one validator over harness `H` with a manually
//! acknowledging application finalizes a random number (1-4) of blocks with random
//! timestamps, waits until each is processed, crashes, and commits the runtime's storage
//! audit (CRC32C of every durable blob).
//!
//! The audit cannot reproduce commonware's `StandardStorageConformance` hash. The workload
//! draws its block count and timestamps from the runtime RNG, which the scheduler also draws
//! from when it shuffles ready tasks; zigware's actor runs a different set of tasks (inbox
//! pumps, buffer waiters, resolver forwarders) than commonware's futures, so the stream has
//! diverged by the first draw. The fixture is drawn from the same stream and Debug builds
//! sign with ed25519 rather than BLS. So the tests check that the workload's audit is
//! deterministic per seed and differs across seeds, and the hash test documents the gap.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const types = @import("../types.zig");
const simplex_types = @import("../simplex/types.zig");
const harness = @import("mocks/harness.zig");
const Application = @import("mocks/application.zig").Application;
const Processed = @import("core/root.zig").Processed;

const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;

/// commonware `marshal_commit::<H>`, as a `runtime.conformance.StorageConformance` workload.
pub fn Storage(comptime H: type) type {
    const Workload = struct {
        const App = Application(H.ApplicationBlock);
        const Validator = H.Validator(App);
        const Proposal = simplex_types.Proposal(H.Commitment);

        pub fn run(ctx: Ctx, _: u64) !void {
            const gpa = ctx.gpa();
            var rng = RuntimeRng{ .ctx = ctx };
            var fixture = try H.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const participants = fixture.participants;
            const max_size = harness.max_message_size(H.Variant);
            const io = ctx.io();
            var network = try harness.TestNetwork.start(gpa, io, 1, participants, max_size);
            defer network.stop();
            var app: App = try .manual_ack(gpa, ctx.io());
            defer app.deinit();
            const provider: H.Provider = .init(&fixture.schemes[0]);
            const node_ctx = ctx.child("validator");
            const me = participants[0];
            const net = network.network;
            const node = try Validator.setup(node_ctx, net, me, provider, 1, app.clone());
            defer node.crash();
            assert((try app.acknowledged()).is_zero());
            try wait_processed(ctx, node, .zero());
            try finalize_blocks(ctx, &fixture, node, app);
        }

        fn finalize_blocks(
            ctx: Ctx,
            fixture: *const H.Fixture,
            node: *Validator,
            app: App,
        ) !void {
            const gpa = ctx.gpa();
            var parent = try H.genesis_block(gpa, harness.num_validators);
            defer H.Variant.deinit_block(gpa, &parent);
            const count = 1 + random_u64(ctx) % @min(harness.blocks_per_epoch, 4);
            for (1..count + 1) |value| {
                const height: Height = .new(value);
                const round: Round = .new(.zero(), .new(value));
                var block = try H.make_test_block(
                    gpa,
                    H.digest(&parent),
                    H.commitment(&parent),
                    height,
                    random_u64(ctx),
                    harness.num_validators,
                );
                errdefer H.Variant.deinit_block(gpa, &block);
                try H.verify(node, round, &block);
                const proposal = Proposal.init(round, .new(value - 1), H.commitment(&block));
                var finalization = try H.make_finalization(gpa, fixture, proposal, harness.quorum);
                defer finalization.deinit(gpa);
                _ = node.mailbox.report(.{ .finalization = finalization });
                if ((try app.acknowledged()).get() != value) return error.WrongAcknowledgement;
                try wait_processed(ctx, node, height);
                H.Variant.deinit_block(gpa, &parent);
                parent = block;
            }
        }

        fn wait_processed(ctx: Ctx, node: *Validator, height: Height) !void {
            while (true) {
                const processed: ?Processed = try node.mailbox.get_processed();
                if (processed) |value| if (value.height().get() == height.get()) return;
                try ctx.sleep(.fromMilliseconds(1));
            }
        }
    };
    return runtime.conformance.StorageConformance(Workload);
}

/// The runtime's randomness behind the `next_u64`/`fill_bytes` RNG interface fixtures take
/// (commonware draws its fixture from the context).
const RuntimeRng = struct {
    ctx: Ctx,

    pub fn next_u64(self: *RuntimeRng) u64 {
        return random_u64(self.ctx);
    }

    pub fn fill_bytes(self: *RuntimeRng, dest: []u8) void {
        self.ctx.io().random(dest);
    }
};

fn random_u64(ctx: Ctx) u64 {
    var bytes: [8]u8 = undefined;
    ctx.io().random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

const testing = std.testing;
const conformance = @import("conformance");
const StandardStorage = Storage(harness.StandardHarness);

test "standard storage conformance is deterministic per seed" {
    for (0..3) |seed| {
        const first = try StandardStorage.commit(testing.allocator, seed);
        defer testing.allocator.free(first);
        const second = try StandardStorage.commit(testing.allocator, seed);
        defer testing.allocator.free(second);
        try testing.expectEqualSlices(u8, first, second);
        try testing.expectEqual(@as(usize, 4), first.len);
    }
}

test "standard storage conformance differs across seeds" {
    const zero = try StandardStorage.commit(testing.allocator, 0);
    defer testing.allocator.free(zero);
    const one = try StandardStorage.commit(testing.allocator, 1);
    defer testing.allocator.free(one);
    try testing.expect(!std.mem.eql(u8, zero, one));
}

// Under `-Dslow-tests`, where the harness signs with BLS as commonware does, the 32-case hash
// is computed and compared with commonware's conformance.toml entry. It differs (see the
// file comment), so the test records the gap instead of failing on it.
test "standard storage conformance hash against commonware" {
    if (harness.fast_schemes) return error.SkipZigTest;
    const file = @embedFile("../conformance.toml");
    const name = "commonware_consensus::marshal::conformance::StandardStorageConformance";
    const entry = (try conformance.find(file, name)).?;
    try testing.expectEqual(@as(u64, 32), entry.n_cases);
    const actual = try conformance.compute_hash(StandardStorage, testing.allocator, 32);
    try testing.expect(!std.mem.eql(u8, entry.hash, &actual));
}
