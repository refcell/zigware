//! Tests of the deferred standard wrapper on the full marshal harness (commonware
//! `marshal/standard/deferred.rs` tests that restart a validator).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const mocks = @import("../mocks/root.zig");
const harness = @import("../mocks/harness.zig");
const deferred_mod = @import("deferred.zig");

const H = harness.StandardHarness;
const B = harness.B;
const Ctx = runtime.deterministic.Context;
const App = mocks.Application(B);
const Validator = H.Validator(App);
const Marshal = @FieldType(Validator, "mailbox");
const Stream = @import("../ancestry.zig").AncestorStream(Marshal);
const soak = @import("../mocks/soak.zig");
const Mock = mocks.verifying.MockVerifyingApp(B, Ctx, harness.Ctx, Stream);
const Wrapper = deferred_mod.Deferred(Ctx, harness.S, Mock, B, types.FixedEpocher);
const Round = types.Round;
const gpa = testing.allocator;

fn epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(harness.blocks_per_epoch).?);
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Validator 0 on `network`, under a child of `ctx` named `name`, with a fresh application.
fn start_validator(
    ctx: Ctx,
    network: *harness.TestNetwork,
    validators: *harness.Fixture,
    comptime name: []const u8,
) !*Validator {
    const app = try App.init(gpa, ctx.io());
    const provider: harness.Provider = .init(&validators.schemes[0]);
    const child = ctx.child(name).with_attribute("index", 0);
    const me = validators.participants[0];
    return Validator.setup(child, network.network, me, provider, 1, app);
}

/// Proposes and certifies the child of `parent` at view 2 through a deferred wrapper over
/// `validator`'s marshal; returns the child's digest.
fn propose_and_certify(ctx: Ctx, validator: *Validator, parent: B, me: harness.K) !B.Digest {
    const io = ctx.io();
    const round = round_at(2);
    const context: harness.Ctx = .{
        .round = round,
        .leader = me,
        .parent = .{ .new(1), parent.digest() },
    };
    const child = try B.init(gpa, context, parent.digest(), .new(2), 200);
    const app = Mock.init(gpa).with_propose_result(child);
    const marshal = validator.mailbox.clone();
    const wrapper = try Wrapper.create(ctx.child("deferred"), app, marshal, epocher());
    defer wrapper.destroy();
    // Let detached tasks (a store behind a sent verdict) finish before the wrapper goes.
    defer io.sleep(.fromMilliseconds(100), .awake) catch {};
    const digest = (try wrapper.propose(undefined, context)) orelse return error.NoProposal;
    try testing.expect(digest.eql(child.digest()));
    // The leader certifies its own proposal, which waits on the propose handshake's store.
    try testing.expectEqual(@as(?bool, true), try wrapper.certify(undefined, round, digest));
    return digest;
}

fn propose_then_certify_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var validators = try harness.fixture(gpa, &rng);
    defer validators.deinit(gpa);
    const participants = validators.participants;
    const size = harness.max_message_size(H.Variant);
    var network: harness.TestNetwork = try .start(gpa, ctx.io(), 1, participants, size);
    defer network.stop();
    const me = participants[0];
    const validator = try start_validator(ctx, &network, &validators, "validator");
    var crashed = false;
    defer if (!crashed) validator.crash();
    // Seed the parent at its round so `propose` fetches it locally.
    const genesis = try harness.make_raw_block(gpa, harness.genesis_parent(), .zero(), 0);
    const parent_round = round_at(1);
    const parent_context: harness.Ctx = .{
        .round = parent_round,
        .leader = harness.default_leader(),
        .parent = .{ .zero(), genesis.digest() },
    };
    const parent = try B.init(gpa, parent_context, genesis.digest(), .new(1), 100);
    const seeded = try mocks.ready(B, gpa, parent);
    try testing.expect(try validator.mailbox.verified(parent_round, seeded));
    const digest = try propose_and_certify(ctx, validator, parent, me);
    // The certified block survives an unclean restart.
    validator.crash();
    crashed = true;
    const restarted = try start_validator(ctx, &network, &validators, "validator_restart");
    defer restarted.crash();
    var block = (try restarted.mailbox.get_block(.{ .digest = digest })) orelse
        return error.CertifiedBlockLost;
    block.deinit();
}

test "propose then certify persists the block across a restart" {
    // commonware `test_deferred_propose_then_certify_persists_block`.
    try soak.run(gpa, .{}, propose_then_certify_body, .{});
}
