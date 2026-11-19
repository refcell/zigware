//! Smoke tests of the model's World and committee replay.

const std = @import("std");
const m = @import("../main.zig");
const d = @import("../deployment.zig");
const w = @import("world.zig");
const r = @import("replay.zig");

test "model: world clones and fingerprints, replay serves genesis" {
    var accounts: [w.users]m.PublicKey = undefined;
    for (&accounts, 0..) |*a, i| a.* = m.account(i);
    var replays: r.Replays = .{};
    defer replays.deinit();
    const genesis = try replays.get(&accounts, &.{}, null);
    try std.testing.expectEqual(@as(u64, 0), genesis.applied);
    // A second request for the same history is served from the memo.
    try std.testing.expect(genesis == try replays.get(&accounts, &.{}, null));
}

test "model: a cloned world has the same fingerprint until one changes" {
    const gpa = m.gpa;
    const fixture = try d.committee(4);
    defer {
        fixture.deinit(gpa);
        gpa.destroy(fixture);
    }
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const operator = m.operator_key().public_key();
    var validator_env: d.Env = undefined;
    try validator_env.init(gpa, 0);
    defer validator_env.deinit();
    const empty: d.Persisted = .{};
    var v = try d.open_validator(&validator_env, "genesis", &empty, null);
    const balances = v.summary().balances;
    v.deinit();
    var world: w.World = .{
        .ledger = try d.TestLedger.init(gpa, &ns, operator, &fixture.verifier, balances),
        .operator = try m.operator(),
        .senders = .{ try m.sender(0), try m.sender(1) },
        .receivers = .{ try m.receiver(0, 1), try m.receiver(1, 1) },
        .budget = .{ .sends = 1 },
    };
    defer world.deinit(gpa);
    try world.ledger.deposit(m.account(0), 3);
    try world.deposited.append(gpa, .{ 0, 3 });
    var copy = try world.clone();
    defer copy.deinit(gpa);
    try std.testing.expectEqual(world.fingerprint(), copy.fingerprint());
    var request = try copy.senders[0].send(1, try m.amounts(&.{.{ 1, 1 }}));
    defer request.deinit(gpa);
    try std.testing.expect(world.fingerprint() != copy.fingerprint());
    copy.budget.sends -= 1;
    var again = try world.clone();
    defer again.deinit(gpa);
    again.budget.sends -= 1;
    try std.testing.expect(again.fingerprint() != copy.fingerprint());
    try std.testing.expect(again.fingerprint() != world.fingerprint());
}
