//! Checking closes, applying posted closes, and resuming validators (commonware
//! `clearing/tests/bajillion/validator.rs`).

const std = @import("std");
const testing = std.testing;
const m = @import("main.zig");
const d = @import("deployment.zig");

const gpa = m.gpa;

// Validators agree on every close, and each holds the operator's balances and proves them.
test "validator: validators agree on closes" {
    var env = try d.Env.init(gpa);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "agree", 4);
    defer deployment.deinit();

    // The funding close processes both deposits.
    try deployment.ledger.deposit(m.account(0), 100);
    try deployment.ledger.deposit(m.account(1), 50);
    const first = try deployment.close_and_drop();
    try testing.expectEqual(@as(u64, 1), first.epoch);
    try testing.expectEqual(@as(u64, 2), first.deposits.count);

    // Alice pays bob 30 and carol 20, and the close of epoch 2 follows the first and commits
    // to its matrix.
    var alice = try m.sender(0);
    defer alice.deinit();
    _ = try m.pay(&alice, &deployment.operator, 2, &.{ .{ 1, 30 }, .{ 2, 20 } });
    var close, const second = try deployment.close();
    defer close.deinit(gpa);
    try testing.expect(second.parent.eql(first.digest()));
    try testing.expect(deployment.ledger.parent().eql(second.digest()));

    // Every validator holds the operator's view of the balances and can prove it.
    for (deployment.validators.items) |*validator| {
        try testing.expect(validator.summary().eql(second));
        for ([_][2]u64{ .{ 0, 50 }, .{ 1, 80 }, .{ 2, 20 }, .{ 3, 0 } }) |entry| {
            const account = m.account(entry[0]);
            try testing.expectEqual(entry[1], try validator.balance(&account));
            try testing.expectEqual(entry[1], deployment.operator.balance(&account));
            var proof = (try validator.prove(&account)) orelse {
                try testing.expectEqual(@as(u64, 0), entry[1]);
                continue;
            };
            defer proof.deinit(gpa);
            try testing.expectEqual(entry[1], proof.balance);
            try testing.expect(proof.verify(m.Sha256, m.PublicKey, &second.balances, account));
            const other = m.account(3);
            try testing.expect(!proof.verify(m.Sha256, m.PublicKey, &second.balances, other));
            try testing.expect(!proof.verify(m.Sha256, m.PublicKey, &first.balances, account));
        }
    }
}
