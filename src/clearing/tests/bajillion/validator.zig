//! Checking closes, applying posted closes, and resuming validators (commonware
//! `clearing/tests/bajillion/validator.rs`).

const std = @import("std");
const testing = std.testing;
const m = @import("main.zig");
const d = @import("deployment.zig");

const gpa = m.gpa;

// Validators agree on every close, and each holds the operator's balances and proves them.
test "validator: validators agree on closes" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
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

// Forced and soft withdrawals add up and pay out at most the balance, after the epoch's
// payments settle, and the payouts stay owed until withdrawn.
test "validator: withdrawals pay up to the balance" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "withdrawals", 1);
    defer deployment.deinit();
    for (0..3) |index| try deployment.ledger.deposit(m.account(index), 10);
    _ = try deployment.close_and_drop();

    // Forced and soft withdrawals add up, and pay out at most the balance.
    try deployment.ledger.withdraw(m.account(0), 3);
    try deployment.ledger.withdraw(m.account(1), 25);
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    for ([_][3]u64{ .{ 0, 4, 0 }, .{ 0, 4, 1 }, .{ 2, 6, 0 } }) |entry| {
        const signer = m.user(entry[0]);
        const withdrawal = m.Withdrawal.sign(&signer, &ns, 2, entry[1], entry[2]);
        try deployment.operator.withdraw(withdrawal);
        try deployment.operator.withdraw(withdrawal);
    }

    // Payments settle before withdrawals.
    var carol = try m.sender(2);
    defer carol.deinit();
    var request = try carol.send(2, try m.amounts(&.{.{ 1, 5 }}));
    defer request.deinit(gpa);
    _ = try deployment.operator.accept(&request);

    // The close processes both forced withdrawals and all three soft ones, and the payouts
    // stay in custody until withdrawn.
    const custody = deployment.ledger.custody();
    const queue = deployment.ledger.queue();
    var close = try m.close_epoch(&deployment.operator, &queue, 0, 2);
    defer close.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), close.withdrawals.len);
    const proposals = try deployment.verify(&close);
    var payouts = try proposals[0].payouts.clone(gpa);
    defer payouts.deinit(gpa);
    var expected = try m.amounts(&.{ .{ 0, 10 }, .{ 1, 15 }, .{ 2, 5 } });
    defer expected.deinit(gpa);
    try testing.expect(payouts.eql(&expected));
    _ = try deployment.post(proposals);
    try testing.expectEqual(custody, deployment.ledger.custody());
    try deployment.withdraw_payouts(2, &payouts);
    try testing.expectEqual(custody - 30, deployment.ledger.custody());

    // The withdrawals empty every balance, and validators keep no record of an empty one.
    const validator = &deployment.validators.items[0];
    for (0..3) |index| {
        const account = m.account(index);
        try testing.expectEqual(@as(u64, 0), try validator.balance(&account));
        try testing.expect(try validator.prove(&account) == null);
        try testing.expectEqual(@as(u64, 0), deployment.operator.balance(&account));
    }
}

// Validators refuse a close that overdrafts an account (O3). Alice's soft withdrawal of epoch
// 2 empties her balance, so no close of epoch 3 holding her payment of 100 is acceptable.
test "validator: validators refuse a close that overdrafts" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "overdraft", 1);
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 100);
    _ = try deployment.close_and_drop();

    // The close of epoch 2 pays alice's whole balance out through a soft withdrawal.
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const alice = m.user(0);
    const withdrawal = m.Withdrawal.sign(&alice, &ns, 2, 100, 0);
    const operator = m.operator_key();
    var queue = deployment.ledger.queue();
    var emptying = try m.forge(&operator, &queue, &.{}, &.{withdrawal}, 0, 0);
    defer emptying.deinit(gpa);
    const proposals = try deployment.verify(&emptying);
    var owed = try m.amounts(&.{.{ 0, 100 }});
    defer owed.deinit(gpa);
    try testing.expect(proposals[0].payouts.eql(&owed));
    _ = try deployment.post(proposals);
    const validator = &deployment.validators.items[0];
    const alice_account = m.account(0);
    try testing.expectEqual(@as(u64, 0), try validator.balance(&alice_account));

    // A close of epoch 3 settling alice's payment of 100 to bob overdrafts her balance, so
    // the validator refuses it and stays at the close of epoch 2.
    var paying = try m.row(3, 0, try m.amounts(&.{.{ 1, 100 }}), &m.Amounts.empty);
    defer paying.deinit(gpa);
    queue = deployment.ledger.queue();
    const overdrafting = try m.forge(&operator, &queue, &.{paying}, &.{}, 0, 0);
    try testing.expectError(error.Overdraft, validator.verify(overdrafting, &queue));
    try testing.expectEqual(@as(u64, 2), validator.summary().epoch);

    // The same validator then settles a close of epoch 3 without her row.
    var affordable = try m.forge(&operator, &queue, &.{}, &.{}, 0, 0);
    defer affordable.deinit(gpa);
    const next = try deployment.verify(&affordable);
    try testing.expectEqual(@as(u64, 3), (try deployment.post(next)).epoch);
}

// A close settles credits and debits whose sums exceed the largest amount, as long as every
// final balance fits.
test "validator: close settles gross flows beyond the largest amount" {
    const max = std.math.maxInt(u64);
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "gross", 1);
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), max);
    _ = try deployment.close_and_drop();

    // Alice pays herself and bob her whole balance each, and bob pays her back from the same
    // epoch's receipt. Her credits and debits each exceed the largest amount, but no balance.
    var rows = [_]m.Row{
        try m.row(2, 0, try m.amounts(&.{ .{ 0, max }, .{ 1, max } }), &m.Amounts.empty),
        try m.row(2, 1, try m.amounts(&.{.{ 0, max }}), &m.Amounts.empty),
    };
    defer for (&rows) |*r| r.deinit(gpa);
    const operator = m.operator_key();
    var queue = deployment.ledger.queue();
    var close = try m.forge(&operator, &queue, &rows, &.{}, 0, 0);
    defer close.deinit(gpa);
    const proposals = try deployment.verify(&close);
    try testing.expect(proposals[0].payouts.is_empty());
    _ = try deployment.post(proposals);
    const validator = &deployment.validators.items[0];
    try testing.expectEqual(@as(u64, max), try validator.balance(&m.account(0)));
    try testing.expectEqual(@as(u64, 0), try validator.balance(&m.account(1)));

    // Withdrawal requests adding up to more than the largest amount pay out the whole balance.
    var forcing = try m.Queues.init(3, &.{}, &.{ .{ 0, max }, .{ 0, max } });
    defer forcing.deinit();
    queue = forcing.queue();
    const draining = try m.forge(&operator, &queue, &.{}, &.{}, 0, 2);
    var proposal = try validator.verify(draining, &queue);
    defer proposal.deinit(gpa);
    var all = try m.amounts(&.{.{ 0, max }});
    defer all.deinit(gpa);
    try testing.expect(proposal.payouts.eql(&all));

    // A balance above the largest amount does not settle.
    var funding = try m.Queues.init(3, &.{.{ 0, 1 }}, &.{});
    defer funding.deinit();
    queue = funding.queue();
    const overflowing = try m.forge(&operator, &queue, &.{}, &.{}, 1, 0);
    try testing.expectError(error.Overflow, validator.verify(overflowing, &queue));
}
