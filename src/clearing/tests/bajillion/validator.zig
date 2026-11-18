//! Checking closes, applying posted closes, and resuming validators (commonware
//! `clearing/tests/bajillion/validator.rs`).

const std = @import("std");
const testing = std.testing;
const m = @import("main.zig");
const d = @import("deployment.zig");
const utils = @import("utils");

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

// A close of epoch 2 settles the request's state for epoch 2, so a close of epoch 3 settling its
// state for epoch 3 too is invalid. Had the close of epoch 2 omitted it, the state for epoch 3
// would settle.
test "validator: request settles at most once" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "settled", 1);
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 100);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer request.deinit(gpa);
    _ = try deployment.operator.accept(&request);
    _ = try deployment.close_and_drop();

    // The state for epoch 3 commits to a previous map the close of epoch 2 did not settle.
    var next: m.Row = .{
        .account = m.account(0),
        .payments = try m.amounts(&.{.{ 1, 10 }}),
        .signature = request.signatures.next,
    };
    defer next.deinit(gpa);
    const operator = m.operator_key();
    const queue = deployment.ledger.queue();
    const forged = try m.forge(&operator, &queue, &.{next}, &.{}, 0, 0);
    const validator = &deployment.validators.items[0];
    try testing.expectError(error.InvalidSignature, validator.verify(forged, &queue));

    // Had the close of epoch 2 omitted the request, validators certify the close of epoch 3
    // carrying its state for epoch 3.
    const omitted = try d.Deployment.init(&env, "omitted", 1);
    defer omitted.deinit();
    try omitted.ledger.deposit(m.account(0), 100);
    _ = try omitted.close_and_drop();
    _ = try omitted.close_and_drop();
    _ = try omitted.operator.accept(&request);
    var closed, _ = try omitted.close();
    defer closed.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), closed.rows.len);
    try testing.expect(closed.rows[0].eql(&next));
    try omitted.check_balances(&.{ .{ 0, 90 }, .{ 1, 10 } });
}

// A restarted validator resumes from the posted summary it persisted whose balances root its
// database holds, along the chain ending at the ledger's last post. A close it attested that
// did not post is off that chain, even when it wrote the same balances. A database that
// applied nothing starts from genesis.
test "validator: validator resumes from its records" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "resume", 1);
    var deployment_live = true;
    defer if (deployment_live) deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 10);

    // The validator attests a candidate for epoch 1 in which alice also pays herself. It writes
    // the same balance as the operator's close, and the operator's close posts.
    const operator = m.operator_key();
    var queue = deployment.ledger.queue();
    var paying = try m.row(1, 0, try m.amounts(&.{.{ 0, 5 }}), &m.Amounts.empty);
    defer paying.deinit(gpa);
    var candidate = try m.forge(&operator, &queue, &.{paying}, &.{}, 1, 0);
    defer candidate.deinit(gpa);
    const attested = try deployment.verify(&candidate);
    const candidate_summary = attested[0].summary;
    d.free_proposals(attested);
    const first = try deployment.close_and_drop();
    try testing.expect(candidate_summary.balances.eql(first.balances));
    try testing.expect(!candidate_summary.eql(first));

    // The close of epoch 2 posts, but the validator stops before applying it.
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 4 }}));
    defer request.deinit(gpa);
    _ = try deployment.operator.accept(&request);
    queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 0, 0);
    defer closed.deinit(gpa);
    const proposals = try deployment.verify(&closed);
    defer d.free_proposals(proposals);
    var certificate = try deployment.certify(proposals);
    defer certificate.deinit(gpa);
    const second = proposals[0].summary;
    try deployment.ledger.post(&deployment.rng, &second, &certificate);
    const posted = deployment.ledger.parent().*;
    var persisted = try deployment.validators.items[0].persisted.clone(gpa);
    defer persisted.deinit(gpa);
    deployment_live = false;
    deployment.deinit();

    // Without its records, the validator cannot tell which close its database applied.
    const empty: d.Persisted = .{};
    try testing.expectError(
        error.InvalidCheckpoint,
        d.open_validator(&env, "resume-0", &empty, &posted),
    );

    // With them, it resumes from the posted close of epoch 1 and replays the close of epoch 2.
    var resumed = try d.open_validator(&env, "resume-0", &persisted, &posted);
    try testing.expect(resumed.summary().eql(first));
    try testing.expectEqual(@as(usize, 1), try resumed.catch_up(&posted));
    try testing.expect(resumed.summary().eql(second));
    try testing.expectEqual(@as(u64, 4), try resumed.balance(&m.account(1)));
    resumed.deinit();
    var restarted = try d.open_validator(&env, "resume-0", &persisted, &posted);
    defer restarted.deinit();
    try testing.expect(restarted.summary().eql(second));
    try testing.expectEqual(@as(usize, 0), try restarted.catch_up(&posted));

    // A database that applied nothing starts from genesis, even after the ledger has posted.
    var fresh = try d.open_validator(&env, "resume-fresh", &empty, &posted);
    defer fresh.deinit();
    try testing.expectEqual(@as(u64, 0), fresh.summary().epoch);
}

// A database that applied an empty close still needs that close's record to resume.
test "validator: validator recovers an empty close" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "empty_close", 1);
    const summary = deployment.close_and_drop() catch |err| {
        deployment.deinit();
        return err;
    };
    var persisted = deployment.validators.items[0].persisted.clone(gpa) catch |err| {
        deployment.deinit();
        return err;
    };
    defer persisted.deinit(gpa);
    deployment.deinit();
    const posted = summary.digest();

    const empty: d.Persisted = .{};
    try testing.expectError(
        error.InvalidCheckpoint,
        d.open_validator(&env, "empty_close-0", &empty, &posted),
    );
    var validator = try d.open_validator(&env, "empty_close-0", &persisted, &posted);
    defer validator.deinit();
    try testing.expect(validator.summary().eql(summary));
    try testing.expectEqual(@as(usize, 0), try validator.catch_up(&posted));
    try testing.expectEqual(@as(u64, 0), try validator.balance(&m.account(0)));
}

/// A deployment with one validator after a funding close: alice then pays bob 4, carol deposits
/// 5, and alice forces out 1, and the ledger posts the close of epoch 2 processing both
/// requests. The validator is taken out of the deployment, with its unapplied proposal.
const Interrupted = struct {
    deployment: *d.Deployment,
    validator: d.TestValidator,
    proposal: d.Proposal,

    fn init(env: *d.Env, name: []const u8) !Interrupted {
        const deployment = try d.Deployment.init(env, name, 1);
        errdefer deployment.deinit();
        try deployment.ledger.deposit(m.account(0), 10);
        _ = try deployment.close_and_drop();
        var alice = try m.sender(0);
        defer alice.deinit();
        var request = try alice.send(2, try m.amounts(&.{.{ 1, 4 }}));
        defer request.deinit(gpa);
        _ = try deployment.operator.accept(&request);
        try deployment.ledger.deposit(m.account(2), 5);
        try deployment.ledger.withdraw(m.account(0), 1);
        const queue = deployment.ledger.queue();
        var closed = try m.close_epoch(&deployment.operator, &queue, 1, 1);
        defer closed.deinit(gpa);
        const proposals = try deployment.verify(&closed);
        defer gpa.free(proposals);
        errdefer proposals[0].deinit(gpa);
        var certificate = try deployment.certify(proposals);
        defer certificate.deinit(gpa);
        const summary = proposals[0].summary;
        try deployment.ledger.post(&deployment.rng, &summary, &certificate);
        try testing.expectEqual(@as(usize, 0), deployment.ledger.queue().deposits.len);
        const validator = deployment.validators.pop().?;
        return .{ .deployment = deployment, .validator = validator, .proposal = proposals[0] };
    }
};

/// Checks that `validator` holds the balances after the close of epoch 2 of `Interrupted`.
fn check_epoch_2(validator: *d.TestValidator) !void {
    for ([_][2]u64{ .{ 0, 5 }, .{ 1, 4 }, .{ 2, 5 } }) |entry| {
        try testing.expectEqual(entry[1], try validator.balance(&m.account(entry[0])));
    }
}

/// One run of `recovers from interrupted apply`: whether the validator resumed behind the
/// posted close.
fn interrupted_apply(seed: u64) !bool {
    var env: d.Env = undefined;
    try env.init(gpa, seed);
    defer env.deinit();
    var run = try Interrupted.init(&env, "interrupted");
    defer run.deployment.deinit();
    defer run.proposal.deinit(gpa);
    var persisted = try run.validator.persisted.clone(gpa);
    defer persisted.deinit(gpa);

    // Storage starts failing to sync while the validator applies the close, so the close may or
    // may not become durable before the crash. The validator is dropped at the crash.
    env.faults.config.sync_rate = utils.Probability.init(1 + seed % 3, 4).?;
    const posted = run.proposal.summary.digest();
    run.validator.apply(&run.proposal, &posted) catch {};
    try env.crash();
    run.validator.deinit();

    // The validator resumes from whichever posted close its database holds and replays the rest.
    const deployment = run.deployment;
    try testing.expect(deployment.ledger.parent().eql(posted));
    var validator = try d.open_validator(&env, "interrupted-0", &persisted, &posted);
    const behind = validator.summary().epoch == 1;
    const replayed = validator.catch_up(&posted) catch |err| {
        validator.deinit();
        return err;
    };
    try deployment.validators.append(gpa, validator);
    const recovered = &deployment.validators.items[0];
    try testing.expectEqual(@as(usize, @intFromBool(behind)), replayed);
    try testing.expect(recovered.summary().digest().eql(posted));
    try check_epoch_2(recovered);

    // After the close of epoch 3 posts, the validator still opens alice's payment to bob in
    // epoch 2 under the root the ledger posted.
    _ = try deployment.close_and_drop();
    var opening = (try recovered.open(2, &m.account(0), &m.account(1))).?;
    defer opening.deinit(gpa);
    const root = deployment.ledger.matrix(2).?;
    const paid = try opening.verify(m.Sha256, root, &m.account(0), &m.account(1));
    try testing.expectEqual(@as(u64, 4), paid);
    return behind;
}

// A validator that crashes while applying a posted close recovers from its records and the
// ledger's final state alone. The ledger has drained the deposit the close processed, so the
// validator replays the close from the prefix it persisted. After a later post, it still serves
// openings of the recovered close.
test "validator: validator recovers from interrupted apply" {
    var resumed = [2]bool{ false, false };
    for (0..8) |seed| {
        const behind = try interrupted_apply(seed);
        resumed[@intFromBool(behind)] = true;
    }
    // The crashes left some databases before the close and others after it.
    try testing.expect(resumed[0] and resumed[1]);
}

// Once the validator applies a posted close, the close survives a crash, and the validator
// resumes from it with nothing to replay.
test "validator: applied close is durable" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    var run = try Interrupted.init(&env, "durable");
    defer run.deployment.deinit();
    defer run.proposal.deinit(gpa);
    const posted = run.proposal.summary.digest();
    run.validator.apply(&run.proposal, &posted) catch |err| {
        run.validator.deinit();
        return err;
    };
    var persisted = run.validator.persisted.clone(gpa) catch |err| {
        run.validator.deinit();
        return err;
    };
    defer persisted.deinit(gpa);
    try env.crash();
    run.validator.deinit();

    var validator = try d.open_validator(&env, "durable-0", &persisted, &posted);
    defer validator.deinit();
    try testing.expect(validator.summary().digest().eql(posted));
    try testing.expectEqual(@as(usize, 0), try validator.catch_up(&posted));
    try check_epoch_2(&validator);
}

// A validator that persisted a close and stopped before its attestation was released derives
// the same proposal when asked for the close again after a restart, so the committee's
// certificate is the same, and its records are unchanged.
test "validator: validator attests the same close again after a restart" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    const deployment = try d.Deployment.init(&env, "again", 1);
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 10);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 4 }}));
    defer request.deinit(gpa);
    _ = try deployment.operator.accept(&request);
    try deployment.ledger.withdraw(m.account(0), 1);
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 0, 1);
    defer closed.deinit(gpa);

    // The validator persists the close, and stops before the certificate is assembled.
    const proposals = try deployment.verify(&closed);
    var certificate = deployment.certify(proposals) catch |err| {
        d.free_proposals(proposals);
        return err;
    };
    defer certificate.deinit(gpa);
    const summary = proposals[0].summary;
    d.free_proposals(proposals);
    var persisted = try deployment.validators.items[0].persisted.clone(gpa);
    defer persisted.deinit(gpa);
    const posted = deployment.ledger.parent().*;
    var stopped = deployment.validators.pop().?;
    stopped.deinit();

    // Asked again, the restarted validator proposes the same summary from a fresh check, so its
    // attestation certifies the same summary, and its records are unchanged.
    var restarted = try d.open_validator(&env, "again-0", &persisted, &posted);
    defer restarted.deinit();
    var again = try restarted.verify(try closed.clone(gpa), &queue);
    defer again.deinit(gpa);
    try testing.expect(again.summary.eql(summary));
    var recertified = try d.certify_all(deployment.fixture.schemes, &again.summary);
    defer recertified.deinit(gpa);
    try testing.expect(try d.certificates_equal(&recertified, &certificate));
    try testing.expect(restarted.persisted.eql(&persisted));

    // The post then applies at the restarted validator as it would have before the stop.
    try deployment.ledger.post(&deployment.rng, &summary, &certificate);
    try restarted.apply(&again, &summary.digest());
    try testing.expect(restarted.summary().eql(summary));
    try testing.expectEqual(@as(u64, 4), try restarted.balance(&m.account(1)));
    try testing.expectEqual(@as(u64, 5), try restarted.balance(&m.account(0)));
}

// Apply makes the payout log durable before the balances change, so a validator whose log is
// behind its balances at a restart has lost part of its storage, and it refuses to resume.
test "validator: validator refuses a log behind its balances" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    var run = try Interrupted.init(&env, "behind");
    defer run.deployment.deinit();
    defer run.proposal.deinit(gpa);
    const posted = run.proposal.summary.digest();
    var persisted: d.Persisted = .{};
    defer persisted.deinit(gpa);
    {
        defer run.validator.deinit();
        const first = run.validator.summary().*;
        try run.validator.apply(&run.proposal, &posted);
        persisted = try run.validator.persisted.clone(gpa);
        try testing.expect(run.deployment.ledger.parent().eql(posted));

        // The log loses the close of epoch 2, while the balances keep it.
        const truncated = try run.validator.reopen_log(first.payouts.size);
        try testing.expect(truncated.root().eql(first.payouts.root));
    }
    try testing.expectError(
        error.InvalidCheckpoint,
        d.open_validator(&env, "behind-0", &persisted, &posted),
    );
}

// A validator that crashes after its payout log commits a posted close, but before its balances
// apply it, restarts with the log one close ahead. It reopens the log at the payouts size its
// balances' close certifies, replays the close, and proves the payout the close owes.
test "validator: validator realigns its payout log after a crash" {
    var env: d.Env = undefined;
    try env.init(gpa, 0);
    defer env.deinit();
    var run = try Interrupted.init(&env, "realign");
    defer run.deployment.deinit();
    defer run.proposal.deinit(gpa);
    var persisted = try run.validator.persisted.clone(gpa);
    defer persisted.deinit(gpa);
    const first = run.validator.summary().*;
    const second = run.proposal.summary;

    // The crash leaves the log at the close of epoch 2 and the balances at the close of epoch 1.
    {
        defer run.validator.deinit();
        const log = try run.validator.reopen_log(null);
        const batch = try d.TestValidator.Log.Value.stage(log, &run.proposal.payouts);
        defer batch.release();
        try log.apply_batch(batch);
        try log.commit();
        try testing.expect(log.root().eql(second.payouts.root));
    }

    // The restart resumes from epoch 1, replays epoch 2, and proves alice's payout of 1.
    const deployment = run.deployment;
    const posted = deployment.ledger.parent().*;
    var validator = try d.open_validator(&env, "realign-0", &persisted, &posted);
    defer validator.deinit();
    try testing.expect(validator.summary().eql(first));
    try testing.expectEqual(@as(usize, 1), try validator.catch_up(&posted));
    try testing.expect(validator.summary().eql(second));
    try check_epoch_2(&validator);
    var proof = (try validator.prove_payout(2, &m.account(0))).?;
    defer proof.deinit(gpa);
    const account, const amount = try deployment.ledger.withdraw_payout(second.epoch, &proof);
    try testing.expect(account.eql(m.account(0)));
    try testing.expectEqual(@as(u64, 1), amount);
}
