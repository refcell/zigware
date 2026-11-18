//! Posting closes, challenging them, withdrawing payouts, and claiming funds after a halt
//! (commonware `clearing/tests/bajillion/ledger.rs`).

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const bajillion = @import("../../bajillion/mod.zig");
const m = @import("main.zig");
const d = @import("deployment.zig");

const gpa = m.gpa;
const max = std.math.maxInt(u64);
const Summary = d.Summary;
const Matrix = bajillion.Matrix(m.PublicKey, m.Sha256, u64);
const Challenge = d.TestLedger.Challenge;
const PayoutProof = d.TestLedger.PayoutProof;
const BalanceProof = d.TestLedger.BalanceProof;

/// A fresh deployment `name` of `n` validators on `env`.
fn deploy(env: *d.Env, name: []const u8, n: u32) !*d.Deployment {
    try env.init(gpa, 0);
    errdefer env.deinit();
    return d.Deployment.init(env, name, n);
}

/// Checks that the ledger refuses to post `summary` under a certificate of `certified`.
fn expect_refused(
    deployment: *d.Deployment,
    summary: *const Summary,
    certified: *const Summary,
    expected: anyerror,
) !void {
    var certificate = try d.certify_all(deployment.fixture.schemes, certified);
    defer certificate.deinit(gpa);
    const posting = deployment.ledger.post(&deployment.rng, summary, &certificate);
    try testing.expectError(expected, posting);
}

/// Verifies `closed` at every validator and posts it.
fn post_close(deployment: *d.Deployment, closed: *const m.TestClose) !Summary {
    return deployment.post(try deployment.verify(closed));
}

/// Closes the operator's epoch processing `deposits` and `forced` queued requests, and posts the
/// close at every validator, keeping its payouts owed.
fn post_epoch(deployment: *d.Deployment, deposits: u64, forced: u64) !Summary {
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, deposits, forced);
    defer closed.deinit(gpa);
    return post_close(deployment, &closed);
}

/// The proof of the payout the close of `epoch` owes user `index`, which it must owe.
fn payout_proof(deployment: *d.Deployment, epoch: m.Epoch, index: u64) !PayoutProof {
    const validator = &deployment.validators.items[0];
    return (try validator.prove_payout(epoch, &m.account(index))) orelse
        error.TestUnexpectedResult;
}

/// Checks that withdrawing `proof` under the posted close of `epoch` pays user `index` `amount`.
fn expect_withdrawn(
    deployment: *d.Deployment,
    epoch: m.Epoch,
    proof: *const PayoutProof,
    index: u64,
    amount: u64,
) !void {
    const account, const paid = try deployment.ledger.withdraw_payout(epoch, proof);
    try testing.expect(account.eql(m.account(index)));
    try testing.expectEqual(amount, paid);
}

// The ledger queues nonzero deposits and forced withdrawals, and never takes custody of more
// than the largest amount.
test "ledger: ledger queues requests" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "queues", 1);
    defer env.deinit();
    defer deployment.deinit();
    const ledger = &deployment.ledger;

    // Zero amounts are refused.
    try testing.expectError(error.ZeroAmount, ledger.deposit(m.account(0), 0));
    try testing.expectError(error.ZeroAmount, ledger.withdraw(m.account(0), 0));

    // The ledger never holds more than the largest amount, so no balance can overflow.
    try ledger.deposit(m.account(0), max - 1);
    try testing.expectError(error.Custody, ledger.deposit(m.account(1), 2));
    try ledger.deposit(m.account(1), 1);
    try ledger.withdraw(m.account(0), 5);
    try testing.expectEqual(@as(u64, max), ledger.custody());

    // Both deposits and the forced withdrawal queue in order for epoch 1, and none is required
    // yet.
    const queue = ledger.queue();
    try testing.expectEqual(@as(m.Epoch, 1), queue.epoch);
    try testing.expectEqual(@as(usize, 2), queue.deposits.len);
    try testing.expect(queue.deposits[0].account.eql(m.account(0)));
    try testing.expectEqual(@as(u64, max - 1), queue.deposits[0].amount);
    try testing.expect(queue.deposits[1].account.eql(m.account(1)));
    try testing.expectEqual(@as(u64, 1), queue.deposits[1].amount);
    try testing.expectEqual(@as(usize, 1), queue.forced_withdrawals.len);
    try testing.expectEqual(@as(usize, 0), queue.required_deposits);
    try testing.expectEqual(@as(usize, 0), queue.required_forced_withdrawals);
}

// A close may defer requests queued while its epoch is open, and the next close must process
// them.
test "ledger: close processes requests queued before its epoch" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "required", 1);
    defer env.deinit();
    defer deployment.deinit();

    // Alice and bob deposit and alice forces a withdrawal while epoch 1 is open.
    try deployment.ledger.deposit(m.account(0), 10);
    try deployment.ledger.deposit(m.account(1), 20);
    try deployment.ledger.withdraw(m.account(0), 1);

    // The close of epoch 1 may defer requests queued while epoch 1 is open.
    _ = try post_epoch(deployment, 1, 0);

    // The close of epoch 2 must process them, and the operator refuses a close that does not,
    // leaving its epoch open.
    const queue = deployment.ledger.queue();
    try testing.expectEqual(@as(usize, 1), queue.required_deposits);
    try testing.expectEqual(@as(usize, 1), queue.required_forced_withdrawals);
    for ([_][2]u64{ .{ 0, 1 }, .{ 1, 0 } }) |counts| {
        try testing.expectError(
            error.InvalidCount,
            deployment.operator.close(&queue, counts[0], counts[1]),
        );
    }
    try testing.expectEqual(@as(m.Epoch, 2), deployment.operator.epoch());
    const summary = try deployment.close_and_drop();
    try testing.expectEqual(@as(u64, 1), summary.deposits.count);
    try testing.expectEqual(@as(u64, 1), summary.forced_withdrawals.count);
    try testing.expectEqual(@as(u64, 9), deployment.operator.balance(&m.account(0)));
    try testing.expectEqual(@as(u64, 29), deployment.ledger.custody());
}

// The ledger refuses a certified summary that defers a request queued before its epoch opened.
test "ledger: ledger rejects closes deferring required requests" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "deferred", 4);
    defer env.deinit();
    defer deployment.deinit();

    // After a funding close, the close of epoch 2 defers a deposit and a forced withdrawal
    // queued while epoch 2 was open.
    try deployment.ledger.deposit(m.account(0), 10);
    _ = try deployment.close_and_drop();
    try deployment.ledger.deposit(m.account(1), 20);
    try deployment.ledger.withdraw(m.account(0), 5);
    _ = try post_epoch(deployment, 0, 0);

    // The deposit and the forced withdrawal were queued while epoch 2 was open, so the close of
    // epoch 3 must process both, even if a certificate covers a summary that defers either.
    var empty = try Matrix.empty(gpa);
    defer empty.deinit();
    for ([_][2]u64{ .{ 0, 1 }, .{ 1, 0 } }) |counts| {
        const deferring: Summary = .{
            .epoch = 3,
            .parent = deployment.ledger.parent().*,
            .matrix = empty.root(),
            .balances = deployment.ledger.balances().*,
            .payouts = deployment.validators.items[0].summary().payouts,
            .deposits = .{ .count = counts[0], .hash = m.Digest.empty },
            .forced_withdrawals = .{ .count = counts[1], .hash = m.Digest.empty },
        };
        try expect_refused(deployment, &deferring, &deferring, error.InvalidCount);
    }
}

// The ledger posts only a certified summary of the close it expects, following the last post
// and within its queues.
test "ledger: ledger posts only certified successors" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "post", 4);
    defer env.deinit();
    defer deployment.deinit();

    // The close of epoch 1 processes alice's deposit, and validators certify it.
    try deployment.ledger.deposit(m.account(0), 10);
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 1, 0);
    defer closed.deinit(gpa);
    const proposals = try deployment.verify(&closed);
    defer d.free_proposals(proposals);
    const summary = proposals[0].summary;
    var certificate = try deployment.certify(proposals);
    defer certificate.deinit(gpa);

    // The summary must be for the expected epoch and follow the last posted one.
    var wrong = summary;
    wrong.epoch = 2;
    try expect_refused(deployment, &wrong, &wrong, error.WrongEpoch);
    wrong = summary;
    wrong.parent = m.Digest.empty;
    try expect_refused(deployment, &wrong, &wrong, error.WrongParent);

    // It must process the queue within its bounds.
    wrong = summary;
    wrong.deposits.count = 2;
    try expect_refused(deployment, &wrong, &wrong, error.InvalidCount);
    wrong = summary;
    wrong.forced_withdrawals.count = 1;
    try expect_refused(deployment, &wrong, &wrong, error.InvalidCount);

    // The certificate must cover this summary.
    var other = summary;
    other.balances = m.Digest.empty;
    try expect_refused(deployment, &summary, &other, error.InvalidCertificate);

    // The certified summary posts once, and its commit joins the claimed ranges.
    const ledger = &deployment.ledger;
    try ledger.post(&deployment.rng, &summary, &certificate);
    try testing.expectEqual(@as(m.Epoch, 2), ledger.epoch());
    try testing.expect(ledger.balances().eql(summary.balances));
    try testing.expect(ledger.matrix(1).?.eql(summary.matrix));
    const ranges = ledger.ranges();
    try testing.expectEqual(@as(usize, 1), ranges.len);
    try testing.expectEqual(@as(u64, 0), ranges[0].key);
    try testing.expectEqual(summary.payouts.size, ranges[0].value);
    const again = ledger.post(&deployment.rng, &summary, &certificate);
    try testing.expectError(error.WrongEpoch, again);
}

// A halted ledger posts no close, even one its validators certified.
test "ledger: halted ledger posts nothing" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "halted", 1);
    defer env.deinit();
    defer deployment.deinit();
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 0, 0);
    defer closed.deinit(gpa);
    const proposals = try deployment.verify(&closed);
    defer d.free_proposals(proposals);
    var certificate = try deployment.certify(proposals);
    defer certificate.deinit(gpa);
    try deployment.ledger.halt();
    const ledger = &deployment.ledger;
    const summary = &proposals[0].summary;
    try testing.expectError(error.Halted, ledger.post(&deployment.rng, summary, &certificate));
    try testing.expectEqual(@as(m.Epoch, 1), ledger.epoch());
}

// A challenge halts the ledger only with a receipt of a posted epoch that the posted close
// credits less than it promised.
test "ledger: challenges need a contradicted receipt" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "challenge", 1);
    defer env.deinit();
    defer deployment.deinit();

    // After a funding close, alice pays bob 10 in epoch 2, and the acknowledgement yields bob's
    // receipt.
    try deployment.ledger.deposit(m.account(0), 100);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer request.deinit(gpa);
    const receipts = try alice.acknowledged(&try deployment.operator.accept(&request));
    defer m.free_receipts(receipts);

    // The receipt's epoch has not closed.
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 0, 0);
    defer closed.deinit(gpa);
    var matrix = try closed.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var challenge: Challenge = .{
        .receipt = try receipts[0].clone(gpa),
        .opening = try matrix.open(gpa, &m.account(0), &m.account(1)),
    };
    defer challenge.deinit(gpa);
    try testing.expectError(error.NotPosted, deployment.ledger.challenge(&challenge));

    // Once it closes, a close crediting the receipt's amount is not contradicted.
    _ = try post_close(deployment, &closed);
    try testing.expectError(error.NoContradiction, deployment.ledger.challenge(&challenge));

    // A receipt raised to 11 fails its proof, and an opening of another pair proves nothing.
    var forged: Challenge = .{
        .receipt = try receipts[0].clone(gpa),
        .opening = try challenge.opening.clone(gpa),
    };
    defer forged.deinit(gpa);
    forged.receipt.amount = 11;
    try testing.expectError(error.InvalidReceipt, deployment.ledger.challenge(&forged));
    var misopened: Challenge = .{
        .receipt = try receipts[0].clone(gpa),
        .opening = try matrix.open(gpa, &m.account(0), &m.account(2)),
    };
    defer misopened.deinit(gpa);
    try testing.expectError(error.InvalidOpening, deployment.ledger.challenge(&misopened));
    try testing.expect(deployment.ledger.halted() == null);
}

// After a halt, each account claims its balance as of the last post once, proven against that
// post's balances root. The deposits no close processed are paid to it once.
test "ledger: halted ledger pays balance and deposit claims" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "claims", 1);
    defer env.deinit();
    defer deployment.deinit();

    // Alice and bob are funded, and alice pays carol 3 in epoch 2. Then alice and dave deposit
    // and bob forces out his whole balance, and no close processes those requests.
    try deployment.ledger.deposit(m.account(0), 10);
    try deployment.ledger.deposit(m.account(1), 20);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var request = try alice.send(2, try m.amounts(&.{.{ 2, 3 }}));
    defer request.deinit(gpa);
    _ = try deployment.operator.accept(&request);
    _ = try deployment.close_and_drop();
    try deployment.ledger.deposit(m.account(0), 4);
    try deployment.ledger.deposit(m.account(3), 7);
    try deployment.ledger.withdraw(m.account(1), 20);

    // The ledger holds every deposit, and the validator proves the balances of alice, bob, and
    // carol as of the last post. Dave has none.
    const custody = deployment.ledger.custody();
    try testing.expectEqual(@as(u64, 41), custody);
    const validator = &deployment.validators.items[0];
    var proofs: [3]BalanceProof = undefined;
    for (&proofs, 0..) |*proof, index| {
        errdefer for (proofs[0..index]) |*made| made.deinit(gpa);
        proof.* = (try validator.prove(&m.account(index))) orelse
            return error.TestUnexpectedResult;
    }
    defer for (&proofs) |*proof| proof.deinit(gpa);
    try testing.expect(try validator.prove(&m.account(3)) == null);
    const alice_proof = &proofs[0];
    const bob_proof = &proofs[1];

    // Claims wait for a halt, and a halted ledger queues no more requests.
    const ledger = &deployment.ledger;
    try testing.expectError(error.NotHalted, ledger.claim(&m.account(0), alice_proof));
    try ledger.halt();
    try testing.expect(ledger.halted().?.eql(.fault));
    try testing.expectError(error.Halted, ledger.deposit(m.account(0), 1));
    try testing.expectError(error.Halted, ledger.withdraw(m.account(0), 1));

    // A proof for another account or of a raised balance is refused. Each account's balance
    // and unprocessed deposits pay once, and the claims together pay out everything the ledger
    // held.
    try testing.expectError(error.InvalidProof, ledger.claim(&m.account(1), alice_proof));
    bob_proof.balance += 1;
    try testing.expectError(error.InvalidProof, ledger.claim(&m.account(1), bob_proof));
    bob_proof.balance -= 1;
    var claimed: u64 = 0;
    claimed += try ledger.claim(&m.account(0), null);
    try testing.expectEqual(@as(u64, 4), claimed);
    claimed += try ledger.claim(&m.account(0), alice_proof);
    try testing.expectEqual(@as(u64, 11), claimed);
    try testing.expectError(error.NothingToClaim, ledger.claim(&m.account(0), alice_proof));
    alice_proof.balance += 1;
    try testing.expectError(error.InvalidProof, ledger.claim(&m.account(0), alice_proof));
    alice_proof.balance -= 1;
    claimed += try ledger.claim(&m.account(1), bob_proof);
    claimed += try ledger.claim(&m.account(2), &proofs[2]);
    claimed += try ledger.claim(&m.account(3), null);
    try testing.expectError(error.NothingToClaim, ledger.claim(&m.account(3), null));
    try testing.expectEqual(custody, claimed);
    try testing.expectEqual(@as(u64, 0), ledger.custody());
}

/// The payouts a posted close owes, kept to withdraw later.
const Owed = struct { epoch: m.Epoch, payouts: m.Amounts };

/// One epoch of `custody backs balances, deposits, and payouts`: each user pays the next, one
/// asks the operator for a soft withdrawal, another forces a withdrawal, and a third deposits.
/// Returns the payouts the posted close owes.
fn custody_epoch(deployment: *d.Deployment, senders: []m.TestSender, epoch: m.Epoch) !m.Amounts {
    const users = senders.len;
    for (senders, 0..) |*from, index| {
        const to = (index + 1) % users;
        _ = try m.pay(from, &deployment.operator, epoch, &.{.{ to, 5 + epoch }});
    }
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const soft = m.user(epoch % users);
    try deployment.operator.withdraw(m.Withdrawal.sign(&soft, &ns, epoch, 12, 0));
    try deployment.ledger.withdraw(m.account((epoch + 1) % users), 9);
    try deployment.ledger.deposit(m.account((epoch + 2) % users), 20);

    // The close processes the queued deposit and forced withdrawal.
    const queue = deployment.ledger.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 1, 1);
    defer closed.deinit(gpa);
    const proposals = try deployment.verify(&closed);
    var payouts = proposals[0].payouts.clone(gpa) catch |err| {
        d.free_proposals(proposals);
        return err;
    };
    errdefer payouts.deinit(gpa);
    _ = try deployment.post(proposals);
    return payouts;
}

// Across epochs of payments, deposits, and withdrawals, the ledger's custody equals the
// balances of the last post plus the deposits still queued and the payouts not yet paid. After
// a halt, claims of the balances and queued deposits, with withdrawals of the payouts still
// owed, take all of it.
test "ledger: custody backs balances, deposits, and payouts" {
    const users = 4;
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "custody", 1);
    defer env.deinit();
    defer deployment.deinit();
    for (0..users) |index| try deployment.ledger.deposit(m.account(index), 100);
    _ = try deployment.close_and_drop();
    var senders: [users]m.TestSender = undefined;
    for (&senders, 0..) |*s, index| {
        errdefer for (senders[0..index]) |*made| made.deinit();
        s.* = try m.sender(index);
    }
    defer for (&senders) |*s| s.deinit();
    var owed: std.ArrayList(Owed) = .empty;
    defer {
        for (owed.items) |*entry| entry.payouts.deinit(gpa);
        owed.deinit(gpa);
    }

    // The payouts of even epochs are withdrawn at once, and those of odd epochs stay owed.
    const validator = &deployment.validators.items[0];
    for (2..6) |epoch| {
        var payouts = try custody_epoch(deployment, &senders, epoch);
        if (epoch % 2 == 0) {
            defer payouts.deinit(gpa);
            try deployment.withdraw_payouts(epoch, &payouts);
        } else {
            errdefer payouts.deinit(gpa);
            try owed.append(gpa, .{ .epoch = epoch, .payouts = payouts });
        }

        // The close leaves no deposit queued, so the funds held are the posted balances plus
        // the payouts still owed.
        var backed: u64 = 0;
        for (owed.items) |*entry| backed += entry.payouts.total().?;
        for (0..users) |index| backed += try validator.balance(&m.account(index));
        try testing.expectEqual(backed, deployment.ledger.custody());
    }

    // A deposit and a forced withdrawal queue after the last post. The halt drops the forced
    // withdrawal, and claims of every balance and of the queued deposit, with withdrawals of
    // the owed payouts, empty the custody.
    try deployment.ledger.deposit(m.account(0), 15);
    try deployment.ledger.withdraw(m.account(1), 50);
    const held = deployment.ledger.custody();
    try deployment.ledger.halt();
    var claimed: u64 = 0;
    for (0..users) |index| {
        var proof = try validator.prove(&m.account(index));
        defer if (proof) |*p| p.deinit(gpa);
        const by = if (proof) |*p| p else null;
        claimed += try deployment.ledger.claim(&m.account(index), by);
    }
    for (owed.items) |*entry| {
        try deployment.withdraw_payouts(entry.epoch, &entry.payouts);
        claimed += entry.payouts.total().?;
    }
    try testing.expectEqual(held, claimed);
    try testing.expectEqual(@as(u64, 0), deployment.ledger.custody());
}

/// Funds alice and bob with 10 each, and posts the close of epoch 2 paying out their forced
/// withdrawals of 4 and 6.
fn post_forced_payouts(deployment: *d.Deployment) !void {
    try deployment.ledger.deposit(m.account(0), 10);
    try deployment.ledger.deposit(m.account(1), 10);
    _ = try deployment.close_and_drop();
    try deployment.ledger.withdraw(m.account(0), 4);
    try deployment.ledger.withdraw(m.account(1), 6);
    _ = try post_epoch(deployment, 0, 2);
}

// A post transfers nothing. Each payout stays in custody until its account withdraws it with a
// proof, or claims it after a halt, and it is paid once.
test "ledger: payouts are withdrawn once before or after a halt" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "payouts", 1);
    defer env.deinit();
    defer deployment.deinit();

    // Alice and bob force withdrawals of 4 and 6, and the posted close pays them out while the
    // ledger keeps holding the funds.
    try post_forced_payouts(deployment);
    try testing.expectEqual(@as(u64, 20), deployment.ledger.custody());

    // The close owes nothing to an account it did not pay out.
    const validator = &deployment.validators.items[0];
    try testing.expect(try validator.prove_payout(2, &m.account(2)) == null);
    var alice = try payout_proof(deployment, 2, 0);
    defer alice.deinit(gpa);
    var bob = try payout_proof(deployment, 2, 1);
    defer bob.deinit(gpa);

    // A proof of a raised amount fails, and the payout is withdrawn once.
    const ledger = &deployment.ledger;
    alice.payout.amount += 1;
    try testing.expectError(error.InvalidProof, ledger.withdraw_payout(2, &alice));
    alice.payout.amount -= 1;
    try expect_withdrawn(deployment, 2, &alice, 0, 4);
    try testing.expectEqual(@as(u64, 16), ledger.custody());
    try testing.expectError(error.Withdrawn, ledger.withdraw_payout(2, &alice));

    // After a halt, the remaining payout is claimed under the same posted payouts root.
    try ledger.halt();
    try expect_withdrawn(deployment, 2, &bob, 1, 6);
    try testing.expectError(error.Withdrawn, ledger.withdraw_payout(2, &bob));
    try testing.expectEqual(@as(u64, 10), ledger.custody());
}

// A payout proof pays under the payouts root of the posted close a withdrawal names, even after
// later posts and a halt. Naming an epoch with no post, or a posted close whose root the proof
// is not under, is refused, and an index is paid once whichever posted root proves it.
test "ledger: payout proofs stay valid under every posted root" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "roots", 1);
    defer env.deinit();
    defer deployment.deinit();

    // The forced withdrawals of 4 by alice and 6 by bob pay out in epoch 2, and each gets a
    // proof under the payouts root of epoch 2.
    try post_forced_payouts(deployment);
    var early = [2]PayoutProof{ try payout_proof(deployment, 2, 0), undefined };
    defer early[0].deinit(gpa);
    early[1] = try payout_proof(deployment, 2, 1);
    defer early[1].deinit(gpa);

    // An idle close of epoch 3 posts and moves the payouts root, and each payout gets a second
    // proof of the same index under the root of epoch 3.
    _ = try post_epoch(deployment, 0, 0);
    var late = [2]PayoutProof{ try payout_proof(deployment, 2, 0), undefined };
    defer late[0].deinit(gpa);
    late[1] = try payout_proof(deployment, 2, 1);
    defer late[1].deinit(gpa);
    try testing.expectEqual(early[0].index, late[0].index);
    try testing.expectEqual(early[1].index, late[1].index);

    // A proof is refused under an epoch with no post, and under a posted root it is not under.
    const ledger = &deployment.ledger;
    for ([_]m.Epoch{ 0, 4 }) |epoch| {
        try testing.expectError(error.NotPosted, ledger.withdraw_payout(epoch, &early[0]));
    }
    try testing.expectError(error.InvalidProof, ledger.withdraw_payout(1, &early[0]));
    try testing.expectError(error.InvalidProof, ledger.withdraw_payout(3, &early[0]));

    // Alice's proof under the root of epoch 2 pays after the post of epoch 3, and her proof
    // under the root of epoch 3 is then refused.
    try expect_withdrawn(deployment, 2, &early[0], 0, 4);
    try testing.expectError(error.Withdrawn, ledger.withdraw_payout(3, &late[0]));

    // After a halt, every posted root stays. Bob's proof under the root of epoch 3 pays, and
    // his proof under the root of epoch 2 is then refused.
    try ledger.halt();
    try expect_withdrawn(deployment, 3, &late[1], 1, 6);
    try testing.expectError(error.Withdrawn, ledger.withdraw_payout(2, &early[1]));
    try testing.expectEqual(@as(u64, 10), ledger.custody());
}

/// The orders `withdrawn ranges stay compact` withdraws payouts in, as permutations of the
/// payouts sorted by index.
const Order = enum { alternating, reversed, strided };

/// The position in index order of the payout withdrawn `position`th in `order` of `count`.
fn reorder(order: Order, position: usize, count: usize, indices: []const u64) usize {
    return switch (order) {
        // Odd indices first, then even ones, each in index order.
        .alternating => alternating: {
            var seen: usize = 0;
            for ([_]u64{ 1, 0 }) |parity| {
                for (indices, 0..) |index, at| {
                    if (index % 2 != parity) continue;
                    if (seen == position) break :alternating at;
                    seen += 1;
                }
            }
            unreachable; // Proof: `position < count` and every index has a parity.
        },
        .reversed => count - 1 - position,
        // A stride coprime with the number of payouts visits each once.
        .strided => position * 4 % count,
    };
}

/// Checks that `ranges` stay apart and number at most one more than the payouts `outstanding`.
fn check_ranges(ranges: anytype, outstanding: usize) !void {
    try testing.expect(ranges.len <= outstanding + 1);
    if (ranges.len < 2) return;
    for (ranges[0 .. ranges.len - 1], ranges[1..]) |a, b| try testing.expect(a.value < b.key);
}

fn by_index(proofs: *const [9]PayoutProof, a: usize, b: usize) bool {
    return proofs[a].index < proofs[b].index;
}

/// One run of `withdrawn ranges stay compact` in `order`.
fn compact_ranges(order: Order) !void {
    const users = 9;
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "ranges", 1);
    defer env.deinit();
    defer deployment.deinit();
    var funded: u64 = 0;
    for (0..users) |index| {
        try deployment.ledger.deposit(m.account(index), 10 + index);
        funded += 10 + index;
    }
    _ = try deployment.close_and_drop();

    // Two closes pay out every account, the first five and then the other four.
    var epochs: [users]m.Epoch = undefined;
    for ([_][2]usize{ .{ 0, 5 }, .{ 5, users } }) |bounds| {
        for (bounds[0]..bounds[1]) |index| try deployment.ledger.withdraw(m.account(index), 3);
        const count = deployment.ledger.queue().forced_withdrawals.len;
        const summary = try post_epoch(deployment, 0, count);
        for (bounds[0]..bounds[1]) |index| epochs[index] = summary.epoch;
    }
    const applied = deployment.validators.items[0].summary();
    const size = applied.payouts.size;
    const posted = applied.epoch;

    // Prove every payout, then order the proofs by index.
    var proofs: [users]PayoutProof = undefined;
    for (&proofs, 0..) |*proof, index| {
        errdefer for (proofs[0..index]) |*made| made.deinit(gpa);
        proof.* = try payout_proof(deployment, epochs[index], index);
    }
    defer for (&proofs) |*proof| proof.deinit(gpa);
    var sorted: [users]usize = undefined;
    for (&sorted, 0..) |*position, at| position.* = at;
    std.mem.sort(usize, &sorted, &proofs, by_index);
    var indices: [users]u64 = undefined;
    for (sorted, &indices) |position, *index| index.* = proofs[position].index;

    // After each withdrawal the ranges stay apart and number at most one more than the payouts
    // outstanding. The last leaves one range over the whole log, and the funds held are then
    // the deposits less every payout.
    var outstanding: usize = users;
    try check_ranges(deployment.ledger.ranges(), outstanding);
    for (0..users) |position| {
        const proof = &proofs[sorted[reorder(order, position, users, &indices)]];
        _ = try deployment.ledger.withdraw_payout(posted, proof);
        outstanding -= 1;
        try check_ranges(deployment.ledger.ranges(), outstanding);
    }
    const ranges = deployment.ledger.ranges();
    try testing.expectEqual(@as(usize, 1), ranges.len);
    try testing.expectEqual(@as(u64, 0), ranges[0].key);
    try testing.expectEqual(size, ranges[0].value);
    try testing.expectEqual(funded - 3 * users, deployment.ledger.custody());
}

// Ranges of withdrawn payouts and commits never overlap or touch. With U payouts outstanding,
// there are at most U + 1 ranges in any withdrawal order, and once every payout is withdrawn
// the ranges collapse to one range over the whole log.
test "ledger: withdrawn ranges stay compact" {
    for ([_]Order{ .alternating, .reversed, .strided }) |order| try compact_ranges(order);
}

// Unpaid payouts stay in custody, so they count toward the largest amount the ledger may hold.
// A deposit that would take the funds held past it is refused until the payouts are withdrawn.
test "ledger: owed payouts count toward the custody bound" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "bound", 1);
    defer env.deinit();
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), max - 1);
    _ = try deployment.close_and_drop();
    try deployment.ledger.withdraw(m.account(0), 10);
    _ = try post_epoch(deployment, 0, 1);
    try testing.expectEqual(@as(u64, max - 1), deployment.ledger.custody());
    var proof = try payout_proof(deployment, 2, 0);
    defer proof.deinit(gpa);

    // Alice's balance alone leaves room for 11 more, but her unpaid payout of 10 is still held.
    const ledger = &deployment.ledger;
    try testing.expectError(error.Custody, ledger.deposit(m.account(1), 2));
    try ledger.deposit(m.account(1), 1);
    try testing.expectEqual(@as(u64, max), ledger.custody());

    // Withdrawing the payout frees its room.
    try expect_withdrawn(deployment, 2, &proof, 0, 10);
    try ledger.deposit(m.account(1), 10);
    try testing.expectEqual(@as(u64, max), ledger.custody());
}

// What the finality precondition prevents (commonware's `reorg` module). The ledger checks a
// summary's counts but not its running hashes, so a ledger holding other requests at the
// positions the counts select posts it anyway. Validators certify a summary against one
// ledger's queue, and a ledger holding a different deposit at the same position posts it, as a
// reorg of the chain under the ledger could make happen. The custody then differs from the
// balances validators credit, so after a halt the credited account's claim is refused and the
// other account's deposit is gone.
test "ledger: summary posts against other queue contents" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "reorg", 1);
    defer env.deinit();
    defer deployment.deinit();
    const fixture = try d.committee(1);
    defer {
        fixture.deinit(gpa);
        gpa.destroy(fixture);
    }
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const validator = &deployment.validators.items[0];
    const operator = m.operator_key().public_key();
    const genesis = validator.summary().balances;
    var canonical = try d.TestLedger.init(gpa, &ns, operator, &fixture.verifier, genesis);
    defer canonical.deinit();
    try deployment.ledger.deposit(m.account(0), 100);
    try canonical.deposit(m.account(1), 5);

    // The operator and validators read the queue the deployment's ledger holds, and the
    // canonical ledger posts the summary they certify with the same epoch, parent, counts,
    // payouts, and certificate.
    const parent = validator.summary().*;
    const queue = deployment.ledger.queue();
    const drained = canonical.queue();
    var closed = try m.close_epoch(&deployment.operator, &queue, 1, 0);
    defer closed.deinit(gpa);
    const proposals = try deployment.verify(&closed);
    defer d.free_proposals(proposals);
    var certificate = try deployment.certify(proposals);
    defer certificate.deinit(gpa);
    const summary = proposals[0].summary;
    try canonical.post(&deployment.rng, &summary, &certificate);
    try validator.apply(&proposals[0], &summary.digest());
    try testing.expectEqual(@as(u64, 100), try validator.balance(&m.account(0)));
    try testing.expectEqual(@as(u64, 0), try validator.balance(&m.account(1)));
    try testing.expectEqual(@as(u64, 5), canonical.custody());

    // The summary's running hash names the deposit validators read, not the one the canonical
    // ledger drained.
    const read = m.chain(m.Deposit, parent.deposits.hash, queue.deposits[0..1]);
    try testing.expect(summary.deposits.hash.eql(read));
    const forced = m.chain(m.Forced, parent.forced_withdrawals.hash, &.{});
    try testing.expect(summary.forced_withdrawals.hash.eql(forced));
    const other = m.chain(m.Deposit, parent.deposits.hash, drained.deposits);
    try testing.expect(!summary.deposits.hash.eql(other));

    // After a halt, the canonical ledger holds too little for alice's credited balance, and
    // bob's deposit is gone.
    try canonical.halt();
    var proof = (try validator.prove(&m.account(0))).?;
    defer proof.deinit(gpa);
    try testing.expectError(error.Custody, canonical.claim(&m.account(0), &proof));
    try testing.expectError(error.NothingToClaim, canonical.claim(&m.account(1), null));
}
