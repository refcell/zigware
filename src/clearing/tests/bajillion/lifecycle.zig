//! Deployments running over several epochs (commonware
//! `clearing/tests/bajillion/lifecycle.rs`).

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const bajillion = @import("../../bajillion/mod.zig");
const m = @import("main.zig");
const d = @import("deployment.zig");

const gpa = m.gpa;
const Outcome = m.roles.sender.Outcome;
const Summary = d.Summary;
const Challenge = d.TestLedger.Challenge;

/// Checks that `summary`'s running hashes extend `parent`'s over the requests it processed
/// from `queue` (commonware `assert_chained`).
fn check_chained(parent: *const Summary, summary: *const Summary, queue: *const m.Queue) !void {
    const prefix = queue.prefix(summary.deposits.count, summary.forced_withdrawals.count).?;
    const deposits = m.chain(m.Deposit, parent.deposits.hash, prefix.deposits);
    try testing.expect(summary.deposits.hash.eql(deposits));
    const forced_hash = parent.forced_withdrawals.hash;
    const forced = m.chain(m.Forced, forced_hash, prefix.forced_withdrawals);
    try testing.expect(summary.forced_withdrawals.hash.eql(forced));
}

/// A fresh deployment `name` of `n` validators on `env`.
fn deploy(env: *d.Env, name: []const u8, n: u32) !*d.Deployment {
    try env.init(gpa, 0);
    errdefer env.deinit();
    return d.Deployment.init(env, name, n);
}

/// Verifies `closed` at every validator and posts it.
fn post_close(deployment: *d.Deployment, closed: *const m.TestClose) !Summary {
    return deployment.post(try deployment.verify(closed));
}

const users = 6;

/// The `{ index, balance }` of every user from `expected`.
fn held(expected: *const [users]u64) [users][2]u64 {
    var entries: [users][2]u64 = undefined;
    for (&entries, expected, 0..) |*entry, balance, index| entry.* = .{ index, balance };
    return entries;
}

/// One epoch's payments of `epochs settle payments and withdrawals`: every user pays the next
/// two users, one request each, and each receiver relies on its receipts. Each amount depends
/// on the payer, so no user's payments and receipts cancel.
fn pay_around(
    deployment: *d.Deployment,
    senders: *[users]m.TestSender,
    receivers: *[users]m.TestReceiver,
    expected: *[users]u64,
    epoch: m.Epoch,
) !void {
    for (0..users) |from| {
        for ([_]u64{ 1, 2 }) |offset| {
            const to = (from + offset) % users;
            const amount = epoch * 10 + offset + from;
            expected[from] -= amount;
            expected[to] += amount;
            const sender = &senders[from];
            var request = try sender.send(epoch, try m.amounts(&.{.{ to, amount }}));
            defer request.deinit(gpa);
            const acknowledgement = try deployment.operator.accept(&request);
            const receipts = try sender.acknowledged(&acknowledgement);
            defer m.free_receipts(receipts);
            for (receipts) |*receipt| _ = try receivers[to].receive(receipt);
        }
    }
}

/// Every receiver records the post of `epoch` and finds each payment it was promised, and every
/// sender resolves the post: the close settled the map it recorded (S5).
fn audit_epoch(
    closed: *const m.TestClose,
    summary: *const Summary,
    senders: *[users]m.TestSender,
    receivers: *[users]m.TestReceiver,
) !void {
    const epoch = summary.epoch;
    var matrix = try closed.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    for (receivers) |*receiver| {
        receiver.posted(epoch);
        const held_receipts = receiver.receipts(epoch);
        try testing.expectEqual(@as(usize, 2), held_receipts.len);
        for (held_receipts) |*entry| {
            var opening = try matrix.open(gpa, &entry.key, &receiver.account);
            defer opening.deinit(gpa);
            const found = try receiver.audit(epoch, &summary.matrix, &entry.key, &opening);
            try testing.expect(found == null);
        }
        receiver.prune(epoch);
    }
    for (senders, 0..) |*sender, index| {
        var opening = try matrix.open(gpa, &m.account(index), &m.account(index));
        defer opening.deinit(gpa);
        const outcome = try sender.posted(epoch, &summary.matrix, &opening);
        try testing.expectEqual(Outcome.match, outcome);
        sender.prune(epoch);
    }
}

// Over several epochs of payments, soft and forced withdrawals, and deposits, every balance and
// payout matches one computed by hand, and the operator, validators, and ledger agree.
test "lifecycle: epochs settle payments and withdrawals" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "epochs", 4);
    defer env.deinit();
    defer deployment.deinit();
    var senders: [users]m.TestSender = undefined;
    for (&senders, 0..) |*s, index| {
        errdefer for (senders[0..index]) |*made| made.deinit();
        s.* = try m.sender(index);
    }
    defer for (&senders) |*s| s.deinit();
    var receivers: [users]m.TestReceiver = undefined;
    for (&receivers, 0..) |*r, index| {
        errdefer for (receivers[0..index]) |*made| made.deinit();
        r.* = try m.receiver(index, 1);
    }
    defer for (&receivers) |*r| r.deinit();

    // Every user deposits 1,000. After the funding close, the operator, validators, and ledger
    // agree on every balance.
    for (0..users) |index| try deployment.ledger.deposit(m.account(index), 1_000);
    var parent = deployment.validators.items[0].summary().*;
    var queues = try copy_queue(&deployment.ledger.queue());
    var funding, var summary = try deployment.close();
    funding.deinit(gpa);
    try check_chained(&parent, &summary, &queues.queue());
    queues.deinit();
    parent = summary;
    for (&receivers) |*receiver| receiver.posted(1);
    var expected: [users]u64 = @splat(1_000);
    try deployment.check_balances(&held(&expected));

    var ns = try m.namespace();
    defer ns.deinit(gpa);
    for (2..7) |epoch| {
        try pay_around(deployment, &senders, &receivers, &expected, epoch);

        // One user withdraws through the operator, another through the ledger, and a third
        // deposits. Every balance covers its withdrawal, so each pays out in full.
        const soft = epoch % users;
        const forced = (epoch + 3) % users;
        const deposited = (epoch + 1) % users;
        const soft_key = m.user(soft);
        try deployment.operator.withdraw(m.Withdrawal.sign(&soft_key, &ns, epoch, 25, 0));
        try deployment.ledger.withdraw(m.account(forced), 15);
        try deployment.ledger.deposit(m.account(deposited), 40);
        expected[soft] -= 25;
        expected[forced] -= 15;
        expected[deposited] += 40;

        // The close processes the deposit and the forced withdrawal, and appends the payouts of
        // both withdrawals and its commit to the payout log. The running hashes extend the
        // parent's over the requests the close processed.
        queues = try copy_queue(&deployment.ledger.queue());
        defer queues.deinit();
        var closed, summary = try deployment.close();
        defer closed.deinit(gpa);
        try testing.expectEqual(@as(m.Epoch, epoch), summary.epoch);
        try testing.expectEqual(@as(u64, 1), summary.deposits.count);
        try testing.expectEqual(@as(u64, 1), summary.forced_withdrawals.count);
        try testing.expectEqual(parent.payouts.size + 3, summary.payouts.size);
        try check_chained(&parent, &summary, &queues.queue());
        parent = summary;
        try audit_epoch(&closed, &summary, &senders, &receivers);
        try deployment.check_balances(&held(&expected));
    }
}

/// A copy of `queue`'s requests, since a close drains the ledger's.
fn copy_queue(queue: *const m.Queue) !m.Queues {
    var queues = try m.Queues.init(queue.epoch, &.{}, &.{});
    gpa.free(queues.deposits);
    gpa.free(queues.forced);
    queues.deposits = try gpa.dupe(m.Deposit, queue.deposits);
    errdefer gpa.free(queues.deposits);
    queues.forced = try gpa.dupe(m.Forced, queue.forced_withdrawals);
    queues.required_deposits = queue.required_deposits;
    queues.required_forced_withdrawals = queue.required_forced_withdrawals;
    return queues;
}

/// Sends `batch` from `from` in `epoch` through `deployment`'s operator, and returns the
/// receipt of its last receiver; the caller frees it.
fn last_receipt(
    deployment: *d.Deployment,
    from: *m.TestSender,
    epoch: m.Epoch,
    batch: []const [2]u64,
) !m.TestSender.Receipt {
    var request = try from.send(epoch, try m.amounts(batch));
    defer request.deinit(gpa);
    const receipts = try from.acknowledged(&try deployment.operator.accept(&request));
    defer m.free_receipts(receipts);
    return receipts[receipts.len - 1].clone(gpa);
}

/// Checks that the ledger halted on a challenge of the close of `epoch`.
fn expect_challenged(deployment: *d.Deployment, epoch: m.Epoch) !void {
    const halt = deployment.ledger.halted() orelse return error.TestUnexpectedResult;
    try testing.expect(halt.eql(.{ .challenge = epoch }));
}

// A posted close that omits a preconfirmed payment lets its receiver halt the ledger, and every
// account then claims the balance of the last posted close.
test "lifecycle: omitted payment halts ledger" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "omitted", 4);
    defer env.deinit();
    defer deployment.deinit();

    // Alice and bob are funded in epoch 1.
    try deployment.ledger.deposit(m.account(0), 100);
    try deployment.ledger.deposit(m.account(1), 100);
    _ = try deployment.close_and_drop();

    // The operator preconfirms a payment to bob.
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.receiver(1, 2);
    defer bob.deinit();
    var receipt = try last_receipt(deployment, &alice, 2, &.{.{ 1, 30 }});
    defer receipt.deinit(gpa);
    _ = try bob.receive(&receipt);

    // It then closes the epoch without it. Nothing else about the close is wrong, so
    // validators certify it and it posts.
    const operator = m.operator_key();
    const queue = deployment.ledger.queue();
    var omitting = try m.forge(&operator, &queue, &.{}, &.{}, 0, 0);
    defer omitting.deinit(gpa);
    const summary = try post_close(deployment, &omitting);
    bob.posted(2);

    // Bob finds the omission in the posted matrix and halts the ledger.
    var matrix = try omitting.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var opening = try matrix.open(gpa, &m.account(0), &m.account(1));
    defer opening.deinit(gpa);
    var challenge = (try bob.audit(2, &summary.matrix, &m.account(0), &opening)).?;
    defer challenge.deinit(gpa);
    try deployment.ledger.challenge(&challenge);
    try expect_challenged(deployment, 2);
    try testing.expectError(error.Halted, deployment.ledger.challenge(&challenge));

    // Halting again, as a deployment's own policy might, keeps the challenge as the reason.
    try deployment.ledger.halt();
    try expect_challenged(deployment, 2);

    // Everyone claims the balances the posted closes finalized.
    const custody = deployment.ledger.custody();
    var claimed: u64 = 0;
    for (0..2) |index| {
        var proof = (try deployment.validators.items[0].prove(&m.account(index))).?;
        defer proof.deinit(gpa);
        claimed += try deployment.ledger.claim(&m.account(index), &proof);
    }
    try testing.expectEqual(@as(u64, 200), claimed);
    try testing.expectEqual(custody, claimed);
}

// A challenge is judged against the posted close of its receipt's epoch, even after later
// closes with other payment matrices posted.
test "lifecycle: late challenge halts after later closes" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "late", 4);
    defer env.deinit();
    defer deployment.deinit();

    // After a funding close, alice pays bob 30 and carol pays bob 10 in epoch 2, and bob holds
    // alice's receipt.
    try deployment.ledger.deposit(m.account(0), 100);
    try deployment.ledger.deposit(m.account(3), 100);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var carol = try m.sender(3);
    defer carol.deinit();
    var bob = try m.receiver(1, 2);
    defer bob.deinit();
    var receipt = try last_receipt(deployment, &alice, 2, &.{.{ 1, 30 }});
    defer receipt.deinit(gpa);
    _ = try bob.receive(&receipt);
    var paid = try carol.send(2, try m.amounts(&.{.{ 1, 10 }}));
    defer paid.deinit(gpa);
    const credits = try carol.acknowledged(&try deployment.operator.accept(&paid));
    defer m.free_receipts(credits);

    // The close of epoch 2 omits alice's payment and settles carol's. The close of epoch 3, in
    // which alice pays bob as much again, posts before bob checks the close of epoch 2.
    var carol_row: m.Row = .{
        .account = m.account(3),
        .payments = try paid.batch.clone(gpa),
        .signature = paid.signatures.current,
    };
    defer carol_row.deinit(gpa);
    const operator = m.operator_key();
    var queue = deployment.ledger.queue();
    var omitting = try m.forge(&operator, &queue, &.{carol_row}, &.{}, 0, 0);
    defer omitting.deinit(gpa);
    const omitted = try post_close(deployment, &omitting);
    bob.posted(2);
    try deployment.ledger.deposit(m.account(2), 50);
    var alice_row = try m.row(3, 0, try m.amounts(&.{.{ 1, 30 }}), &m.Amounts.empty);
    defer alice_row.deinit(gpa);
    queue = deployment.ledger.queue();
    var next = try m.forge(&operator, &queue, &.{alice_row}, &.{}, 1, 0);
    defer next.deinit(gpa);
    const latest = try post_close(deployment, &next);
    bob.posted(3);
    try testing.expect(!latest.matrix.eql(omitted.matrix));

    // A receipt the close of its epoch credits in full shows no contradiction.
    var matrix = try omitting.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var settled: Challenge = .{
        .receipt = try credits[credits.len - 1].clone(gpa),
        .opening = try matrix.open(gpa, &m.account(3), &m.account(1)),
    };
    defer settled.deinit(gpa);
    try testing.expectError(error.NoContradiction, deployment.ledger.challenge(&settled));

    // The omitted payment still halts the ledger. Claims follow the balances of the latest
    // close.
    var opening = try matrix.open(gpa, &m.account(0), &m.account(1));
    defer opening.deinit(gpa);
    var challenge = (try bob.audit(2, &omitted.matrix, &m.account(0), &opening)).?;
    defer challenge.deinit(gpa);
    try deployment.ledger.challenge(&challenge);
    try testing.expect(deployment.ledger.balances().eql(latest.balances));
    var proof = (try deployment.validators.items[0].prove(&m.account(2))).?;
    defer proof.deinit(gpa);
    try testing.expectEqual(@as(u64, 50), try deployment.ledger.claim(&m.account(2), &proof));
}

// A posted close that settles a state earlier than the one a receipt carries credits the
// receiver less than the receipt promised, so the receiver's challenge halts the ledger.
test "lifecycle: partial credit halts ledger" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "partial", 4);
    defer env.deinit();
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 100);
    _ = try deployment.close_and_drop();

    // Alice pays bob 5 and then 5 more, and bob holds the receipt for the cumulative 10.
    var alice = try m.sender(0);
    defer alice.deinit();
    var bob = try m.receiver(1, 2);
    defer bob.deinit();
    var first = try alice.send(2, try m.amounts(&.{.{ 1, 5 }}));
    defer first.deinit(gpa);
    m.free_receipts(try alice.acknowledged(&try deployment.operator.accept(&first)));
    var receipt = try last_receipt(deployment, &alice, 2, &.{.{ 1, 5 }});
    defer receipt.deinit(gpa);
    try testing.expectEqual(@as(u64, 10), try bob.receive(&receipt));

    // The close settles an earlier state alice did sign, so it posts.
    var earlier: m.Row = .{
        .account = m.account(0),
        .payments = try m.amounts(&.{.{ 1, 5 }}),
        .signature = first.signatures.current,
    };
    defer earlier.deinit(gpa);
    const operator = m.operator_key();
    const queue = deployment.ledger.queue();
    var underpaying = try m.forge(&operator, &queue, &.{earlier}, &.{}, 0, 0);
    defer underpaying.deinit(gpa);
    const summary = try post_close(deployment, &underpaying);
    bob.posted(2);

    // Bob is credited 5 of the 10 promised, so his challenge halts the ledger.
    var matrix = try underpaying.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var opening = try matrix.open(gpa, &m.account(0), &m.account(1));
    defer opening.deinit(gpa);
    const credited = try opening.verify(m.Sha256, &summary.matrix, &m.account(0), &m.account(1));
    try testing.expectEqual(@as(u64, 5), credited);
    var challenge = (try bob.audit(2, &summary.matrix, &m.account(0), &opening)).?;
    defer challenge.deinit(gpa);
    try deployment.ledger.challenge(&challenge);
    try expect_challenged(deployment, 2);
}

// A countersigned map keeps its predecessor when an earlier post contradicts the operator's
// acknowledgement. Extending that map cannot authorize its payments under the posted root.
test "lifecycle: sender keeps its epoch anchor after a conflicting post" {
    var env: d.Env = undefined;
    const deployment = try deploy(&env, "conflicting_post", 4);
    defer env.deinit();
    defer deployment.deinit();
    try deployment.ledger.deposit(m.account(0), 100);
    _ = try deployment.close_and_drop();
    var alice = try m.sender(0);
    defer alice.deinit();
    var batch = try m.amounts(&.{.{ 1, 10 }});
    defer batch.deinit(gpa);
    var request = try alice.send(2, try batch.clone(gpa));
    defer request.deinit(gpa);

    // The operator preconfirms the next state while retaining the signed current state.
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const next: bajillion.State(m.PublicKey, m.Digest) = .{
        .epoch = 3,
        .account = m.account(0),
        .payments = batch.root(m.Sha256),
        .previous = request.latest,
    };
    const operator = m.operator_key();
    m.free_receipts(try alice.acknowledged(&next.acknowledge(&operator, &ns)));

    // The current state pays bob in epoch 2, making the next state's predecessor invalid.
    var queue = deployment.ledger.queue();
    var paying: m.Row = .{
        .account = m.account(0),
        .payments = try batch.clone(gpa),
        .signature = request.signatures.current,
    };
    defer paying.deinit(gpa);
    var current = try m.forge(&operator, &queue, &.{paying}, &.{}, 0, 0);
    defer current.deinit(gpa);
    const summary = try post_close(deployment, &current);
    var matrix = try current.matrix(m.Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    var opening = try matrix.open(gpa, &m.account(0), &m.account(0));
    defer opening.deinit(gpa);
    const outcome = try alice.posted(2, &summary.matrix, &opening);
    try testing.expectEqual(Outcome.conflict, outcome);

    // A new payment to carol must not make bob's payment settle again in epoch 3.
    var successor = try alice.send(3, try m.amounts(&.{.{ 2, 1 }}));
    defer successor.deinit(gpa);
    queue = deployment.ledger.queue();
    var both: m.Row = .{
        .account = m.account(0),
        .payments = try m.amounts(&.{ .{ 1, 10 }, .{ 2, 1 } }),
        .signature = successor.signatures.current,
    };
    defer both.deinit(gpa);
    var repeated = try m.forge(&operator, &queue, &.{both}, &.{}, 0, 0);
    defer repeated.deinit(gpa);
    for (deployment.validators.items) |*validator| {
        try testing.expectEqual(@as(u64, 90), try validator.balance(&m.account(0)));
        try testing.expectEqual(@as(u64, 10), try validator.balance(&m.account(1)));
        const verifying = validator.verify(try repeated.clone(gpa), &queue);
        try testing.expectError(error.InvalidSignature, verifying);
    }
}

/// A deployment whose users, operator, and validators sign with three different schemes, and
/// whose amounts exceed the largest `u128` (commonware's `schemes` module).
const schemes = struct {
    const cryptography = @import("cryptography");
    const codec = @import("codec");
    const storage = @import("storage");
    const utils = @import("utils");
    const secp = cryptography.secp256r1.standard;
    const bls = cryptography.bls12381;

    const User = secp.PublicKey;
    const Key = bls.PrivateKey;
    const A = u256;
    /// secp256r1 certificates over summaries from at least `2f + 1` of `3f + 1` validators.
    const Scheme = cryptography.secp256r1.certificate.Scheme(
        Summary,
        utils.N3f1,
        cryptography.ed25519.PublicKey,
    );
    const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
    const Operator = m.roles.operator.Operator(User, Key, m.Sha256, A);
    const Sender = m.roles.sender.Sender(secp.PrivateKey, Key.PublicKey, m.Sha256, A);
    const Receiver = m.roles.receiver.Receiver(User, Key.PublicKey, m.Sha256, A);
    const Validator = m.roles.validator.Validator(
        User,
        Key.PublicKey,
        m.Sha256,
        storage.translator.EightCap,
        A,
    );
    const Ledger = m.roles.ledger.Ledger(User, Key.PublicKey, Scheme, m.Sha256, A);
    const Amounts = bajillion.Amounts(User, A);
    const Close = Operator.Close;

    /// One more than the largest `u128`.
    const unit: A = 1 << 128;

    /// `count` times `unit`.
    fn units(count: u64) A {
        return @as(A, count) << 128;
    }

    const Deployment = struct {
        ns: bajillion.Namespace,
        fixture: Fixture,
        operator: Operator,
        validators: [4]Validator,
        ledger: Ledger,
        rng: utils.rng.TestRng,

        /// Starts in place: the ledger borrows the fixture's verifier.
        fn init(self: *Deployment, env: *d.Env, key: Key) !void {
            self.rng = utils.rng.test_rng();
            self.ns = try m.namespace();
            errdefer self.ns.deinit(gpa);
            const make = cryptography.secp256r1.certificate.fixture;
            self.fixture = try make(Scheme, gpa, &self.rng, m.namespace_bytes, 4);
            errdefer self.fixture.deinit(gpa);
            const empty: Validator.Persisted = .{};
            for (&self.validators, 0..) |*validator, index| {
                errdefer for (self.validators[0..index]) |*made| made.deinit();
                var name_buffer: [16]u8 = undefined;
                const name = try std.fmt.bufPrint(&name_buffer, "schemes-{d}", .{index});
                const config: Validator.Config = .{
                    .namespace = &self.ns,
                    .operator = key.public_key(),
                    .limits = m.limits,
                    .name = name,
                };
                validator.* = try Validator.init(gpa, env, config, empty, null);
            }
            errdefer for (&self.validators) |*validator| validator.deinit();
            self.operator = try Operator.init(gpa, key, &self.ns, m.limits);
            errdefer self.operator.deinit();
            const balances = self.validators[0].summary().balances;
            const verifier = &self.fixture.verifier;
            self.ledger = try Ledger.init(gpa, &self.ns, key.public_key(), verifier, balances);
        }

        fn deinit(self: *Deployment) void {
            self.ledger.deinit();
            self.operator.deinit();
            for (&self.validators) |*validator| validator.deinit();
            self.fixture.deinit(gpa);
            self.ns.deinit(gpa);
        }

        /// Closes the operator's epoch processing every queued request, posts it at every
        /// validator, and withdraws its payouts with proofs.
        fn close(self: *Deployment) !Summary {
            const queue = self.ledger.queue();
            const deposits = queue.deposits.len;
            const forced = queue.forced_withdrawals.len;
            var assembled = try self.operator.close(&queue, deposits, forced);
            assembled.flows.deinit(gpa);
            defer assembled.close.deinit(gpa);
            var proposals: [4]Validator.Proposal = undefined;
            var made: usize = 0;
            defer for (proposals[0..made]) |*proposal| proposal.deinit(gpa);
            for (&self.validators, &proposals) |*validator, *proposal| {
                proposal.* = try validator.verify(try assembled.close.clone(gpa), &queue);
                made += 1;
            }
            const summary = proposals[0].summary;
            var attestations: [4]Scheme.Attestation = undefined;
            for (self.fixture.schemes, &attestations) |*scheme, *attestation| {
                attestation.* = (try scheme.sign(gpa, summary)).?;
            }
            const first = &self.fixture.schemes[0];
            var certificate = try first.assemble(gpa, &attestations, parallel.sequential);
            defer certificate.deinit(gpa);
            try self.ledger.post(&self.rng, &summary, &certificate);
            const posted = summary.digest();
            for (&self.validators, &proposals) |*validator, *proposal| {
                try testing.expect(proposal.summary.eql(summary));
                try validator.apply(proposal, &posted);
            }
            for (proposals[0].payouts.entries) |entry| {
                var proof = (try self.validators[0].prove_payout(summary.epoch, &entry[0])).?;
                defer proof.deinit(gpa);
                const ledger = &self.ledger;
                const account, const amount = try ledger.withdraw_payout(summary.epoch, &proof);
                try testing.expect(account.eql(entry[0]));
                try testing.expectEqual(entry[1], amount);
            }
            return summary;
        }
    };

    /// Alice pays bob just over two units, withdraws one unit through the operator, and bob
    /// forces one unit out through the ledger, all in epoch 2.
    fn pay_and_withdraw(deployment: *Deployment, keys: *const [3]secp.PrivateKey) !void {
        const key = Key.from_seed(0);
        const ns = &deployment.ns;
        var alice = try Sender.init(gpa, keys[0], ns, key.public_key());
        defer alice.deinit();
        var bob = try Receiver.init(gpa, keys[1].public_key(), ns, key.public_key(), 2);
        defer bob.deinit();
        const paid = units(2) + 1;
        const batch = try Amounts.init(gpa, &.{.{ keys[1].public_key(), paid }});
        var request = try alice.send(2, batch);
        defer request.deinit(gpa);
        const acknowledgement = try deployment.operator.accept(&request);
        const receipts = try alice.acknowledged(&acknowledgement);
        defer gpa.free(receipts);
        defer for (receipts) |*receipt| receipt.deinit(gpa);
        for (receipts) |*receipt| try testing.expectEqual(paid, try bob.receive(receipt));
        const live = deployment.operator.live(&keys[0].public_key());
        try testing.expectEqual(units(3) - 1, live);
        const withdrawal = Close.WithdrawalType.sign(&keys[0], ns, 2, unit, 0);
        try deployment.operator.withdraw(withdrawal);
        try deployment.ledger.withdraw(keys[1].public_key(), unit);
        const summary = try deployment.close();

        // The receiver records the post and finds the payment in the posted matrix.
        bob.posted(2);
        const matrix = deployment.validators[0].matrix();
        const from = keys[0].public_key();
        var opening = try matrix.open(gpa, &from, &keys[1].public_key());
        defer opening.deinit(gpa);
        try testing.expect(try bob.audit(2, &summary.matrix, &from, &opening) == null);
    }

    // The reference roles run with secp256r1 users, a BLS12-381 operator, secp256r1 validator
    // certificates, and `u256` amounts beyond the largest `u128`.
    test "lifecycle: schemes and amounts are independent" {
        var keys: [3]secp.PrivateKey = undefined;
        for (&keys, 0..) |*user, index| user.* = secp.PrivateKey.from_seed(index);
        var env: d.Env = undefined;
        try env.init(gpa, 0);
        defer env.deinit();
        var deployment: Deployment = undefined;
        try deployment.init(&env, Key.from_seed(0));
        defer deployment.deinit();
        try deployment.ledger.deposit(keys[0].public_key(), units(5));
        _ = try deployment.close();
        try pay_and_withdraw(&deployment, &keys);

        // Every role holds the balances, and the ledger holds them alone.
        const balances = [2]struct { User, A }{
            .{ keys[0].public_key(), units(2) - 1 },
            .{ keys[1].public_key(), unit + 1 },
        };
        for (balances) |entry| {
            try testing.expectEqual(entry[1], deployment.operator.balance(&entry[0]));
            for (&deployment.validators) |*validator| {
                try testing.expectEqual(entry[1], try validator.balance(&entry[0]));
            }
        }
        try testing.expectEqual(units(3), deployment.ledger.custody());

        // After a halt, each user claims its balance with a proof against the last close.
        try deployment.ledger.halt();
        for (balances) |entry| {
            var proof = (try deployment.validators[0].prove(&entry[0])).?;
            defer proof.deinit(gpa);
            const encoded = try codec.encode(Validator.BalanceProof, gpa, proof);
            defer gpa.free(encoded);
            var decoded = try codec.decode(Validator.BalanceProof, gpa, encoded);
            defer decoded.deinit(gpa);
            try testing.expect(decoded.eql(&proof));
            try testing.expectEqual(entry[1], try deployment.ledger.claim(&entry[0], &proof));
        }
        try testing.expectEqual(@as(A, 0), deployment.ledger.custody());
    }
};

test {
    _ = schemes;
}
