//! Tests of `validator.zig` (commonware `bajillion/validator.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const parallel = @import("parallel");
const mod = @import("mod.zig");
const validator = @import("validator.zig");
const summary = @import("summary.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const PublicKey = t.PublicKey;
const PrivateKey = t.PrivateKey;
const TestClose = mod.Close(PublicKey, PublicKey, u64);
const Row = TestClose.RowType;
const Withdrawal = TestClose.WithdrawalType;
const Queue = TestClose.QueueType;
const Deposit = mod.Deposit(PublicKey, u64);
const Forced = mod.ForcedWithdrawal(PublicKey, u64);
const Checkpoint = validator.Checkpoint(PublicKey, Sha256, u64);
const Checked = validator.Checked(PublicKey, Sha256, u64);
const TestSummary = summary.Summary(Sha256);
const gpa = testing.allocator;

const TestStore = t.Store(t.DefaultIndex);

/// Settles `checked` on `store` and drops the proposal, then frees `checked`.
fn expect_settles(store: *TestStore, checked: *Checked) !void {
    defer checked.deinit(gpa);
    var proposal = try store.settle(checked);
    proposal.deinit(gpa);
}

fn expect_check_error(
    expected: validator.CheckError,
    close: TestClose,
    parent: *const Checkpoint,
    ledger: *const Queue,
) !void {
    var result = t.check(close, parent, ledger);
    if (result) |*checked| checked.deinit(gpa) else |_| {}
    try testing.expectError(expected, result);
}

test "validator: payout codec" {
    const payout: validator.Payout(PublicKey, u64) = .{ .account = t.account(3), .amount = 9 };
    const encoded = codec.encode_fixed(validator.Payout(PublicKey, u64), payout);
    try testing.expectEqual(@as(usize, 40), encoded.len);
    const decoded = try codec.decode_cfg(validator.Payout(PublicKey, u64), gpa, &encoded, {});
    try testing.expect(decoded.eql(payout));
}

test "validator: validators reject invalid closes" {
    try check_rejections();
}

fn check_rejections() !void {
    const operator = t.operator_key();
    var harness = try t.Harness.init();
    defer harness.deinit();
    var store = try harness.open(t.DefaultIndex, .{});
    defer store.deinit();
    var start = try t.genesis(store.balances.root());
    defer start.deinit();
    const funding = [_]Deposit{.{ .account = t.account(0), .amount = 10 }};
    const funded = try t.sign_close(&operator, 1, &.{}, &.{}, 1, 0);
    var parent = try store.post(&start, funded, &t.queue(1, &funding, &.{}));
    defer parent.deinit();
    const deposits = [_]Deposit{.{ .account = t.account(1), .amount = 5 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 1 }};
    const queued = t.queue(2, &deposits, &forced);
    const empty = t.empty_root();

    // A close of the next epoch processing the queue is valid.
    var valid = try t.check(
        try t.sign_close(&operator, 2, &.{try t.row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1),
        &parent,
        &queued,
    );
    try expect_settles(&store, &valid);

    // It must be the next epoch and process the queue within its bounds.
    try expect_check_error(error.WrongEpoch, try t.sign_close(
        &operator,
        3,
        &.{try t.row(2, 0, &.{.{ 1, 10 }}, empty)},
        &.{},
        1,
        1,
    ), &parent, &queued);
    for ([_][2]u64{ .{ 2, 1 }, .{ 1, 2 } }) |counts| {
        const close = try t.sign_close(&operator, 2, &.{}, &.{}, counts[0], counts[1]);
        try expect_check_error(error.InvalidCount, close, &parent, &queued);
    }
    var required = queued;
    required.required_deposits = 1;
    required.required_forced_withdrawals = 1;
    for ([_][2]u64{ .{ 0, 1 }, .{ 1, 0 } }) |counts| {
        const close = try t.sign_close(&operator, 2, &.{}, &.{}, counts[0], counts[1]);
        try expect_check_error(error.InvalidCount, close, &parent, &required);
    }

    // The queue must be the ledger's while it expects this close.
    var stale = queued;
    stale.epoch = 3;
    const valid_row = try t.row(2, 0, &.{.{ 1, 10 }}, empty);
    const close = try t.sign_close(&operator, 2, &.{valid_row}, &.{}, 1, 1);
    try expect_check_error(error.WrongEpoch, close, &parent, &stale);

    try check_operator_signature(&parent, &queued);
    try check_user_signatures(&store, &parent, &queued);
    try check_checkpoint(&store, &parent);
}

/// Validators reject a close the operator did not sign before checking any user signature,
/// and the operator's signature covers every count, row, and soft withdrawal.
fn check_operator_signature(parent: *const Checkpoint, queued: *const Queue) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const impostor = t.user(5);
    var forged = try t.row(2, 0, &.{.{ 1, 10 }}, empty);
    forged.signature = impostor.sign("forged", "forged");
    var close = try t.sign_close(&impostor, 2, &.{forged}, &.{}, 1, 1);
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    close = try t.sign_close(&operator, 2, &.{try t.row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    close.deposits = 0;
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    // Adding a row or a soft withdrawal its account signed breaks the operator's signature.
    close = try t.sign_close(&operator, 2, &.{try t.row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    const added = try t.row(2, 1, &.{.{ 0, 1 }}, empty);
    const rows = try gpa.alloc(Row, 2);
    rows[0] = close.rows[0];
    rows[1] = added;
    std.mem.sort(Row, rows, {}, t.less_row);
    gpa.free(close.rows);
    close.rows = rows;
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    close = try t.sign_close(&operator, 2, &.{try t.row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    const signer = t.user(0);
    gpa.free(close.withdrawals);
    close.withdrawals = try gpa.dupe(Withdrawal, &.{Withdrawal.sign(&signer, &namespace, 2, 1, 0)});
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);
}

/// Every sender must sign its row for this epoch on top of its row in the parent close, and
/// soft withdrawals must be for this epoch and signed by their account.
fn check_user_signatures(
    store: *TestStore,
    parent: *const Checkpoint,
    queued: *const Queue,
) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var altered = try t.row(2, 0, &.{.{ 1, 10 }}, empty);
    var nine = try t.amounts(gpa, &.{.{ 1, 9 }});
    std.mem.swap(t.TestAmounts, &altered.payments, &nine);
    nine.deinit(gpa);
    var elsewhere = try t.amounts(gpa, &.{.{ 1, 1 }});
    defer elsewhere.deinit(gpa);
    const rows = [_]Row{
        altered,
        try t.row(1, 0, &.{.{ 1, 10 }}, empty),
        try t.row(2, 0, &.{.{ 1, 10 }}, elsewhere.root(Sha256)),
    };
    for (rows) |invalid| {
        const close = try t.sign_close(&operator, 2, &.{invalid}, &.{}, 1, 1);
        try expect_check_error(error.InvalidSignature, close, parent, queued);
    }

    const signer = t.user(0);
    const wrong_epoch = Withdrawal.sign(&signer, &namespace, 3, 1, 0);
    var close = try t.sign_close(&operator, 2, &.{}, &.{wrong_epoch}, 1, 1);
    try expect_check_error(error.WrongEpoch, close, parent, queued);
    var forged = Withdrawal.sign(&signer, &namespace, 2, 1, 0);
    forged.amount = 2;
    close = try t.sign_close(&operator, 2, &.{}, &.{forged}, 1, 1);
    try expect_check_error(error.InvalidSignature, close, parent, queued);

    // No balance may go negative, even when the sender signed the payment.
    close = try t.sign_close(&operator, 2, &.{try t.row(2, 1, &.{.{ 0, 6 }}, empty)}, &.{}, 1, 1);
    var overdraft = try t.check(close, parent, queued);
    defer overdraft.deinit(gpa);
    try testing.expectError(error.Overdraft, store.settle(&overdraft));
}

/// A sender's next row builds on the map the posted close settled for it, and a checkpoint
/// whose matrix is not its summary's is refused.
fn check_checkpoint(store: *TestStore, grandparent: *const Checkpoint) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    const deposits = [_]Deposit{.{ .account = t.account(1), .amount = 5 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 1 }};
    const paying = try t.row(2, 0, &.{.{ 1, 5 }}, empty);
    var parent = try store.post(
        grandparent,
        try t.sign_close(&operator, 2, &.{paying}, &.{}, 1, 1),
        &t.queue(2, &deposits, &forced),
    );
    defer parent.deinit();
    const next = t.queue(3, &.{}, &.{});
    const unanchored = try t.row(3, 0, &.{.{ 1, 1 }}, empty);
    var close = try t.sign_close(&operator, 3, &.{unanchored}, &.{}, 0, 0);
    try expect_check_error(error.InvalidSignature, close, &parent, &next);
    var settled = try t.amounts(gpa, &.{.{ 1, 5 }});
    defer settled.deinit(gpa);
    const anchored = try t.row(3, 0, &.{.{ 1, 1 }}, settled.root(Sha256));
    const anchored_close = try t.sign_close(&operator, 3, &.{anchored}, &.{}, 0, 0);
    var checked = try t.check(anchored_close, &parent, &next);
    try expect_settles(store, &checked);

    var mismatched = parent.clone();
    mismatched.matrix.deinit();
    mismatched.matrix = try mod.Matrix(PublicKey, Sha256, u64).empty(gpa);
    defer mismatched.deinit();
    close = try t.sign_close(&operator, 3, &.{}, &.{}, 0, 0);
    try expect_check_error(error.InvalidCheckpoint, close, &mismatched, &next);
}

test "validator: check chains the running hashes" {
    const operator = t.operator_key();
    var harness = try t.Harness.init();
    defer harness.deinit();
    var store = try harness.open(t.DefaultIndex, .{});
    defer store.deinit();
    var start = try t.genesis(store.balances.root());
    defer start.deinit();

    // The close of epoch 1 processes two of three deposits and the forced withdrawal.
    const all = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 20 },
        .{ .account = t.account(2), .amount = 30 },
    };
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 3 }};
    const close = try t.sign_close(&operator, 1, &.{}, &.{}, 2, 1);
    var first = try store.post(&start, close, &t.queue(1, &all, &forced));
    defer first.deinit();
    const deposits = first.summary.deposits;
    try testing.expectEqual(@as(u64, 2), deposits.count);
    try testing.expect(deposits.hash.eql(t.chain(Deposit, .empty, all[0..2])));
    try testing.expectEqual(@as(u64, 1), first.summary.forced_withdrawals.count);
    try testing.expect(first.summary.forced_withdrawals.hash.eql(t.chain(Forced, .empty, &forced)));

    // The close of epoch 2 processes the remaining deposit and no forced withdrawal.
    var queued = t.queue(2, all[2..], &.{});
    queued.required_deposits = 1;
    const next_close = try t.sign_close(&operator, 2, &.{}, &.{}, 1, 0);
    var second = try store.post(&first, next_close, &queued);
    defer second.deinit();
    const next = second.summary.deposits;
    try testing.expectEqual(@as(u64, 1), next.count);
    try testing.expect(next.hash.eql(t.chain(Deposit, deposits.hash, all[2..])));
    try testing.expect(next.hash.eql(t.chain(Deposit, .empty, &all)));
    try testing.expectEqual(@as(u64, 0), second.summary.forced_withdrawals.count);
    const carried = first.summary.forced_withdrawals.hash;
    try testing.expect(second.summary.forced_withdrawals.hash.eql(carried));
}

const Log = validator.Payouts(PublicKey, Sha256, u64);
const Payout = validator.Payout(PublicKey, u64);
const PayoutProof = validator.PayoutProof(PublicKey, Digest, u64);

/// Stages and applies the payouts `entries` of one posted close on `log`.
fn pay(log: *Log, entries: []const [2]u64) !void {
    var payouts = try t.amounts(gpa, entries);
    defer payouts.deinit(gpa);
    const batch = try Payout.stage(log, &payouts);
    defer batch.release();
    try log.apply_batch(batch);
}

/// The proof of the one operation at `index` in `log` under its current root, and the payout
/// there, if the operation is one.
fn prove(log: *Log, index: u64) !struct { PayoutProof.Proof, ?Payout } {
    const items = try log.proof(index, 1);
    defer codec.free_items(Log.Operation, gpa, items.items);
    defer gpa.free(items.items);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    const payout: ?Payout = switch (items.items[0]) {
        .append => |logged| logged,
        .commit => null,
    };
    return .{ items.proof, payout };
}

test "validator: stage keeps the floor at zero" {
    var harness = try t.Harness.init();
    defer harness.deinit();
    var log = try harness.open_log(null);
    defer log.deinit();
    try pay(&log, &.{ .{ 0, 4 }, .{ 2, 30 } });
    try testing.expectEqual(@as(u64, 0), log.inactivity_floor());
    try testing.expectEqual(@as(u64, 4), log.bounds().end);

    // A commit that raises the floor leaves the log unable to stage a close's payouts.
    var raised = try log.new_batch();
    raised.with_inactivity_floor(1);
    const merkleized = merkleized: {
        errdefer raised.deinit();
        break :merkleized try raised.merkleize(&log);
    };
    defer merkleized.release();
    try log.apply_batch(merkleized);
    try testing.expectEqual(@as(u64, 1), log.inactivity_floor());
    var payouts = try t.amounts(gpa, &.{ .{ 0, 4 }, .{ 2, 30 } });
    defer payouts.deinit(gpa);
    try testing.expectError(error.FloorRegressed, Payout.stage(&log, &payouts));
}

test "validator: payout proof verifies only the logged payout" {
    var harness = try t.Harness.init();
    defer harness.deinit();
    var log = try harness.open_log(null);
    defer log.deinit();
    // The close of epoch 1 pays out 3 and 4 on the forced withdrawals of users 0 and 1.
    try pay(&log, &.{ .{ 0, 3 }, .{ 1, 4 } });
    const root = log.root();

    // The payout at index 1 proves, and its proof round-trips.
    const proof, const logged = try prove(&log, 1);
    const payout = logged.?;
    var valid: PayoutProof = .{ .index = 1, .payout = payout, .proof = proof };
    defer valid.deinit(gpa);
    try testing.expect(valid.verify(Sha256, &root));
    const encoded = try codec.encode(PayoutProof, gpa, valid);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(PayoutProof, gpa, encoded, {});
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&valid));

    // Another index, account, or amount does not verify, and neither does an index past the
    // log or one no log can hold.
    const other = if (payout.account.eql(t.account(0))) t.account(1) else t.account(0);
    const forged = [_]struct { u64, Payout }{
        .{ 2, payout },
        .{ 1, .{ .account = other, .amount = payout.amount } },
        .{ 1, .{ .account = payout.account, .amount = payout.amount + 1 } },
        .{ 100, payout },
        .{ std.math.maxInt(u64), payout },
    };
    for (forged) |claim| {
        var claimed = valid;
        claimed.index = claim[0];
        claimed.payout = claim[1];
        try testing.expect(!claimed.verify(Sha256, &root));
    }

    // The root binds the log's size and its count of inactive peaks.
    var resized = valid;
    resized.proof.leaves += 1;
    try testing.expect(!resized.verify(Sha256, &root));
    var inactive = valid;
    inactive.proof.inactive_peaks = 1;
    try testing.expect(!inactive.verify(Sha256, &root));

    // The commit position does not verify as a payout.
    const commit = log.bounds().end - 1;
    const commit_proof, const at_commit = try prove(&log, commit);
    try testing.expect(at_commit == null);
    var claimed: PayoutProof = .{ .index = commit, .payout = payout, .proof = commit_proof };
    defer claimed.deinit(gpa);
    try testing.expect(!claimed.verify(Sha256, &root));

    // After a later close, the proof fails under the new root and a fresh one verifies.
    try pay(&log, &.{});
    const later = log.root();
    try testing.expect(!valid.verify(Sha256, &later));
    const fresh_proof, _ = try prove(&log, valid.index);
    var fresh: PayoutProof = .{ .index = valid.index, .payout = payout, .proof = fresh_proof };
    defer fresh.deinit(gpa);
    try testing.expect(fresh.verify(Sha256, &later));
}

test "validator: payout proof distinguishes payouts from commits" {
    var harness = try t.Harness.init();
    defer harness.deinit();
    var log = try harness.open_log(null);
    defer log.deinit();
    const payout: Payout = .{ .account = t.account(0), .amount = 7 };
    var batch = try log.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try batch.append(payout);
        batch.with_metadata(payout);
        batch.with_inactivity_floor(0);
        break :merkleized try batch.merkleize(&log);
    };
    defer merkleized.release();
    try log.apply_batch(merkleized);
    try log.commit();
    try testing.expect((try log.get_metadata()).?.eql(payout));
    const root = log.root();
    for ([_]u64{ 1, 2 }) |index| {
        const proof, _ = try prove(&log, index);
        var claimed: PayoutProof = .{ .index = index, .payout = payout, .proof = proof };
        defer claimed.deinit(gpa);
        try testing.expectEqual(index == 1, claimed.verify(Sha256, &root));
    }
}
