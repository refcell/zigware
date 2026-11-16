//! Tests of `validator.zig` (commonware `bajillion/validator.rs` tests). Until the balances
//! database lands, parents are built from checked closes directly instead of being settled.

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

/// Returns a row of `sender` for `epoch` paying `entries`, signed on top of `previous`.
fn row(epoch: u64, sender: u64, entries: []const [2]u64, previous: Digest) !Row {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const payments = try t.amounts(gpa, entries);
    const state: mod.State(PublicKey, Digest) = .{
        .epoch = epoch,
        .account = t.account(sender),
        .payments = payments.root(Sha256),
        .previous = previous,
    };
    const signer = t.user(sender);
    return .{
        .account = t.account(sender),
        .payments = payments,
        .signature = state.sign(&signer, &namespace),
    };
}

fn less_row(_: void, a: Row, b: Row) bool {
    return a.account.order(b.account) == .lt;
}

/// Signs a close of `rows` and `withdrawals` as `operator`, without checking its contents.
/// Takes ownership of the rows.
fn sign_close(
    operator: *const PrivateKey,
    epoch: u64,
    rows: []const Row,
    withdrawals: []const Withdrawal,
    deposits: u64,
    forced_withdrawals: u64,
) !TestClose {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const owned_rows = try gpa.dupe(Row, rows);
    std.mem.sort(Row, owned_rows, {}, less_row);
    const owned_withdrawals = try gpa.dupe(Withdrawal, withdrawals);
    return TestClose.sign(
        Sha256,
        gpa,
        operator,
        &namespace,
        epoch,
        owned_rows,
        owned_withdrawals,
        deposits,
        forced_withdrawals,
        parallel.sequential,
    );
}

fn queue(
    epoch: u64,
    deposits: []const Deposit,
    forced: []const Forced,
) Queue {
    return .{
        .epoch = epoch,
        .deposits = deposits,
        .required_deposits = 0,
        .forced_withdrawals = forced,
        .required_forced_withdrawals = 0,
    };
}

fn genesis() !Checkpoint {
    return .{
        .summary = TestSummary.genesis(PublicKey, u64, Sha256.hash(&.{"balances"})),
        .matrix = try mod.Matrix(PublicKey, Sha256, u64).empty(gpa),
    };
}

/// Checks `close` as the successor of `parent` against `queue`, then frees the close.
fn check(close: TestClose, parent: *const Checkpoint, ledger: *const Queue) !Checked {
    var owned = close;
    defer owned.deinit(gpa);
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const operator = t.operator_key().public_key();
    return Checked.check(
        PublicKey,
        gpa,
        &owned,
        &namespace,
        &operator,
        parent,
        ledger,
        parallel.sequential,
    );
}

fn expect_check_error(
    expected: validator.CheckError,
    close: TestClose,
    parent: *const Checkpoint,
    ledger: *const Queue,
) !void {
    var result = check(close, parent, ledger);
    if (result) |*checked| checked.deinit(gpa) else |_| {}
    try testing.expectError(expected, result);
}

/// The checkpoint `checked` leaves once it posts, standing in for settling it.
fn post(checked: *Checked) Checkpoint {
    defer checked.deinit(gpa);
    return .{
        .summary = .{
            .epoch = checked.epoch,
            .parent = checked.parent.digest(),
            .matrix = checked.matrix.root(),
            .balances = checked.parent.balances,
            .payouts = checked.parent.payouts,
            .deposits = checked.deposits,
            .forced_withdrawals = checked.forced_withdrawals,
        },
        .matrix = checked.matrix.clone(),
    };
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
    var start = try genesis();
    defer start.deinit();
    const funding = [_]Deposit{.{ .account = t.account(0), .amount = 10 }};
    var funded = try check(
        try sign_close(&operator, 1, &.{}, &.{}, 1, 0),
        &start,
        &queue(1, &funding, &.{}),
    );
    var parent = post(&funded);
    defer parent.deinit();
    const deposits = [_]Deposit{.{ .account = t.account(1), .amount = 5 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 1 }};
    const queued = queue(2, &deposits, &forced);
    const empty = t.empty_root();

    // A close of the next epoch processing the queue is valid.
    var valid = try check(
        try sign_close(&operator, 2, &.{try row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1),
        &parent,
        &queued,
    );
    valid.deinit(gpa);

    // It must be the next epoch and process the queue within its bounds.
    try expect_check_error(error.WrongEpoch, try sign_close(
        &operator,
        3,
        &.{try row(2, 0, &.{.{ 1, 10 }}, empty)},
        &.{},
        1,
        1,
    ), &parent, &queued);
    for ([_][2]u64{ .{ 2, 1 }, .{ 1, 2 } }) |counts| {
        const close = try sign_close(&operator, 2, &.{}, &.{}, counts[0], counts[1]);
        try expect_check_error(error.InvalidCount, close, &parent, &queued);
    }
    var required = queued;
    required.required_deposits = 1;
    required.required_forced_withdrawals = 1;
    for ([_][2]u64{ .{ 0, 1 }, .{ 1, 0 } }) |counts| {
        const close = try sign_close(&operator, 2, &.{}, &.{}, counts[0], counts[1]);
        try expect_check_error(error.InvalidCount, close, &parent, &required);
    }

    // The queue must be the ledger's while it expects this close.
    var stale = queued;
    stale.epoch = 3;
    const valid_row = try row(2, 0, &.{.{ 1, 10 }}, empty);
    const close = try sign_close(&operator, 2, &.{valid_row}, &.{}, 1, 1);
    try expect_check_error(error.WrongEpoch, close, &parent, &stale);

    try check_operator_signature(&parent, &queued);
    try check_user_signatures(&parent, &queued);
    try check_checkpoint(&parent);
}

/// Validators reject a close the operator did not sign before checking any user signature,
/// and the operator's signature covers every count, row, and soft withdrawal.
fn check_operator_signature(parent: *const Checkpoint, queued: *const Queue) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const impostor = t.user(5);
    var forged = try row(2, 0, &.{.{ 1, 10 }}, empty);
    forged.signature = impostor.sign("forged", "forged");
    var close = try sign_close(&impostor, 2, &.{forged}, &.{}, 1, 1);
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    close = try sign_close(&operator, 2, &.{try row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    close.deposits = 0;
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    // Adding a row or a soft withdrawal its account signed breaks the operator's signature.
    close = try sign_close(&operator, 2, &.{try row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    const added = try row(2, 1, &.{.{ 0, 1 }}, empty);
    const rows = try gpa.alloc(Row, 2);
    rows[0] = close.rows[0];
    rows[1] = added;
    std.mem.sort(Row, rows, {}, less_row);
    gpa.free(close.rows);
    close.rows = rows;
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);

    close = try sign_close(&operator, 2, &.{try row(2, 0, &.{.{ 1, 10 }}, empty)}, &.{}, 1, 1);
    const signer = t.user(0);
    gpa.free(close.withdrawals);
    close.withdrawals = try gpa.dupe(Withdrawal, &.{Withdrawal.sign(&signer, &namespace, 2, 1, 0)});
    try expect_check_error(error.InvalidOperatorSignature, close, parent, queued);
}

/// Every sender must sign its row for this epoch on top of its row in the parent close, and
/// soft withdrawals must be for this epoch and signed by their account.
fn check_user_signatures(parent: *const Checkpoint, queued: *const Queue) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    var altered = try row(2, 0, &.{.{ 1, 10 }}, empty);
    var nine = try t.amounts(gpa, &.{.{ 1, 9 }});
    std.mem.swap(t.TestAmounts, &altered.payments, &nine);
    nine.deinit(gpa);
    var elsewhere = try t.amounts(gpa, &.{.{ 1, 1 }});
    defer elsewhere.deinit(gpa);
    const rows = [_]Row{
        altered,
        try row(1, 0, &.{.{ 1, 10 }}, empty),
        try row(2, 0, &.{.{ 1, 10 }}, elsewhere.root(Sha256)),
    };
    for (rows) |invalid| {
        const close = try sign_close(&operator, 2, &.{invalid}, &.{}, 1, 1);
        try expect_check_error(error.InvalidSignature, close, parent, queued);
    }

    const signer = t.user(0);
    const wrong_epoch = Withdrawal.sign(&signer, &namespace, 3, 1, 0);
    var close = try sign_close(&operator, 2, &.{}, &.{wrong_epoch}, 1, 1);
    try expect_check_error(error.WrongEpoch, close, parent, queued);
    var forged = Withdrawal.sign(&signer, &namespace, 2, 1, 0);
    forged.amount = 2;
    close = try sign_close(&operator, 2, &.{}, &.{forged}, 1, 1);
    try expect_check_error(error.InvalidSignature, close, parent, queued);

    // An overdraft checks; settling refuses it.
    close = try sign_close(&operator, 2, &.{try row(2, 1, &.{.{ 0, 6 }}, empty)}, &.{}, 1, 1);
    var overdraft = try check(close, parent, queued);
    overdraft.deinit(gpa);
}

/// A sender's next row builds on the map the posted close settled for it, and a checkpoint
/// whose matrix is not its summary's is refused.
fn check_checkpoint(grandparent: *const Checkpoint) !void {
    const operator = t.operator_key();
    const empty = t.empty_root();
    const deposits = [_]Deposit{.{ .account = t.account(1), .amount = 5 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 1 }};
    var paying = try check(
        try sign_close(&operator, 2, &.{try row(2, 0, &.{.{ 1, 5 }}, empty)}, &.{}, 1, 1),
        grandparent,
        &queue(2, &deposits, &forced),
    );
    var parent = post(&paying);
    defer parent.deinit();
    const next = queue(3, &.{}, &.{});
    var close = try sign_close(&operator, 3, &.{try row(3, 0, &.{.{ 1, 1 }}, empty)}, &.{}, 0, 0);
    try expect_check_error(error.InvalidSignature, close, &parent, &next);
    var settled = try t.amounts(gpa, &.{.{ 1, 5 }});
    defer settled.deinit(gpa);
    const anchored = try row(3, 0, &.{.{ 1, 1 }}, settled.root(Sha256));
    var checked = try check(try sign_close(&operator, 3, &.{anchored}, &.{}, 0, 0), &parent, &next);
    checked.deinit(gpa);

    var mismatched = parent.clone();
    mismatched.matrix.deinit();
    mismatched.matrix = try mod.Matrix(PublicKey, Sha256, u64).empty(gpa);
    defer mismatched.deinit();
    close = try sign_close(&operator, 3, &.{}, &.{}, 0, 0);
    try expect_check_error(error.InvalidCheckpoint, close, &mismatched, &next);
}

test "validator: check chains the running hashes" {
    const operator = t.operator_key();
    var start = try genesis();
    defer start.deinit();

    // The close of epoch 1 processes two of three deposits and the forced withdrawal.
    const all = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 20 },
        .{ .account = t.account(2), .amount = 30 },
    };
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 3 }};
    var checked = try check(
        try sign_close(&operator, 1, &.{}, &.{}, 2, 1),
        &start,
        &queue(1, &all, &forced),
    );
    var first = post(&checked);
    defer first.deinit();
    const deposits = first.summary.deposits;
    try testing.expectEqual(@as(u64, 2), deposits.count);
    try testing.expect(deposits.hash.eql(chain(Deposit, .empty, all[0..2])));
    try testing.expectEqual(@as(u64, 1), first.summary.forced_withdrawals.count);
    try testing.expect(first.summary.forced_withdrawals.hash.eql(chain(Forced, .empty, &forced)));

    // The close of epoch 2 processes the remaining deposit and no forced withdrawal.
    var queued = queue(2, all[2..], &.{});
    queued.required_deposits = 1;
    checked = try check(try sign_close(&operator, 2, &.{}, &.{}, 1, 0), &first, &queued);
    var second = post(&checked);
    defer second.deinit();
    const next = second.summary.deposits;
    try testing.expectEqual(@as(u64, 1), next.count);
    try testing.expect(next.hash.eql(chain(Deposit, deposits.hash, all[2..])));
    try testing.expect(next.hash.eql(chain(Deposit, .empty, &all)));
    try testing.expectEqual(@as(u64, 0), second.summary.forced_withdrawals.count);
    const carried = first.summary.forced_withdrawals.hash;
    try testing.expect(second.summary.forced_withdrawals.hash.eql(carried));
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`.
fn chain(comptime R: type, hash: Digest, requests: []const R) Digest {
    var result = hash;
    for (requests) |request| {
        const encoded = codec.encode_fixed(R, request);
        result = Sha256.hash(&.{ &result.bytes, &encoded });
    }
    return result;
}
