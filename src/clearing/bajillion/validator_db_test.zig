//! Tests of settling and applying closes on the validators' databases (commonware
//! `bajillion/validator.rs` tests over `Balances` and `Payouts`).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const storage = @import("storage");
const t = @import("testing.zig");

const Digest = t.Digest;
const PublicKey = t.PublicKey;
const Checkpoint = t.Checkpoint;
const Checked = t.Checked;
const Deposit = t.Deposit;
const Forced = t.Forced;
const TestStore = t.Store(t.DefaultIndex);
const Proposal = TestStore.Proposal;
const Payout = @import("validator.zig").Payout(PublicKey, u64);
const gpa = testing.allocator;

/// The close of one epoch of `churn` with the queue it processes in full: it credits six of 13
/// accounts, and every fourth epoch pays three of them out in full. The accounts of users 42,
/// 46, and 51 share their first byte.
const Churn = struct {
    epoch: u64,
    deposits: [6]Deposit,
    forced: [3]Forced,
    forced_len: usize,

    fn init(epoch: u64) Churn {
        var churn: Churn = .{
            .epoch = epoch,
            .deposits = undefined,
            .forced = undefined,
            .forced_len = if (epoch % 4 == 0) 3 else 0,
        };
        for (&churn.deposits, 0..) |*deposit, index| {
            deposit.* = .{
                .account = t.account(40 + (index + epoch) % 13),
                .amount = 1 + epoch * 3 + index,
            };
        }
        for (&churn.forced, 0..) |*forced, index| {
            forced.* = .{
                .account = t.account(40 + (index * 5 + epoch) % 13),
                .amount = std.math.maxInt(u64),
            };
        }
        return churn;
    }

    fn queue(self: *const Churn) t.Queue {
        return t.queue(self.epoch, &self.deposits, self.forced[0..self.forced_len]);
    }

    fn close(self: *const Churn) !t.TestClose {
        const operator = t.operator_key();
        return t.sign_close(&operator, self.epoch, &.{}, &.{}, 6, self.forced_len);
    }
};

/// Posts the churn closes of epochs `first` to `first + roots.len - 1` in order on `store`
/// from `parent`, committing after each, and returns the last checkpoint. Writes the balances
/// root after each close to `roots`.
fn replay(store: anytype, parent: *const Checkpoint, first: u64, roots: []Digest) !Checkpoint {
    var current = parent.clone();
    errdefer current.deinit();
    for (roots, 0..) |*root, offset| {
        const churn = Churn.init(first + offset);
        const queued = churn.queue();
        const next = try store.post(&current, try churn.close(), &queued);
        current.deinit();
        current = next;
        try store.commit();
        root.* = store.balances.root();
    }
    return current;
}

/// The checkpoint `proposal`'s close leaves once it posts.
fn checkpoint(proposal: *const Proposal) Checkpoint {
    return .{ .summary = proposal.summary, .matrix = proposal.matrix.clone() };
}

/// Reopens both databases of `store` as after a restart.
fn reopen(harness: *t.Harness, store: *TestStore) !void {
    store.deinit();
    store.* = try harness.open(t.DefaultIndex, .{});
}

fn expect_roots(store: anytype, balances: Digest, payouts: Digest) !void {
    try testing.expect(store.balances.root().eql(balances));
    try testing.expect(store.log.root().eql(payouts));
}

fn expect_same_roots(store: anytype, roots: [2]Digest) !void {
    try expect_roots(store, roots[0], roots[1]);
}

/// Checks `close` against `parent` and `ledger`, signed by the operator with no rows or soft
/// withdrawals, processing `deposits` and `forced` requests.
fn check_counts(
    epoch: u64,
    deposits: u64,
    forced: u64,
    parent: *const Checkpoint,
    ledger: *const t.Queue,
) !Checked {
    const operator = t.operator_key();
    const close = try t.sign_close(&operator, epoch, &.{}, &.{}, deposits, forced);
    return t.check(close, parent, ledger);
}

/// Opens a store over the default index in its own storage.
const Opened = struct {
    harness: t.Harness,
    store: TestStore,

    fn init(self: *Opened) !void {
        self.harness = try t.Harness.init();
        errdefer self.harness.deinit();
        self.store = try self.harness.open(t.DefaultIndex, .{});
    }

    fn deinit(self: *Opened) void {
        self.store.deinit();
        self.harness.deinit();
    }
};

// A posted close appends exactly its payouts to the payout log, in account order from the
// parent's payouts size up to its commit. Settling refuses a log not at the parent's payouts
// root.
test "validator: settle appends the payouts in account order" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var parent = try t.genesis(store.balances.root());
    defer parent.deinit();
    try testing.expect(parent.summary.payouts.root.eql(store.log.root()));
    try testing.expectEqual(parent.summary.payouts.size, store.log.bounds().end);

    // The close of epoch 1 credits three accounts and pays two of them out.
    const deposits = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 20 },
        .{ .account = t.account(2), .amount = 30 },
    };
    const forced = [_]Forced{
        .{ .account = t.account(2), .amount = 30 },
        .{ .account = t.account(0), .amount = 4 },
    };
    var checked = try check_counts(1, 3, 2, &parent, &t.queue(1, &deposits, &forced));
    defer checked.deinit(gpa);
    var proposal = try store.settle(&checked);
    defer proposal.deinit(gpa);
    var expected = try t.amounts(gpa, &.{ .{ 0, 4 }, .{ 2, 30 } });
    defer expected.deinit(gpa);
    try testing.expect(proposal.payouts.eql(&expected));
    const summary = proposal.summary;
    try testing.expectEqual(parent.summary.payouts.size + 3, summary.payouts.size);
    var first = try store.apply(&proposal, &summary.digest());
    defer first.deinit();
    try testing.expect(store.log.root().eql(summary.payouts.root));
    try testing.expectEqual(summary.payouts.size, store.log.bounds().end);

    // Each payout sits at the parent's payouts size plus its account's position in the
    // close's payouts, and the commit follows them.
    const start = parent.summary.payouts.size;
    for (expected.entries) |entry| {
        const position = expected.position(&entry[0]).?;
        const payout = (try store.log.get(start + position)).?;
        try testing.expect(payout.eql(.{ .account = entry[0], .amount = entry[1] }));
    }
    try testing.expectEqual(null, expected.position(&t.account(1)));
    try testing.expectEqual(null, try store.log.get(summary.payouts.size - 1));

    // A close with no payouts appends only its commit.
    var idle_checked = try check_counts(2, 0, 0, &first, &t.queue(2, &.{}, &.{}));
    defer idle_checked.deinit(gpa);
    var idle = try store.settle(&idle_checked);
    defer idle.deinit(gpa);
    try testing.expect(idle.payouts.is_empty());
    try testing.expectEqual(summary.payouts.size + 1, idle.summary.payouts.size);

    // A log at another root refuses the close, even with the balances at the parent's.
    var other: Opened = undefined;
    try other.init();
    defer other.deinit();
    const refused = idle_checked.settle(gpa, &store.balances, &other.store.log);
    try testing.expectError(error.InvalidCheckpoint, refused);
}

// A proposal applies only as the posted close, on the databases it settled on. A refused
// apply leaves both databases as they were.
test "validator: applies only the posted close" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var parent = try t.genesis(store.balances.root());
    defer parent.deinit();
    const deposits = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 20 },
    };
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 3 }};
    const queued = t.queue(1, &deposits, &forced);

    // Two closes for epoch 1 differ in how many deposits they process.
    var first_checked = try check_counts(1, 1, 1, &parent, &queued);
    defer first_checked.deinit(gpa);
    var second_checked = try check_counts(1, 2, 1, &parent, &queued);
    defer second_checked.deinit(gpa);
    var first = try store.settle(&first_checked);
    defer first.deinit(gpa);
    var duplicate = try store.settle(&second_checked);
    defer duplicate.deinit(gpa);
    var second = try store.settle(&second_checked);
    defer second.deinit(gpa);
    try testing.expect(!first.summary.eql(second.summary));
    try testing.expect(duplicate.summary.eql(second.summary));

    // A proposal that did not post is refused before either database changes.
    const posted = second.summary.digest();
    const before = store.roots();
    try testing.expectError(error.InvalidCheckpoint, store.apply(&first, &posted));
    try reopen(&opened.harness, store);
    try expect_same_roots(store, before);

    // The posted one applies once. A second copy of it is stale on top of it, and the refusal
    // leaves the committed roots.
    var applied = try store.apply(&second, &posted);
    defer applied.deinit();
    try store.commit();
    try expect_roots(store, applied.summary.balances, applied.summary.payouts.root);
    try testing.expectEqual(@as(?u64, 20), try store.balances.get(&t.account(1)));
    try testing.expectError(error.InvalidCheckpoint, store.apply(&duplicate, &posted));
    try reopen(&opened.harness, store);
    try expect_roots(store, applied.summary.balances, applied.summary.payouts.root);

    // The other candidate does not settle on it.
    var other = try check_counts(1, 1, 1, &parent, &queued);
    defer other.deinit(gpa);
    try testing.expectError(error.InvalidCheckpoint, store.settle(&other));
}

// Apply checks the posted digest and both databases' roots before it touches either database.
// Each refusal leaves both databases where they were, including a payout log at the parent's
// root beside balances elsewhere.
test "validator: apply refuses before touching either database" {
    var here: Opened = undefined;
    try here.init();
    defer here.deinit();
    var elsewhere: Opened = undefined;
    try elsewhere.init();
    defer elsewhere.deinit();
    var parent = try t.genesis(here.store.balances.root());
    defer parent.deinit();
    const deposits = [_]Deposit{.{ .account = t.account(0), .amount = 10 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 4 }};
    const queued = t.queue(1, &deposits, &forced);
    var checked = try check_counts(1, 1, 1, &parent, &queued);
    defer checked.deinit(gpa);
    const operator = t.operator_key();
    const close = try t.sign_close(&operator, 1, &.{}, &.{}, 1, 1);
    var moved_checkpoint = try elsewhere.store.post(&parent, close, &queued);
    defer moved_checkpoint.deinit();
    try elsewhere.store.commit();
    const at_parent = here.store.roots();
    const moved = elsewhere.store.roots();

    // The posted digest is not the proposal's.
    {
        var proposal = try here.store.settle(&checked);
        defer proposal.deinit(gpa);
        try testing.expectError(error.InvalidCheckpoint, here.store.apply(&proposal, &.empty));
    }
    try reopen(&here.harness, &here.store);
    try expect_same_roots(&here.store, at_parent);

    // The balances are elsewhere, so the log beside them must not advance; then the log is.
    var proposal = try here.store.settle(&checked);
    defer proposal.deinit(gpa);
    const posted = proposal.summary.digest();
    const mixed = [_]struct { *t.Db(t.DefaultIndex), *t.Log }{
        .{ &elsewhere.store.balances, &here.store.log },
        .{ &here.store.balances, &elsewhere.store.log },
    };
    for (mixed) |databases| {
        const result = proposal.apply(databases[0], databases[1], &posted);
        try testing.expectError(error.InvalidCheckpoint, result);
        try reopen(&here.harness, &here.store);
        try reopen(&elsewhere.harness, &elsewhere.store);
        try expect_same_roots(&here.store, at_parent);
        try expect_same_roots(&elsewhere.store, moved);
    }
}

// A validator that applies several posted closes before committing its balances may stop with
// the balances holding any of them, because applied writes can reach disk before a commit, and
// with the log at the last one. Reopening the log at the payouts size of the close the
// balances hold discards the rest, and replaying from that close reaches the roots of a
// validator that committed after every close.
test "validator: log rewinds past several closes" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var start = try t.genesis(store.balances.root());
    defer start.deinit();
    var first_root: [1]Digest = undefined;
    var applied: [4]Checkpoint = undefined;
    applied[0] = try replay(store, &start, 1, &first_root);
    var count: usize = 1;
    defer for (applied[0..count]) |*checkpoint_| checkpoint_.deinit();

    // The closes of epochs 2 to 4 apply without a balances commit. The close of epoch 4 pays
    // forced withdrawals out, so the log gains payouts and not only commits.
    while (count < applied.len) : (count += 1) {
        const churn = Churn.init(count + 1);
        const queued = churn.queue();
        applied[count] = try store.post(&applied[count - 1], try churn.close(), &queued);
    }
    const last = &applied[applied.len - 1];
    try testing.expect(last.summary.payouts.size > applied[0].summary.payouts.size + 3);

    // The balances hold one of the applied closes, and the log is past it.
    opened.harness.storage.crash();
    try reopen(&opened.harness, store);
    const held = for (&applied, 0..) |*checkpoint_, index| {
        if (checkpoint_.summary.balances.eql(store.balances.root())) break index;
    } else return error.TestUnexpectedResult; // The balances must hold an applied close.
    try testing.expect(store.log.root().eql(last.summary.payouts.root));
    try testing.expect(applied[held].summary.payouts.size < last.summary.payouts.size);

    // The log reopens at that close's payouts size, and the replay converges with a validator
    // that committed after every close.
    store.log.deinit();
    store.log = try opened.harness.open_log(applied[held].summary.payouts.size);
    try testing.expect(store.log.root().eql(applied[held].summary.payouts.root));
    var rewound: [6]Digest = undefined;
    const tail = rewound[held + 1 ..];
    var rewound_parent = try replay(store, &applied[held], held + 2, tail);
    defer rewound_parent.deinit();
    var fresh: Opened = undefined;
    try fresh.init();
    defer fresh.deinit();
    var expected: [6]Digest = undefined;
    var fresh_parent = try replay(&fresh.store, &start, 1, &expected);
    defer fresh_parent.deinit();
    for (tail, expected[held + 1 ..]) |a, b| try testing.expect(a.eql(b));
    try testing.expect(rewound_parent.summary.eql(fresh_parent.summary));
    try expect_same_roots(store, fresh.store.roots());
}

// Settling stages a batch without applying it, and when the payout log then cannot be made
// durable, apply fails before it applies anything to the balances.
test "validator: apply writes no balance before the log is durable" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var start = try t.genesis(store.balances.root());
    defer start.deinit();
    const deposits = [_]Deposit{.{ .account = t.account(0), .amount = 10 }};
    const operator = t.operator_key();
    const close = try t.sign_close(&operator, 1, &.{}, &.{}, 1, 0);
    var parent = try store.post(&start, close, &t.queue(1, &deposits, &.{}));
    defer parent.deinit();
    const apply_calls = &store.balances.metrics.apply_batch_calls;
    try testing.expectEqual(@as(u64, 1), apply_calls.metric().get());

    // The close of epoch 2 pays out a forced withdrawal. Every write and sync fails, so the
    // log's commit fails before the balances apply anything.
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 4 }};
    var checked = try check_counts(2, 0, 1, &parent, &t.queue(2, &.{}, &forced));
    defer checked.deinit(gpa);
    var proposal = try store.settle(&checked);
    defer proposal.deinit(gpa);
    const posted = proposal.summary.digest();
    opened.harness.storage.allow_mutations(0);
    defer opened.harness.storage.mutations_allowed = null;
    if (store.apply(&proposal, &posted)) |applied| {
        var owned = applied;
        owned.deinit();
        return error.TestUnexpectedResult;
    } else |err| try testing.expect(err != error.InvalidCheckpoint);
    try testing.expectEqual(@as(u64, 1), apply_calls.metric().get());
}

// Settling needs the databases at the parent's roots. The successor of a candidate that did
// not post settles on the posted databases when the candidate wrote the same balances and
// payouts, because the roots are the same.
test "validator: settle needs the parent roots" {
    var posted: Opened = undefined;
    try posted.init();
    defer posted.deinit();
    var parent = try t.genesis(posted.store.balances.root());
    defer parent.deinit();
    const deposits = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 20 },
    };
    const forced = [_]Forced{.{ .account = t.account(1), .amount = 2 }};
    const queued = t.queue(1, &deposits, &forced);
    const operator = t.operator_key();

    // Alice also pays herself in the candidate, so it writes the same balances and payouts as
    // the posted close under another matrix.
    const alike = try t.row(1, 0, &.{.{ 0, 5 }}, t.empty_root());
    const candidate = try t.sign_close(&operator, 1, &.{alike}, &.{}, 1, 1);
    var checked = try t.check(candidate, &parent, &queued);
    defer checked.deinit(gpa);
    var proposal = try posted.store.settle(&checked);
    defer proposal.deinit(gpa);
    const close = try t.sign_close(&operator, 1, &.{}, &.{}, 1, 1);
    var applied = try posted.store.post(&parent, close, &queued);
    defer applied.deinit();
    try testing.expect(!proposal.summary.eql(applied.summary));
    try testing.expect(proposal.summary.balances.eql(applied.summary.balances));
    try testing.expect(proposal.summary.payouts.eql(applied.summary.payouts));

    // The successor of the candidate settles on the posted databases, but not on balances
    // that applied a close with other writes or none, nor beside a log at another root.
    var candidate_checkpoint = checkpoint(&proposal);
    defer candidate_checkpoint.deinit();
    var successor = try check_counts(2, 0, 0, &candidate_checkpoint, &t.queue(2, &.{}, &.{}));
    defer successor.deinit(gpa);
    var settled = try posted.store.settle(&successor);
    settled.deinit(gpa);
    var other: Opened = undefined;
    try other.init();
    defer other.deinit();
    const more = try t.sign_close(&operator, 1, &.{}, &.{}, 2, 1);
    var other_checkpoint = try other.store.post(&parent, more, &queued);
    defer other_checkpoint.deinit();
    var empty: Opened = undefined;
    try empty.init();
    defer empty.deinit();
    for ([_]*t.Db(t.DefaultIndex){ &other.store.balances, &empty.store.balances }) |balances| {
        const result = successor.settle(gpa, balances, &posted.store.log);
        try testing.expectError(error.InvalidCheckpoint, result);
    }
    const result = successor.settle(gpa, &posted.store.balances, &empty.store.log);
    try testing.expectError(error.InvalidCheckpoint, result);
}

// The balances root commits to every batch the database applied, not only to the balances it
// holds, so validators must apply exactly the posted closes.
test "validator: balances root depends on history" {
    var once: Opened = undefined;
    try once.init();
    defer once.deinit();
    var twice: Opened = undefined;
    try twice.init();
    defer twice.deinit();
    var start = try t.genesis(once.store.balances.root());
    defer start.deinit();
    const deposits = [_]Deposit{
        .{ .account = t.account(0), .amount = 10 },
        .{ .account = t.account(1), .amount = 5 },
    };
    const operator = t.operator_key();

    // One database credits both deposits in one close, the other in two.
    const both = try t.sign_close(&operator, 1, &.{}, &.{}, 2, 0);
    var once_checkpoint = try once.store.post(&start, both, &t.queue(1, &deposits, &.{}));
    defer once_checkpoint.deinit();
    const one = try t.sign_close(&operator, 1, &.{}, &.{}, 1, 0);
    var middle = try twice.store.post(&start, one, &t.queue(1, &deposits, &.{}));
    defer middle.deinit();
    const other = try t.sign_close(&operator, 2, &.{}, &.{}, 1, 0);
    var parent = try twice.store.post(&middle, other, &t.queue(2, deposits[1..], &.{}));
    defer parent.deinit();
    for ([_]u64{ 0, 1 }) |index| {
        const account = t.account(index);
        const a = try once.store.balances.get(&account);
        try testing.expectEqual(a, try twice.store.balances.get(&account));
    }
    try testing.expect(!once.store.balances.root().eql(twice.store.balances.root()));
    try expect_unchanged_balances(&twice.store, &parent);
}

/// A close writes only the balances it changes, yet a close that changes no balance still
/// changes the root.
fn expect_unchanged_balances(store: *TestStore, parent: *const Checkpoint) !void {
    const operator = t.operator_key();
    const next = t.queue(3, &.{}, &.{});

    // Alice paying herself changes the matrix but no balance, so it stages the same balances
    // root as an empty close.
    const self_payment = try t.row(3, 0, &.{.{ 0, 5 }}, t.empty_root());
    const paying_close = try t.sign_close(&operator, 3, &.{self_payment}, &.{}, 0, 0);
    var paying_checked = try t.check(paying_close, parent, &next);
    defer paying_checked.deinit(gpa);
    var paying = try store.settle(&paying_checked);
    defer paying.deinit(gpa);
    var idle_checked = try check_counts(3, 0, 0, parent, &next);
    defer idle_checked.deinit(gpa);
    var staged = try store.settle(&idle_checked);
    defer staged.deinit(gpa);
    try testing.expect(!paying.summary.matrix.eql(staged.summary.matrix));
    try testing.expect(paying.summary.balances.eql(staged.summary.balances));

    // Alice withdrawing exactly what a deposit credits her keeps her balance, so the close
    // stages the same balances root as an empty close while it owes her the payout.
    const deposits = [_]Deposit{.{ .account = t.account(0), .amount = 4 }};
    const forced = [_]Forced{.{ .account = t.account(0), .amount = 4 }};
    var withdrawing_checked = try check_counts(3, 1, 1, parent, &t.queue(3, &deposits, &forced));
    defer withdrawing_checked.deinit(gpa);
    var withdrawing = try store.settle(&withdrawing_checked);
    defer withdrawing.deinit(gpa);
    var owed = try t.amounts(gpa, &.{.{ 0, 4 }});
    defer owed.deinit(gpa);
    try testing.expect(withdrawing.payouts.eql(&owed));
    try testing.expect(withdrawing.summary.balances.eql(staged.summary.balances));

    // A close that changes no balance still changes the root.
    var idle = try store.apply(&staged, &staged.summary.digest());
    defer idle.deinit();
    try testing.expect(!store.balances.root().eql(parent.summary.balances));
    try testing.expectEqual(@as(?u64, 10), try store.balances.get(&t.account(0)));
}

/// Replays `roots.len` churn closes on a fresh store over the index `I` and writes the
/// balances root after each to `roots`.
fn replay_on_index(
    comptime I: type,
    translator: I.Translator,
    start: *const Checkpoint,
    roots: []Digest,
) !void {
    var harness = try t.Harness.init();
    defer harness.deinit();
    var store = try harness.open(I, translator);
    defer store.deinit();
    try testing.expect(store.balances.root().eql(start.summary.balances));
    var last = try replay(&store, start, 1, roots);
    last.deinit();
}

// The index and its translator do not affect the balances root, so validators may choose them
// freely.
test "validator: index does not affect the balances root" {
    // Three of the accounts share their first byte, so they collide in the plain index under
    // OneCap.
    const first = codec.encode_fixed(PublicKey, t.account(42))[0];
    for ([_]u64{ 46, 51 }) |index| {
        try testing.expectEqual(first, codec.encode_fixed(PublicKey, t.account(index))[0]);
    }
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    var start = try t.genesis(opened.store.balances.root());
    defer start.deinit();
    var expected: [40]Digest = undefined;
    var last = try replay(&opened.store, &start, 1, &expected);
    last.deinit();

    const OneCap = storage.translator.OneCap;
    const Partitioned = storage.index.partitioned.unordered.Index(OneCap, u64, 1);
    var roots: [40]Digest = undefined;
    try replay_on_index(t.Index(OneCap), .{}, &start, &roots);
    for (roots, expected) |a, b| try testing.expect(a.eql(b));
    try replay_on_index(Partitioned, .init(.{}), &start, &roots);
    for (roots, expected) |a, b| try testing.expect(a.eql(b));
}

// Databases that applied a close that did not post rewind by reopening at the last posted
// close's commit, while the balances retain that commit's inactivity floor. The payout log
// rewinds to the payouts size that close certifies.
test "validator: bounded reopen rewinds to a posted close" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var start = try t.genesis(store.balances.root());
    defer start.deinit();
    var early: [3]Digest = undefined;
    var parent = try replay(store, &start, 1, &early);
    defer parent.deinit();
    const size = store.balances.bounds().end;

    // A close of epoch 4 that did not post is applied and committed by mistake.
    const deposits = [_]Deposit{.{ .account = t.account(7), .amount = 999 }};
    const forced = [_]Forced{.{ .account = t.account(7), .amount = 1 }};
    const operator = t.operator_key();
    const candidate = try t.sign_close(&operator, 4, &.{}, &.{}, 1, 1);
    var mistaken = try store.post(&parent, candidate, &t.queue(4, &deposits, &forced));
    mistaken.deinit();
    try store.commit();
    try testing.expect(!store.balances.root().eql(parent.summary.balances));
    try testing.expect(!store.log.root().eql(parent.summary.payouts.root));

    // Reopened at the commits of epoch 3, they apply the posted closes as if they never
    // applied the candidate.
    store.deinit();
    store.balances = try opened.harness.open_balances(t.DefaultIndex, .{}, size);
    store.log = try opened.harness.open_log(parent.summary.payouts.size);
    try expect_roots(store, parent.summary.balances, parent.summary.payouts.root);
    var rewound: [9]Digest = undefined;
    var rewound_parent = try replay(store, &parent, 4, &rewound);
    defer rewound_parent.deinit();
    var fresh: Opened = undefined;
    try fresh.init();
    defer fresh.deinit();
    var expected: [12]Digest = undefined;
    var fresh_parent = try replay(&fresh.store, &start, 1, &expected);
    defer fresh_parent.deinit();
    for (rewound, expected[3..]) |a, b| try testing.expect(a.eql(b));
    try testing.expect(rewound_parent.summary.eql(fresh_parent.summary));
    try testing.expect(store.log.root().eql(fresh.store.log.root()));
}

// Balances pruned to their sync boundary reopen at an earlier posted close only while that
// close's inactivity floor is retained. The payout log is never pruned, so it always reopens
// at the payouts size that close certifies.
test "validator: bounded reopen fails once the floor is pruned" {
    var opened: Opened = undefined;
    try opened.init();
    defer opened.deinit();
    const store = &opened.store;
    var parent = try t.genesis(store.balances.root());
    defer parent.deinit();
    var rewound: u64 = 0;
    var refused: u64 = 0;
    for (1..61) |epoch| {
        const churn = Churn.init(epoch);
        const queued = churn.queue();
        const size = store.balances.bounds().end;
        var previous = parent.clone();
        defer previous.deinit();
        const next = try store.post(&parent, try churn.close(), &queued);
        parent.deinit();
        parent = next;
        try store.commit();
        try store.balances.prune(store.balances.sync_boundary());
        if (previous.summary.epoch == 0) continue;

        // Reopen at the commits of the previous close, then return to the latest one.
        store.balances.deinit();
        if (opened.harness.open_balances(t.DefaultIndex, .{}, size)) |balances| {
            rewound += 1;
            store.balances = balances;
            store.log.deinit();
            store.log = try opened.harness.open_log(previous.summary.payouts.size);
            const summary = previous.summary;
            try expect_roots(store, summary.balances, summary.payouts.root);
            var again = try store.post(&previous, try churn.close(), &queued);
            again.deinit();
            try store.commit();
        } else |err| {
            try testing.expectEqual(error.HistoricalFloorPruned, err);
            refused += 1;
            store.balances = try opened.harness.open_balances(t.DefaultIndex, .{}, null);
        }
        try expect_roots(store, parent.summary.balances, parent.summary.payouts.root);
    }
    try testing.expect(rewound > 0 and refused > 0);
}
