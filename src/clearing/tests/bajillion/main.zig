//! End-to-end tests of Bajillion, run against reference implementations of its five roles
//! (commonware `clearing/tests/bajillion`).
//!
//! The roles are built from the crate's public API alone. They show that a deployment can build
//! every role, and each keeps that role's obligations.

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const bajillion = @import("../../bajillion/mod.zig");

pub const roles = struct {
    pub const map = @import("roles/map.zig");
    pub const sender = @import("roles/sender.zig");
    pub const receiver = @import("roles/receiver.zig");
    pub const operator = @import("roles/operator.zig");
    pub const ledger = @import("roles/ledger.zig");
    pub const validator = @import("roles/validator.zig");
};

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const PrivateKey = cryptography.ed25519.PrivateKey;
pub const PublicKey = cryptography.ed25519.PublicKey;
pub const Epoch = bajillion.Epoch;
pub const Amounts = bajillion.Amounts(PublicKey, u64);
pub const TestOperator = roles.operator.Operator(PublicKey, PrivateKey, Sha256, u64);
pub const TestSender = roles.sender.Sender(PrivateKey, PublicKey, Sha256, u64);
pub const TestReceiver = roles.receiver.Receiver(PublicKey, PublicKey, Sha256, u64);
pub const TestClose = bajillion.Close(PublicKey, PublicKey, u64);
pub const Row = TestClose.RowType;
pub const Withdrawal = TestClose.WithdrawalType;
pub const Queue = TestClose.QueueType;
pub const Deposit = bajillion.Deposit(PublicKey, u64);
pub const Forced = bajillion.ForcedWithdrawal(PublicKey, u64);
pub const Assembled = TestClose.Assembled;
/// The tests' allocator. With `-Dslow-tests` it is `smp_allocator`: the model checks clone
/// a world per transition on up to 64 workers, and the testing allocator's one lock and
/// bookkeeping made the largest check 17 times slower than commonware's, whose clones use the
/// system allocator. The default run keeps the testing allocator and its leak checks.
pub const gpa = if (build_options.slow_tests) std.heap.smp_allocator else std.testing.allocator;

/// Namespace of the deployment under test.
pub const namespace_bytes = "_COMMONWARE_CLEARING_BAJILLION_TEST";

/// Close limits large enough not to constrain any test that uses them.
pub const limits: bajillion.Limits = .{ .rows = 1_024, .receivers = 1_024, .withdrawals = 1_024 };

/// The signature namespaces of the deployment under test; the caller frees them.
pub fn namespace() !bajillion.Namespace {
    return bajillion.Namespace.init(gpa, namespace_bytes);
}

/// The signing key of user `index`.
pub fn user(index: u64) PrivateKey {
    return PrivateKey.from_seed(index);
}

/// The account of user `index`.
pub fn account(index: u64) PublicKey {
    return user(index).public_key();
}

/// The operator's signing key.
pub fn operator_key() PrivateKey {
    return PrivateKey.from_seed(1_000);
}

/// User `index` sending through the deployment's operator.
pub fn sender(index: u64) !TestSender {
    var ns = try namespace();
    defer ns.deinit(gpa);
    return TestSender.init(gpa, user(index), &ns, operator_key().public_key());
}

/// User `index` receiving while the ledger expects the close of `next`.
pub fn receiver(index: u64, next: Epoch) !TestReceiver {
    var ns = try namespace();
    defer ns.deinit(gpa);
    return TestReceiver.init(gpa, account(index), &ns, operator_key().public_key(), next);
}

/// An operator for the first epoch.
pub fn operator() !TestOperator {
    var ns = try namespace();
    defer ns.deinit(gpa);
    return TestOperator.init(gpa, operator_key(), &ns, limits);
}

/// An operator restarted from a copy of what `from` persisted.
pub fn restart(from: *const TestOperator) !TestOperator {
    var ns = try namespace();
    defer ns.deinit(gpa);
    var persisted = try from.persisted.clone(gpa);
    errdefer persisted.deinit(gpa);
    return TestOperator.restart(gpa, operator_key(), &ns, limits, persisted);
}

/// Amounts paying user `index` its `amount` for each `{ index, amount }`.
pub fn amounts(entries: []const [2]u64) !Amounts {
    var list: std.ArrayList(Amounts.Entry) = .empty;
    defer list.deinit(gpa);
    for (entries) |entry| try list.append(gpa, .{ account(entry[0]), entry[1] });
    return Amounts.init(gpa, list.items);
}

/// Queues for one epoch's close, owning their requests.
pub const Queues = struct {
    epoch: Epoch,
    deposits: []Deposit,
    forced: []Forced,
    required_deposits: usize = 0,
    required_forced_withdrawals: usize = 0,

    /// Queues holding a deposit for each `{ index, amount }` in `deposits` and a forced
    /// withdrawal for each in `forced`, none of which the close must process.
    pub fn init(epoch: Epoch, deposits: []const [2]u64, forced: []const [2]u64) !Queues {
        const owned_deposits = try gpa.alloc(Deposit, deposits.len);
        errdefer gpa.free(owned_deposits);
        for (deposits, owned_deposits) |entry, *d| {
            d.* = .{ .account = account(entry[0]), .amount = entry[1] };
        }
        const owned_forced = try gpa.alloc(Forced, forced.len);
        for (forced, owned_forced) |entry, *f| {
            f.* = .{ .account = account(entry[0]), .amount = entry[1] };
        }
        return .{ .epoch = epoch, .deposits = owned_deposits, .forced = owned_forced };
    }

    pub fn deinit(self: *Queues) void {
        gpa.free(self.deposits);
        gpa.free(self.forced);
        self.* = undefined;
    }

    pub fn queue(self: *const Queues) Queue {
        return .{
            .epoch = self.epoch,
            .deposits = self.deposits,
            .required_deposits = self.required_deposits,
            .forced_withdrawals = self.forced,
            .required_forced_withdrawals = self.required_forced_withdrawals,
        };
    }
};

/// Closes `op`'s epoch, processing the oldest `deposits` and `forced_withdrawals` requests in
/// `queue`. Returns the close; the caller frees it.
pub fn close_epoch(op: *TestOperator, queue: *const Queue, deposits: u64, forced: u64) !TestClose {
    var assembled = try op.close(queue, deposits, forced);
    assembled.flows.deinit(gpa);
    return assembled.close;
}

/// Funds users by closing the operator's epoch with a deposit of each `{ index, amount }`.
pub fn fund(op: *TestOperator, balances: []const [2]u64) !TestClose {
    var queues = try Queues.init(op.epoch(), balances, &.{});
    defer queues.deinit();
    return close_epoch(op, &queues.queue(), balances.len, 0);
}

/// Closes the operator's epoch without processing any queued request.
pub fn close(op: *TestOperator) !TestClose {
    const queue: Queue = .{
        .epoch = op.epoch(),
        .deposits = &.{},
        .required_deposits = 0,
        .forced_withdrawals = &.{},
        .required_forced_withdrawals = 0,
    };
    return close_epoch(op, &queue, 0, 0);
}

/// Sends `batch` from `from` in `epoch`, has `op` accept it, and records the acknowledgement.
/// Returns the amount the first receipt promises.
pub fn pay(from: *TestSender, op: *TestOperator, epoch: Epoch, batch: []const [2]u64) !u64 {
    var request = try from.send(epoch, try amounts(batch));
    defer request.deinit(gpa);
    const acknowledgement = try op.accept(&request);
    const receipts = try from.acknowledged(&acknowledgement);
    defer free_receipts(receipts);
    return receipts[0].amount;
}

pub fn free_receipts(receipts: []TestSender.Receipt) void {
    for (receipts) |*receipt| receipt.deinit(gpa);
    gpa.free(receipts);
}

/// The row user `from` signs for `payments` (taken) in `epoch` on top of `previous`.
pub fn row(epoch: Epoch, from: u64, payments: Amounts, previous: *const Amounts) !Row {
    var ns = try namespace();
    defer ns.deinit(gpa);
    const state: bajillion.State(PublicKey, Digest) = .{
        .epoch = epoch,
        .account = account(from),
        .payments = payments.root(Sha256),
        .previous = previous.root(Sha256),
    };
    const signer = user(from);
    return .{
        .account = account(from),
        .payments = payments,
        .signature = state.sign(&signer, &ns),
    };
}

/// A close of `queue`'s epoch with the given rows and soft withdrawals (copied), signed by
/// `signer` without checking their signatures or the validators' limits, as a faulty operator
/// could.
pub fn forge(
    signer: *const PrivateKey,
    queue: *const Queue,
    rows: []const Row,
    withdrawals: []const Withdrawal,
    deposits: u64,
    forced: u64,
) !TestClose {
    var ns = try namespace();
    defer ns.deinit(gpa);
    const owned_rows = try gpa.alloc(Row, rows.len);
    var cloned: usize = 0;
    errdefer {
        for (owned_rows[0..cloned]) |*r| r.deinit(gpa);
        gpa.free(owned_rows);
    }
    for (rows, owned_rows) |*from, *to| {
        to.* = try from.clone(gpa);
        cloned += 1;
    }
    const owned_withdrawals = try gpa.dupe(Withdrawal, withdrawals);
    var assembled = try TestClose.assemble(
        Sha256,
        gpa,
        signer,
        &ns,
        queue,
        owned_rows,
        owned_withdrawals,
        deposits,
        forced,
        parallel.sequential,
    );
    assembled.flows.deinit(gpa);
    return assembled.close;
}

/// `hash` extended by `H(hash || request)` for each of `requests`.
pub fn chain(comptime R: type, hash: Digest, requests: []const R) Digest {
    var result = hash;
    for (requests) |request| {
        const encoded = codec.encode_fixed(R, request);
        result = Sha256.hash(&.{ &result.bytes, &encoded });
    }
    return result;
}

/// Whether two closes encode the same.
pub fn closes_equal(a: *const TestClose, b: *const TestClose) !bool {
    const x = try codec.encode(TestClose, gpa, a.*);
    defer gpa.free(x);
    const y = try codec.encode(TestClose, gpa, b.*);
    defer gpa.free(y);
    return std.mem.eql(u8, x, y);
}

test {
    std.testing.refAllDecls(roles.validator);
    _ = @import("operator.zig");
    _ = @import("deployment.zig");
    _ = @import("validator.zig");
    _ = @import("payments.zig");
    _ = @import("ledger.zig");
    _ = @import("lifecycle.zig");
    _ = @import("checker.zig");
    _ = @import("model/smoke_test.zig");
    _ = @import("model/model_test.zig");
}
