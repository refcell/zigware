//! Closes, soft withdrawals, and the requests queued on the ledger
//! (commonware `bajillion/close.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const mod = @import("mod.zig");
const amounts_module = @import("amounts.zig");
const matrix_module = @import("matrix.zig");
const settlement = @import("settlement.zig");
const arb = @import("arbitrary.zig");

const Namespace = mod.Namespace;
const Epoch = mod.Epoch;

/// Why rows and withdrawals do not assemble into a close.
pub const AssemblyError = error{
    /// A count is outside the queue's bounds.
    InvalidCount,
    /// A row pays no receiver.
    NoReceivers,
    /// A soft withdrawal is for another epoch.
    WrongEpoch,
    /// An account has two rows, or a withdrawal request repeats.
    Duplicate,
};

/// An account's signed request to withdraw up to `amount` through the operator in the close of
/// `epoch` (commonware `Withdrawal<P, A>`).
///
/// A close identifies a request by its signed part (`order_request`), not by its signature.
pub fn Withdrawal(comptime P: type, comptime A: type) type {
    mod.assert_public_key(P);
    mod.assert_amount(A);
    return struct {
        const Self = @This();

        /// Size of the signed part of a request.
        pub const request_size: usize = 8 + P.fixed_size + codec.fixed_size(A).? + 8;
        pub const fixed_size: usize = request_size + P.Signature.fixed_size;

        /// Epoch whose close may pay the withdrawal.
        epoch: Epoch,
        /// Account withdrawing.
        account: P,
        /// Largest amount to withdraw.
        amount: A,
        /// Distinguishes requests with the same epoch, account, and amount.
        tag: u64,
        /// The account's signature over the request.
        signature: P.Signature,

        /// Signs a request to withdraw up to `amount` from `signer`'s account in `epoch`.
        pub fn sign(
            signer: anytype,
            namespace: *const Namespace,
            epoch: Epoch,
            amount: A,
            tag: u64,
        ) Self {
            const account = signer.public_key();
            const message_bytes = message(epoch, &account, amount, tag);
            const signature = signer.sign(namespace.withdrawal, &message_bytes);
            return .{
                .epoch = epoch,
                .account = account,
                .amount = amount,
                .tag = tag,
                .signature = signature,
            };
        }

        /// The bytes an account signs in `Namespace.withdrawal` to request withdrawing up to
        /// `amount` in `epoch` with `tag`: the epoch, account, amount, and tag in their fixed
        /// encodings.
        pub fn message(epoch: Epoch, account: *const P, amount: A, tag: u64) [request_size]u8 {
            var out: [request_size]u8 = undefined;
            var writer = codec.Writer.init(&out);
            write_request(epoch, account, amount, tag, &writer);
            assert(writer.written().len == request_size);
            return out;
        }

        fn write_request(
            epoch: Epoch,
            account: *const P,
            amount: A,
            tag: u64,
            writer: *codec.Writer,
        ) void {
            codec.write(u64, epoch, writer);
            account.write(writer);
            codec.write(A, amount, writer);
            codec.write(u64, tag, writer);
        }

        /// Returns whether the amount is positive and the account signed the request.
        pub fn verify(self: *const Self, namespace: *const Namespace) bool {
            if (self.amount == 0) return false;
            const bytes = message(self.epoch, &self.account, self.amount, self.tag);
            return self.account.verify(namespace.withdrawal, &bytes, &self.signature);
        }

        /// Orders requests by their signed part: epoch, account, amount, then tag.
        pub fn order_request(a: *const Self, b: *const Self) std.math.Order {
            if (a.epoch != b.epoch) return std.math.order(a.epoch, b.epoch);
            const by_account = a.account.order(b.account);
            if (by_account != .eq) return by_account;
            if (a.amount != b.amount) return std.math.order(a.amount, b.amount);
            return std.math.order(a.tag, b.tag);
        }

        pub fn eql(a: Self, b: Self) bool {
            return order_request(&a, &b) == .eq and a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            write_request(self.epoch, &self.account, self.amount, self.tag, writer);
            self.signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .epoch = try codec.read(u64, gpa, reader),
                .account = try codec.read(P, gpa, reader),
                .amount = try codec.read(A, gpa, reader),
                .tag = try codec.read(u64, gpa, reader),
                .signature = try codec.read(P.Signature, gpa, reader),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .epoch = u.int(u64),
                .account = try arb.value(P, gpa, u),
                .amount = try arb.value(A, gpa, u),
                .tag = u.int(u64),
                .signature = try arb.value(P.Signature, gpa, u),
            };
        }
    };
}

/// A request queued on the ledger for an account and an amount: a deposit credits it, and a
/// forced withdrawal requests up to the amount, paying that amount or emptying the balance.
fn Queued(comptime P: type, comptime A: type, comptime kind: enum { deposit, forced }) type {
    mod.assert_public_key(P);
    mod.assert_amount(A);
    return struct {
        const Self = @This();
        comptime {
            _ = kind;
        }

        pub const fixed_size: usize = P.fixed_size + codec.fixed_size(A).?;

        account: P,
        amount: A,

        pub fn eql(a: Self, b: Self) bool {
            return a.account.eql(b.account) and a.amount == b.amount;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.account.write(writer);
            codec.write(A, self.amount, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const account = try codec.read(P, gpa, reader);
            return .{ .account = account, .amount = try codec.read(A, gpa, reader) };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const account = try arb.value(P, gpa, u);
            return .{ .account = account, .amount = try arb.value(A, gpa, u) };
        }
    };
}

/// A deposit queued on the ledger (commonware `Deposit<P, A>`).
pub fn Deposit(comptime P: type, comptime A: type) type {
    return Queued(P, A, .deposit);
}

/// A forced withdrawal queued on the ledger (commonware `ForcedWithdrawal<P, A>`).
pub fn ForcedWithdrawal(comptime P: type, comptime A: type) type {
    return Queued(P, A, .forced);
}

/// Returns `count` as a number of queued requests, or null if it is not between `required` and
/// `queued`.
fn bounded(required: usize, queued: usize, count: u64) ?usize {
    const value = std.math.cast(usize, count) orelse return null;
    if (value < required or value > queued) return null;
    return value;
}

/// The requests queued on the ledger that the next close may process (commonware
/// `Queue<P, A>`). Borrows its slices.
///
/// The next close processes the oldest requests of each queue. It must take every request
/// still queued when the previous close posted, and may take any queued since.
pub fn Queue(comptime P: type, comptime A: type) type {
    return struct {
        const Self = @This();

        /// Epoch whose close the ledger expects next.
        epoch: Epoch,
        /// Unprocessed deposits, oldest first.
        deposits: []const Deposit(P, A),
        /// Number of deposits the next close must process.
        required_deposits: usize,
        /// Unprocessed forced withdrawals, oldest first.
        forced_withdrawals: []const ForcedWithdrawal(P, A),
        /// Number of forced withdrawals the next close must process.
        required_forced_withdrawals: usize,

        pub const Prefix = struct {
            deposits: []const Deposit(P, A),
            forced_withdrawals: []const ForcedWithdrawal(P, A),
        };

        /// The oldest `deposits` deposits and `forced_withdrawals` forced withdrawals, or null
        /// if a count is not between its queue's required count and length.
        pub fn prefix(self: *const Self, deposits: u64, forced_withdrawals: u64) ?Prefix {
            const d = bounded(self.required_deposits, self.deposits.len, deposits) orelse
                return null;
            const f = bounded(
                self.required_forced_withdrawals,
                self.forced_withdrawals.len,
                forced_withdrawals,
            ) orelse return null;
            assert(d >= self.required_deposits and f >= self.required_forced_withdrawals);
            return .{
                .deposits = self.deposits[0..d],
                .forced_withdrawals = self.forced_withdrawals[0..f],
            };
        }
    };
}

/// A sender's payment map settled by a close, with the sender's signature over its state
/// (commonware `Row<P, A>`). Owns its payment map.
pub fn Row(comptime P: type, comptime A: type) type {
    return struct {
        const Self = @This();
        const Amounts = amounts_module.Amounts(P, A);

        /// The maximum number of receivers.
        pub const Cfg = usize;

        /// Account paying.
        account: P,
        /// Cumulative amount paid to each receiver.
        payments: Amounts,
        /// The sender's signature over its state in the close's epoch.
        signature: P.Signature,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.payments.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self.*;
            copy.payments = try self.payments.clone(gpa);
            return copy;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.account.eql(b.account) and a.payments.eql(&b.payments) and
                a.signature.eql(b.signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.account.write(writer);
            self.payments.write(writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return P.fixed_size + self.payments.encode_size() + P.Signature.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, receivers: Cfg) codec.Error!Self {
            const account = try codec.read(P, gpa, reader);
            var payments = try Amounts.read(gpa, reader, .inclusive(1, receivers));
            errdefer payments.deinit(gpa);
            const signature = try codec.read(P.Signature, gpa, reader);
            return .{ .account = account, .payments = payments, .signature = signature };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const payments = try Amounts.arbitrary_nonempty(gpa, u);
            return .{
                .account = try arb.value(P, gpa, u),
                .payments = payments,
                .signature = try arb.value(P.Signature, gpa, u),
            };
        }
    };
}

/// Bounds on the size of a `Close`. Decoding rejects a close that exceeds them.
pub const Limits = struct {
    /// Maximum number of senders.
    rows: usize,
    /// Maximum number of receivers in one sender's payment map.
    receivers: usize,
    /// Maximum number of soft withdrawals.
    withdrawals: usize,
};

/// The operator's close of an epoch (commonware `Close<P, O, A>`).
///
/// Rows are strictly increasing by account, and withdrawals by their signed request, so no
/// account has two rows and no request appears twice. Every row pays at least one receiver. A
/// close owns its rows and withdrawals; `deinit` frees them.
pub fn Close(comptime P: type, comptime O: type, comptime A: type) type {
    mod.assert_public_key(O);
    return struct {
        const Self = @This();
        pub const RowType = Row(P, A);
        pub const WithdrawalType = Withdrawal(P, A);
        pub const QueueType = Queue(P, A);
        pub const Flows = settlement.Flows(P, A);
        pub const Cfg = Limits;

        epoch: Epoch,
        rows: []RowType,
        withdrawals: []WithdrawalType,
        deposits: u64,
        forced_withdrawals: u64,
        signature: O.Signature,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.rows) |*row| row.deinit(gpa);
            gpa.free(self.rows);
            gpa.free(self.withdrawals);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            const rows = try gpa.alloc(RowType, self.rows.len);
            var cloned: usize = 0;
            errdefer {
                for (rows[0..cloned]) |*row| row.deinit(gpa);
                gpa.free(rows);
            }
            for (self.rows, rows) |*from, *to| {
                to.* = try from.clone(gpa);
                cloned += 1;
            }
            var copy = self.*;
            copy.rows = rows;
            copy.withdrawals = try gpa.dupe(WithdrawalType, self.withdrawals);
            return copy;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (a.epoch != b.epoch or a.deposits != b.deposits) return false;
            if (a.forced_withdrawals != b.forced_withdrawals) return false;
            if (!a.signature.eql(b.signature)) return false;
            if (a.rows.len != b.rows.len or a.withdrawals.len != b.withdrawals.len) return false;
            for (a.rows, b.rows) |*x, *y| if (!x.eql(y)) return false;
            for (a.withdrawals, b.withdrawals) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        /// Returns whether rows and withdrawals are strictly increasing.
        pub fn is_canonical(rows: []const RowType, withdrawals: []const WithdrawalType) bool {
            for (rows[0..rows.len -| 1], rows[@min(1, rows.len)..]) |a, b| {
                if (a.account.order(b.account) != .lt) return false;
            }
            const count = withdrawals.len;
            for (withdrawals[0..count -| 1], withdrawals[@min(1, count)..]) |*a, *b| {
                if (WithdrawalType.order_request(a, b) != .lt) return false;
            }
            return true;
        }

        /// Encodes the part of a close the operator signs; the matrix root stands in for the
        /// rows it commits to. The caller frees the result.
        pub fn message(
            comptime D: type,
            gpa: Allocator,
            epoch: Epoch,
            root: *const D,
            withdrawals: []const WithdrawalType,
            deposits: u64,
            forced_withdrawals: u64,
        ) Allocator.Error![]u8 {
            const size = 8 + D.fixed_size + codec.encode_size([]const WithdrawalType, withdrawals) +
                codec.varint.size(u64, deposits) + codec.varint.size(u64, forced_withdrawals);
            const out = try gpa.alloc(u8, size);
            var writer = codec.Writer.init(out);
            codec.write(u64, epoch, &writer);
            root.write(&writer);
            codec.write([]const WithdrawalType, withdrawals, &writer);
            codec.varint.write(u64, deposits, &writer);
            codec.varint.write(u64, forced_withdrawals, &writer);
            assert(writer.written().len == size);
            return out;
        }

        fn RootsOp(comptime H: type) type {
            return struct {
                pub fn map(_: @This(), row: *const RowType) H.Digest {
                    return row.payments.root(H);
                }
            };
        }

        /// The root of the matrix over `rows`, which must be canonical; payment map roots are
        /// computed with `strategy`.
        pub fn matrix_root(
            comptime H: type,
            gpa: Allocator,
            rows: []const RowType,
            strategy: anytype,
        ) Allocator.Error!H.Digest {
            const roots = try gpa.alloc(H.Digest, rows.len);
            defer gpa.free(roots);
            strategy.map_into(rows, roots, RootsOp(H){});
            var builder: amounts_module.RootBuilder(H) = .{};
            for (rows, roots) |*row, *root| {
                builder.add(&matrix_module.leaf(H, P, &row.account, root));
            }
            assert(builder.count == rows.len);
            return builder.finish();
        }

        /// Signs the close of `epoch` over rows and withdrawals already in canonical order,
        /// taking ownership of both slices (allocated with `gpa`, freed on error).
        pub fn sign(
            comptime H: type,
            gpa: Allocator,
            signer: anytype,
            namespace: *const Namespace,
            epoch: Epoch,
            rows: []RowType,
            withdrawals: []WithdrawalType,
            deposits: u64,
            forced_withdrawals: u64,
            strategy: anytype,
        ) Allocator.Error!Self {
            assert(is_canonical(rows, withdrawals));
            var close: Self = .{
                .epoch = epoch,
                .rows = rows,
                .withdrawals = withdrawals,
                .deposits = deposits,
                .forced_withdrawals = forced_withdrawals,
                .signature = undefined,
            };
            errdefer close.deinit(gpa);
            close.signature = try close.operator_signature(H, gpa, signer, namespace, strategy);
            return close;
        }

        /// The operator's signature over the close's signed part, its matrix root computed
        /// with `strategy`.
        fn operator_signature(
            self: *const Self,
            comptime H: type,
            gpa: Allocator,
            signer: anytype,
            namespace: *const Namespace,
            strategy: anytype,
        ) Allocator.Error!O.Signature {
            const root = try matrix_root(H, gpa, self.rows, strategy);
            const bytes = try message(
                H.Digest,
                gpa,
                self.epoch,
                &root,
                self.withdrawals,
                self.deposits,
                self.forced_withdrawals,
            );
            defer gpa.free(bytes);
            return signer.sign(namespace.close, bytes);
        }

        /// A close with each touched account's flow.
        pub const Assembled = struct {
            close: Self,
            flows: Flows,

            pub fn deinit(self: *Assembled, gpa: Allocator) void {
                self.close.deinit(gpa);
                self.flows.deinit(gpa);
                self.* = undefined;
            }
        };

        fn less_row(_: void, a: RowType, b: RowType) bool {
            return a.account.order(b.account) == .lt;
        }

        fn less_withdrawal(_: void, a: WithdrawalType, b: WithdrawalType) bool {
            return WithdrawalType.order_request(&a, &b) == .lt;
        }

        /// Assembles and signs the close of `queue`'s epoch from the senders' `rows` and the
        /// honored soft `withdrawals`, in any order, processing the oldest `deposits` deposits
        /// and `forced_withdrawals` forced withdrawals. Takes ownership of both slices
        /// (allocated with `gpa`, freed on error). Returns the close with each touched
        /// account's flow.
        ///
        /// Assembly recomputes every root and checks neither signatures nor `Limits`.
        pub fn assemble(
            comptime H: type,
            gpa: Allocator,
            signer: anytype,
            namespace: *const Namespace,
            queue: *const QueueType,
            rows: []RowType,
            withdrawals: []WithdrawalType,
            deposits: u64,
            forced_withdrawals: u64,
            strategy: anytype,
        ) (AssemblyError || Allocator.Error)!Assembled {
            var owned: Self = .{
                .epoch = queue.epoch,
                .rows = rows,
                .withdrawals = withdrawals,
                .deposits = deposits,
                .forced_withdrawals = forced_withdrawals,
                .signature = undefined,
            };
            errdefer owned.deinit(gpa);
            const queued = queue.prefix(deposits, forced_withdrawals) orelse
                return error.InvalidCount;
            for (rows) |*row| if (row.payments.is_empty()) return error.NoReceivers;
            for (withdrawals) |*w| if (w.epoch != queue.epoch) return error.WrongEpoch;
            std.mem.sort(RowType, rows, {}, less_row);
            std.mem.sort(WithdrawalType, withdrawals, {}, less_withdrawal);
            if (!is_canonical(rows, withdrawals)) return error.Duplicate;
            var flows = try Flows.init(
                gpa,
                queue.epoch,
                rows,
                withdrawals,
                queued.deposits,
                queued.forced_withdrawals,
            );
            errdefer flows.deinit(gpa);
            owned.signature = try owned.operator_signature(H, gpa, signer, namespace, strategy);
            return .{ .close = owned, .flows = flows };
        }

        /// The payment matrix the close settles.
        pub fn matrix(
            self: *const Self,
            comptime H: type,
            gpa: Allocator,
            strategy: anytype,
        ) Allocator.Error!matrix_module.Matrix(P, H, A) {
            const M = matrix_module.Matrix(P, H, A);
            const roots = try gpa.alloc(H.Digest, self.rows.len);
            defer gpa.free(roots);
            strategy.map_into(@as([]const RowType, self.rows), roots, RootsOp(H){});
            const rows = try gpa.alloc(M.Row, self.rows.len);
            defer gpa.free(rows);
            var cloned: usize = 0;
            errdefer for (rows[0..cloned]) |*row| row[1].deinit(gpa);
            for (self.rows, roots, rows) |*from, root, *to| {
                to.* = .{ from.account, try from.payments.clone(gpa), root };
                cloned += 1;
            }
            return M.from_sorted(gpa, rows);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u64, self.epoch, writer);
            codec.write([]const RowType, self.rows, writer);
            codec.write([]const WithdrawalType, self.withdrawals, writer);
            codec.varint.write(u64, self.deposits, writer);
            codec.varint.write(u64, self.forced_withdrawals, writer);
            self.signature.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 8 + codec.encode_size([]const RowType, self.rows) +
                codec.encode_size([]const WithdrawalType, self.withdrawals) +
                codec.varint.size(u64, self.deposits) +
                codec.varint.size(u64, self.forced_withdrawals) + O.Signature.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, limits: Limits) codec.Error!Self {
            const epoch = try codec.read(u64, gpa, reader);
            const rows_cfg: codec.Cfg([]const RowType) = .{
                .range = .to_inclusive(limits.rows),
                .item = limits.receivers,
            };
            const rows = try codec.read_cfg([]const RowType, gpa, reader, rows_cfg);
            errdefer codec.free([]const RowType, gpa, rows);
            const withdrawals_range: codec.RangeCfg(usize) = .to_inclusive(limits.withdrawals);
            const Withdrawals = []const WithdrawalType;
            const withdrawals = try codec.read_range(Withdrawals, gpa, reader, withdrawals_range);
            errdefer gpa.free(withdrawals);
            if (!is_canonical(rows, withdrawals)) return reader.invalid(
                "clearing::bajillion::Close",
                "rows and withdrawals must be strictly increasing",
            );
            return .{
                .epoch = epoch,
                .rows = @constCast(rows),
                .withdrawals = @constCast(withdrawals),
                .deposits = try codec.varint.read(u64, reader),
                .forced_withdrawals = try codec.varint.read(u64, reader),
                .signature = try codec.read(O.Signature, gpa, reader),
            };
        }

        fn order_rows(a: *const RowType, b: *const RowType) std.math.Order {
            return a.account.order(b.account);
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const all_rows = try arb.collect(RowType, gpa, u);
            const rows = arb.sort_dedup(RowType, all_rows, order_rows);
            const all_withdrawals = try arb.collect(WithdrawalType, gpa, u);
            const by_request = WithdrawalType.order_request;
            const withdrawals = arb.sort_dedup(WithdrawalType, all_withdrawals, by_request);
            // Values come from an arena (`codec.arbitrary.generate`), so dropped duplicates
            // need not be freed; the slices are shrunk so `deinit` frees their exact size.
            return .{
                .epoch = u.int(u64),
                .rows = try gpa.realloc(all_rows, rows.len),
                .withdrawals = try gpa.realloc(all_withdrawals, withdrawals.len),
                .deposits = u.int(u64),
                .forced_withdrawals = u.int(u64),
                .signature = try arb.value(O.Signature, gpa, u),
            };
        }
    };
}
