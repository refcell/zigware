//! Checking closes against the last posted one, and the payouts and proofs validators keep
//! (commonware `bajillion/validator.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const parallel = @import("parallel");
const storage = @import("storage");
const mod = @import("mod.zig");
const amounts_module = @import("amounts.zig");
const matrix_module = @import("matrix.zig");
const payment = @import("payment.zig");
const settlement = @import("settlement.zig");
const close_module = @import("close.zig");
const summary_module = @import("summary.zig");
const arb = @import("arbitrary.zig");

const Namespace = mod.Namespace;
const Epoch = mod.Epoch;
const Mmr = storage.mmr.Family;
const qmdb = storage.qmdb;
const merkle = storage.merkle;

/// Why a close fails its check.
pub const CheckError = error{
    /// The checkpoint's matrix is not its summary's.
    InvalidCheckpoint,
    /// The next epoch does not fit.
    Overflow,
    /// The close, the queue, or a soft withdrawal is for another epoch.
    WrongEpoch,
    /// A count is outside the queue's bounds.
    InvalidCount,
    /// The operator's signature does not verify.
    InvalidOperatorSignature,
    /// A sender did not sign its row's map on top of the map the parent settled for it, or a
    /// soft withdrawal does not verify.
    InvalidSignature,
};

/// A payout a posted close owes an account (commonware `Payout<P, A>`).
pub fn Payout(comptime P: type, comptime A: type) type {
    mod.assert_public_key(P);
    mod.assert_amount(A);
    return struct {
        const Self = @This();

        pub const fixed_size: usize = P.fixed_size + codec.fixed_size(A).?;

        /// Account paid.
        account: P,
        /// Amount paid.
        amount: A,

        pub fn eql(a: Self, b: Self) bool {
            return a.account.eql(b.account) and a.amount == b.amount;
        }

        /// Stages the payout log's batch for one posted close. It appends `payouts` in account
        /// order, then a commit with no metadata that keeps the inactivity floor at zero, so no
        /// payout is ever pruned. It fails with `error.FloorRegressed` on a log whose floor a
        /// commit has raised. The caller releases the batch.
        pub fn stage(
            log: anytype,
            payouts: *const amounts_module.Amounts(P, A),
        ) !*@TypeOf(log.*).MerkleizedBatch {
            comptime assert(@TypeOf(log.*).Value == Self);
            var batch = try log.new_batch();
            errdefer batch.deinit();
            batch.with_inactivity_floor(0);
            for (payouts.entries) |entry| {
                try batch.append(.{ .account = entry[0], .amount = entry[1] });
            }
            assert(batch.size() == log.bounds().end + payouts.entries.len);
            return batch.merkleize(log);
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

/// The payout log's operation over payouts of `P` and `A`.
pub fn PayoutOperation(comptime P: type, comptime A: type) type {
    return qmdb.keyless.Operation(Mmr, qmdb.value.Fixed(Payout(P, A)));
}

/// Bytes per chunk of the balances database's activity bitmap (commonware `CHUNK`).
pub const balances_chunk_size: usize = 32;

/// Proof of an account's balance under a balances root (commonware `BalanceProof<D, A>`).
/// Owns its proof.
///
/// A proof reveals the balance, and verifies only for a positive one, because the balances
/// database holds no zero balance. Verification lands with qmdb `current`'s database; the
/// codec is here so the type round-trips and matches commonware's conformance hash.
pub fn BalanceProof(comptime D: type, comptime A: type) type {
    mod.assert_amount(A);
    return struct {
        const Self = @This();
        pub const Proof = qmdb.current.unordered.proof.constant.KeyValue(
            storage.mmb.Family,
            D,
            balances_chunk_size,
        );

        /// The account's balance.
        balance: A,
        /// Opening of the balance under the balances root.
        proof: Proof,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.balance == b.balance and a.proof.eql(b.proof);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(A, self.balance, writer);
            self.proof.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.fixed_size(A).? + self.proof.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const balance = try codec.read(A, gpa, reader);
            const max_digests = merkle.proof.max_proof_digests_per_element;
            return .{ .balance = balance, .proof = try Proof.read(gpa, reader, max_digests) };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const balance = try arb.value(A, gpa, u);
            var proof = try Proof.arbitrary(gpa, u);
            const digests = &proof.proof.range_proof.proof.digests;
            const max_digests = merkle.proof.max_proof_digests_per_element;
            if (digests.len > max_digests) digests.* = try gpa.realloc(digests.*, max_digests);
            assert(digests.len <= max_digests);
            return .{ .balance = balance, .proof = proof };
        }
    };
}

/// The validators' payout log (commonware `Payouts<E, P, H, S, A>`): a keyless database over
/// the MMR whose operations are payouts and commits, on a fixed journal.
pub fn Payouts(comptime P: type, comptime H: type, comptime A: type) type {
    const Journal = storage.journal.contiguous.fixed.Journal(PayoutOperation(P, A));
    return qmdb.keyless.Db(Mmr, qmdb.value.Fixed(Payout(P, A)), Journal, H);
}

/// Proof that the payout log holds a payout at an index (commonware `PayoutProof<P, D, A>`).
/// Owns its proof's digests.
pub fn PayoutProof(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Proof = merkle.Proof(Mmr, D);
        const Operation = PayoutOperation(P, A);

        /// Index of the payout in the log.
        index: u64,
        /// The payout.
        payout: Payout(P, A),
        /// Opening of the payout's operation under the log's root.
        proof: Proof,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.index == b.index and a.payout.eql(b.payout) and a.proof.eql(&b.proof);
        }

        /// Whether the payout log with root `root` holds `self.payout` at `self.index`.
        ///
        /// An index no log can hold returns false. A commit never verifies as a payout,
        /// because the log encodes commits with another tag.
        pub fn verify(self: *const Self, comptime H: type, root: *const D) bool {
            comptime assert(H.Digest == D);
            const operation: Operation = .{ .append = self.payout };
            const encoded = codec.encode_fixed(Operation, operation);
            const hasher = qmdb.hasher(H);
            return self.proof.verify_element_inclusion(&hasher, self.index, &encoded, root);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            qmdb.operation.write_location(self.index, writer);
            self.payout.write(writer);
            self.proof.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return qmdb.operation.location_size(self.index) + Payout(P, A).fixed_size +
                self.proof.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const index = try qmdb.operation.read_location(Mmr, reader);
            const payout = try Payout(P, A).read(gpa, reader, {});
            const max_digests = merkle.proof.max_proof_digests_per_element;
            const proof = try Proof.read(gpa, reader, max_digests);
            return .{ .index = index, .payout = payout, .proof = proof };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const index = qmdb.operation.arbitrary_location(Mmr, u);
            const payout = try Payout(P, A).arbitrary(gpa, u);
            const leaves = qmdb.operation.arbitrary_location(Mmr, u);
            const inactive_peaks = u.int(u64);
            var digests = try arb.collect(D, gpa, u);
            const max_digests = merkle.proof.max_proof_digests_per_element;
            if (digests.len > max_digests) {
                digests = try gpa.realloc(digests, max_digests);
            }
            return .{
                .index = index,
                .payout = payout,
                .proof = .{
                    .leaves = leaves,
                    .inactive_peaks = inactive_peaks,
                    .digests = digests,
                },
            };
        }
    };
}

/// The summary and payment matrix of a posted close (commonware `Checkpoint<P, H, A>`).
///
/// Before the first close, it is `Summary.genesis` of the empty balances database's root with
/// `Matrix.empty`. Holds a reference to its matrix.
pub fn Checkpoint(comptime P: type, comptime H: type, comptime A: type) type {
    return struct {
        const Self = @This();

        /// The close's summary.
        summary: summary_module.Summary(H),
        /// The close's payment matrix.
        matrix: matrix_module.Matrix(P, H, A),

        pub fn clone(self: *const Self) Self {
            return .{ .summary = self.summary, .matrix = self.matrix.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.matrix.deinit();
            self.* = undefined;
        }
    };
}

/// A close whose epoch, counts, and signatures checked, awaiting settlement on the balances
/// (commonware `Checked<P, H, A>`). Owns its flows and a reference to its matrix.
pub fn Checked(comptime P: type, comptime H: type, comptime A: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;
        const Matrix = matrix_module.Matrix(P, H, A);
        const Processed = summary_module.Processed(D);

        /// Epoch of the close.
        epoch: Epoch,
        /// Summary of the parent close.
        parent: summary_module.Summary(H),
        /// Payment matrix of the close.
        matrix: Matrix,
        /// Flow of every account the close touches.
        flows: settlement.Flows(P, A),
        /// The deposits the close processes, as their count and the queue's running hash.
        deposits: Processed,
        /// The forced withdrawals the close processes, as their count and running hash.
        forced_withdrawals: Processed,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.matrix.deinit();
            self.flows.deinit(gpa);
            self.* = undefined;
        }

        /// Checks `close` as the successor of the posted close `parent` against the ledger's
        /// `queue` (commonware `Close::check`). It checks the operator's signature before any
        /// user's, and chains each queue's running hash from `parent`'s summary over the
        /// prefix of `queue` that the close's counts select. The close stays the caller's.
        pub fn check(
            comptime O: type,
            gpa: Allocator,
            close: *const close_module.Close(P, O, A),
            namespace: *const Namespace,
            operator: *const O,
            parent: *const Checkpoint(P, H, A),
            queue: *const close_module.Queue(P, A),
            strategy: anytype,
        ) (CheckError || Allocator.Error)!Self {
            if (!parent.matrix.root().eql(parent.summary.matrix)) return error.InvalidCheckpoint;
            const epoch = std.math.add(Epoch, parent.summary.epoch, 1) catch
                return error.Overflow;
            if (close.epoch != epoch or queue.epoch != epoch) return error.WrongEpoch;
            for (close.withdrawals) |*w| if (w.epoch != epoch) return error.WrongEpoch;
            const queued = queue.prefix(close.deposits, close.forced_withdrawals) orelse
                return error.InvalidCount;

            // Check the operator's signature over the matrix root before any user signature,
            // so a close the operator did not sign costs only hashing.
            var matrix = try close.matrix(H, gpa, strategy);
            errdefer matrix.deinit();
            try verify_operator(O, gpa, close, namespace, operator, &matrix.root());
            try verify_users(O, close, namespace, &parent.matrix, &matrix, strategy);

            var flows = try settlement.Flows(P, A).init(
                gpa,
                epoch,
                close.rows,
                close.withdrawals,
                queued.deposits,
                queued.forced_withdrawals,
            );
            errdefer flows.deinit(gpa);
            const summary = parent.summary;
            const forced = summary.forced_withdrawals;
            assert(matrix.rows().len == close.rows.len);
            return .{
                .epoch = epoch,
                .parent = summary,
                .matrix = matrix,
                .flows = flows,
                .deposits = summary.deposits.next(H, close_module.Deposit(P, A), queued.deposits),
                .forced_withdrawals = forced.next(
                    H,
                    close_module.ForcedWithdrawal(P, A),
                    queued.forced_withdrawals,
                ),
            };
        }

        fn verify_operator(
            comptime O: type,
            gpa: Allocator,
            close: *const close_module.Close(P, O, A),
            namespace: *const Namespace,
            operator: *const O,
            root: *const D,
        ) (CheckError || Allocator.Error)!void {
            const message = try close_module.Close(P, O, A).message(
                D,
                gpa,
                close.epoch,
                root,
                close.withdrawals,
                close.deposits,
                close.forced_withdrawals,
            );
            defer gpa.free(message);
            if (!operator.verify(namespace.close, message, &close.signature)) {
                return error.InvalidOperatorSignature;
            }
        }

        fn UsersOp(comptime O: type) type {
            return struct {
                close: *const close_module.Close(P, O, A),
                namespace: *const Namespace,
                previous: *const Matrix,
                current: *const Matrix,
                empty: D,

                pub fn identity(_: @This()) void {}

                pub fn reduce(_: @This(), _: void, _: void) void {}

                pub fn fold(op: @This(), _: void, index: usize) CheckError!void {
                    if (index < op.close.rows.len) {
                        const row = &op.close.rows[index];
                        const state: payment.State(P, D) = .{
                            .epoch = op.close.epoch,
                            .account = row.account,
                            .payments = op.current.rows()[index][1],
                            .previous = op.previous.payments_root(&row.account) orelse op.empty,
                        };
                        if (!state.verify(op.namespace, &row.signature)) {
                            return error.InvalidSignature;
                        }
                    } else {
                        const withdrawal = &op.close.withdrawals[index - op.close.rows.len];
                        if (!withdrawal.verify(op.namespace)) return error.InvalidSignature;
                    }
                }
            };
        }

        /// Each sender must have signed exactly its row's payment map on top of the map the
        /// parent close settled for it, and each account its soft withdrawal.
        fn verify_users(
            comptime O: type,
            close: *const close_module.Close(P, O, A),
            namespace: *const Namespace,
            previous: *const Matrix,
            current: *const Matrix,
            strategy: anytype,
        ) CheckError!void {
            const op: UsersOp(O) = .{
                .close = close,
                .namespace = namespace,
                .previous = previous,
                .current = current,
                .empty = amounts_module.Amounts(P, A).empty.root(H),
            };
            const count = close.rows.len + close.withdrawals.len;
            return strategy.try_fold(parallel.Range.upto(count), op);
        }
    };
}
