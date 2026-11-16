//! Payment states, requests, acknowledgements, receipts, and challenges
//! (commonware `bajillion/payment.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const mod = @import("mod.zig");
const amounts_module = @import("amounts.zig");
const matrix_module = @import("matrix.zig");
const lookup_module = @import("lookup.zig");
const arb = @import("arbitrary.zig");

const bmt = storage.bmt;
const Namespace = mod.Namespace;
const Epoch = mod.Epoch;

/// Why a request is refused.
pub const RequestError = error{
    /// The request has no state for the epoch.
    WrongEpoch,
    /// The batch pays no receiver.
    NoReceivers,
    /// The sender's signature does not verify, or covers a state the operator would not
    /// countersign.
    InvalidSignature,
    /// The next epoch, an amount, or the payment map does not fit while deriving the states.
    Overflow,
    /// The latest state's root is that of its map with the batch already added, so both states
    /// derived from the pair could settle.
    InvalidLatest,
    /// The request builds on a root other than the one its latest state builds on.
    InvalidPrevious,
};

/// Why a challenge is refused.
pub const ChallengeError = error{
    /// The receipt is for another epoch.
    WrongEpoch,
    /// The opening does not verify.
    InvalidOpening,
    /// The close credits at least what the receipt promises.
    NoContradiction,
    /// The receipt does not verify.
    InvalidReceipt,
};

/// A sender's commitment to its payment map in one epoch (commonware `State<P, D>`).
///
/// The sender signs it to authorize the debit, the operator countersigns it to preconfirm the
/// payments, and a close settles it only on top of the sender's row in the close before.
pub fn State(comptime P: type, comptime D: type) type {
    mod.assert_public_key(P);
    return struct {
        const Self = @This();

        pub const fixed_size: usize = 8 + P.fixed_size + 2 * D.fixed_size;

        /// Epoch of the payments.
        epoch: Epoch,
        /// Account paying.
        account: P,
        /// Root of the sender's payment map in `epoch`.
        payments: D,
        /// Root of the sender's payment map in the previous epoch.
        previous: D,

        pub fn eql(a: Self, b: Self) bool {
            return a.epoch == b.epoch and a.account.eql(b.account) and
                a.payments.eql(b.payments) and a.previous.eql(b.previous);
        }

        /// The state's encoding, the message every signature over it covers.
        pub fn message(self: Self) [fixed_size]u8 {
            return codec.encode_fixed(Self, self);
        }

        /// Signs the state as its sender, in `Namespace.state`.
        pub fn sign(self: Self, signer: anytype, namespace: *const Namespace) P.Signature {
            comptime assert(@TypeOf(signer.*).Signature == P.Signature);
            return signer.sign(namespace.state, &self.message());
        }

        /// Returns whether `signature` is the sender's signature over the state.
        pub fn verify(self: Self, namespace: *const Namespace, signature: *const P.Signature) bool {
            return self.account.verify(namespace.state, &self.message(), signature);
        }

        /// Countersigns the state as the operator, in `Namespace.acknowledgement`.
        pub fn acknowledge(
            self: Self,
            signer: anytype,
            namespace: *const Namespace,
        ) @TypeOf(signer.*).Signature {
            return signer.sign(namespace.acknowledgement, &self.message());
        }

        /// Returns whether `signature` is `operator`'s countersignature over the state.
        pub fn verify_acknowledgement(
            self: Self,
            namespace: *const Namespace,
            operator: anytype,
            signature: *const @TypeOf(operator.*).Signature,
        ) bool {
            return operator.verify(namespace.acknowledgement, &self.message(), signature);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u64, self.epoch, writer);
            self.account.write(writer);
            self.payments.write(writer);
            self.previous.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .epoch = try codec.read(u64, gpa, reader),
                .account = try codec.read(P, gpa, reader),
                .payments = try codec.read(D, gpa, reader),
                .previous = try codec.read(D, gpa, reader),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .epoch = u.int(u64),
                .account = try arb.value(P, gpa, u),
                .payments = try arb.value(D, gpa, u),
                .previous = try arb.value(D, gpa, u),
            };
        }
    };
}

/// A sender's signatures over the two states of a `Request`, each over its state's encoding in
/// `Namespace.state` (commonware `Signatures<P>`).
pub fn Signatures(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const fixed_size: usize = 2 * P.Signature.fixed_size;

        /// Over the state of the request's epoch.
        current: P.Signature,
        /// Over the state of the next epoch.
        next: P.Signature,

        pub fn eql(a: Self, b: Self) bool {
            return a.current.eql(b.current) and a.next.eql(b.next);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.current.write(writer);
            self.next.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .current = try codec.read(P.Signature, gpa, reader),
                .next = try codec.read(P.Signature, gpa, reader),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .current = try arb.value(P.Signature, gpa, u),
                .next = try arb.value(P.Signature, gpa, u),
            };
        }
    };
}

/// The sender's latest countersigned state of an epoch with the map it commits to.
pub fn Latest(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        state: *const State(P, D),
        payments: *const amounts_module.Amounts(P, A),
    };
}

/// A sender's request to pay a batch of receivers in its epoch, or in the next if its epoch
/// closes first (commonware `Request<P, D, A>`).
///
/// It carries the roots its two states claim, so each signature verifies from the request
/// alone. The state of the request's epoch adds the batch to the sender's latest countersigned
/// map of that epoch, on top of `previous`, and the state of the next epoch pays only the batch
/// on top of that map (`latest`). The request owns its batch; `deinit` frees it.
pub fn Request(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Amounts = amounts_module.Amounts(P, A);
        pub const StateType = State(P, D);

        /// The maximum number of receivers in a batch.
        pub const Cfg = usize;

        /// Epoch the request is for.
        epoch: Epoch,
        /// Account paying.
        account: P,
        /// Amount paid to each receiver.
        batch: Amounts,
        /// Root of the sender's payment map in the epoch before `epoch`.
        previous: D,
        /// Root of the sender's latest countersigned payment map in `epoch`.
        latest: D,
        /// Root of the sender's payment map in `epoch` with the batch added.
        payments: D,
        /// Sender's signatures over its states.
        signatures: Signatures(P),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.batch.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self.*;
            copy.batch = try self.batch.clone(gpa);
            return copy;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.epoch == b.epoch and a.account.eql(b.account) and
                a.batch.eql(&b.batch) and a.previous.eql(b.previous) and
                a.latest.eql(b.latest) and a.payments.eql(b.payments) and
                a.signatures.eql(b.signatures);
        }

        /// Derives the states of `account`'s request to pay `batch` in `epoch`, taking ownership
        /// of `batch` (freed on error). `latest` is its latest countersigned state of `epoch`
        /// with the map that state commits to, or null if it has paid nothing in `epoch`. The
        /// state of `epoch` adds `batch` to that map, or to the empty map, on top of `previous`,
        /// and the state of the next epoch pays only `batch` on top of that map. When `latest`
        /// is given, `previous` must be the root that state builds on (S1).
        ///
        /// The latest state's root is taken as its map's root. A root that already holds the
        /// batch is refused, because both states derived from it could settle.
        pub fn states(
            comptime H: type,
            gpa: Allocator,
            epoch: Epoch,
            account: P,
            batch: Amounts,
            latest: ?Latest(P, D, A),
            previous: D,
        ) (RequestError || Allocator.Error)!States(P, D, A) {
            comptime assert(H.Digest == D);
            var owned = batch;
            errdefer owned.deinit(gpa);
            if (owned.is_empty()) return error.NoReceivers;
            // Extending a countersigned map on another root could settle its payments again
            // after a post that conflicts with its state.
            if (latest) |l| if (!l.state.previous.eql(previous)) return error.InvalidPrevious;

            // The latest state holds the root of its map, and a map that starts with the batch
            // has the batch's root, so each map is hashed at most once.
            const next: StateType = .{
                .epoch = std.math.add(u64, epoch, 1) catch return error.Overflow,
                .account = account,
                .payments = owned.root(H),
                .previous = if (latest) |l| l.state.payments else Amounts.empty.root(H),
            };
            var payments: Amounts = if (latest) |l|
                l.payments.combine(gpa, &owned) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.Overflow,
                }
            else
                try owned.clone(gpa);
            errdefer payments.deinit(gpa);
            const root = if (latest == null) next.payments else payments.root(H);

            // A next state that builds on the map the current state pays could settle after it
            // and pay the batch twice.
            if (next.previous.eql(root)) return error.InvalidLatest;
            return .{
                .batch = owned,
                .current = .{
                    .epoch = epoch,
                    .account = account,
                    .payments = root,
                    .previous = previous,
                },
                .payments = payments,
                .next = next,
            };
        }

        /// Verifies the sender's signature over the request's state for `epoch`, either its
        /// state of its own epoch or its state of the next.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            namespace: *const Namespace,
            epoch: Epoch,
        ) RequestError!Verified(P, D, A) {
            comptime assert(H.Digest == D);
            var payments: D = undefined;
            var previous: D = undefined;
            var signature: *const P.Signature = undefined;
            if (epoch == self.epoch) {
                payments = self.payments;
                previous = self.previous;
                signature = &self.signatures.current;
            } else if (self.epoch != std.math.maxInt(u64) and self.epoch + 1 == epoch) {
                payments = self.batch.root(H);
                previous = self.latest;
                signature = &self.signatures.next;
            } else {
                return error.WrongEpoch;
            }
            if (self.batch.is_empty()) return error.NoReceivers;
            const state: StateType = .{
                .epoch = epoch,
                .account = self.account,
                .payments = payments,
                .previous = previous,
            };
            if (!state.verify(namespace, signature)) return error.InvalidSignature;
            return .{ .request = self, .state = state, .signature = signature.* };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u64, self.epoch, writer);
            self.account.write(writer);
            self.batch.write(writer);
            self.previous.write(writer);
            self.latest.write(writer);
            self.payments.write(writer);
            self.signatures.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 8 + P.fixed_size + self.batch.encode_size() + 3 * D.fixed_size +
                Signatures(P).fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, receivers: Cfg) codec.Error!Self {
            const epoch = try codec.read(u64, gpa, reader);
            const account = try codec.read(P, gpa, reader);
            var batch = try Amounts.read(gpa, reader, .inclusive(1, receivers));
            errdefer batch.deinit(gpa);
            return .{
                .epoch = epoch,
                .account = account,
                .batch = batch,
                .previous = try codec.read(D, gpa, reader),
                .latest = try codec.read(D, gpa, reader),
                .payments = try codec.read(D, gpa, reader),
                .signatures = try codec.read(Signatures(P), gpa, reader),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const batch = try Amounts.arbitrary_nonempty(gpa, u);
            return .{
                .epoch = u.int(u64),
                .account = try arb.value(P, gpa, u),
                .batch = batch,
                .previous = try arb.value(D, gpa, u),
                .latest = try arb.value(D, gpa, u),
                .payments = try arb.value(D, gpa, u),
                .signatures = try Signatures(P).arbitrary(gpa, u),
            };
        }
    };
}

/// The states of one request, the batch it pays, and the payment map its state of the
/// request's epoch commits to (commonware `States<P, D, A>`). Owns both maps.
pub fn States(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        const Amounts = amounts_module.Amounts(P, A);

        /// The batch the request pays.
        batch: Amounts,
        /// The state for the request's epoch.
        current: State(P, D),
        /// The payment map `current` commits to, the sender's map with the batch added.
        payments: Amounts,
        /// The state for the next epoch. It commits to `batch` alone.
        next: State(P, D),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.batch.deinit(gpa);
            self.payments.deinit(gpa);
            self.* = undefined;
        }

        /// Returns the request carrying these states, their claimed roots, and `signatures`
        /// over them. Each signature covers its state's encoding in `Namespace.state`.
        pub fn request(
            self: *const Self,
            gpa: Allocator,
            signatures: Signatures(P),
        ) Allocator.Error!Request(P, D, A) {
            assert(self.current.account.eql(self.next.account));
            return .{
                .epoch = self.current.epoch,
                .account = self.current.account,
                .batch = try self.batch.clone(gpa),
                .previous = self.current.previous,
                .latest = self.next.previous,
                .payments = self.current.payments,
                .signatures = signatures,
            };
        }

        /// Signs both states with `signer` in `Namespace.state`, and returns the request as
        /// `request` does.
        pub fn sign(
            self: *const Self,
            gpa: Allocator,
            signer: anytype,
            namespace: *const Namespace,
        ) Allocator.Error!Request(P, D, A) {
            return self.request(gpa, .{
                .current = self.current.sign(signer, namespace),
                .next = self.next.sign(signer, namespace),
            });
        }
    };
}

/// A request whose state for one epoch carries a valid sender signature (commonware
/// `Verified`). Borrows its request.
pub fn Verified(comptime P: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        const Amounts = amounts_module.Amounts(P, A);

        request: *const Request(P, D, A),
        state: State(P, D),
        signature: P.Signature,

        /// Admits the verified state against the operator's record of its sender. `latest` is
        /// the sender's latest countersigned state in the state's epoch with its map, if any.
        /// `previous` is the root of the sender's row in the close of the epoch before, or the
        /// empty map's root.
        ///
        /// Returns `retry` if the state is `latest`'s, and `new` if it pays `latest`'s map plus
        /// the batch on top of `previous`. Any other state is refused as one the operator would
        /// not countersign, including one whose batch overflows the map.
        pub fn admit(
            self: Self,
            comptime H: type,
            gpa: Allocator,
            latest: ?Latest(P, D, A),
            previous: D,
        ) (RequestError || Allocator.Error)!Admission(P, D, A) {
            comptime assert(H.Digest == D);
            if (latest) |l| if (l.state.eql(self.state)) return .{ .retry = self.state };
            if (!self.state.previous.eql(previous)) return error.InvalidSignature;
            const payments = if (latest) |l| l.payments else &Amounts.empty;
            const batch = &self.request.batch;
            var extended = payments.combine(gpa, batch) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidSignature,
            };
            if (!extended.root(H).eql(self.state.payments)) {
                extended.deinit(gpa);
                return error.InvalidSignature;
            }
            return .{ .new = .{
                .state = self.state,
                .payments = extended,
                .signature = self.signature,
            } };
        }
    };
}

/// What the operator may countersign for a verified request (commonware `Admission`).
pub fn Admission(comptime P: type, comptime D: type, comptime A: type) type {
    return union(enum) {
        const Self = @This();

        /// The request repeats the sender's latest countersigned state. Countersigning it again
        /// pays nothing twice.
        retry: State(P, D),
        /// A new state extending the sender's latest map by the batch.
        new: New,

        pub const New = struct {
            /// The state to countersign.
            state: State(P, D),
            /// The payment map `state` commits to; owned.
            payments: amounts_module.Amounts(P, A),
            /// The sender's signature over `state`.
            signature: P.Signature,
        };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .retry => {},
                .new => |*new| new.payments.deinit(gpa),
            }
            self.* = undefined;
        }
    };
}

/// A preconfirmation that `state`'s sender paid `receiver` a cumulative `amount` in the state's
/// epoch (commonware `Receipt<P, O, D, A>`). Owns its proof.
///
/// The close of that epoch must credit the receiver at least `amount` from the sender, or the
/// receiver can halt the ledger with a `Challenge`.
pub fn Receipt(comptime P: type, comptime O: type, comptime D: type, comptime A: type) type {
    mod.assert_public_key(O);
    mod.assert_amount(A);
    return struct {
        const Self = @This();
        const Amounts = amounts_module.Amounts(P, A);

        /// The sender's state.
        state: State(P, D),
        /// The sender's signature over `state`.
        signature: P.Signature,
        /// The operator's countersignature over `state`.
        acknowledgement: O.Signature,
        /// Account paid.
        receiver: P,
        /// Cumulative amount paid to `receiver` in the state's payment map.
        amount: A,
        /// Position of `receiver` in the state's payment map.
        position: u32,
        /// Opening of `receiver`'s entry under the state's payment map root.
        proof: bmt.Proof(D),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self.*;
            copy.proof = try self.proof.clone(gpa);
            return copy;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.state.eql(b.state) and a.signature.eql(b.signature) and
                a.acknowledgement.eql(b.acknowledgement) and a.receiver.eql(b.receiver) and
                a.amount == b.amount and a.position == b.position and a.proof.eql(&b.proof);
        }

        /// Returns a receipt for each of `receivers` from `state`, the sender's `signature`
        /// over it, the operator's `acknowledgement` countersigning it, and `payments`, the map
        /// it commits to, or null if `payments` does not commit to `state` or holds no amount
        /// for a receiver. The receipts verify exactly when both signatures do. The caller
        /// frees the slice and each receipt.
        pub fn issue(
            comptime H: type,
            gpa: Allocator,
            state: State(P, D),
            signature: P.Signature,
            acknowledgement: O.Signature,
            payments: *const Amounts,
            receivers: []const P,
        ) Allocator.Error!?[]Self {
            comptime assert(H.Digest == D);
            var tree = try payments.tree(H, gpa);
            defer tree.deinit(gpa);
            if (!tree.root().eql(state.payments)) return null;
            const receipts = try gpa.alloc(Self, receivers.len);
            var issued: usize = 0;
            errdefer {
                for (receipts[0..issued]) |*receipt| receipt.deinit(gpa);
                gpa.free(receipts);
            }
            for (receivers, receipts) |*receiver, *receipt| {
                var opening = try payments.lookup(D, gpa, &tree, receiver);
                const member = switch (opening) {
                    .member => |m| m,
                    .non_member => {
                        opening.deinit(gpa);
                        for (receipts[0..issued]) |*done| done.deinit(gpa);
                        gpa.free(receipts);
                        return null;
                    },
                };
                receipt.* = .{
                    .state = state,
                    .signature = signature,
                    .acknowledgement = acknowledgement,
                    .receiver = receiver.*,
                    .amount = member.value,
                    .position = member.position,
                    .proof = member.proof,
                };
                issued += 1;
            }
            assert(issued == receivers.len);
            return receipts;
        }

        /// Returns whether both signatures cover the state and its payment map holds the
        /// receipt's entry.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            namespace: *const Namespace,
            operator: *const O,
        ) bool {
            if (!self.state.verify(namespace, &self.signature)) return false;
            const ack = &self.acknowledgement;
            if (!self.state.verify_acknowledgement(namespace, operator, ack)) return false;
            const entry = amounts_module.leaf(H, P, A, &self.receiver, self.amount);
            const root = &self.state.payments;
            self.proof.verify_element_inclusion(H, self.position, &entry, root, null) catch
                return false;
            return true;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.state.write(writer);
            self.signature.write(writer);
            self.acknowledgement.write(writer);
            self.receiver.write(writer);
            codec.write(A, self.amount, writer);
            codec.write(u32, self.position, writer);
            self.proof.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return State(P, D).fixed_size + P.Signature.fixed_size + O.Signature.fixed_size +
                P.fixed_size + codec.fixed_size(A).? + 4 + self.proof.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .state = try codec.read(State(P, D), gpa, reader),
                .signature = try codec.read(P.Signature, gpa, reader),
                .acknowledgement = try codec.read(O.Signature, gpa, reader),
                .receiver = try codec.read(P, gpa, reader),
                .amount = try codec.read(A, gpa, reader),
                .position = try codec.read(u32, gpa, reader),
                .proof = try bmt.Proof(D).read(gpa, reader, 1),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .state = try State(P, D).arbitrary(gpa, u),
                .signature = try arb.value(P.Signature, gpa, u),
                .acknowledgement = try arb.value(O.Signature, gpa, u),
                .receiver = try arb.value(P, gpa, u),
                .amount = try arb.value(A, gpa, u),
                .position = u.int(u32),
                .proof = try lookup_module.arbitrary_proof(D, gpa, u),
            };
        }
    };
}

/// Evidence that a posted close credits a receiver less than a receipt promised (commonware
/// `Challenge<P, O, D, A>`). Owns its receipt and opening.
pub fn Challenge(comptime P: type, comptime O: type, comptime D: type, comptime A: type) type {
    return struct {
        const Self = @This();
        const ReceiptType = Receipt(P, O, D, A);
        const OpeningType = matrix_module.Opening(P, D, A);

        /// The receipt the close contradicts.
        receipt: ReceiptType,
        /// Opening of the receipt's entry in the matrix of the posted close of its epoch.
        opening: OpeningType,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.receipt.deinit(gpa);
            self.opening.deinit(gpa);
            self.* = undefined;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.receipt.eql(&b.receipt) and a.opening.eql(&b.opening);
        }

        /// Checks that the posted close of `epoch` with payment matrix root `matrix` credits the
        /// receipt's receiver less from its sender than the receipt promises. The receipt's
        /// signatures are checked last, so every earlier refusal costs only hashes.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            namespace: *const Namespace,
            operator: *const O,
            epoch: Epoch,
            matrix: *const D,
        ) ChallengeError!void {
            const receipt = &self.receipt;
            if (receipt.state.epoch != epoch) return error.WrongEpoch;
            const sender = &receipt.state.account;
            const credited = try self.opening.verify(H, matrix, sender, &receipt.receiver);
            if (credited >= receipt.amount) return error.NoContradiction;
            if (!receipt.verify(H, namespace, operator)) return error.InvalidReceipt;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.receipt.write(writer);
            self.opening.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return self.receipt.encode_size() + self.opening.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            var receipt = try codec.read(ReceiptType, gpa, reader);
            errdefer receipt.deinit(gpa);
            return .{ .receipt = receipt, .opening = try codec.read(OpeningType, gpa, reader) };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .receipt = try ReceiptType.arbitrary(gpa, u),
                .opening = try OpeningType.arbitrary(gpa, u),
            };
        }
    };
}
