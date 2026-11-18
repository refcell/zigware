//! A reference sender that pays through the operator and resolves its requests and its recorded
//! maps against posted closes (commonware `clearing/tests/bajillion/roles/sender.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bajillion = @import("../../../bajillion/mod.zig");
const map = @import("map.zig");

const Epoch = bajillion.Epoch;
const Namespace = bajillion.Namespace;

/// Why the sender refused to act.
pub const Refusal = error{
    /// A request is still pending.
    Pending,
    /// No request is pending.
    NotPending,
    /// The sender holds a countersigned map of a later epoch.
    LaterEpoch,
    /// The acknowledgement countersigns none of the pending request's states.
    InvalidAcknowledgement,
    /// The sender already resolved the post of the acknowledged state's epoch.
    Closed,
    /// The sender holds no acknowledged state of the epoch.
    NotAcknowledged,
    /// The recorded state and map issue no receipt for a receiver.
    InvalidReceipt,
} || bajillion.RequestError || bajillion.InvalidOpening || Allocator.Error;

/// What a posted close settled for the sender (S5).
pub const Outcome = enum {
    /// The close settled the map the sender recorded for the epoch, or it has no row of the
    /// sender and the sender recorded no map.
    match,
    /// The close settled a state of the pending request. The sender records that state's map
    /// and clears the request.
    settled,
    /// The close settled another map, or it has no row of the sender where the sender recorded
    /// a map. Openings of the row show its payments.
    conflict,
};

/// A sender with signing key `S`, operator key `O`, hasher `H`, and amounts `A`.
pub fn Sender(comptime S: type, comptime O: type, comptime H: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const P = S.PublicKey;
        pub const D = H.Digest;
        pub const Amounts = bajillion.Amounts(P, A);
        pub const State = bajillion.State(P, D);
        pub const Request = bajillion.Request(P, D, A);
        pub const States = bajillion.States(P, D, A);
        pub const Receipt = bajillion.Receipt(P, O, D, A);
        pub const Opening = bajillion.Opening(P, D, A);

        /// A countersigned state with the sender's signature, the operator's acknowledgement
        /// if the sender received it, and the payment map the state commits to (S2, S3).
        pub const Countersigned = struct {
            state: State,
            signature: P.Signature,
            acknowledgement: ?O.Signature,
            /// Owned.
            payments: Amounts,

            fn clone(self: *const Countersigned, gpa: Allocator) Allocator.Error!Countersigned {
                var copy = self.*;
                copy.payments = try self.payments.clone(gpa);
                return copy;
            }

            fn eql(a: *const Countersigned, b: *const Countersigned) bool {
                const acks_equal = if (a.acknowledgement) |x|
                    (if (b.acknowledgement) |y| x.eql(y) else false)
                else
                    b.acknowledgement == null;
                return a.state.eql(b.state) and a.signature.eql(b.signature) and acks_equal and
                    a.payments.eql(&b.payments);
            }
        };

        /// A request awaiting an answer, with its states. Owns both.
        pub const Pending = struct {
            request: Request,
            states: States,

            fn deinit(self: *Pending, gpa: Allocator) void {
                self.request.deinit(gpa);
                self.states.deinit(gpa);
            }

            fn clone(self: *const Pending, gpa: Allocator) Allocator.Error!Pending {
                var request = try self.request.clone(gpa);
                errdefer request.deinit(gpa);
                var states = self.states;
                states.batch = try self.states.batch.clone(gpa);
                errdefer states.batch.deinit(gpa);
                states.payments = try self.states.payments.clone(gpa);
                return .{ .request = request, .states = states };
            }
        };

        const Records = map.Map(Epoch, Countersigned, map.order_int(Epoch));
        const Posted = map.Map(Epoch, D, map.order_int(Epoch));

        /// What the sender persists. A restart resumes from it alone.
        pub const Persisted = struct {
            /// The latest countersigned state of each epoch the sender paid in, or the state
            /// the post of that epoch settled.
            countersigned: Records = .{},
            /// The sender's row root in each posted close (S5).
            posted: Posted = .{},
            /// The request awaiting an answer with its states, persisted before it is sent.
            pending: ?Pending = null,

            pub fn deinit(self: *Persisted, gpa: Allocator) void {
                for (self.countersigned.items()) |*entry| entry.value.payments.deinit(gpa);
                self.countersigned.deinit(gpa);
                self.posted.deinit(gpa);
                if (self.pending) |*p| p.deinit(gpa);
                self.* = undefined;
            }

            pub fn clone(self: *const Persisted, gpa: Allocator) Allocator.Error!Persisted {
                var copy: Persisted = .{};
                errdefer copy.deinit(gpa);
                for (self.countersigned.items()) |*entry| {
                    var value = try entry.value.clone(gpa);
                    errdefer value.payments.deinit(gpa);
                    _ = try copy.countersigned.put(gpa, entry.key, value);
                }
                copy.posted = try self.posted.clone_shallow(gpa);
                if (self.pending) |*p| copy.pending = try p.clone(gpa);
                return copy;
            }

            pub fn eql(a: *const Persisted, b: *const Persisted) bool {
                if (a.countersigned.count() != b.countersigned.count()) return false;
                for (a.countersigned.items(), b.countersigned.items()) |*x, *y| {
                    if (x.key != y.key or !x.value.eql(&y.value)) return false;
                }
                if (a.posted.count() != b.posted.count()) return false;
                for (a.posted.items(), b.posted.items()) |x, y| {
                    if (x.key != y.key or !x.value.eql(y.value)) return false;
                }
                const x = a.pending orelse return b.pending == null;
                const y = b.pending orelse return false;
                return x.request.eql(&y.request);
            }
        };

        gpa: Allocator,
        signer: S,
        account: P,
        namespace: Namespace,
        operator: O,
        persisted: Persisted,

        /// A sender with no countersigned state and no pending request.
        pub fn init(gpa: Allocator, signer: S, namespace: *const Namespace, operator: O) !Self {
            return restart(gpa, signer, namespace, operator, .{});
        }

        /// A sender resuming from what it persisted, taking ownership of `persisted`.
        pub fn restart(
            gpa: Allocator,
            signer: S,
            namespace: *const Namespace,
            operator: O,
            persisted: Persisted,
        ) !Self {
            return .{
                .gpa = gpa,
                .account = signer.public_key(),
                .signer = signer,
                .namespace = try namespace.clone(gpa),
                .operator = operator,
                .persisted = persisted,
            };
        }

        pub fn deinit(self: *Self) void {
            self.persisted.deinit(self.gpa);
            self.namespace.deinit(self.gpa);
            self.* = undefined;
        }

        /// Two senders are equal when they persisted the same records.
        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.persisted.eql(&b.persisted);
        }

        /// The countersigned payment map of `epoch`.
        pub fn payments(self: *const Self, epoch: Epoch) ?*const Amounts {
            const countersigned = self.persisted.countersigned.get(&epoch) orelse return null;
            return &countersigned.payments;
        }

        /// The pending request, if any.
        pub fn pending(self: *const Self) ?*const Request {
            if (self.persisted.pending) |*p| return &p.request;
            return null;
        }

        /// The root a request in `epoch` builds on (S1). An existing countersigned map keeps
        /// its predecessor. A new map uses the posted row root of the epoch before if recorded,
        /// else its countersigned map's root, else the empty map's root.
        fn previous(self: *const Self, epoch: Epoch) D {
            if (self.persisted.countersigned.get(&epoch)) |c| return c.state.previous;
            if (epoch > 0) {
                const before = epoch - 1;
                if (self.persisted.posted.get(&before)) |root| return root.*;
                if (self.persisted.countersigned.get(&before)) |c| return c.state.payments;
            }
            return Amounts.empty.root(H);
        }

        /// Signs a request paying `batch` (taken) in `epoch` on top of the countersigned map of
        /// that epoch, or on top of it in the next. The request is persisted before a copy of
        /// it is returned for sending; the caller frees the copy.
        pub fn send(self: *Self, epoch: Epoch, batch: Amounts) Refusal!Request {
            var owned = batch;
            // One request at a time, and none for an epoch before one with a countersigned map.
            if (self.persisted.pending != null) {
                owned.deinit(self.gpa);
                return error.Pending;
            }
            if (self.persisted.countersigned.last()) |latest| if (latest.key > epoch) {
                owned.deinit(self.gpa);
                return error.LaterEpoch;
            };
            const latest: ?bajillion.Latest(P, D, A) =
                if (self.persisted.countersigned.get(&epoch)) |c|
                    .{ .state = &c.state, .payments = &c.payments }
                else
                    null;
            const before = self.previous(epoch);
            var states =
                try Request.states(H, self.gpa, epoch, self.account, owned, latest, before);
            errdefer states.deinit(self.gpa);
            var request = try states.sign(self.gpa, &self.signer, &self.namespace);
            errdefer request.deinit(self.gpa);
            const copy = try request.clone(self.gpa);
            self.persisted.pending = .{ .request = request, .states = states };
            return copy;
        }

        /// The pending state `acknowledgement` countersigns, as a countersigned record holding a
        /// copy of its map, or null if it countersigns neither.
        fn countersigned_by(self: *const Self, ack: *const O.Signature) !?Countersigned {
            const p = &self.persisted.pending.?;
            const candidates = [_]struct { *const State, P.Signature, *const Amounts }{
                .{ &p.states.current, p.request.signatures.current, &p.states.payments },
                .{ &p.states.next, p.request.signatures.next, &p.states.batch },
            };
            for (candidates) |candidate| {
                const state = candidate[0];
                const ns = &self.namespace;
                if (!state.verify_acknowledgement(ns, &self.operator, ack)) continue;
                return .{
                    .state = state.*,
                    .signature = candidate[1],
                    .acknowledgement = ack.*,
                    .payments = try candidate[2].clone(self.gpa),
                };
            }
            return null;
        }

        /// Records the pending state the operator countersigned, with both signatures and its
        /// map, in one write that also clears the request (S2, S3). Only then does it return a
        /// receipt for each receiver of its batch. A state of an epoch whose post the sender
        /// resolved is refused, and the request stays pending. The caller frees the receipts.
        pub fn acknowledged(self: *Self, acknowledgement: *const O.Signature) Refusal![]Receipt {
            const p = if (self.persisted.pending) |*value| value else return error.NotPending;
            const receivers = try self.gpa.alloc(P, p.states.batch.entries.len);
            defer self.gpa.free(receivers);
            for (p.states.batch.entries, receivers) |entry, *receiver| receiver.* = entry[0];
            const epoch = recorded: {
                var countersigned = try self.countersigned_by(acknowledgement) orelse
                    return error.InvalidAcknowledgement;
                errdefer countersigned.payments.deinit(self.gpa);
                // A post is final for its epoch, so a state of a resolved epoch is not
                // recorded, and the request stays pending (S2).
                const at = countersigned.state.epoch;
                if (self.persisted.posted.last()) |resolved| {
                    if (at <= resolved.key) return error.Closed;
                }
                const records = &self.persisted.countersigned;
                if (try records.put(self.gpa, at, countersigned)) |old| {
                    var replaced = old;
                    replaced.payments.deinit(self.gpa);
                }
                break :recorded at;
            };
            // One write records the state and clears the request before any receipt (S3).
            p.deinit(self.gpa);
            self.persisted.pending = null;
            return self.receipts(epoch, receivers);
        }

        /// Issues receipts for `receivers` from the acknowledged state of `epoch` the sender
        /// persisted. The caller frees the receipts.
        pub fn receipts(self: *const Self, epoch: Epoch, receivers: []const P) Refusal![]Receipt {
            const c = self.persisted.countersigned.get(&epoch) orelse
                return error.NotAcknowledged;
            const acknowledgement = c.acknowledgement orelse return error.NotAcknowledged;
            return try Receipt.issue(
                H,
                self.gpa,
                c.state,
                c.signature,
                acknowledgement,
                &c.payments,
                receivers,
            ) orelse error.InvalidReceipt;
        }

        /// Drops the pending request after a refusal of its only delivery (S4).
        pub fn refused(self: *Self) Refusal!void {
            var p = self.persisted.pending orelse return error.NotPending;
            p.deinit(self.gpa);
            self.persisted.pending = null;
        }

        /// Records the final post of `epoch` with matrix root `root` from an opening of this
        /// sender's row, resolves the pending request against it, and returns what the close
        /// settled (S5). Posts must arrive in epoch order.
        pub fn posted(
            self: *Self,
            epoch: Epoch,
            root: *const D,
            opening: *const Opening,
        ) Refusal!Outcome {
            const row = try opening.verify_row(H, root, &self.account);
            const empty = Amounts.empty.root(H);
            const posted_root = row orelse empty;
            _ = try self.persisted.posted.put(self.gpa, epoch, posted_root);
            if (try self.resolve_pending(epoch, row, posted_root)) return .settled;
            const record = if (self.persisted.countersigned.get(&epoch)) |c|
                c.state.payments
            else
                empty;
            return if (record.eql(posted_root)) .match else .conflict;
        }

        /// Settles the pending request if a state of `epoch` has the posted row root, and drops
        /// it if none of its states can still settle. Returns whether it settled.
        fn resolve_pending(self: *Self, epoch: Epoch, row: ?D, posted_root: D) !bool {
            const p = if (self.persisted.pending) |*value| value else return false;
            const proposed = [_]struct { *const State, P.Signature, *const Amounts }{
                .{ &p.states.current, p.request.signatures.current, &p.states.payments },
                .{ &p.states.next, p.request.signatures.next, &p.states.batch },
            };
            var live = false;
            for (proposed) |candidate| {
                const state = candidate[0];
                if (state.epoch == epoch and row != null and state.payments.eql(row.?)) {
                    const settled: Countersigned = .{
                        .state = state.*,
                        .signature = candidate[1],
                        .acknowledgement = null,
                        .payments = try candidate[2].clone(self.gpa),
                    };
                    if (try self.persisted.countersigned.put(self.gpa, epoch, settled)) |old| {
                        var replaced = old;
                        replaced.payments.deinit(self.gpa);
                    }
                    p.deinit(self.gpa);
                    self.persisted.pending = null;
                    return true;
                }
                if (state.epoch > epoch and
                    (state.epoch - 1 > epoch or state.previous.eql(posted_root))) live = true;
            }
            if (!live) {
                p.deinit(self.gpa);
                self.persisted.pending = null;
            }
            return false;
        }

        /// Forgets the countersigned states and posted roots of epochs before `epoch`.
        pub fn prune(self: *Self, epoch: Epoch) void {
            const records = &self.persisted.countersigned;
            const dropped = records.below(&epoch);
            for (records.items()[0..dropped]) |*entry| entry.value.payments.deinit(self.gpa);
            records.drop_front(dropped);
            self.persisted.posted.drop_front(self.persisted.posted.below(&epoch));
        }
    };
}
