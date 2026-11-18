//! A reference operator that admits requests and soft withdrawals and closes each epoch
//! (commonware `clearing/tests/bajillion/roles/operator.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const bajillion = @import("../../../bajillion/mod.zig");
const map = @import("map.zig");

const Epoch = bajillion.Epoch;
const Namespace = bajillion.Namespace;
const Limits = bajillion.Limits;

/// Why the operator refused a request, a soft withdrawal, or a close.
pub const Refusal = error{
    /// Admitting it would take the close past the operator's limits.
    Full,
    /// The batch exceeds what the sender can still spend in the epoch.
    InsufficientBalance,
    /// The soft withdrawal or the queue is for another epoch.
    WrongEpoch,
    /// The soft withdrawal's signature does not verify.
    InvalidWithdrawal,
    /// The next epoch does not fit.
    Overflow,
} || bajillion.RequestError || bajillion.AssemblyError || bajillion.FlowError ||
    Allocator.Error;

/// A map that counts its reads, so tests can tell whether the operator consulted it.
fn Records(comptime K: type, comptime V: type, comptime order: anytype) type {
    return struct {
        const Self = @This();
        pub const Inner = map.Map(K, V, order);

        inner: Inner = .{},
        reads: usize = 0,

        pub fn get(self: *Self, key: *const K) ?*V {
            self.reads += 1;
            return self.inner.get(key);
        }
    };
}

/// An operator with user keys `P`, signing key `K`, hasher `H`, and amounts `A`.
pub fn Operator(comptime P: type, comptime K: type, comptime H: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const O = K.PublicKey;
        pub const D = H.Digest;
        pub const Amounts = bajillion.Amounts(P, A);
        pub const State = bajillion.State(P, D);
        pub const Request = bajillion.Request(P, D, A);
        pub const Close = bajillion.Close(P, O, A);
        pub const Row = Close.RowType;
        pub const Withdrawal = Close.WithdrawalType;
        pub const Queue = Close.QueueType;
        pub const Assembled = Close.Assembled;

        /// A state the operator countersigned, with its map and the sender's signature.
        pub const Admitted = struct {
            state: State,
            /// Owned.
            payments: Amounts,
            signature: P.Signature,
        };

        /// A soft withdrawal's request: account, amount, and tag.
        pub const WithdrawalKey = struct {
            account: P,
            amount: A,
            tag: u64,

            fn order(a: *const WithdrawalKey, b: *const WithdrawalKey) std.math.Order {
                const by_account = a.account.order(b.account);
                if (by_account != .eq) return by_account;
                const by_amount = std.math.order(a.amount, b.amount);
                if (by_amount != .eq) return by_amount;
                return std.math.order(a.tag, b.tag);
            }
        };

        const order_account = map.order_method(P);

        /// What the operator persists. A restart resumes from it alone.
        pub const Persisted = struct {
            /// Epoch the operator is collecting.
            epoch: Epoch = 1,
            /// Balance of every account with a positive one after the last close.
            balances: Records(P, A, order_account) = .{},
            /// Root of each sender's row in the last close.
            previous: Records(P, D, order_account) = .{},
            /// The latest countersigned state of each sender in the open epoch.
            admitted: Records(P, Admitted, order_account) = .{},
            /// The soft withdrawals of the open epoch.
            withdrawals: map.Map(WithdrawalKey, Withdrawal, WithdrawalKey.order) = .{},
            /// The last close the operator released.
            released: ?Close = null,

            pub fn deinit(self: *Persisted, gpa: Allocator) void {
                self.balances.inner.deinit(gpa);
                self.previous.inner.deinit(gpa);
                for (self.admitted.inner.items()) |*entry| entry.value.payments.deinit(gpa);
                self.admitted.inner.deinit(gpa);
                self.withdrawals.deinit(gpa);
                if (self.released) |*released| released.deinit(gpa);
                self.* = undefined;
            }

            pub fn clone(self: *const Persisted, gpa: Allocator) Allocator.Error!Persisted {
                var copy: Persisted = .{ .epoch = self.epoch };
                errdefer copy.deinit(gpa);
                copy.balances.inner = try self.balances.inner.clone_shallow(gpa);
                copy.balances.reads = self.balances.reads;
                copy.previous.inner = try self.previous.inner.clone_shallow(gpa);
                copy.previous.reads = self.previous.reads;
                for (self.admitted.inner.items()) |*entry| {
                    var admitted = entry.value;
                    admitted.payments = try entry.value.payments.clone(gpa);
                    errdefer admitted.payments.deinit(gpa);
                    _ = try copy.admitted.inner.put(gpa, entry.key, admitted);
                }
                copy.admitted.reads = self.admitted.reads;
                copy.withdrawals = try self.withdrawals.clone_shallow(gpa);
                if (self.released) |*released| copy.released = try released.clone(gpa);
                return copy;
            }

            pub fn eql(a: *const Persisted, b: *const Persisted) bool {
                if (a.epoch != b.epoch) return false;
                const ab = a.balances.inner.items();
                const bb = b.balances.inner.items();
                if (ab.len != bb.len) return false;
                for (ab, bb) |x, y| if (!x.key.eql(y.key) or x.value != y.value) return false;
                const ap = a.previous.inner.items();
                const bp = b.previous.inner.items();
                if (ap.len != bp.len) return false;
                for (ap, bp) |x, y| if (!x.key.eql(y.key) or !x.value.eql(y.value)) return false;
                const aa = a.admitted.inner.items();
                const ba = b.admitted.inner.items();
                if (aa.len != ba.len) return false;
                for (aa, ba) |*x, *y| {
                    if (!x.value.state.eql(y.value.state)) return false;
                    if (!x.value.payments.eql(&y.value.payments)) return false;
                    if (!x.value.signature.eql(y.value.signature)) return false;
                }
                const aw = a.withdrawals.items();
                const bw = b.withdrawals.items();
                if (aw.len != bw.len) return false;
                for (aw, bw) |x, y| if (!x.value.eql(y.value)) return false;
                const x = if (a.released) |*released| released else return b.released == null;
                const y = if (b.released) |*released| released else return false;
                return x.eql(y);
            }
        };

        gpa: Allocator,
        signer: K,
        namespace: Namespace,
        limits: Limits,
        persisted: Persisted,

        /// An operator for the first epoch.
        pub fn init(
            gpa: Allocator,
            signer: K,
            namespace: *const Namespace,
            limits: Limits,
        ) Allocator.Error!Self {
            return restart(gpa, signer, namespace, limits, .{});
        }

        /// An operator resuming from what it persisted, taking ownership of `persisted`.
        pub fn restart(
            gpa: Allocator,
            signer: K,
            namespace: *const Namespace,
            limits: Limits,
            persisted: Persisted,
        ) Allocator.Error!Self {
            return .{
                .gpa = gpa,
                .signer = signer,
                .namespace = try namespace.clone(gpa),
                .limits = limits,
                .persisted = persisted,
            };
        }

        pub fn deinit(self: *Self) void {
            self.persisted.deinit(self.gpa);
            self.namespace.deinit(self.gpa);
            self.* = undefined;
        }

        /// A copy holding copies of the namespace and of what the role persisted.
        pub fn clone(self: *const Self) Allocator.Error!Self {
            var copy = self.*;
            copy.namespace = try self.namespace.clone(self.gpa);
            errdefer copy.namespace.deinit(self.gpa);
            copy.persisted = try self.persisted.clone(self.gpa);
            return copy;
        }

        /// Two operators are equal when they persisted the same records.
        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.persisted.eql(&b.persisted);
        }

        /// The epoch the operator is collecting.
        pub fn epoch(self: *const Self) Epoch {
            return self.persisted.epoch;
        }

        /// The reads of the balances, previous roots, and admissions so far.
        pub fn reads(self: *const Self) usize {
            const p = &self.persisted;
            return p.balances.reads + p.previous.reads + p.admitted.reads;
        }

        /// The account's balance after the last close.
        pub fn balance(self: *Self, account: *const P) A {
            const held = self.persisted.balances.get(account) orelse return 0;
            return held.*;
        }

        /// What the account can still spend in the open epoch: its balance less what its
        /// admitted map pays.
        pub fn live(self: *Self, account: *const P) A {
            const paid: A = if (self.payments(account)) |p| p.total().? else 0;
            const held = self.balance(account);
            assert(paid <= held); // Admitted payments never exceed the balance (O3).
            return held - paid;
        }

        /// The admitted payment map of `account` in the open epoch.
        pub fn payments(self: *Self, account: *const P) ?*const Amounts {
            const admitted = self.persisted.admitted.get(account) orelse return null;
            return &admitted.payments;
        }

        /// The rows of the open epoch in account order, as copies the caller owns.
        pub fn rows(self: *const Self, gpa: Allocator) Allocator.Error![]Row {
            const admitted = self.persisted.admitted.inner.items();
            const result = try gpa.alloc(Row, admitted.len);
            var made: usize = 0;
            errdefer {
                for (result[0..made]) |*row| row.deinit(gpa);
                gpa.free(result);
            }
            for (admitted, result) |*entry, *row| {
                row.* = .{
                    .account = entry.value.state.account,
                    .payments = try entry.value.payments.clone(gpa),
                    .signature = entry.value.signature,
                };
                made += 1;
            }
            return result;
        }

        /// The soft withdrawals of the open epoch, as a copy the caller owns.
        pub fn withdrawals(self: *const Self, gpa: Allocator) Allocator.Error![]Withdrawal {
            const entries = self.persisted.withdrawals.items();
            const result = try gpa.alloc(Withdrawal, entries.len);
            for (entries, result) |entry, *withdrawal| withdrawal.* = entry.value;
            return result;
        }

        /// Admits `request` and countersigns it (O1 to O4), persisting the admission before it
        /// answers. A retry is countersigned again and pays nothing twice.
        pub fn accept(self: *Self, request: *const Request) Refusal!O.Signature {
            const verified = try request.verify(H, &self.namespace, self.persisted.epoch);
            const empty = Amounts.empty.root(H);
            const previous = if (self.persisted.previous.get(&request.account)) |root|
                root.*
            else
                empty;
            const latest_admitted = self.persisted.admitted.get(&request.account);
            const latest: ?bajillion.Latest(P, D, A) = if (latest_admitted) |l|
                .{ .state = &l.state, .payments = &l.payments }
            else
                null;
            var admission = try verified.admit(H, self.gpa, latest, previous);
            const state = switch (admission) {
                .retry => |state| state,
                .new => |*new| state: {
                    errdefer admission.deinit(self.gpa);
                    try self.admit_new(request, latest_admitted == null, new);
                    break :state new.state;
                },
            };
            return state.acknowledge(&self.signer, &self.namespace);
        }

        /// Checks the limits (O5) and the spendable balance (O3) for a new state, then records
        /// it, taking its map.
        fn admit_new(
            self: *Self,
            request: *const Request,
            new_row: bool,
            new: *const bajillion.Admission(P, D, A).New,
        ) Refusal!void {
            const full_rows = self.persisted.admitted.inner.count() >= self.limits.rows;
            if ((new_row and full_rows) or new.payments.len() > self.limits.receivers) {
                return error.Full;
            }
            const spendable = self.live(&request.account);
            const total = request.batch.total() orelse return error.InsufficientBalance;
            if (total > spendable) return error.InsufficientBalance;
            const admitted: Admitted = .{
                .state = new.state,
                .payments = new.payments,
                .signature = new.signature,
            };
            const records = &self.persisted.admitted.inner;
            if (try records.put(self.gpa, request.account, admitted)) |old| {
                var replaced = old;
                replaced.payments.deinit(self.gpa);
            }
        }

        /// Forgets the admission of `account` in the open epoch, as an operator that lost it.
        pub fn forget(self: *Self, account: *const P) void {
            var removed = self.persisted.admitted.inner.remove(account) orelse return;
            removed.payments.deinit(self.gpa);
        }

        /// Admits a soft withdrawal of the open epoch (O6). A repeat is accepted once.
        pub fn withdraw(self: *Self, withdrawal: Withdrawal) Refusal!void {
            if (withdrawal.epoch != self.persisted.epoch) return error.WrongEpoch;
            if (!withdrawal.verify(&self.namespace)) return error.InvalidWithdrawal;
            const key: WithdrawalKey = .{
                .account = withdrawal.account,
                .amount = withdrawal.amount,
                .tag = withdrawal.tag,
            };
            const entries = &self.persisted.withdrawals;
            if (entries.contains(&key)) return;
            if (entries.count() >= self.limits.withdrawals) return error.Full;
            _ = try entries.put(self.gpa, key, withdrawal);
        }

        /// Closes the open epoch, processing the oldest `deposits` and `forced_withdrawals`
        /// requests in `queue`, applies the close to the balances, and moves to the next epoch
        /// (O7, O8). Returns the close with each touched account's flow; the caller frees it.
        pub fn close(
            self: *Self,
            queue: *const Queue,
            deposits: u64,
            forced_withdrawals: u64,
        ) Refusal!Assembled {
            const open = self.persisted.epoch;
            if (queue.epoch != open) return error.WrongEpoch;
            const next = std.math.add(Epoch, open, 1) catch return error.Overflow;
            const rows_owned = try self.rows(self.gpa);
            const withdrawals_owned = self.withdrawals(self.gpa) catch |err| {
                for (rows_owned) |*row| row.deinit(self.gpa);
                self.gpa.free(rows_owned);
                return err;
            };
            var assembled = try Close.assemble(
                H,
                self.gpa,
                &self.signer,
                &self.namespace,
                queue,
                rows_owned,
                withdrawals_owned,
                deposits,
                forced_withdrawals,
                parallel.sequential,
            );
            errdefer assembled.deinit(self.gpa);
            try self.apply(&assembled);
            self.persisted.epoch = next;
            return assembled;
        }

        /// Settles the flows of `assembled` on the balances and records the close's rows.
        fn apply(self: *Self, assembled: *const Assembled) Refusal!void {
            const flows = assembled.flows.flows;
            const settled = try self.gpa.alloc(A, flows.len);
            defer self.gpa.free(settled);
            for (flows, settled) |entry, *after| {
                after.* = (try entry[1].settle(self.balance(&entry[0]))).balance;
            }
            var released = try assembled.close.clone(self.gpa);
            errdefer released.deinit(self.gpa);
            var previous: map.Map(P, D, order_account) = .{};
            errdefer previous.deinit(self.gpa);
            for (assembled.close.rows) |*row| {
                _ = try previous.put(self.gpa, row.account, row.payments.root(H));
            }
            try self.persisted.balances.inner.entries.ensureUnusedCapacity(self.gpa, flows.len);
            const p = &self.persisted;
            for (flows, settled) |entry, after| {
                if (after == 0) {
                    _ = p.balances.inner.remove(&entry[0]);
                } else {
                    _ = p.balances.inner.put(self.gpa, entry[0], after) catch unreachable;
                    // Proof: capacity for every flow's account was reserved above.
                }
            }
            p.previous.inner.deinit(self.gpa);
            p.previous.inner = previous;
            for (p.admitted.inner.items()) |*entry| entry.value.payments.deinit(self.gpa);
            p.admitted.inner.clear();
            p.withdrawals.clear();
            if (p.released) |*old| old.deinit(self.gpa);
            p.released = released;
        }
    };
}
