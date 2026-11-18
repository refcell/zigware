//! A reference ledger that holds deposited funds, posts certified summaries, pays out posted
//! payouts, and pays claims after a halt (commonware
//! `clearing/tests/bajillion/roles/ledger.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const bajillion = @import("../../../bajillion/mod.zig");
const map = @import("map.zig");

const Epoch = bajillion.Epoch;
const Namespace = bajillion.Namespace;

/// Why the ledger halted.
pub const Halt = union(enum) {
    /// A challenge of the close of `epoch` succeeded.
    challenge: Epoch,
    /// The ledger halted for a fault outside the protocol, such as an operator that stopped.
    fault,

    pub fn eql(a: Halt, b: Halt) bool {
        return switch (a) {
            .challenge => |epoch| b == .challenge and b.challenge == epoch,
            .fault => b == .fault,
        };
    }
};

/// Why the ledger refused a call.
pub const Refusal = error{
    /// The ledger halted.
    Halted,
    /// The ledger has not halted.
    NotHalted,
    /// The account has nothing left to claim.
    NothingToClaim,
    /// The call would take more than the ledger holds or can hold.
    Custody,
    /// No close of the named epoch has posted.
    NotPosted,
    /// The payout at the proven index was already paid.
    Withdrawn,
    /// The balance or payout proof does not verify under its posted root.
    InvalidProof,
    /// The amount is zero.
    ZeroAmount,
} || bajillion.SummaryError || bajillion.ChallengeError || Allocator.Error;

/// A ledger with user keys `P`, operator key `O`, certificate verifier `V`, hasher `H`, and
/// amounts `A`.
pub fn Ledger(P: type, O: type, V: type, H: type, A: type) type {
    return struct {
        const Self = @This();
        pub const D = H.Digest;
        pub const Summary = bajillion.Summary(H);
        pub const Deposit = bajillion.Deposit(P, A);
        pub const Forced = bajillion.ForcedWithdrawal(P, A);
        pub const Queue = bajillion.Queue(P, A);
        pub const Challenge = bajillion.Challenge(P, O, D, A);
        pub const PayoutProof = bajillion.PayoutProof(P, D, A);
        pub const BalanceProof = bajillion.BalanceProof(D, A);
        const order_account = map.order_method(P);

        /// What the ledger persists. A restart resumes from it alone.
        pub const Persisted = struct {
            /// Digest of the last posted summary.
            parent: D,
            /// Balances root of the last posted summary.
            balances: D,
            /// Matrix root of each posted close, by epoch from 1.
            matrices: std.ArrayList(D) = .empty,
            /// Payouts root of each posted close, by epoch from 1.
            payouts: std.ArrayList(D) = .empty,
            /// The funds the ledger holds.
            held: A = 0,
            /// Deposits no close has processed, oldest first.
            deposits: std.ArrayList(Deposit) = .empty,
            /// How many of `deposits` the next close must process.
            required_deposits: usize = 0,
            /// Forced withdrawals no close has processed, oldest first.
            forced_withdrawals: std.ArrayList(Forced) = .empty,
            /// How many of `forced_withdrawals` the next close must process.
            required_forced_withdrawals: usize = 0,
            /// The payout-log positions claimed so far, as disjoint ranges `[start, end)` that
            /// never touch: every commit and every paid payout (L6).
            ranges: map.Map(u64, u64, map.order_int(u64)) = .{},
            /// Why the ledger halted, if it did.
            halt: ?Halt = null,
            /// Accounts that claimed their balance after the halt (L9).
            claimed: map.Map(P, void, order_account) = .{},
            /// Deposits each account can claim after the halt.
            claimable: map.Map(P, A, order_account) = .{},

            pub fn deinit(self: *Persisted, gpa: Allocator) void {
                self.matrices.deinit(gpa);
                self.payouts.deinit(gpa);
                self.deposits.deinit(gpa);
                self.forced_withdrawals.deinit(gpa);
                self.ranges.deinit(gpa);
                self.claimed.deinit(gpa);
                self.claimable.deinit(gpa);
                self.* = undefined;
            }

            pub fn clone(self: *const Persisted, gpa: Allocator) Allocator.Error!Persisted {
                var copy = self.*;
                copy.matrices = .empty;
                copy.payouts = .empty;
                copy.deposits = .empty;
                copy.forced_withdrawals = .empty;
                copy.ranges = .{};
                copy.claimed = .{};
                copy.claimable = .{};
                errdefer copy.deinit(gpa);
                copy.matrices = try self.matrices.clone(gpa);
                copy.payouts = try self.payouts.clone(gpa);
                copy.deposits = try self.deposits.clone(gpa);
                copy.forced_withdrawals = try self.forced_withdrawals.clone(gpa);
                copy.ranges = try self.ranges.clone_shallow(gpa);
                copy.claimed = try self.claimed.clone_shallow(gpa);
                copy.claimable = try self.claimable.clone_shallow(gpa);
                return copy;
            }

            pub fn eql(a: *const Persisted, b: *const Persisted) bool {
                if (!a.parent.eql(b.parent) or !a.balances.eql(b.balances)) return false;
                if (a.held != b.held) return false;
                if (a.required_deposits != b.required_deposits) return false;
                if (a.required_forced_withdrawals != b.required_forced_withdrawals) return false;
                if (!digests_equal(a.matrices.items, b.matrices.items)) return false;
                if (!digests_equal(a.payouts.items, b.payouts.items)) return false;
                if (!requests_equal(Deposit, a.deposits.items, b.deposits.items)) return false;
                const af = a.forced_withdrawals.items;
                if (!requests_equal(Forced, af, b.forced_withdrawals.items)) return false;
                const ar = a.ranges.items();
                const br = b.ranges.items();
                if (ar.len != br.len) return false;
                for (ar, br) |x, y| if (x.key != y.key or x.value != y.value) return false;
                const ah = a.halt orelse return b.halt == null and rest_equal(a, b);
                const bh = b.halt orelse return false;
                return ah.eql(bh) and rest_equal(a, b);
            }

            fn rest_equal(a: *const Persisted, b: *const Persisted) bool {
                const ac = a.claimed.items();
                const bc = b.claimed.items();
                if (ac.len != bc.len) return false;
                for (ac, bc) |x, y| if (!x.key.eql(y.key)) return false;
                const al = a.claimable.items();
                const bl = b.claimable.items();
                if (al.len != bl.len) return false;
                for (al, bl) |x, y| if (!x.key.eql(y.key) or x.value != y.value) return false;
                return true;
            }

            fn digests_equal(a: []const D, b: []const D) bool {
                if (a.len != b.len) return false;
                for (a, b) |x, y| if (!x.eql(y)) return false;
                return true;
            }

            fn requests_equal(comptime R: type, a: []const R, b: []const R) bool {
                if (a.len != b.len) return false;
                for (a, b) |x, y| if (!x.account.eql(y.account) or x.amount != y.amount) {
                    return false;
                };
                return true;
            }
        };

        gpa: Allocator,
        namespace: Namespace,
        operator: O,
        /// Borrowed; outlives the ledger.
        verifier: *const V,
        persisted: Persisted,

        /// A ledger at genesis, on top of a balances database with root `balances` (L1).
        pub fn init(
            gpa: Allocator,
            namespace: *const Namespace,
            operator: O,
            verifier: *const V,
            balances_root: D,
        ) Allocator.Error!Self {
            const genesis = Summary.genesis(P, A, balances_root);
            var persisted: Persisted = .{ .parent = genesis.digest(), .balances = balances_root };
            errdefer persisted.deinit(gpa);
            // The initial commit sits at position 0 of the payout log.
            _ = try persisted.ranges.put(gpa, 0, genesis.payouts.size);
            return .{
                .gpa = gpa,
                .namespace = try namespace.clone(gpa),
                .operator = operator,
                .verifier = verifier,
                .persisted = persisted,
            };
        }

        pub fn deinit(self: *Self) void {
            self.persisted.deinit(self.gpa);
            self.namespace.deinit(self.gpa);
            self.* = undefined;
        }

        /// Two ledgers are equal when they persisted the same records.
        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.persisted.eql(&b.persisted);
        }

        /// The epoch of the close the ledger expects next.
        pub fn epoch(self: *const Self) Epoch {
            return self.persisted.matrices.items.len + 1;
        }

        /// Digest of the last posted summary.
        pub fn parent(self: *const Self) *const D {
            return &self.persisted.parent;
        }

        /// Balances root of the last posted summary.
        pub fn balances(self: *const Self) *const D {
            return &self.persisted.balances;
        }

        /// Matrix root of the posted close of `at`.
        pub fn matrix(self: *const Self, at: Epoch) ?*const D {
            if (at == 0 or at > self.persisted.matrices.items.len) return null;
            return &self.persisted.matrices.items[at - 1];
        }

        /// Payouts root of the posted close of `at`.
        pub fn payouts(self: *const Self, at: Epoch) ?*const D {
            if (at == 0 or at > self.persisted.payouts.items.len) return null;
            return &self.persisted.payouts.items[at - 1];
        }

        /// The claimed payout-log ranges.
        pub fn ranges(self: *const Self) []const map.Map(u64, u64, map.order_int(u64)).Entry {
            return self.persisted.ranges.items();
        }

        /// The funds the ledger holds.
        pub fn custody(self: *const Self) A {
            return self.persisted.held;
        }

        /// Why the ledger halted, if it did.
        pub fn halted(self: *const Self) ?Halt {
            return self.persisted.halt;
        }

        /// The queues the next close processes a prefix of. Borrows the ledger's records.
        pub fn queue(self: *const Self) Queue {
            const p = &self.persisted;
            return .{
                .epoch = self.epoch(),
                .deposits = p.deposits.items,
                .required_deposits = p.required_deposits,
                .forced_withdrawals = p.forced_withdrawals.items,
                .required_forced_withdrawals = p.required_forced_withdrawals,
            };
        }

        /// Takes a deposit of `amount` into custody for `account` (L2, L3).
        pub fn deposit(self: *Self, account: P, amount: A) Refusal!void {
            const p = &self.persisted;
            if (p.halt != null) return error.Halted;
            if (amount == 0) return error.ZeroAmount;
            const held = std.math.add(A, p.held, amount) catch return error.Custody;
            try p.deposits.append(self.gpa, .{ .account = account, .amount = amount });
            p.held = held;
        }

        /// Queues a forced withdrawal of `amount` for `account` (L2).
        pub fn withdraw(self: *Self, account: P, amount: A) Refusal!void {
            const p = &self.persisted;
            if (p.halt != null) return error.Halted;
            if (amount == 0) return error.ZeroAmount;
            try p.forced_withdrawals.append(self.gpa, .{ .account = account, .amount = amount });
        }

        /// Posts `summary` under `certificate` (L5): it must follow the last post, process
        /// within the queues' bounds, and carry a valid certificate.
        pub fn post(
            self: *Self,
            rng: anytype,
            summary: *const Summary,
            certificate: *const V.Certificate,
        ) Refusal!void {
            const p = &self.persisted;
            if (p.halt != null) return error.Halted;
            try summary.verify(
                self.gpa,
                rng,
                self.verifier,
                certificate,
                self.epoch(),
                p.parent,
                .{ .min = p.required_deposits, .max = p.deposits.items.len },
                .{ .min = p.required_forced_withdrawals, .max = p.forced_withdrawals.items.len },
                parallel.sequential,
            );
            try p.matrices.ensureUnusedCapacity(self.gpa, 1);
            try p.payouts.ensureUnusedCapacity(self.gpa, 1);
            // The certificate vouches that the payouts size counts this close's commit.
            try self.fold(summary.payouts.size - 1);
            const deposits: usize = @intCast(summary.deposits.count);
            const forced: usize = @intCast(summary.forced_withdrawals.count);
            drop_front(Deposit, &p.deposits, deposits);
            drop_front(Forced, &p.forced_withdrawals, forced);
            p.required_deposits = p.deposits.items.len;
            p.required_forced_withdrawals = p.forced_withdrawals.items.len;
            p.matrices.appendAssumeCapacity(summary.matrix);
            p.payouts.appendAssumeCapacity(summary.payouts.root);
            p.balances = summary.balances;
            p.parent = summary.digest();
        }

        fn drop_front(comptime R: type, list: *std.ArrayList(R), count: usize) void {
            assert(count <= list.items.len);
            const rest = list.items.len - count;
            std.mem.copyForwards(R, list.items[0..rest], list.items[count..]);
            list.shrinkRetainingCapacity(rest);
        }

        /// Pays out the payout `proof` shows under the payouts root of the posted close of
        /// `at`, once (L6). Returns the account and amount paid.
        pub fn withdraw_payout(
            self: *Self,
            at: Epoch,
            proof: *const PayoutProof,
        ) Refusal!struct { P, A } {
            const root = self.payouts(at) orelse return error.NotPosted;
            if (!proof.verify(H, root)) return error.InvalidProof;
            if (self.covers(proof.index)) return error.Withdrawn;
            const held = std.math.sub(A, self.persisted.held, proof.payout.amount) catch
                return error.Custody;
            try self.fold(proof.index);
            self.persisted.held = held;
            return .{ proof.payout.account, proof.payout.amount };
        }

        /// Whether a claimed range covers `index`.
        fn covers(self: *const Self, index: u64) bool {
            const ranges_ = &self.persisted.ranges;
            const below = ranges_.below(&(index +| 1));
            if (below == 0) return false;
            return index < ranges_.items()[below - 1].value;
        }

        /// Claims position `index`, merging it with the ranges it touches.
        fn fold(self: *Self, index: u64) Allocator.Error!void {
            const ranges_ = &self.persisted.ranges;
            var start = index;
            var end = index + 1;
            const below = ranges_.below(&(index +| 1));
            if (below > 0) {
                const before = ranges_.items()[below - 1];
                if (before.value >= index) {
                    _ = ranges_.remove(&before.key);
                    start = before.key;
                    end = @max(end, before.value);
                }
            }
            if (ranges_.remove(&end)) |after| end = after;
            _ = try ranges_.put(self.gpa, start, end);
            assert(start <= index and index < end);
        }

        /// Halts the ledger on a valid challenge of a posted close (L7).
        pub fn challenge(self: *Self, submitted: *const Challenge) Refusal!void {
            if (self.persisted.halt != null) return error.Halted;
            const at = submitted.receipt.state.epoch;
            const root = self.matrix(at) orelse return error.NotPosted;
            try submitted.verify(H, &self.namespace, &self.operator, at, root);
            try self.stop(.{ .challenge = at });
        }

        /// Halts the ledger for a fault outside the protocol. Halting twice keeps the first.
        pub fn halt(self: *Self) Allocator.Error!void {
            if (self.persisted.halt == null) try self.stop(.fault);
        }

        /// Records the halt and drains the queues: unprocessed deposits become claimable and
        /// forced withdrawals are dropped (L8).
        fn stop(self: *Self, reason: Halt) Allocator.Error!void {
            const p = &self.persisted;
            for (p.deposits.items) |d| {
                const claimable = if (p.claimable.get(&d.account)) |value| value.* else 0;
                // Claimable deposits never exceed the funds held.
                _ = try p.claimable.put(self.gpa, d.account, claimable + d.amount);
            }
            p.deposits.clearRetainingCapacity();
            p.forced_withdrawals.clearRetainingCapacity();
            p.required_deposits = 0;
            p.required_forced_withdrawals = 0;
            p.halt = reason;
        }

        /// Pays `account` its proven balance, once, and its claimable deposits after a halt
        /// (L9). Returns the amount paid.
        pub fn claim(self: *Self, account: *const P, balance: ?*const BalanceProof) Refusal!A {
            const p = &self.persisted;
            if (p.halt == null) return error.NotHalted;
            var proven: A = 0;
            if (balance) |proof| {
                if (!proof.verify(H, P, &p.balances, account.*)) return error.InvalidProof;
                if (!p.claimed.contains(account)) proven = proof.balance;
            }
            const deposits: A = if (p.claimable.get(account)) |value| value.* else 0;
            if (proven == 0 and deposits == 0) return error.NothingToClaim;
            const paid = std.math.add(A, proven, deposits) catch return error.Custody;
            const held = std.math.sub(A, p.held, paid) catch return error.Custody;
            if (proven != 0) _ = try p.claimed.put(self.gpa, account.*, {});
            _ = p.claimable.remove(account);
            p.held = held;
            return paid;
        }
    };
}
