//! Choosing the transfers of a batch in block order, for a proposer (commonware
//! `glue/src/transfers/select.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const utils = @import("utils");
const transfers = @import("mod.zig");

const amount = utils.amount;
const Lookahead = utils.prefetch.Lookahead;

/// Selects the transfers of a batch in block order against the accounts the batch starts from
/// (commonware `Selection<K, A>`). Each candidate applies in order and is accepted only if the
/// batch still settles, so one candidate that cannot settle does not reject the others. A
/// dropped candidate leaves no debit, credit, or effect behind, so a verifier settling the
/// accepted transfers as a batch reaches the same accounts.
///
/// Candidates arrive in rounds. `touch` records the keys a round touches and returns the range
/// of `keys` holding the new ones, in the order their accounts must be staged; `register` takes
/// those accounts, `apply` applies the round, and `settle` produces the slot to merkleize for
/// every key.
pub fn Selection(comptime K: type, comptime A: type) type {
    transfers.assert_account(A);
    return struct {
        const Self = @This();
        const Amount = A.Amount;
        const Change = transfers.Change(A);
        const Indexed = struct { index: usize, change: Change };
        const Saved = struct { index: usize, account: A };
        const Hashed = struct { key: *const K, hash: u64 };

        /// Places keys in the table, keyed by the selection's seed.
        hasher: transfers.SeededHasher,
        /// Every touched key and its index, in staging order.
        index: transfers.KeyIndex(K) = .empty,
        /// The index of each non-empty change's key in the round touched last, in order.
        round: std.ArrayList(usize) = .empty,
        /// Each registered key's starting account, null for a key the database does not hold.
        reads: std.ArrayList(?A) = .empty,
        /// Each registered key's starting balance.
        starts: std.ArrayList(Amount) = .empty,
        /// Each registered key's starting account with the accepted effects applied.
        accounts: std.ArrayList(A) = .empty,
        /// The sum of the accepted debits to each registered key.
        debits: std.ArrayList(Amount) = .empty,
        /// The sum of the accepted credits to each registered key.
        credits: std.ArrayList(Amount) = .empty,
        /// Scratch: the changes of the transfer being applied, each with its key's index.
        changes: std.ArrayList(Indexed) = .empty,
        /// Scratch: each account as it was before an effect of the transfer being applied.
        undo: std.ArrayList(Saved) = .empty,
        /// Scratch: the keys of the round being touched, with their hashes.
        hashed: std.ArrayList(Hashed) = .empty,

        /// A selection with no keys whose hash is keyed with `seed` (commonware
        /// `Selection::with_seed`; `Selection::new` draws the seed at random).
        pub fn init(seed: u64) Self {
            return .{ .hasher = .{ .seed = seed } };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.index.deinit(gpa);
            self.round.deinit(gpa);
            self.reads.deinit(gpa);
            self.starts.deinit(gpa);
            self.accounts.deinit(gpa);
            self.debits.deinit(gpa);
            self.credits.deinit(gpa);
            self.changes.deinit(gpa);
            self.undo.deinit(gpa);
            self.hashed.deinit(gpa);
            self.* = undefined;
        }

        /// Every key touched so far, in the order their accounts are staged.
        pub fn keys(self: *const Self) []const K {
            return self.index.keys.items;
        }

        /// Records the keys `list` touches and returns the range of `keys` holding the ones not
        /// touched before, in the order their accounts must be staged and registered. Keys
        /// touched only by empty changes are left out.
        pub fn touch(self: *Self, gpa: Allocator, list: anytype) Allocator.Error!parallel.Range {
            // Every key is hashed first, so the index is sized for the round before the first
            // lookup and each key's home slot is prefetched ahead of its lookup.
            const start = self.index.len();
            self.hashed.clearRetainingCapacity();
            try self.hashed.ensureTotalCapacity(gpa, transfers.estimated_changes(list));
            const collect: Collect = .{ .gpa = gpa, .hashed = &self.hashed };
            try transfers.for_each_touch(list, self.hasher, collect);
            const hashed = self.hashed.items;
            try self.index.reserve(gpa, hashed.len, self.hasher);

            // Each change's index is kept, so applying this round looks up no key again.
            self.round.clearRetainingCapacity();
            try self.round.ensureTotalCapacity(gpa, hashed.len);
            var ahead = Lookahead.init(transfers.prefetch_distance);
            for (hashed, 0..) |entry, i| {
                for (ahead.advance(Hashed, hashed[i..])) |later| self.index.prefetch(later.hash);
                const index, _ =
                    try self.index.find_or_insert(gpa, entry.key, entry.hash, self.hasher);
                self.round.appendAssumeCapacity(index);
            }
            assert(self.round.items.len == hashed.len);
            return .init(start, self.index.len());
        }

        const Collect = struct {
            gpa: Allocator,
            hashed: *std.ArrayList(Hashed),

            pub fn touch(collect: Collect, entry: transfers.Touch(K, A)) Allocator.Error!void {
                try collect.hashed.append(collect.gpa, .{ .key = entry.key, .hash = entry.hash });
            }
        };

        /// Registers the starting accounts of the keys touched since the last registration, in
        /// `keys` order, null for a key the database does not hold.
        pub fn register(self: *Self, gpa: Allocator, reads: []const ?A) Allocator.Error!void {
            if (self.reads.items.len + reads.len != self.index.len()) {
                @panic("reads must hold the accounts of exactly the unregistered keys");
            }
            const total = self.index.len();
            try self.reads.ensureTotalCapacity(gpa, total);
            try self.starts.ensureTotalCapacity(gpa, total);
            try self.accounts.ensureTotalCapacity(gpa, total);
            try self.debits.ensureTotalCapacity(gpa, total);
            try self.credits.ensureTotalCapacity(gpa, total);
            for (reads) |read| {
                const account = read orelse A.default;
                self.reads.appendAssumeCapacity(read);
                self.accounts.appendAssumeCapacity(account);
                self.starts.appendAssumeCapacity(account.balance());
                self.debits.appendAssumeCapacity(0);
                self.credits.appendAssumeCapacity(0);
            }
            assert(self.reads.items.len == total);
        }

        /// Applies `list` in order, writing whether each transfer was accepted to `accepted`.
        pub fn apply(
            self: *Self,
            gpa: Allocator,
            list: anytype,
            accepted: []bool,
        ) Allocator.Error!void {
            assert(accepted.len == list.len);
            var cursor: usize = 0;
            for (list, accepted) |*transfer, *result| {
                result.* = try self.apply_one(gpa, transfer, &cursor);
            }
        }

        /// Applies one transfer, accepting it only if every key it touches still settles.
        fn apply_one(
            self: *Self,
            gpa: Allocator,
            transfer: anytype,
            cursor: *usize,
        ) Allocator.Error!bool {
            try self.resolve(gpa, transfer, cursor);
            // Apply every change before checking any key, so each key is checked against all
            // of the transfer's changes to it, as when the batch settles.
            self.undo.clearRetainingCapacity();
            var applied: usize = 0;
            var fits = true;
            for (self.changes.items) |*indexed| {
                if (!try self.apply_change(gpa, indexed)) {
                    fits = false;
                    break;
                }
                applied += 1;
            }
            // Each touched key's debits must fit its starting balance, and its final balance
            // must not exceed the largest amount.
            if (fits) {
                for (self.changes.items) |indexed| {
                    if (self.settled_balance(indexed.index) == null) {
                        fits = false;
                        break;
                    }
                }
            }
            if (!fits) self.drop(applied);
            return fits;
        }

        /// Resolves every change of `transfer` to its key's index before applying any, so
        /// undoing a dropped transfer needs no further lookups. A change in the same place as
        /// in the round touched last takes the index found then, once its key confirms it.
        fn resolve(self: *Self, gpa: Allocator, transfer: anytype, cursor: *usize) !void {
            self.changes.clearRetainingCapacity();
            var changes = transfer.changes();
            while (changes.next()) |entry| {
                if (entry.change.is_empty()) continue;
                const round = self.round.items;
                const touched: ?usize = if (cursor.* < round.len and
                    transfers.key_eql(K, &self.keys()[round[cursor.*]], entry.key))
                    round[cursor.*]
                else
                    null;
                cursor.* += 1;
                const index = touched orelse self.index.find(
                    entry.key,
                    self.hasher.hash(transfers.key_bytes(K, entry.key)),
                ) orelse self.index.len();
                if (index >= self.reads.items.len) {
                    @panic("every key a transfer touches must be registered before it applies");
                }
                try self.changes.append(gpa, .{ .index = index, .change = entry.change });
            }
        }

        /// Applies one change: its effect, after saving its key's account, then its debit and
        /// credit, both checked against the largest amount before either is added. Returns
        /// false if the effect is refused or a sum overflows.
        fn apply_change(self: *Self, gpa: Allocator, indexed: *const Indexed) !bool {
            const index = indexed.index;
            const change = &indexed.change;
            if (change.effect) |effect| {
                const saved: Saved = .{ .index = index, .account = self.accounts.items[index] };
                try self.undo.append(gpa, saved);
                if (!self.accounts.items[index].apply(effect)) return false;
            }
            const debits = self.debits.items;
            const credits = self.credits.items;
            const debit = amount.checked_add(Amount, debits[index], change.debit) orelse
                return false;
            const credit = amount.checked_add(Amount, credits[index], change.credit) orelse
                return false;
            self.debits.items[index] = debit;
            self.credits.items[index] = credit;
            return true;
        }

        /// The balance the key at `index` settles to with the accepted changes, or null if its
        /// debits exceed its starting balance or the result exceeds the largest amount.
        fn settled_balance(self: *const Self, index: usize) ?Amount {
            const remaining = amount.checked_sub(
                Amount,
                self.starts.items[index],
                self.debits.items[index],
            ) orelse return null;
            return amount.checked_add(Amount, remaining, self.credits.items[index]);
        }

        /// Removes the first `applied` changes of a dropped transfer from the sums and restores
        /// the saved accounts newest first, so an account saved more than once ends at its
        /// earliest save, as it was before the transfer.
        fn drop(self: *Self, applied: usize) void {
            assert(applied <= self.changes.items.len);
            for (self.changes.items[0..applied]) |indexed| {
                const index = indexed.index;
                self.debits.items[index] = amount.checked_sub(
                    Amount,
                    self.debits.items[index],
                    indexed.change.debit,
                ).?; // A key's debit sum includes each applied debit.
                self.credits.items[index] = amount.checked_sub(
                    Amount,
                    self.credits.items[index],
                    indexed.change.credit,
                ).?; // A key's credit sum includes each applied credit.
            }
            while (self.undo.pop()) |saved| self.accounts.items[saved.index] = saved.account;
        }

        /// Settles the accepted transfers, returning the slot to merkleize for every key in
        /// `keys` order.
        pub fn settle(
            self: *const Self,
            gpa: Allocator,
            strategy: anytype,
        ) Allocator.Error![]transfers.Slot(A) {
            if (self.reads.items.len != self.index.len()) {
                @panic("every touched key must be registered before the selection settles");
            }
            return transfers.settle_batches(A, gpa, strategy, self.index.len(), SettleOp{
                .selection = self,
            });
        }

        const SettleOp = struct {
            selection: *const Self,

            /// `apply` accepts a transfer only if every key it touches still settles, so no
            /// balance here underflows or overflows.
            pub fn settle(
                op: SettleOp,
                _: usize,
                range: parallel.Range,
                slots: []transfers.Slot(A),
            ) error{}!void {
                const selection = op.selection;
                for (slots, range.start..) |*slot, index| {
                    const start: A = selection.reads.items[index] orelse A.default;
                    const balance = selection.settled_balance(index).?;
                    const account = selection.accounts.items[index];
                    slot.* = transfers.settled_slot(A, account, balance, &start);
                }
            }
        };
    };
}
