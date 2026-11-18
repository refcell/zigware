//! A reference receiver that holds the operator to its preconfirmations (commonware
//! `clearing/tests/bajillion/roles/receiver.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bajillion = @import("../../../bajillion/mod.zig");
const map = @import("map.zig");

const Epoch = bajillion.Epoch;
const Namespace = bajillion.Namespace;

/// Why the receiver refused a receipt or an audit.
pub const Refusal = error{
    /// The receipt pays another account.
    WrongReceiver,
    /// The receipt promises no more than one already held.
    NotIncreasing,
    /// The close of the receipt's epoch already posted.
    Closed,
    /// The ledger halted.
    Halted,
    /// The close of the audited epoch has not posted.
    NotClosed,
    /// The receipt does not verify.
    InvalidReceipt,
} || bajillion.InvalidOpening || Allocator.Error;

/// A receiver with account key `P`, operator key `O`, hasher `H`, and amounts `A`, keeping the
/// largest receipt per epoch and sender until it audits that epoch's posted close.
pub fn Receiver(comptime P: type, comptime O: type, comptime H: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const D = H.Digest;
        pub const Receipt = bajillion.Receipt(P, O, D, A);
        pub const Challenge = bajillion.Challenge(P, O, D, A);
        pub const Opening = bajillion.Opening(P, D, A);
        /// The largest receipt held from each sender in one epoch; owns the receipts.
        pub const BySender = map.Map(P, Receipt, map.order_method(P));
        const Receipts = map.Map(Epoch, BySender, map.order_int(Epoch));

        /// What the receiver persists (R2). A restart resumes from it alone.
        pub const Persisted = struct {
            /// Epoch of the close the ledger expects, as far as the receiver knows.
            next: Epoch,
            /// Whether the ledger halted.
            halted: bool = false,
            /// The largest receipt held per epoch and sender.
            receipts: Receipts = .{},

            pub fn deinit(self: *Persisted, gpa: Allocator) void {
                for (self.receipts.items()) |*epoch| free_epoch(gpa, &epoch.value);
                self.receipts.deinit(gpa);
                self.* = undefined;
            }

            pub fn clone(self: *const Persisted, gpa: Allocator) Allocator.Error!Persisted {
                var copy: Persisted = .{ .next = self.next, .halted = self.halted };
                errdefer copy.deinit(gpa);
                for (self.receipts.items()) |*epoch| {
                    var by_sender: BySender = .{};
                    errdefer free_epoch(gpa, &by_sender);
                    for (epoch.value.items()) |*entry| {
                        var receipt = try entry.value.clone(gpa);
                        errdefer receipt.deinit(gpa);
                        _ = try by_sender.put(gpa, entry.key, receipt);
                    }
                    _ = try copy.receipts.put(gpa, epoch.key, by_sender);
                }
                return copy;
            }

            pub fn eql(a: *const Persisted, b: *const Persisted) bool {
                if (a.next != b.next or a.halted != b.halted) return false;
                if (a.receipts.count() != b.receipts.count()) return false;
                for (a.receipts.items(), b.receipts.items()) |*x, *y| {
                    if (x.key != y.key or x.value.count() != y.value.count()) return false;
                    for (x.value.items(), y.value.items()) |*r, *s| {
                        if (!r.key.eql(s.key) or !r.value.eql(&s.value)) return false;
                    }
                }
                return true;
            }

            fn free_epoch(gpa: Allocator, by_sender: *BySender) void {
                for (by_sender.items()) |*entry| entry.value.deinit(gpa);
                by_sender.deinit(gpa);
            }
        };

        gpa: Allocator,
        account: P,
        namespace: Namespace,
        operator: O,
        persisted: Persisted,

        /// A receiver while the ledger expects the close of `next`.
        pub fn init(
            gpa: Allocator,
            account: P,
            namespace: *const Namespace,
            operator: O,
            next: Epoch,
        ) Allocator.Error!Self {
            return .{
                .gpa = gpa,
                .account = account,
                .namespace = try namespace.clone(gpa),
                .operator = operator,
                .persisted = .{ .next = next },
            };
        }

        /// A receiver resuming from the halt it recorded and the receipts it held, in any
        /// order. The receipts stay the caller's.
        pub fn resume_from(
            gpa: Allocator,
            account: P,
            namespace: *const Namespace,
            operator: O,
            next: Epoch,
            halted: bool,
            held: []const Receipt,
        ) Refusal!Self {
            var self = try init(gpa, account, namespace, operator, next);
            errdefer self.deinit();
            self.persisted.halted = halted;
            for (held) |*receipt| {
                try self.verify(receipt);
                if (receipt.amount > self.amount(receipt.state.epoch, &receipt.state.account)) {
                    try self.insert(try receipt.clone(gpa));
                }
            }
            return self;
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

        /// Two receivers are equal when they persisted the same records.
        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.persisted.eql(&b.persisted);
        }

        /// The largest amount a held receipt promises from `sender` in `epoch`.
        pub fn amount(self: *const Self, epoch: Epoch, sender: *const P) A {
            const by_sender = self.persisted.receipts.get(&epoch) orelse return 0;
            const receipt = by_sender.get(sender) orelse return 0;
            return receipt.amount;
        }

        /// The receipts held for `epoch`, one per sender, in sender order.
        pub fn receipts(self: *const Self, epoch: Epoch) []BySender.Entry {
            const by_sender = self.persisted.receipts.get(&epoch) orelse return &.{};
            return by_sender.items();
        }

        /// Checks that `receipt` pays this account and that `Receipt.verify` accepts it (R1).
        fn verify(self: *const Self, receipt: *const Receipt) Refusal!void {
            if (!receipt.receiver.eql(self.account)) return error.WrongReceiver;
            if (!receipt.verify(H, &self.namespace, &self.operator)) return error.InvalidReceipt;
        }

        /// Holds `receipt` (taken) in place of any earlier one from its sender in its epoch.
        fn insert(self: *Self, receipt: Receipt) Allocator.Error!void {
            var owned = receipt;
            errdefer owned.deinit(self.gpa);
            const epoch = owned.state.epoch;
            const records = &self.persisted.receipts;
            if (records.get(&epoch) == null) _ = try records.put(self.gpa, epoch, .{});
            const by_sender = records.get(&epoch).?;
            if (try by_sender.put(self.gpa, owned.state.account, owned)) |old| {
                var replaced = old;
                replaced.deinit(self.gpa);
            }
        }

        /// Relies on `receipt` (R1, R2), and returns the amount it promises. The receipt stays
        /// the caller's.
        pub fn receive(self: *Self, receipt: *const Receipt) Refusal!A {
            if (self.persisted.halted) return error.Halted;
            if (receipt.state.epoch < self.persisted.next) return error.Closed;
            // The receipt is verified before it is compared with the one held, so a receipt
            // this account cannot rely on reveals nothing about what it holds.
            try self.verify(receipt);
            const held = self.amount(receipt.state.epoch, &receipt.state.account);
            if (receipt.amount <= held) return error.NotIncreasing;
            try self.insert(try receipt.clone(self.gpa));
            assert(self.amount(receipt.state.epoch, &receipt.state.account) == receipt.amount);
            return receipt.amount;
        }

        /// Records the final post of `epoch`, after which no receipt of it is accepted.
        pub fn posted(self: *Self, epoch: Epoch) void {
            self.persisted.next = @max(self.persisted.next, epoch +| 1);
        }

        /// Records that the ledger halted, after which no receipt is accepted.
        pub fn halt(self: *Self) void {
            self.persisted.halted = true;
        }

        /// Compares the receipt held from `sender` in `epoch` with what the posted close
        /// credits under its matrix root `root` (R3). Returns the challenge to submit if it
        /// credits less; the caller frees it.
        pub fn audit(
            self: *const Self,
            epoch: Epoch,
            root: *const D,
            sender: *const P,
            opening: *const Opening,
        ) Refusal!?Challenge {
            if (epoch >= self.persisted.next) return error.NotClosed;
            const by_sender = self.persisted.receipts.get(&epoch) orelse return null;
            const receipt = by_sender.get(sender) orelse return null;
            const credited = try opening.verify(H, root, sender, &self.account);
            if (credited >= receipt.amount) return null;
            var copy = try receipt.clone(self.gpa);
            errdefer copy.deinit(self.gpa);
            return .{ .receipt = copy, .opening = try opening.clone(self.gpa) };
        }

        /// Forgets the receipts of epochs before `epoch`, once their closes are audited.
        pub fn prune(self: *Self, epoch: Epoch) void {
            const records = &self.persisted.receipts;
            const dropped = records.below(&epoch);
            for (records.items()[0..dropped]) |*entry| Persisted.free_epoch(self.gpa, &entry.value);
            records.drop_front(dropped);
        }
    };
}
