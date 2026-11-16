//! Balances and payouts that a close settles (commonware `bajillion/settlement.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const mod = @import("mod.zig");
const amounts_module = @import("amounts.zig");
const arb = @import("arbitrary.zig");

const Epoch = mod.Epoch;

/// Why a flow does not settle on a balance.
pub const FlowError = error{
    /// The balance would go negative.
    Overdraft,
    /// A total, the balance, or the number of payouts does not fit.
    Overflow,
};

/// An exact sum of amounts that may exceed the largest amount (commonware `Total<A>`).
///
/// The sum is `low` plus `carries` times one more than the largest amount, so a close settles
/// whenever every balance it settles fits before its payout, however large its gross flows.
pub fn Total(comptime A: type) type {
    mod.assert_amount(A);
    return struct {
        const Self = @This();

        low: A,
        carries: u64,

        pub const zero: Self = .{ .low = 0, .carries = 0 };

        pub fn init(amount: A) Self {
            return .{ .low = amount, .carries = 0 };
        }

        /// Returns `self + other`, or null if the carries overflow.
        pub fn add(self: Self, other: Self) ?Self {
            const low, const carry = @addWithOverflow(self.low, other.low);
            var carries = std.math.add(u64, self.carries, other.carries) catch return null;
            carries = std.math.add(u64, carries, carry) catch return null;
            return .{ .low = low, .carries = carries };
        }

        /// Returns `self - other`, or null if the difference is negative.
        pub fn sub(self: Self, other: Self) ?Self {
            const low, const borrow = @subWithOverflow(self.low, other.low);
            var carries = std.math.sub(u64, self.carries, other.carries) catch return null;
            carries = std.math.sub(u64, carries, borrow) catch return null;
            return .{ .low = low, .carries = carries };
        }

        /// Returns the sum as an amount, or null if it exceeds the largest amount.
        pub fn get(self: Self) ?A {
            return if (self.carries == 0) self.low else null;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(A, self.low, writer);
            codec.varint.write(u64, self.carries, writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.fixed_size(A).? + codec.varint.size(u64, self.carries);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const low = try codec.read(A, gpa, reader);
            return .{ .low = low, .carries = try codec.varint.read(u64, reader) };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const low = try arb.value(A, gpa, u);
            return .{ .low = low, .carries = u.int(u64) };
        }
    };
}

/// What an account holds and is paid once its `Flow` settles.
pub fn Settled(comptime A: type) type {
    return struct {
        /// Balance left after the payout.
        balance: A,
        /// Amount paid out.
        payout: A,
    };
}

/// Funds moving into and out of one account in the close of an epoch (commonware `Flow<A>`).
///
/// Each part is an exact sum, so it may exceed the largest amount even when the balance it
/// settles fits.
pub fn Flow(comptime A: type) type {
    return struct {
        const Self = @This();
        const T = Total(A);

        /// Epoch of the close.
        epoch: Epoch,
        /// Incoming payments and processed deposits.
        credit: T,
        /// Outgoing payments.
        debit: T,
        /// Requested forced and soft withdrawals.
        withdraw: T,

        /// A flow of the close of `epoch` that moves nothing.
        pub fn zero(epoch: Epoch) Self {
            return .{ .epoch = epoch, .credit = .zero, .debit = .zero, .withdraw = .zero };
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.meta.eql(a, b);
        }

        /// Settles the flow on the account's `previous` balance. The payout is the lesser of the
        /// settled balance and the amount requested.
        pub fn settle(self: Self, previous: A) FlowError!Settled(A) {
            const credited = T.init(previous).add(self.credit) orelse return error.Overflow;
            const debited = credited.sub(self.debit) orelse return error.Overdraft;
            const settled = debited.get() orelse return error.Overflow;
            const requested = self.withdraw.get() orelse settled;
            const payout = @min(requested, settled);
            assert(payout <= settled);
            return .{ .balance = settled - payout, .payout = payout };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u64, self.epoch, writer);
            self.credit.write(writer);
            self.debit.write(writer);
            self.withdraw.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 8 + self.credit.encode_size() + self.debit.encode_size() +
                self.withdraw.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .epoch = try codec.read(u64, gpa, reader),
                .credit = try T.read(gpa, reader, {}),
                .debit = try T.read(gpa, reader, {}),
                .withdraw = try T.read(gpa, reader, {}),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .epoch = u.int(u64),
                .credit = try T.arbitrary(gpa, u),
                .debit = try T.arbitrary(gpa, u),
                .withdraw = try T.arbitrary(gpa, u),
            };
        }
    };
}

/// The effects of a close: the new balance of each account in `Flows` order, or null if it does
/// not change, and the amount paid out to each withdrawing account. Owns both.
pub fn Settlement(comptime P: type, comptime A: type) type {
    return struct {
        balances: []?A,
        payouts: amounts_module.Amounts(P, A),

        pub fn deinit(self: *@This(), gpa: Allocator) void {
            gpa.free(self.balances);
            self.payouts.deinit(gpa);
            self.* = undefined;
        }
    };
}

/// The flows of a close, aggregated per account, in account order (commonware `Flows<P, A>`).
pub fn Flows(comptime P: type, comptime A: type) type {
    mod.assert_public_key(P);
    return struct {
        const Self = @This();
        const T = Total(A);

        pub const Entry = struct { P, Flow(A) };
        const Part = enum { credit, debit, withdraw };

        /// Flow of every account the close touches, in account order; owned.
        flows: []Entry,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.flows);
            self.* = undefined;
        }

        /// Aggregates the payments of `rows` (items with `account` and `payments`), the soft
        /// `withdrawals`, the processed `deposits`, and the processed `forced_withdrawals` of
        /// the close of `epoch`. A total gains at most one carry per amount added, so no close
        /// that fits in memory overflows one.
        pub fn init(
            gpa: Allocator,
            epoch: Epoch,
            rows: anytype,
            withdrawals: anytype,
            deposits: anytype,
            forced_withdrawals: anytype,
        ) Allocator.Error!Self {
            var count: usize = rows.len + withdrawals.len + deposits.len + forced_withdrawals.len;
            for (rows) |row| count += row.payments.len();
            const parts = try gpa.alloc(Entry, count);
            errdefer gpa.free(parts);
            var filled: usize = 0;
            for (rows) |row| {
                var paid: T = .zero;
                for (row.payments.entries) |entry| {
                    const amount = T.init(entry[1]);
                    parts[filled] = part(epoch, entry[0], .credit, amount);
                    filled += 1;
                    paid = paid.add(amount).?; // A close sums fewer than 2^64 amounts.
                }
                parts[filled] = part(epoch, row.account, .debit, paid);
                filled += 1;
            }
            for (deposits) |deposit| {
                parts[filled] = part(epoch, deposit.account, .credit, T.init(deposit.amount));
                filled += 1;
            }
            inline for (.{ forced_withdrawals, withdrawals }) |requests| {
                for (requests) |request| {
                    const amount = T.init(request.amount);
                    parts[filled] = part(epoch, request.account, .withdraw, amount);
                    filled += 1;
                }
            }
            assert(filled == count);
            return .{ .flows = try merge(gpa, parts) };
        }

        fn part(epoch: Epoch, holder: P, comptime which: Part, amount: T) Entry {
            var flow: Flow(A) = .zero(epoch);
            @field(flow, @tagName(which)) = amount;
            return .{ holder, flow };
        }

        fn less(_: void, a: Entry, b: Entry) bool {
            return a[0].order(b[0]) == .lt;
        }

        /// Sorts the parts by account and sums each account's into one flow, in place.
        fn merge(gpa: Allocator, parts: []Entry) Allocator.Error![]Entry {
            std.mem.sort(Entry, parts, {}, less);
            var kept: usize = 0;
            for (parts) |entry| {
                if (kept > 0 and parts[kept - 1][0].eql(entry[0])) {
                    const flow = &parts[kept - 1][1];
                    flow.credit = flow.credit.add(entry[1].credit).?; // Fewer than 2^64 amounts.
                    flow.debit = flow.debit.add(entry[1].debit).?;
                    flow.withdraw = flow.withdraw.add(entry[1].withdraw).?;
                    continue;
                }
                parts[kept] = entry;
                kept += 1;
            }
            assert(kept <= parts.len);
            return gpa.realloc(parts, kept);
        }

        /// The number of accounts the close touches.
        pub fn len(self: *const Self) usize {
            return self.flows.len;
        }

        /// The account at `index` in account order.
        pub fn account(self: *const Self, index: usize) *const P {
            return &self.flows[index][0];
        }

        /// Settles the flows on top of `previous`, the previous balance of each account in
        /// account order, which must hold one balance per account.
        pub fn settle(
            self: *const Self,
            gpa: Allocator,
            previous: []const A,
        ) (FlowError || Allocator.Error)!Settlement(P, A) {
            assert(previous.len == self.flows.len);
            const balances = try gpa.alloc(?A, self.flows.len);
            errdefer gpa.free(balances);
            const payouts = try gpa.alloc(amounts_module.Amounts(P, A).Entry, self.flows.len);
            var paid: usize = 0;
            {
                errdefer gpa.free(payouts);
                for (self.flows, previous, balances) |entry, before, *balance| {
                    const settled = try entry[1].settle(before);
                    balance.* = if (settled.balance != before) settled.balance else null;
                    if (settled.payout == 0) continue;
                    payouts[paid] = .{ entry[0], settled.payout };
                    paid += 1;
                }
            }
            const shrunk = gpa.realloc(payouts, paid) catch |err| {
                gpa.free(payouts);
                return err;
            };
            const amounts = amounts_module.Amounts(P, A).from_sorted(gpa, shrunk) catch
                return error.Overflow;
            return .{ .balances = balances, .payouts = amounts };
        }
    };
}
