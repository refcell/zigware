//! Tests of `settlement.zig` (commonware `bajillion/settlement.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const settlement = @import("settlement.zig");
const close = @import("close.zig");
const t = @import("testing.zig");

const PublicKey = t.PublicKey;
const TestFlows = settlement.Flows(PublicKey, u64);
const TestFlow = settlement.Flow(u64);
const Row = close.Row(PublicKey, u64);
const Deposit = close.Deposit(PublicKey, u64);
const Forced = close.ForcedWithdrawal(PublicKey, u64);
const Withdrawal = close.Withdrawal(PublicKey, u64);
const gpa = testing.allocator;
const max = std.math.maxInt(u64);

fn flow_of(flows: *const TestFlows, account: PublicKey) TestFlow {
    for (flows.flows) |entry| if (entry[0].eql(account)) return entry[1];
    unreachable; // Proof: callers ask only for accounts the close touches.
}

// Flows whose credits and debits exceed the largest amount settle exactly and round-trip.
test "settlement: flows round trip beyond the largest amount" {
    // Alice pays herself and bob the largest amount each and deposits it too, so her credits
    // and debits each exceed the largest amount while her balance does not change.
    const alice = t.account(0);
    const bob = t.account(1);
    var payments = try t.TestAmounts.init(gpa, &.{ .{ alice, max }, .{ bob, max } });
    defer payments.deinit(gpa);
    const rows = [_]Row{.{ .account = alice, .payments = payments, .signature = undefined }};
    const deposits = [_]Deposit{.{ .account = alice, .amount = max }};
    var flows = try TestFlows.init(gpa, 2, &rows, &[_]Withdrawal{}, &deposits, &[_]Forced{});
    defer flows.deinit(gpa);
    const paying = flow_of(&flows, alice);
    const paid = flow_of(&flows, bob);
    try testing.expectEqual(@as(u64, 1), paying.credit.carries);
    try testing.expectEqual(@as(u64, 1), paying.debit.carries);
    const Settled = settlement.Settled(u64);
    try testing.expectEqual(Settled{ .balance = 5, .payout = 0 }, try paying.settle(5));
    try testing.expectEqual(Settled{ .balance = max, .payout = 0 }, try paid.settle(0));

    // Every flow round trips.
    for ([_]TestFlow{ paying, paid }) |flow| {
        const encoded = try codec.encode(TestFlow, gpa, flow);
        defer gpa.free(encoded);
        try testing.expect((try codec.decode(TestFlow, gpa, encoded)).eql(flow));
    }
}

// A requested total beyond the largest amount pays out the whole balance.
test "settlement: payout is capped by the balance beyond the largest amount" {
    // Alice holds 10 and is forced to withdraw the largest amount and 3 more in one close, so
    // her requested total exceeds the largest amount while its low part is only 2.
    const alice = t.account(0);
    const forced = [_]Forced{
        .{ .account = alice, .amount = max },
        .{ .account = alice, .amount = 3 },
    };
    var flows = try TestFlows.init(gpa, 2, &[_]Row{}, &[_]Withdrawal{}, &[_]Deposit{}, &forced);
    defer flows.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), flows.len());
    const settled = try flows.flows[0][1].settle(10);
    try testing.expectEqual(settlement.Settled(u64){ .balance = 0, .payout = 10 }, settled);
}

// Settling reports only the balances that change, pays out in account order, and refuses an
// overdraft or a balance past the largest amount.
test "settlement: settle reports changes and payouts" {
    const keys = t.accounts(3);
    var payments = try t.TestAmounts.init(gpa, &.{.{ keys[1], 4 }});
    defer payments.deinit(gpa);
    const rows = [_]Row{.{ .account = keys[0], .payments = payments, .signature = undefined }};
    const forced = [_]Forced{.{ .account = keys[2], .amount = 3 }};
    var flows = try TestFlows.init(gpa, 1, &rows, &[_]Withdrawal{}, &[_]Deposit{}, &forced);
    defer flows.deinit(gpa);
    var settled = try flows.settle(gpa, &.{ 10, 0, 3 });
    defer settled.deinit(gpa);
    try testing.expectEqualSlices(?u64, &.{ 6, 4, 0 }, settled.balances);
    try testing.expectEqual(@as(u64, 3), settled.payouts.get(&keys[2]));
    try testing.expectEqual(@as(usize, 1), settled.payouts.len());
    try testing.expectError(error.Overdraft, flows.settle(gpa, &.{ 3, 0, 0 }));
    try testing.expectError(error.Overflow, flows.settle(gpa, &.{ 10, max, 0 }));
}
