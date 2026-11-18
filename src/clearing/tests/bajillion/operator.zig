//! Sharded admission and restarts of operators built from the helpers (commonware
//! `clearing/tests/bajillion/operator.rs`).

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const bajillion = @import("../../bajillion/mod.zig");
const m = @import("main.zig");

const gpa = m.gpa;
const Flow = bajillion.Flow(u64);
const Entry = bajillion.Flows(m.PublicKey, u64).Entry;

fn flows_equal(a: []const Entry, b: []const Entry) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!x[0].eql(y[0]) or !std.meta.eql(x[1], y[1])) return false;
    }
    return true;
}

// Two operators that restart from one operator's persisted state and each admit half the
// accounts produce rows and soft withdrawals that assemble into the same close, byte for byte,
// with the same flows, as one operator admitting everything.
test "operator: assembly matches monolithic close" {
    const users = 6;
    const shard_count = 2;
    var replica = try m.operator();
    defer replica.deinit();
    var funding: [users][2]u64 = undefined;
    for (&funding, 0..) |*entry, index| entry.* = .{ index, 100 };
    var funded = try m.fund(&replica, &funding);
    funded.deinit(gpa);
    var shards: [shard_count]m.TestOperator = undefined;
    for (&shards, 0..) |*shard, index| {
        errdefer for (shards[0..index]) |*made| made.deinit();
        shard.* = try m.restart(&replica);
    }
    defer for (&shards) |*shard| shard.deinit();

    // The same requests and soft withdrawals reach the single operator and the shard serving
    // their account.
    var senders: [users]m.TestSender = undefined;
    for (&senders, 0..) |*s, index| {
        errdefer for (senders[0..index]) |*made| made.deinit();
        s.* = try m.sender(index);
    }
    defer for (&senders) |*s| s.deinit();
    for (0..users) |from| {
        for ([_]u64{ 1, 3 }) |offset| {
            const to = (from + offset) % users;
            var request = try senders[from].send(2, try m.amounts(&.{.{ to, 10 + from }}));
            defer request.deinit(gpa);
            const acknowledgement = try shards[from % shard_count].accept(&request);
            _ = try replica.accept(&request);
            m.free_receipts(try senders[from].acknowledged(&acknowledgement));
        }
    }
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const two = m.user(2);
    const withdrawal = m.Withdrawal.sign(&two, &ns, 2, 15, 0);
    try shards[0].withdraw(withdrawal);
    try replica.withdraw(withdrawal);

    // Both close epoch 2 identically.
    var queues = try m.Queues.init(2, &.{.{ 5, 7 }}, &.{.{ 4, 5 }});
    defer queues.deinit();
    const queue = queues.queue();
    var assembled = try replica.close(&queue, 1, 1);
    defer assembled.deinit(gpa);
    var rows: std.ArrayList(m.Row) = .empty;
    defer rows.deinit(gpa);
    var withdrawals: std.ArrayList(m.Withdrawal) = .empty;
    defer withdrawals.deinit(gpa);
    for (&shards) |*shard| {
        const shard_rows = try shard.rows(gpa);
        defer gpa.free(shard_rows);
        try rows.appendSlice(gpa, shard_rows);
        const shard_withdrawals = try shard.withdrawals(gpa);
        defer gpa.free(shard_withdrawals);
        try withdrawals.appendSlice(gpa, shard_withdrawals);
    }
    const operator = m.operator_key();
    var sharded = try m.TestClose.assemble(
        m.Sha256,
        gpa,
        &operator,
        &ns,
        &queue,
        try rows.toOwnedSlice(gpa),
        try withdrawals.toOwnedSlice(gpa),
        1,
        1,
        parallel.sequential,
    );
    defer sharded.deinit(gpa);
    try testing.expect(try m.closes_equal(&assembled.close, &sharded.close));
    try testing.expect(flows_equal(assembled.flows.flows, sharded.flows.flows));
}

fn settle_all(flows: []const Flow, balance: u64) !u64 {
    var result = balance;
    for (flows) |flow| result = (try flow.settle(result)).balance;
    return result;
}

fn less_epoch(_: void, a: Flow, b: Flow) bool {
    return a.epoch < b.epoch;
}

// Flows routed to the shard serving each account and applied there in epoch order (O8) give
// the balances the operator holds, however the closes' flows arrive. Bob's forced withdrawal
// of epoch 2 and his deposit of epoch 3 do not commute, so applying them out of order leaves
// him the wrong balance.
test "operator: flows apply per account in epoch order" {
    var op = try m.operator();
    defer op.deinit();
    var funded = try m.fund(&op, &.{ .{ 0, 100 }, .{ 1, 100 } });
    funded.deinit(gpa);
    var alice = try m.sender(0);
    defer alice.deinit();

    // In epoch 2 alice pays bob 30 and bob forces out more than he holds. In epoch 3 he
    // deposits 40. After both closes the operator holds 70 for alice and 40 for bob.
    _ = try m.pay(&alice, &op, 2, &.{.{ 1, 30 }});
    var forcing = try m.Queues.init(2, &.{}, &.{.{ 1, 150 }});
    defer forcing.deinit();
    var second = try op.close(&forcing.queue(), 0, 1);
    defer second.deinit(gpa);
    var depositing = try m.Queues.init(3, &.{.{ 1, 40 }}, &.{});
    defer depositing.deinit();
    var third = try op.close(&depositing.queue(), 1, 0);
    defer third.deinit(gpa);
    try testing.expectEqual(@as(u64, 2), second.close.epoch);
    try testing.expectEqual(@as(u64, 3), third.close.epoch);
    const alice_account = m.account(0);
    const bob = m.account(1);
    try testing.expectEqual(@as(u64, 70), op.balance(&alice_account));
    try testing.expectEqual(@as(u64, 40), op.balance(&bob));

    // Epoch 3's flows reach the shards before epoch 2's. Applied in epoch order, each
    // account's flows give the operator's balance. Applied as delivered, bob's withdrawal
    // takes his deposit too, and he keeps 20 while the operator holds 40 for him.
    var holders: std.ArrayList(m.PublicKey) = .empty;
    defer holders.deinit(gpa);
    for ([_][]const Entry{ third.flows.flows, second.flows.flows }) |flows| {
        for (flows) |entry| try holders.append(gpa, entry[0]);
    }
    for (holders.items) |holder| {
        var delivered: std.ArrayList(Flow) = .empty;
        defer delivered.deinit(gpa);
        for ([_][]const Entry{ third.flows.flows, second.flows.flows }) |flows| {
            for (flows) |entry| if (entry[0].eql(holder)) try delivered.append(gpa, entry[1]);
        }
        const ordered = try gpa.dupe(Flow, delivered.items);
        defer gpa.free(ordered);
        std.mem.sort(Flow, ordered, {}, less_epoch);
        const funded_balance: u64 = if (holder.eql(alice_account) or holder.eql(bob)) 100 else 0;
        try testing.expectEqual(op.balance(&holder), try settle_all(ordered, funded_balance));
        if (holder.eql(bob)) {
            try testing.expectEqual(@as(u64, 20), try settle_all(delivered.items, 100));
        }
    }
}

// An operator restarted from what it persisted, its admissions and soft withdrawals of the
// open epoch included, closes the epoch exactly as the original. A restart after the close
// holds the close it released.
test "operator: restarted operator closes like the original" {
    // Alice pays bob 10 in epoch 2, and the operator closes it.
    var op = try m.operator();
    defer op.deinit();
    var funded = try m.fund(&op, &.{.{ 0, 100 }});
    funded.deinit(gpa);
    var alice = try m.sender(0);
    defer alice.deinit();
    _ = try m.pay(&alice, &op, 2, &.{.{ 1, 10 }});
    var second = try m.close(&op);
    second.deinit(gpa);

    // In epoch 3, the operator admits a request on top of the row the close of epoch 2
    // settled for alice, and a soft withdrawal, persisting each before it answers.
    var request = try alice.send(3, try m.amounts(&.{.{ 1, 5 }}));
    defer request.deinit(gpa);
    const acknowledgement = try op.accept(&request);
    const receipts = try alice.acknowledged(&acknowledgement);
    defer m.free_receipts(receipts);
    try testing.expectEqual(@as(u64, 5), receipts[0].amount);
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const bob_key = m.user(1);
    try op.withdraw(m.Withdrawal.sign(&bob_key, &ns, 3, 4, 0));

    // The restarted operator holds both from its records alone. It countersigns the request
    // again as a retry, paying nothing twice, and closes the epoch as the original does.
    var restarted = try m.restart(&op);
    defer restarted.deinit();
    try testing.expectEqual(@as(u64, 3), restarted.epoch());
    const alice_account = m.account(0);
    var expected = try m.amounts(&.{.{ 1, 5 }});
    defer expected.deinit(gpa);
    try testing.expect(restarted.payments(&alice_account).?.eql(&expected));
    try testing.expectEqual(@as(u64, 85), restarted.live(&alice_account));
    const again = try restarted.accept(&request);
    try testing.expect(again.eql(acknowledgement));
    try testing.expectEqual(@as(u64, 85), restarted.live(&alice_account));
    var released = try m.close(&op);
    defer released.deinit(gpa);
    var restarted_close = try m.close(&restarted);
    defer restarted_close.deinit(gpa);
    try testing.expect(try m.closes_equal(&released, &restarted_close));

    // A restart after the close holds the close to release again.
    var after = try m.restart(&op);
    defer after.deinit();
    try testing.expect(after.persisted.released.?.eql(&released));
    try testing.expect(after.eql(&restarted));
}
