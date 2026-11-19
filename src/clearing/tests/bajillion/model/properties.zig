//! The invariants the model checks in every reachable state (commonware `model.rs`
//! `Model::properties`).

const std = @import("std");
const m = @import("../main.zig");
const checker = @import("../checker.zig");
const wl = @import("workload.zig");
const w = @import("world.zig");

const Workload = wl.Workload;
const World = w.World;
const users = w.users;

pub const properties = [_]checker.Property(Workload){
    .{
        .name = "custody backs the balances, the unprocessed deposits, and the unpaid payouts",
        .holds = custody,
    },
    .{ .name = "every step had the outcome the model predicted", .holds = predicted },
    .{
        .name = "the operator holds the committee's balances after the last close it released",
        .holds = operator_agrees,
    },
    .{
        .name = "the committee's balances and posted payouts are what the released closes settle",
        .holds = committee_agrees,
    },
    .{
        .name = "every receipt of a posted epoch is honored unless its admission was forgotten",
        .holds = receipts_honored,
    },
    .{
        .name = "a request is admitted in at most one epoch unless its admission was forgotten",
        .holds = admitted_once,
    },
    .{ .name = "claimed ranges never overlap or touch", .holds = ranges_apart },
};

fn custody(model: *Workload, world: *const World) anyerror!bool {
    const settlement = model.settled(world, false);
    const deposits = Workload.unprocessed(world);
    var backed: u64 = 0;
    for (0..users) |user| {
        if (!world.claimed[user]) backed += settlement.balances[user];
        if (!world.claimed_deposits[user]) backed += deposits[user];
    }
    for (settlement.payouts()) |payout| {
        if (!world.withdrawn.contains(&.{ payout.epoch, payout.user })) backed += payout.amount;
    }
    return world.ledger.custody() == backed;
}

fn predicted(_: *Workload, world: *const World) anyerror!bool {
    if (world.violation) |violation| std.log.warn("model violation: {s}", .{violation});
    return world.violation == null;
}

fn operator_agrees(model: *Workload, world: *const World) anyerror!bool {
    const snapshot = try model.snapshot(world);
    const balances = if (world.candidate) |*c| &c.balances else &snapshot.balances;
    // Reading a balance only counts the operator's reads, which no state depends on.
    const operator = @constCast(&world.operator);
    for (&model.accounts, balances) |*account, balance| {
        if (operator.balance(account) != balance) return false;
    }
    return true;
}

fn committee_agrees(model: *Workload, world: *const World) anyerror!bool {
    const snapshot = try model.snapshot(world);
    const settlement = model.settled(world, false);
    if (!std.mem.eql(u64, &snapshot.balances, &settlement.balances)) return false;
    if (settlement.payouts().len != snapshot.payouts.items.len) return false;
    for (settlement.payouts()) |payout| {
        const proof = snapshot.payout(payout.epoch, payout.user) orelse return false;
        if (proof.payout.amount != payout.amount) return false;
    }
    const candidate = if (world.candidate) |*c| c else return true;
    const with_candidate = model.settled(world, true);
    return std.mem.eql(u64, &candidate.balances, &with_candidate.balances);
}

fn receipts_honored(model: *Workload, world: *const World) anyerror!bool {
    for (world.held.items()) |entry| {
        const receiver, const epoch, const sender = entry.key;
        const p = world.post(epoch) orelse continue;
        if (world.omitted.contains(&.{ epoch, sender })) continue;
        const row = Workload.row_in(&p.processed.close, &model.accounts[sender]) orelse
            return false;
        if (row.payments.get(&model.accounts[receiver]) < entry.value) return false;
    }
    return true;
}

fn admitted_once(_: *Workload, world: *const World) anyerror!bool {
    for (world.sent.items, 0..) |*sent, request| {
        // Every admission of the request but its last must have been forgotten.
        var previous: ?u64 = null;
        for (world.admitted.items()) |entry| {
            if (entry.key[0] != request) continue;
            if (previous) |epoch| {
                if (!world.omitted.contains(&.{ epoch, sent.user })) return false;
            }
            previous = entry.key[1];
        }
    }
    return true;
}

fn ranges_apart(_: *Workload, world: *const World) anyerror!bool {
    const ranges = world.ledger.ranges();
    if (ranges.len < 2) return true;
    for (ranges[0 .. ranges.len - 1], ranges[1..]) |a, b| if (a.value >= b.key) return false;
    _ = m;
    return true;
}
