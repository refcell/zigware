//! The steps enabled in a state of the model (commonware `model.rs` `Model::actions`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const wl = @import("workload.zig");
const w = @import("world.zig");

const Workload = wl.Workload;
const Step = wl.Step;
const holds = w.holds;
const World = w.World;
const users = w.users;

/// Appends every step enabled in `world` to `out`.
pub fn actions(
    model: *Workload,
    gpa: Allocator,
    world: *const World,
    out: *std.ArrayList(Step),
) !void {
    // A state whose last step was not the predicted one is outside the oracles' domain.
    if (world.violation != null) return;
    // The workload acts until the ledger halts.
    if (!world.halted) {
        try requests(gpa, world, out);
        try closes(model, gpa, world, out);
        if (world.budget.halts > 0) try out.append(gpa, .halt);
        if (world.candidate != null) try out.append(gpa, .post);
    }
    try network(model, gpa, world, out);
}

/// Deposits, withdrawals, sends, resends, and replays.
fn requests(gpa: Allocator, world: *const World, out: *std.ArrayList(Step)) !void {
    const budget = &world.budget;
    if (budget.deposits > 0) {
        for (0..users) |user| try out.append(gpa, .{ .deposit = user });
    }
    if (budget.forced > 0) {
        for (0..users) |user| try out.append(gpa, .{ .force_withdraw = user });
    }
    const both: [2]u64 = .{ world.ledger.epoch(), world.operator.epoch() };
    const epochs = both[0..if (both[0] != both[1]) 2 else 1];
    if (budget.soft > 0) {
        for (0..users) |user| for (epochs) |epoch| {
            try out.append(gpa, .{ .soft_withdraw = .{ .user = user, .epoch = epoch } });
        };
    }
    if (budget.sends > 0) {
        for (0..users) |user| {
            if (world.pending[user] != null) continue;
            for (0..users) |receiver| {
                if (receiver == user) continue;
                for (epochs) |epoch| try out.append(gpa, .{
                    .send = .{ .user = user, .receiver = receiver, .epoch = epoch },
                });
            }
        }
    }
    if (budget.duplicates > 0) {
        for (0..users) |user| {
            if (world.pending[user] != null) try out.append(gpa, .{ .resend = user });
        }
    }
    if (budget.replays > 0) {
        for (world.sent.items, 0..) |*sent, request| {
            if (!holds(world.pending[sent.user], request)) {
                try out.append(gpa, .{ .replay = request });
            }
        }
    }
}

/// A close of every count the queues allow, each with every omission the budget allows.
fn closes(model: *Workload, gpa: Allocator, world: *const World, out: *std.ArrayList(Step)) !void {
    if (world.candidate != null) return;
    if (world.operator.epoch() != world.ledger.epoch()) return;
    if (world.last_posted() >= model.epochs) return;
    const queue = world.ledger.queue();
    for (queue.required_deposits..queue.deposits.len + 1) |deposits| {
        for (queue.required_forced_withdrawals..queue.forced_withdrawals.len + 1) |forced| {
            try out.append(gpa, .{
                .close = .{ .deposits = deposits, .forced = forced, .omit = null },
            });
            if (world.budget.omissions == 0) continue;
            for (0..users) |user| {
                if (Workload.latest_admitted(world, world.operator.epoch(), user) == null) {
                    continue;
                }
                try out.append(gpa, .{
                    .close = .{ .deposits = deposits, .forced = forced, .omit = user },
                });
            }
        }
    }
}

/// The network delivers, and the roles act on what the ledger holds.
fn network(model: *Workload, gpa: Allocator, world: *const World, out: *std.ArrayList(Step)) !void {
    // Copies in flight are sorted, so each request is delivered once per state.
    for (world.requests.items, 0..) |request, at| {
        if (at > 0 and world.requests.items[at - 1] == request) continue;
        try out.append(gpa, .{ .deliver = request });
    }
    for (0..world.replies.items.len) |index| {
        try out.append(gpa, .{ .reply = index });
        if (world.budget.losses > 0) try out.append(gpa, .{ .lose = index });
    }
    const last = world.last_posted();
    for (0..users) |user| {
        if (world.resolved[user] < last) try out.append(gpa, .{ .resolve = user });
    }
    for (0..world.challenges.items.len) |index| try out.append(gpa, .{ .challenge = index });
    const settlement = model.settled(world, false);
    for (settlement.payouts()) |payout| {
        try out.append(gpa, .{
            .withdraw_payout = .{ .epoch = payout.epoch, .user = payout.user },
        });
    }
    if (world.halted) {
        for (0..users) |user| try out.append(gpa, .{ .claim = user });
    }
}
