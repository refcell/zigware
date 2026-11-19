//! The model of the reference roles under every interleaving of a bounded workload (commonware
//! `clearing/tests/bajillion/model.rs`), on `checker.zig` in place of Stateright. Each step runs
//! the roles with real signatures, certificates, and proofs, and the committee is one reference
//! validator replayed on fresh databases per history. The model predicts every step's outcome
//! from its own records and checks seven invariants in every reachable state. Witnesses record
//! that the explored paths reach the flows the crate documents. The first workload runs in the
//! normal suite; the others, which commonware marks slow, run with `-Dslow-tests`.

const std = @import("std");
const build_options = @import("build_options");
const m = @import("../main.zig");
const checker = @import("../checker.zig");
const wl = @import("workload.zig");
const w = @import("world.zig");

const gpa = m.gpa;

/// Commonware's checker has no bound; the largest workload here reaches 3.1 million states.
const max_states = 1 << 23;

/// Checks every interleaving of the workload of `epochs` with `budget`, and that its paths
/// reach each flow in `flows`.
fn check(epochs: m.Epoch, budget: w.Budget, flows: []const []const u8) !void {
    var model = try wl.Workload.init(epochs, budget);
    defer model.deinit();
    // As commonware's `threads(available_parallelism)`.
    const cores = std.Thread.getCpuCount() catch 1;
    const workers: u32 = @intCast(@min(cores, checker.max_workers));
    const options: checker.Options = .{
        .max_states = max_states,
        .workers = workers,
        .io = std.testing.io,
    };
    var result = checker.Checker(wl.Workload).run(gpa, &model, options) catch |err| {
        std.debug.print("model: the check stopped with {t}\n", .{err});
        return err;
    };
    defer result.deinit(gpa);
    if (result.violation) |violation| {
        std.debug.print("model: \"{s}\" fails after:\n", .{violation.property});
        for (violation.path) |step| std.debug.print("  {any}\n", .{step});
        return error.TestUnexpectedResult;
    }
    for (flows) |flow| {
        const reached = for (model.witnessed.items) |seen| {
            if (std.mem.eql(u8, seen, flow)) break true;
        } else false;
        if (reached) continue;
        std.debug.print("model: no path reaches \"{s}\"\n", .{flow});
        return error.TestUnexpectedResult;
    }
    if (build_options.slow_tests) {
        const stats = .{ result.unique, result.transitions, result.max_depth };
        std.debug.print("model: {d} states, {d} transitions, depth {d}\n", stats);
    }
    try std.testing.expect(result.unique > 1);
}

// One payment attempt around the funding cut is refused, or is admitted and stays pending, and
// the funding posts. A request the cut overtakes is admitted in the epoch after its own.
test "model: admits one payment" {
    try check(1, .{ .sends = 1 }, &.{
        "every epoch posts",
        "a request is admitted in the epoch after its own",
        "a next state is admitted while the preceding close awaits its post",
        "a post keeps a request pending",
        "a request refused once is dropped",
    });
}

// Two payment attempts over two epochs, a request sent again, and a reply lost settle each
// payment at most once in every order of sends, deliveries, cuts, posts, and resolutions.
test "model: retries payments" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try check(2, .{ .sends = 2, .duplicates = 1, .losses = 1 }, &.{
        "every epoch posts",
        "a payment is admitted while the last close awaits its post",
        "a request is admitted in the epoch after its own",
        "a copy is refused after its own epoch settled it",
        "a state builds on a map whose close awaits its post",
        "a post keeps a request pending",
        "a post settles a request before its acknowledgement arrives",
        "a post drops a request",
        "a retried request is acknowledged again",
        "a request refused once is dropped",
        "a close defers a queued request",
    });
}

// A payment attempt and a forced withdrawal over two epochs, while the operator may forget an
// admission and the deployment may halt, end in challenges, claims, and payouts that drain the
// custody.
test "model: halts and claims" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try check(2, .{ .sends = 1, .forced = 1, .omissions = 1, .halts = 1 }, &.{
        "every epoch posts",
        "an omitted payment halts the ledger",
        "the ledger halts with a request pending",
        "the ledger halts with a forced withdrawal queued",
        "claims and withdrawals drain the custody after a halt",
        "a claim with nothing left to claim is refused",
        "a payout proven again is refused",
    });
}

// Two payment attempts over three epochs, while the operator may forget an admission, build
// the second on the posted row even when that row lacks the state the operator countersigned.
test "model: rebuilds on the posted row" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try check(3, .{ .sends = 2, .omissions = 1 }, &.{
        "every epoch posts",
        "an omitted payment halts the ledger",
        "a payment builds on a row the close omitted",
        "a state builds on a map whose close awaits its post",
        "a post drops a request whose next state builds on another row",
        "a post omits a map its sender recorded",
        "an acknowledgement of a resolved epoch is refused",
    });
}

// A copy of a refused request, delivered again after its sender stopped awaiting it, is
// admitted and settles within two epochs. The post of the epoch it settles in tells its sender
// that the close settled a map it did not record.
test "model: replays a dropped request" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    try check(2, .{ .sends = 1, .replays = 1 }, &.{
        "every epoch posts",
        "a request refused once is dropped",
        "a request its sender no longer awaits is admitted",
        "a post settles a map its sender did not record",
    });
}

// A payment attempt, a deposit, a soft withdrawal, and a forced withdrawal over two epochs
// while the deployment may halt at any point. Whatever the queues and the operator hold at a
// halt, claims and payout withdrawals recover every unit the ledger holds.
test "model: recovers funds after a halt" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const budget: w.Budget = .{ .sends = 1, .deposits = 1, .soft = 1, .forced = 1, .halts = 1 };
    try check(2, budget, &.{
        "every epoch posts",
        "a payment is admitted while the last close awaits its post",
        "a soft withdrawal is collected while a close awaits its post",
        "a soft withdrawal for a closed epoch is refused",
        "a forced withdrawal is queued while the last close awaits its post",
        "a forced withdrawal queued after the cut is required of the next close",
        "a close defers a queued request",
        "a close must process a forced withdrawal queued before the last post",
        "a soft and a forced withdrawal of one account settle in one close",
        "a payout is capped by the balance",
        "the ledger halts while a close awaits its post",
        "the ledger halts with deposits queued",
        "the ledger halts with a forced withdrawal queued",
        "the ledger halts with a soft withdrawal collected",
        "the ledger halts with a request pending",
        "a withdrawal the halt dropped is claimed as balance",
        "a user claims its balance after withdrawing a payout",
        "claims and withdrawals drain the custody after a halt",
        "a claim with nothing left to claim is refused",
        "a payout proven again is refused",
    });
}
