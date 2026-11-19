//! What each step of the model does to a world, and whether its outcome is the one the model
//! predicted (commonware `model.rs` `Model::next_state` and the `Workload` helpers it calls).

const std = @import("std");
const utils = @import("utils");
const m = @import("../main.zig");
const d = @import("../deployment.zig");
const wl = @import("workload.zig");
const w = @import("world.zig");
const r = @import("replay.zig");

const gpa = m.gpa;
const Epoch = m.Epoch;
const Sha256 = m.Sha256;
const Outcome = m.roles.sender.Outcome;
const Receipt = m.TestSender.Receipt;
const Workload = wl.Workload;
const Step = wl.Step;
const World = w.World;
const users = w.users;
const holds = w.holds;

/// The world after `step`, or null when the step is not one the workload takes.
pub fn next_state(model: *Workload, world: *const World, step: Step) !?World {
    var next = try world.clone();
    errdefer next.deinit(gpa);
    if (!try apply(model, &next, step)) {
        next.deinit(gpa);
        return null;
    }
    return next;
}

fn apply(model: *Workload, world: *World, step: Step) !bool {
    switch (step) {
        .deposit => |user| {
            world.budget.deposits -= 1;
            world.ledger.deposit(model.accounts[user], model.amount) catch
                world.fail("deposit refused");
            try world.deposited.append(gpa, .{ user, model.amount });
        },
        .force_withdraw => |user| {
            world.budget.forced -= 1;
            world.ledger.withdraw(model.accounts[user], model.amount) catch
                world.fail("forced withdrawal refused");
            if (world.candidate != null) try model.witness(
                "a forced withdrawal is queued while the last close awaits its post",
            );
        },
        .soft_withdraw => |s| try soft_withdraw(model, world, s.user, s.epoch),
        .send => |s| return send(model, world, s.user, s.receiver, s.epoch),
        .resend => |user| {
            world.budget.duplicates -= 1;
            const index = world.pending[user].?;
            world.sent.items[index].copies += 1;
            try in_flight(world, index);
        },
        .replay => |request| {
            // The network's copy: the count of copies the sender sent stays the same.
            world.budget.replays -= 1;
            try in_flight(world, request);
        },
        .deliver => |request| try deliver(model, world, request),
        .reply => |index| try reply(world, model, index),
        .lose => |index| {
            world.budget.losses -= 1;
            _ = world.replies.orderedRemove(index);
        },
        .close => |c| try close(model, world, c.deposits, c.forced, c.omit),
        .post => try post(model, world),
        .resolve => |user| try resolve(model, world, user),
        .challenge => |index| try challenge(model, world, index),
        .withdraw_payout => |p| try withdraw_payout(model, world, p.epoch, p.user),
        .halt => {
            world.budget.halts -= 1;
            const forced = model.forced_queued(world);
            try world.ledger.halt();
            try halt_world(model, world, forced);
        },
        .claim => |user| try claim(model, world, user),
    }
    return true;
}

/// Puts a copy of request `index` in flight, keeping the copies in request order.
fn in_flight(world: *World, index: usize) !void {
    try world.requests.append(gpa, index);
    std.mem.sort(usize, world.requests.items, {}, std.sort.asc(usize));
}

/// Signs a soft withdrawal of `user` for the close of `epoch` and gives it to the operator,
/// which collects it exactly if `epoch` is the one it admits in.
fn soft_withdraw(model: *Workload, world: *World, user: usize, epoch: Epoch) !void {
    world.budget.soft -= 1;
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const signer = m.user(user);
    const withdrawal = m.Withdrawal.sign(&signer, &ns, epoch, model.amount, world.budget.soft);
    const open = epoch == world.operator.epoch();
    if (world.operator.withdraw(withdrawal)) |_| {
        if (!open) return world.fail("a soft withdrawal for a closed epoch is collected");
        if (world.candidate != null) try model.witness(
            "a soft withdrawal is collected while a close awaits its post",
        );
    } else |err| {
        if (err != error.WrongEpoch or open) return world.fail("a soft withdrawal is refused");
        try model.witness("a soft withdrawal for a closed epoch is refused");
    }
}

/// `user` signs a request paying `receiver` in `epoch`, unless it holds a countersigned state
/// of a later epoch (S1). Returns false when the sender rightly refuses to sign.
fn send(model: *Workload, world: *World, user: usize, receiver: usize, epoch: Epoch) !bool {
    world.budget.sends -= 1;
    var later = false;
    for (world.countersigned.items()) |entry| {
        if (world.sent.items[entry.key[0]].user == user and entry.key[1] > epoch) later = true;
    }
    var batch = try m.amounts(&.{.{ receiver, model.payment }});
    defer batch.deinit(gpa);
    var request = world.senders[user].send(epoch, try batch.clone(gpa)) catch |err| {
        if (err == error.LaterEpoch and later) return false;
        world.fail("send refused");
        return true;
    };
    errdefer request.deinit(gpa);
    if (later) world.fail("send signed on top of a later state");

    // The states extend the latest countersigned map of the epoch on the roots S1 names.
    var latest = try Workload.map_of(world, &world.countersigned, epoch, user);
    defer latest.deinit(gpa);
    var combined = try latest.combine(gpa, &batch);
    defer combined.deinit(gpa);
    const own = model.expected_previous(world, epoch, user);
    const asked = request.epoch == epoch and request.account.eql(model.accounts[user]) and
        request.batch.eql(&batch) and request.payments.eql(combined.root(Sha256)) and
        request.previous.eql(own) and request.latest.eql(latest.root(Sha256));
    if (!asked) world.fail("send: the request is not the one asked for");
    const index = world.sent.items.len;
    try world.requests.ensureUnusedCapacity(gpa, 1);
    try world.sent.append(gpa, .{ .user = user, .request = request, .copies = 1 });
    world.pending[user] = index;
    world.requests.appendAssumeCapacity(index);
    return true;
}

fn payments_root(world: *World, account: *const m.PublicKey) ?m.Digest {
    const payments = world.operator.payments(account) orelse return null;
    return payments.root(Sha256);
}

fn optional_eql(a: ?m.Digest, b: ?m.Digest) bool {
    if (a) |x| return if (b) |y| x.eql(y) else false;
    return b == null;
}

/// The operator receives a copy of request `request`, and its outcome must be the verdict.
fn deliver(model: *Workload, world: *World, request: usize) !void {
    const position = std.mem.indexOfScalar(usize, world.requests.items, request).?;
    _ = world.requests.orderedRemove(position);
    const predicted = try model.verdict(world, request);
    const account = model.accounts[world.sent.items[request].user];
    const before = payments_root(world, &account);
    const epoch = world.operator.epoch();
    const outcome = world.operator.accept(&world.sent.items[request].request);
    const actual: wl.Verdict = if (outcome) |_|
        (if (optional_eql(before, payments_root(world, &account))) .retry else .admit)
    else |err| switch (err) {
        error.WrongEpoch => .wrong_epoch,
        error.InvalidSignature => .stale,
        error.InsufficientBalance => .insufficient,
        else => return world.fail("deliver: an unexpected refusal"),
    };
    if (actual != predicted) world.fail("deliver: the operator did other than predicted");
    try record_delivery(model, world, request, actual, epoch);
    const acknowledgement: @FieldType(w.Reply, "acknowledgement") = if (outcome) |signature|
        .{ .epoch = epoch, .signature = signature }
    else |_|
        null;
    try world.replies.append(gpa, .{ .request = request, .acknowledgement = acknowledgement });
}

fn record_delivery(
    model: *Workload,
    world: *World,
    request: usize,
    actual: wl.Verdict,
    epoch: Epoch,
) !void {
    const sent = &world.sent.items[request];
    const own = sent.request.epoch;
    switch (actual) {
        .admit => {
            if (epoch == own + 1) {
                try model.witness("a request is admitted in the epoch after its own");
            }
            if (world.candidate != null) try witness_admitted_early(model, world, sent, epoch);
            if (world.omitted.contains(&.{ epoch - 1, sent.user })) {
                try model.witness("a payment builds on a row the close omitted");
            }
            if (!holds(world.pending[sent.user], request)) {
                try model.witness("a request its sender no longer awaits is admitted");
            }
            _ = try world.admitted.put(gpa, .{ request, epoch }, {});
        },
        .retry => try model.witness("a retried request is acknowledged again"),
        .stale => {
            const settled = world.admitted.contains(&.{ request, own });
            if (sent.copies > 1 and epoch > own and settled) {
                try model.witness("a copy is refused after its own epoch settled it");
            }
        },
        else => {},
    }
}

/// Witnesses an admission while the last close awaits its post.
fn witness_admitted_early(
    model: *Workload,
    world: *World,
    sent: *const w.Sent,
    epoch: Epoch,
) !void {
    try model.witness("a payment is admitted while the last close awaits its post");
    if (epoch == sent.request.epoch + 1) try model.witness(
        "a next state is admitted while the preceding close awaits its post",
    );
    for (world.countersigned.items()) |entry| {
        const builds = world.sent.items[entry.key[0]].user == sent.user and
            entry.key[1] + 1 == epoch;
        if (!builds) continue;
        try model.witness("a state builds on a map whose close awaits its post");
        break;
    }
}

/// A sender receives the reply at `index`.
fn reply(world: *World, model: *Workload, index: usize) !void {
    const answer = world.replies.orderedRemove(index);
    const user = world.sent.items[answer.request].user;
    const current = holds(world.pending[user], answer.request);
    if (answer.acknowledgement) |ack| {
        try acknowledge(model, world, answer.request, ack.epoch, ack.signature, current);
    } else if (current and world.sent.items[answer.request].copies == 1) {
        // The sender drops a refused request only if it sent it once (S4).
        world.senders[user].refused() catch world.fail("refusal: no request pending");
        world.pending[user] = null;
        try model.witness("a request refused once is dropped");
    }
    check_pending(world, user);
}

/// An acknowledgement of the pending request countersigns one of its states and yields a
/// receipt for each receiver of the batch (S2, S3). A post is final for its epoch, so the
/// sender refuses a state of an epoch whose post it resolved and keeps the request pending.
fn acknowledge(
    model: *Workload,
    world: *World,
    request: usize,
    epoch: Epoch,
    signature: w.Signature,
    current: bool,
) !void {
    const user = world.sent.items[request].user;
    const closed = epoch <= world.resolved[user];
    const receipts = world.senders[user].acknowledged(&signature) catch |err| {
        if (err == error.Closed and current and closed) {
            return model.witness("an acknowledgement of a resolved epoch is refused");
        }
        const foreign = err == error.NotPending or err == error.InvalidAcknowledgement;
        if (foreign and !current) return;
        return world.fail("an acknowledgement is refused");
    };
    defer m.free_receipts(receipts);
    if (!current or closed) return world.fail("an acknowledgement is recorded");
    var latest = try Workload.map_of(world, &world.countersigned, epoch, user);
    defer latest.deinit(gpa);
    const batch = &world.sent.items[request].request.batch;
    var expected = try latest.combine(gpa, batch);
    defer expected.deinit(gpa);
    if (!receipts_match(receipts, batch, &expected)) {
        world.fail("acknowledgement: the sender issued other receipts");
    }
    _ = try world.countersigned.put(gpa, .{ request, epoch }, {});
    world.pending[user] = null;
    for (receipts) |*receipt| try receive(model, world, receipt);
}

/// Whether `receipts` pay exactly the receivers of `batch`, once each, their amounts in
/// `expected`.
fn receipts_match(
    receipts: []const Receipt,
    batch: *const m.Amounts,
    expected: *const m.Amounts,
) bool {
    if (receipts.len != batch.entries.len) return false;
    for (receipts, 0..) |*receipt, at| {
        for (receipts[0..at]) |*earlier| if (earlier.receiver.eql(receipt.receiver)) return false;
    }
    for (batch.entries) |entry| {
        const found = for (receipts) |*receipt| {
            if (receipt.receiver.eql(entry[0])) break receipt;
        } else return false;
        if (found.amount != expected.get(&entry[0])) return false;
    }
    return true;
}

/// Delivers `receipt` to its receiver and checks the outcome R1 and R2 predict: it is kept
/// exactly if its epoch has not posted, the ledger has not halted, and it promises more than
/// the one held.
fn receive(model: *Workload, world: *World, receipt: *const Receipt) !void {
    const receiver = model.user_of(&receipt.receiver);
    const sender = model.user_of(&receipt.state.account);
    const epoch = receipt.state.epoch;
    const amount = receipt.amount;
    const key: [3]u64 = .{ receiver, epoch, sender };
    const held = if (world.held.get(&key)) |value| value.* else 0;
    const role = &world.receivers[receiver];
    var predicted: bool = undefined;
    if (role.receive(receipt)) |kept| {
        predicted = !world.halted and epoch > world.last_posted() and amount > held and
            kept == amount and role.amount(epoch, &model.accounts[sender]) == amount;
        if (predicted) _ = try world.held.put(gpa, key, amount);
    } else |err| {
        predicted = if (world.halted)
            err == error.Halted
        else if (epoch <= world.last_posted())
            err == error.Closed
        else
            amount <= held and err == error.NotIncreasing;
    }
    if (!predicted) world.fail("a receipt had another outcome than predicted");
}

/// Checks that `user`'s sender awaits exactly the request the model records as pending.
fn check_pending(world: *World, user: usize) void {
    const awaited = world.senders[user].pending();
    const same = if (world.pending[user]) |index|
        (if (awaited) |request| request.eql(&world.sent.items[index].request) else false)
    else
        awaited == null;
    if (!same) world.fail("a sender awaits a request other than the recorded one");
}

/// The operator closes its epoch, after forgetting `omit`'s admission if set, and the
/// committee certifies the close.
fn close(model: *Workload, world: *World, deposits: u64, forced: u64, omit: ?usize) !void {
    const queue = world.ledger.queue();
    if (deposits < queue.deposits.len or forced < queue.forced_withdrawals.len) {
        try model.witness("a close defers a queued request");
    }
    if (queue.required_forced_withdrawals > 0) try model.witness(
        "a close must process a forced withdrawal queued before the last post",
    );
    if (omit) |user| {
        world.budget.omissions -= 1;
        _ = try world.omitted.put(gpa, .{ world.operator.epoch(), user }, {});
        world.operator.forget(&model.accounts[user]);
    }
    var assembled = world.operator.close(&queue, deposits, forced) catch
        return world.fail("close refused");
    assembled.flows.deinit(gpa);
    errdefer assembled.close.deinit(gpa);
    const prefix = queue.prefix(deposits, forced).?;
    for (assembled.close.withdrawals) |soft| {
        const both = for (prefix.forced_withdrawals) |f| {
            if (f.account.eql(soft.account)) break true;
        } else false;
        if (!both) continue;
        try model.witness("a soft and a forced withdrawal of one account settle in one close");
        break;
    }
    const owned_deposits = try gpa.dupe(m.Deposit, prefix.deposits);
    errdefer gpa.free(owned_deposits);
    const owned_forced = try gpa.dupe(m.Forced, prefix.forced_withdrawals);
    const processed: w.Processed = .{
        .close = assembled.close,
        .deposits = owned_deposits,
        .forced = owned_forced,
    };
    // Requests queued after the processed ones cannot change the outcome: the queues grow
    // only at their tails.
    return certify_candidate(model, world, processed, queue.forced_withdrawals.len);
}

/// The committee checks `processed` (taken) against the requests it processes, and the close
/// becomes the candidate.
fn certify_candidate(model: *Workload, world: *World, processed: w.Processed, queued: usize) !void {
    var owned = processed;
    errdefer owned.deinit();
    const replayed = try model.replays.get(&model.accounts, world.posted.items, &owned);
    switch (replayed.candidate.?) {
        .settled => |settled| world.candidate = .{
            .processed = owned,
            .summary = settled.summary,
            .balances = settled.balances,
            .forced_queued = queued,
        },
        .refused => {
            owned.deinit();
            world.fail("validators refused the close");
        },
    }
}

const Published = struct { summary: d.Summary, forced_queued: usize };

/// Posts the candidate under the committee's certificate, or null if the ledger refused.
fn publish(model: *Workload, world: *World) !?Published {
    try world.posted.ensureUnusedCapacity(gpa, 1);
    var candidate = world.candidate.?;
    world.candidate = null;
    errdefer candidate.processed.deinit();
    var certificate = try d.certify_all(model.fixture.schemes, &candidate.summary);
    defer certificate.deinit(gpa);
    var rng = utils.rng.test_rng();
    world.ledger.post(&rng, &candidate.summary, &certificate) catch {
        candidate.processed.deinit();
        world.fail("post refused");
        return null;
    };
    const posted: w.Posted = .{ .processed = candidate.processed, .summary = candidate.summary };
    world.posted.appendAssumeCapacity(posted);
    return .{ .summary = candidate.summary, .forced_queued = candidate.forced_queued };
}

/// The ledger posts the certified summary, and every receiver audits it.
fn post(model: *Workload, world: *World) !void {
    const published = try publish(model, world) orelse return;
    // The post requires every request still queued of the next close (L5).
    const queue = world.ledger.queue();
    const required = queue.required_deposits == queue.deposits.len and
        queue.required_forced_withdrawals == queue.forced_withdrawals.len;
    if (!required) world.fail("post: the next close is not required to process the queues");
    const processed = &world.posted.items[world.posted.items.len - 1].processed;
    if (queue.forced_withdrawals.len + processed.forced.len > published.forced_queued) {
        try model.witness("a forced withdrawal queued after the cut is required of the next close");
    }
    if (world.last_posted() == model.epochs) try model.witness("every epoch posts");
    try audit_all(model, world, &published.summary);
}

/// Every receiver records the post and audits each receipt it kept for the epoch with the
/// opening the committee serves, challenging a post that credits less (R3, V6).
fn audit_all(model: *Workload, world: *World, summary: *const d.Summary) !void {
    const epoch = summary.epoch;
    const snapshot = try model.snapshot(world);
    const closed = &world.posted.items[epoch - 1].processed.close;
    for (0..users) |receiver| {
        world.receivers[receiver].posted(epoch);
        for (0..users) |sender| {
            const held = (world.held.get(&.{ receiver, epoch, sender }) orelse continue).*;
            const from = &model.accounts[sender];
            const to = &model.accounts[receiver];
            const credited = if (Workload.row_in(closed, from)) |row| row.payments.get(to) else 0;
            const opening = snapshot.opening(epoch, sender, receiver);
            const role = &world.receivers[receiver];
            const found = role.audit(epoch, &summary.matrix, from, opening) catch {
                world.fail("an audit is refused");
                continue;
            };
            try judge_audit(world, found, .{
                .held = held,
                .credited = credited,
                .epoch = epoch,
                .from = from.*,
                .to = to.*,
            });
        }
    }
}

const Audited = struct {
    held: u64,
    credited: u64,
    epoch: Epoch,
    from: m.PublicKey,
    to: m.PublicKey,
};

/// Checks that an audit challenged (taken) exactly a post crediting less than held.
fn judge_audit(world: *World, found: ?w.Challenge, audited: Audited) !void {
    var raised = found orelse {
        if (audited.credited < audited.held) world.fail("an audit misses a short credit");
        return;
    };
    const receipt = &raised.receipt;
    const valid = audited.credited < audited.held and receipt.amount == audited.held and
        receipt.receiver.eql(audited.to) and receipt.state.account.eql(audited.from) and
        receipt.state.epoch == audited.epoch;
    if (!valid) {
        raised.deinit(gpa);
        return world.fail("an audit raises an unexpected challenge");
    }
    world.challenges.append(gpa, raised) catch |err| {
        raised.deinit(gpa);
        return err;
    };
}

/// A sender resolves the next post it has not resolved (S5).
fn resolve(model: *Workload, world: *World, user: usize) !void {
    const epoch = world.resolved[user] + 1;
    const snapshot = try model.snapshot(world);
    const opening = snapshot.opening(epoch, user, user);
    const root = world.post(epoch).?.summary.matrix;
    const resolution = model.resolution(world, epoch, user);

    // A post that settles the pending request settles the map the sender then records. Any
    // other post matches the sender's record when its row is the map the requests the model
    // holds as countersigned in the epoch build. Otherwise it conflicts (S5).
    var recorded = try Workload.map_of(world, &world.countersigned, epoch, user);
    defer recorded.deinit(gpa);
    const row_root = model.row_root_of(world, epoch, user);
    const predicted: Outcome = if (resolution != null and resolution.? == .settled)
        .settled
    else if (recorded.root(Sha256).eql(row_root))
        .match
    else
        .conflict;
    const matched = if (world.senders[user].posted(epoch, &root, opening)) |outcome|
        outcome == predicted
    else |_|
        false;
    if (matched) {
        try record_resolution(model, world, user, epoch, resolution);
    } else world.fail("resolve: other than predicted");
    if (predicted == .conflict) try model.witness(if (world.omitted.contains(&.{ epoch, user }))
        "a post omits a map its sender recorded"
    else
        "a post settles a map its sender did not record");
    world.resolved[user] = epoch;
    check_pending(world, user);
}

fn record_resolution(
    model: *Workload,
    world: *World,
    user: usize,
    epoch: Epoch,
    resolution: ?wl.Resolution,
) !void {
    switch (resolution orelse return) {
        .settled => {
            const index = world.pending[user].?;
            world.pending[user] = null;
            _ = try world.countersigned.put(gpa, .{ index, epoch }, {});
            try model.witness("a post settles a request before its acknowledgement arrives");
        },
        .dropped => {
            const index = world.pending[user].?;
            world.pending[user] = null;
            try model.witness("a post drops a request");
            if (world.sent.items[index].request.epoch == epoch) try model.witness(
                "a post drops a request whose next state builds on another row",
            );
        },
        .pending => try model.witness("a post keeps a request pending"),
    }
}

/// The ledger receives the challenge at `index`.
fn challenge(model: *Workload, world: *World, index: usize) !void {
    var submitted = world.challenges.orderedRemove(index);
    defer submitted.deinit(gpa);
    const forced = model.forced_queued(world);
    if (world.ledger.challenge(&submitted)) |_| {
        if (world.halted) return world.fail("a challenge halts a halted ledger");
        const halt = world.ledger.halted();
        if (halt == null or halt.? != .challenge) {
            world.fail("challenge: the ledger did not record the halt");
        }
        try model.witness("an omitted payment halts the ledger");
        try halt_world(model, world, forced);
    } else |err| {
        if (err != error.Halted or !world.halted) world.fail("a challenge is refused");
    }
}

/// Records the halt and what the ledger and the operator held back at that moment, where
/// `forced` marks the users with a forced withdrawal queued, and tells every receiver.
fn halt_world(model: *Workload, world: *World, forced: [users]bool) !void {
    world.halted = true;
    for (&world.receivers) |*receiver| receiver.halt();
    if (world.candidate != null) {
        try model.witness("the ledger halts while a close awaits its post");
    }
    for (Workload.unprocessed(world)) |amount| if (amount > 0) {
        try model.witness("the ledger halts with deposits queued");
        break;
    };
    if (std.mem.indexOfScalar(bool, &forced, true) != null) {
        try model.witness("the ledger halts with a forced withdrawal queued");
    }
    const soft = try world.operator.withdrawals(gpa);
    defer gpa.free(soft);
    if (soft.len > 0) try model.witness("the ledger halts with a soft withdrawal collected");
    for (world.pending) |pending| if (pending != null) {
        try model.witness("the ledger halts with a request pending");
        break;
    };
    for (forced, 0..) |queued, user| if (queued) {
        world.dropped[user] = true;
    };
    for (soft) |withdrawal| world.dropped[model.user_of(&withdrawal.account)] = true;
}

/// A user withdraws a payout of a posted close, with the committee's proof.
fn withdraw_payout(model: *Workload, world: *World, epoch: Epoch, user: usize) !void {
    const snapshot = try model.snapshot(world);
    const proof = snapshot.payout(epoch, user).?;
    const paid = world.withdrawn.contains(&.{ epoch, user });
    if (world.ledger.withdraw_payout(snapshot.applied, proof)) |result| {
        const to, const amount = result;
        const expected = !paid and to.eql(model.accounts[user]) and
            amount == proof.payout.amount;
        if (!expected) return world.fail("a payout is paid other than predicted");
        _ = try world.withdrawn.put(gpa, .{ epoch, user }, {});
        if (amount < model.amount) try model.witness("a payout is capped by the balance");
    } else |err| {
        if (err != error.Withdrawn or !paid) return world.fail("a payout withdrawal is refused");
        try model.witness("a payout proven again is refused");
    }
}

/// A claim pays the balance of the last post once and the unprocessed deposits once (L9).
fn claim(model: *Workload, world: *World, user: usize) !void {
    const snapshot = try model.snapshot(world);
    const balance = if (world.claimed[user]) 0 else model.settled(world, false).balances[user];
    const deposits = if (world.claimed_deposits[user]) 0 else Workload.unprocessed(world)[user];
    const expected = balance + deposits;
    const proof: ?*const r.BalanceProof = if (snapshot.proofs[user]) |*p| p else null;
    if (world.ledger.claim(&model.accounts[user], proof)) |paid| {
        if (expected == 0 or paid != expected) {
            return world.fail("a claim pays other than expected");
        }
        if (balance > 0) {
            world.claimed[user] = true;
            if (world.dropped[user]) try model.witness(
                "a withdrawal the halt dropped is claimed as balance",
            );
            for (world.withdrawn.items()) |entry| if (entry.key[1] == user) {
                try model.witness("a user claims its balance after withdrawing a payout");
                break;
            };
        }
        world.claimed_deposits[user] = true;
        if (world.ledger.custody() == 0) try model.witness(
            "claims and withdrawals drain the custody after a halt",
        );
    } else |err| {
        if (err != error.NothingToClaim or expected != 0) return world.fail("a claim is refused");
        try model.witness("a claim with nothing left to claim is refused");
    }
}
