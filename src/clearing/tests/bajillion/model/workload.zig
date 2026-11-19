//! A bounded workload over a deployment of two users, the faults the network and the operator
//! may inject, and the model's predictions (commonware `model.rs` `Workload`, `Verdict`,
//! `Resolution`, and the `Model` impl's `init_states`, `actions`, and `properties`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const m = @import("../main.zig");
const d = @import("../deployment.zig");
const w = @import("world.zig");
const r = @import("replay.zig");

const gpa = m.gpa;
const Epoch = m.Epoch;
const Digest = m.Digest;
const Sha256 = m.Sha256;
const Amounts = m.Amounts;
const World = w.World;
const users = w.users;

/// The most epochs a workload may post, so every payout fits a fixed buffer.
pub const max_epochs = 3;

pub const Step = union(enum) {
    /// A user deposits through the ledger.
    deposit: usize,
    /// A user asks the ledger for a forced withdrawal.
    force_withdraw: usize,
    /// A user asks the operator for a soft withdrawal in the close of `epoch`.
    soft_withdraw: struct { user: usize, epoch: Epoch },
    /// A user signs a request paying another in `epoch`.
    send: struct { user: usize, receiver: usize, epoch: Epoch },
    /// A sender sends another copy of its pending request.
    resend: usize,
    /// The network puts in flight again a copy of a request its sender does not await.
    replay: usize,
    /// The operator receives a copy of the request with this index.
    deliver: usize,
    /// A sender receives the reply at this index.
    reply: usize,
    /// The network loses the reply at this index.
    lose: usize,
    /// The operator closes its epoch processing the given counts, after forgetting one user's
    /// admission if `omit` names one, and the committee certifies the close.
    close: struct { deposits: u64, forced: u64, omit: ?usize },
    /// The ledger posts the certified summary, and every receiver audits it.
    post,
    /// A sender resolves the next post it has not resolved.
    resolve: usize,
    /// The ledger receives the challenge at this index.
    challenge: usize,
    /// A user withdraws a payout of a posted close.
    withdraw_payout: struct { epoch: Epoch, user: usize },
    /// The deployment's policy halts the ledger.
    halt,
    /// A user claims after the halt.
    claim: usize,
};

/// What the model predicts the operator does with a delivered request.
pub const Verdict = enum { admit, retry, wrong_epoch, stale, insufficient };

/// What a sender's pending request becomes at a post.
pub const Resolution = enum { settled, dropped, pending };

pub const Payout = struct { epoch: Epoch, user: usize, amount: u64 };

/// Every user's balance and every payout the released closes settle.
pub const Settlement = struct {
    balances: [users]u64 = @splat(0),
    buffer: [max_epochs * users]Payout = undefined,
    count: usize = 0,

    pub fn payouts(self: *const Settlement) []const Payout {
        return self.buffer[0..self.count];
    }
};

fn empty_root() Digest {
    return Amounts.empty.root(Sha256);
}

/// A fresh operator, sender, and receiver for every user.
const Roles = struct {
    operator: m.TestOperator,
    senders: [users]m.TestSender,
    receivers: [users]m.TestReceiver,

    fn init() !Roles {
        var operator = try m.operator();
        errdefer operator.deinit();
        var s0 = try m.sender(0);
        errdefer s0.deinit();
        var s1 = try m.sender(1);
        errdefer s1.deinit();
        var r0 = try m.receiver(0, 1);
        errdefer r0.deinit();
        return .{
            .operator = operator,
            .senders = .{ s0, s1 },
            .receivers = .{ r0, try m.receiver(1, 1) },
        };
    }

    fn deinit(self: *Roles) void {
        self.operator.deinit();
        for (&self.senders) |*sender| sender.deinit();
        for (&self.receivers) |*receiver| receiver.deinit();
    }
};

pub const Workload = struct {
    pub const State = World;
    pub const Action = Step;

    accounts: [users]m.PublicKey,
    fixture: *d.Fixture,
    /// The balances root of the empty database, which the ledger starts on.
    genesis: Digest,
    /// Deposit queued for each user before the first close.
    funding: [users]u64 = .{ 3, 2 },
    /// Amount of every payment.
    payment: u64 = 1,
    /// Amount of every deposit made after genesis and of every withdrawal.
    amount: u64 = 2,
    /// Closes the ledger may post. The epoch after the last one stays open.
    epochs: Epoch,
    budget: w.Budget,
    /// Flows the explored paths reached.
    witnessed: std.ArrayList([]const u8) = .empty,
    /// Guards `witnessed`: the checker's workers record flows at once.
    witness_mutex: std.Io.Mutex = .init,
    replays: r.Replays = .{},

    /// A workload of two users funded with 3 and 2, paying 1 at a time, depositing and
    /// withdrawing 2 at a time, over `epochs` epochs, with `budget`.
    pub fn init(epochs: Epoch, budget: w.Budget) !Workload {
        assert(epochs > 0 and epochs <= max_epochs);
        const fixture = try d.committee(4);
        errdefer {
            fixture.deinit(gpa);
            gpa.destroy(fixture);
        }
        var accounts: [users]m.PublicKey = undefined;
        for (&accounts, 0..) |*account, index| account.* = m.account(index);
        return .{
            .accounts = accounts,
            .fixture = fixture,
            .genesis = try genesis_root(),
            .epochs = epochs,
            .budget = budget,
        };
    }

    fn genesis_root() !Digest {
        const env = try gpa.create(d.Env);
        defer gpa.destroy(env);
        try env.init(gpa, 0);
        defer env.deinit();
        const empty: d.Persisted = .{};
        var validator = try d.open_validator(env, "genesis", &empty, null);
        defer validator.deinit();
        return validator.summary().balances;
    }

    pub fn deinit(self: *Workload) void {
        self.replays.deinit();
        self.witnessed.deinit(gpa);
        self.fixture.deinit(gpa);
        gpa.destroy(self.fixture);
        self.* = undefined;
    }

    /// Records that the explored paths reached `flow`.
    pub fn witness(self: *Workload, flow: []const u8) !void {
        self.witness_mutex.lockUncancelable(std.testing.io);
        defer self.witness_mutex.unlock(std.testing.io);
        for (self.witnessed.items) |seen| if (std.mem.eql(u8, seen, flow)) return;
        try self.witnessed.append(gpa, flow);
    }

    pub fn user_of(self: *const Workload, account: *const m.PublicKey) usize {
        for (&self.accounts, 0..) |*candidate, index| if (candidate.eql(account.*)) return index;
        unreachable; // Proof: every account in the model belongs to a user.
    }

    /// The committee's view of the posted closes.
    pub fn snapshot(self: *Workload, world: *const World) !*const r.Replayed {
        return self.replays.get(&self.accounts, world.posted.items, null);
    }

    /// The released close of `epoch`, posted or the candidate, if any.
    pub fn released(world: *const World, epoch: Epoch) ?*const w.Processed {
        if (world.post(epoch)) |p| return &p.processed;
        if (world.candidate) |*c| if (c.processed.close.epoch == epoch) return &c.processed;
        return null;
    }

    /// `sender`'s row in `close`, if it has one.
    pub fn row_in(close: *const m.TestClose, sender: *const m.PublicKey) ?*const m.Row {
        for (close.rows) |*row| if (row.account.eql(sender.*)) return row;
        return null;
    }

    /// The root of `user`'s row in the released close of `epoch`, or the empty map's root.
    pub fn row_root_of(
        self: *const Workload,
        world: *const World,
        epoch: Epoch,
        user: usize,
    ) Digest {
        const processed = released(world, epoch) orelse return empty_root();
        const row = row_in(&processed.close, &self.accounts[user]) orelse return empty_root();
        return row.payments.root(Sha256);
    }

    pub const StateRoots = struct { payments: Digest, previous: Digest };

    /// The payments and previous roots of the state of `epoch` the request at `index` claims.
    pub fn state_of(world: *const World, index: usize, epoch: Epoch) StateRoots {
        const request = &world.sent.items[index].request;
        if (request.epoch == epoch) {
            return .{ .payments = request.payments, .previous = request.previous };
        }
        // A state after the request's epoch must be the next one.
        assert(request.epoch + 1 == epoch);
        return .{ .payments = request.batch.root(Sha256), .previous = request.latest };
    }

    /// The map the batches of `user`'s requests in `states` with `epoch` add up to, in request
    /// order. The caller frees it.
    pub fn map_of(world: *const World, states: *const w.Pairs, epoch: Epoch, user: usize) !Amounts {
        var total = Amounts.empty;
        errdefer total.deinit(gpa);
        for (states.items()) |entry| {
            const index = entry.key[0];
            if (entry.key[1] != epoch or world.sent.items[index].user != user) continue;
            const next = try total.combine(gpa, &world.sent.items[index].request.batch);
            total.deinit(gpa);
            total = next;
        }
        return total;
    }

    /// The latest request of `user` the operator admitted in `epoch`.
    pub fn latest_admitted(world: *const World, epoch: Epoch, user: usize) ?usize {
        var latest: ?usize = null;
        for (world.admitted.items()) |entry| {
            const index = entry.key[0];
            if (entry.key[1] == epoch and world.sent.items[index].user == user) latest = index;
        }
        return latest;
    }

    /// Predicts what the operator does with the request at `index` from the closes it released,
    /// the admissions the model recorded, and the balances the closes settle (O2, O3, O4, O6).
    pub fn verdict(self: *const Workload, world: *const World, index: usize) !Verdict {
        const sent = &world.sent.items[index];
        const request = &sent.request;
        const epoch = world.operator.epoch();
        if (request.epoch != epoch and request.epoch + 1 != epoch) return .wrong_epoch;
        const claimed = state_of(world, index, epoch);

        // The latest admitted state is countersigned again, and any other state must build on
        // the row of the close before and extend the latest map.
        if (latest_admitted(world, epoch, sent.user)) |latest| {
            const roots = state_of(world, latest, epoch);
            if (roots.payments.eql(claimed.payments) and roots.previous.eql(claimed.previous)) {
                return .retry;
            }
        }
        if (!claimed.previous.eql(self.row_root_of(world, epoch - 1, sent.user))) return .stale;
        var admitted = try map_of(world, &world.admitted, epoch, sent.user);
        defer admitted.deinit(gpa);
        var combined = try admitted.combine(gpa, &request.batch);
        defer combined.deinit(gpa);
        if (!combined.root(Sha256).eql(claimed.payments)) return .stale;
        const balance = self.settled(world, true).balances[sent.user];
        if (request.batch.total().? > balance - admitted.total().?) return .insufficient;
        return .admit;
    }

    /// The root a request of `user` for `epoch` must build on (S1): the posted row root of the
    /// epoch before once the sender resolved that post, else the root of its latest
    /// countersigned state of that epoch, else the empty map's root.
    pub fn expected_previous(
        self: *const Workload,
        world: *const World,
        epoch: Epoch,
        user: usize,
    ) Digest {
        if (world.resolved[user] + 1 >= epoch) return self.row_root_of(world, epoch - 1, user);
        var found = empty_root();
        for (world.countersigned.items()) |entry| {
            const index = entry.key[0];
            if (entry.key[1] + 1 != epoch or world.sent.items[index].user != user) continue;
            found = state_of(world, index, epoch - 1).payments;
        }
        return found;
    }

    /// Predicts what the post of `epoch` does with `user`'s pending request, if it has one (S5).
    pub fn resolution(
        self: *const Workload,
        world: *const World,
        epoch: Epoch,
        user: usize,
    ) ?Resolution {
        const index = world.pending[user] orelse return null;
        const request = &world.sent.items[index].request;
        const posted = self.row_root_of(world, epoch, user);
        const within = epoch >= request.epoch and epoch <= request.epoch + 1;
        if (within and state_of(world, index, epoch).payments.eql(posted)) return .settled;
        if (request.epoch + 1 <= epoch) return .dropped;
        if (request.epoch == epoch and !request.latest.eql(posted)) return .dropped;
        return .pending;
    }

    /// Every user's balance and every payout the released closes settle, from the deposits and
    /// forced withdrawals they process, their rows, and their soft withdrawals. With
    /// `candidate`, the candidate counts as released.
    pub fn settled(self: *const Workload, world: *const World, candidate: bool) Settlement {
        var result: Settlement = .{};
        for (world.posted.items) |*p| self.settle_one(&result, &p.processed);
        if (candidate) if (world.candidate) |*c| self.settle_one(&result, &c.processed);
        return result;
    }

    fn settle_one(self: *const Workload, result: *Settlement, processed: *const w.Processed) void {
        const balances = &result.balances;
        for (processed.deposits) |deposit| {
            balances[self.user_of(&deposit.account)] += deposit.amount;
        }
        for (processed.close.rows) |*row| {
            balances[self.user_of(&row.account)] -= row.payments.total().?;
            for (row.payments.entries) |entry| balances[self.user_of(&entry[0])] += entry[1];
        }
        var requested: [users]u64 = @splat(0);
        for (processed.close.withdrawals) |soft| {
            requested[self.user_of(&soft.account)] += soft.amount;
        }
        for (processed.forced) |forced| requested[self.user_of(&forced.account)] += forced.amount;
        for (requested, 0..) |amount, user| {
            const payout = @min(amount, balances[user]);
            balances[user] -= payout;
            if (payout == 0) continue;
            assert(result.count < result.buffer.len);
            result.buffer[result.count] = .{
                .epoch = processed.close.epoch,
                .user = user,
                .amount = payout,
            };
            result.count += 1;
        }
    }

    /// The deposits no posted close processed, by user.
    pub fn unprocessed(world: *const World) [users]u64 {
        var processed: usize = 0;
        for (world.posted.items) |*p| processed += p.processed.deposits.len;
        var amounts: [users]u64 = @splat(0);
        for (world.deposited.items[processed..]) |entry| amounts[entry[0]] += entry[1];
        return amounts;
    }

    /// The users with a forced withdrawal queued at the ledger.
    pub fn forced_queued(self: *const Workload, world: *const World) [users]bool {
        var queued: [users]bool = @splat(false);
        for (world.ledger.queue().forced_withdrawals) |forced| {
            queued[self.user_of(&forced.account)] = true;
        }
        return queued;
    }

    // The checker's interface.

    pub fn init_states(self: *Workload, allocator: Allocator) ![]World {
        const states = try allocator.alloc(World, 1);
        errdefer allocator.free(states);
        var ns = try m.namespace();
        defer ns.deinit(gpa);
        const operator = m.operator_key().public_key();
        const verifier = &self.fixture.verifier;
        var ledger = try d.TestLedger.init(gpa, &ns, operator, verifier, self.genesis);
        errdefer ledger.deinit();
        // The ledger starts at the genesis summary and queues the funding deposits.
        var deposited: std.ArrayList([2]u64) = .empty;
        errdefer deposited.deinit(gpa);
        for (self.funding, 0..) |amount, user| {
            if (amount == 0) continue;
            try ledger.deposit(self.accounts[user], amount);
            try deposited.append(gpa, .{ user, amount });
        }
        var roles = try Roles.init();
        errdefer roles.deinit();
        states[0] = .{
            .ledger = ledger,
            .operator = roles.operator,
            .senders = roles.senders,
            .receivers = roles.receivers,
            .deposited = deposited,
            .budget = self.budget,
        };
        return states;
    }

    pub const actions = @import("actions.zig").actions;
    pub const next_state = @import("steps.zig").next_state;

    pub fn fingerprint(_: *Workload, world: *const World) u64 {
        return world.fingerprint();
    }

    pub const properties = @import("properties.zig").properties;
};
