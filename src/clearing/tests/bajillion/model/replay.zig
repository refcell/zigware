//! The committee of the model: one reference validator replayed on fresh databases for each
//! history, memoized (commonware `model.rs` `Replayed`, `replay`, `REPLAYS`).

const std = @import("std");
const assert = std.debug.assert;
const m = @import("../main.zig");
const d = @import("../deployment.zig");
const w = @import("world.zig");

const gpa = m.gpa;
const Epoch = m.Epoch;
const users = w.users;

pub const BalanceProof = d.TestValidator.BalanceProof;
pub const PayoutProof = d.TestValidator.PayoutProof;
pub const Opening = d.TestValidator.Opening;

/// The candidate's summary and every user's balance after it.
pub const Settled = struct { summary: d.Summary, balances: [users]u64 };

/// What the committee derives from the posted closes, and from a candidate close on top.
pub const Replayed = struct {
    /// Balance of every user after the last post.
    balances: [users]u64,
    /// Balance proofs under the last posted balances root, for every positive balance.
    proofs: [users]?BalanceProof,
    /// Epoch of the last post. The payout proofs are under its payouts root.
    applied: Epoch,
    /// Every payout the posted closes owe, with its proof under the last payouts root.
    payouts: std.ArrayList(struct { epoch: Epoch, user: usize, proof: PayoutProof }) = .empty,
    /// What each sender paid each receiver in each posted close, as the validator opens it.
    openings: std.ArrayList(struct { epoch: Epoch, from: usize, to: usize, opening: Opening }) =
        .empty,
    /// The candidate's outcome, or null without a candidate.
    candidate: ?union(enum) { settled: Settled, refused: anyerror } = null,

    pub fn deinit(self: *Replayed) void {
        for (&self.proofs) |*proof| if (proof.*) |*p| p.deinit(gpa);
        for (self.payouts.items) |*entry| entry.proof.deinit(gpa);
        self.payouts.deinit(gpa);
        for (self.openings.items) |*entry| entry.opening.deinit(gpa);
        self.openings.deinit(gpa);
        self.* = undefined;
    }

    /// The proof of the payout the close of `epoch` owes `user`, if it owes one.
    pub fn payout(self: *const Replayed, epoch: Epoch, user: usize) ?*const PayoutProof {
        for (self.payouts.items) |*entry| {
            if (entry.epoch == epoch and entry.user == user) return &entry.proof;
        }
        return null;
    }

    /// The opening of what `from` paid `to` in the posted close of `epoch`.
    pub fn opening(self: *const Replayed, epoch: Epoch, from: usize, to: usize) *const Opening {
        for (self.openings.items) |*entry| {
            if (entry.epoch == epoch and entry.from == from and entry.to == to) {
                return &entry.opening;
            }
        }
        unreachable; // Proof: the replay opens every pair of every posted close.
    }
};

/// Replays computed so far, by the digest of the last post and the candidate. Every workload
/// has the same accounts, so they are left out of the key. Safe to share between the checker's
/// workers: as commonware's `REPLAYS`, a replay is computed outside the lock, and a second
/// computation of the same key is dropped for the first one stored.
pub const Replays = struct {
    computed: std.AutoHashMapUnmanaged([32]u8, *Replayed) = .empty,
    mutex: std.Io.Mutex = .init,

    const io = std.testing.io;

    pub fn deinit(self: *Replays) void {
        var values = self.computed.valueIterator();
        while (values.next()) |replayed| {
            replayed.*.deinit();
            gpa.destroy(replayed.*);
        }
        self.computed.deinit(gpa);
        self.* = undefined;
    }

    /// The committee's view of `posted`, with `candidate` evaluated on top of them.
    pub fn get(
        self: *Replays,
        accounts: *const [users]m.PublicKey,
        posted: []const w.Posted,
        candidate: ?*const w.Processed,
    ) !*const Replayed {
        var hasher = m.Sha256.init();
        var last = m.Digest.empty;
        if (posted.len > 0) last = posted[posted.len - 1].summary.digest();
        hasher.update(&last.bytes);
        if (candidate) |c| try c.digest_into(&hasher);
        const key = hasher.finalize().bytes;
        if (self.find(&key)) |found| return found;
        const replayed = try gpa.create(Replayed);
        errdefer gpa.destroy(replayed);
        replayed.* = try replay(accounts, posted, candidate);
        errdefer replayed.deinit();
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const slot = try self.computed.getOrPut(gpa, key);
        if (slot.found_existing) {
            // Another worker stored the same replay first; it is immutable, so either serves.
            replayed.deinit();
            gpa.destroy(replayed);
            return slot.value_ptr.*;
        }
        slot.value_ptr.* = replayed;
        return replayed;
    }

    fn find(self: *Replays, key: *const [32]u8) ?*const Replayed {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.computed.get(key.*);
    }
};

/// Replays `posted` from genesis on fresh databases, serves what the model reads under the last
/// post, and evaluates `candidate` as the next post would apply it.
fn replay(
    accounts: *const [users]m.PublicKey,
    posted: []const w.Posted,
    candidate: ?*const w.Processed,
) !Replayed {
    const env = try gpa.create(d.Env);
    defer gpa.destroy(env);
    try env.init(gpa, 0);
    defer env.deinit();
    const empty: d.Persisted = .{};
    var validator = try d.open_validator(env, "committee", &empty, null);
    defer validator.deinit();
    for (posted) |*post| {
        const queue = post.processed.queue();
        var proposal = try validator.verify(try post.processed.close.clone(gpa), &queue);
        defer proposal.deinit(gpa);
        // A posted close must check again from the requests it processed.
        if (!proposal.summary.eql(post.summary)) return error.ReplayDiverged;
        try validator.apply(&proposal, &post.summary.digest());
    }
    var replayed = try serve(&validator, accounts, posted);
    errdefer replayed.deinit();
    if (candidate) |c| replayed.candidate = try evaluate(&validator, accounts, c);
    return replayed;
}

/// Balances, proofs, payout proofs, and openings under the last post.
fn serve(
    validator: *d.TestValidator,
    accounts: *const [users]m.PublicKey,
    posted: []const w.Posted,
) !Replayed {
    var replayed: Replayed = .{
        .balances = undefined,
        .proofs = @splat(null),
        .applied = validator.summary().epoch,
    };
    errdefer replayed.deinit();
    for (accounts, 0..) |*account, user| {
        replayed.balances[user] = try validator.balance(account);
        replayed.proofs[user] = try validator.prove(account);
        for (posted) |*post| {
            const epoch = post.summary.epoch;
            if (try validator.prove_payout(epoch, account)) |proof| {
                var owned = proof;
                errdefer owned.deinit(gpa);
                try replayed.payouts.append(gpa, .{ .epoch = epoch, .user = user, .proof = owned });
            }
            for (accounts, 0..) |*receiver, to| {
                // A validator must open every posted close it applied.
                var opening = (try validator.open(epoch, account, receiver)) orelse
                    return error.ReplayDiverged;
                errdefer opening.deinit(gpa);
                try replayed.openings.append(gpa, .{
                    .epoch = epoch,
                    .from = user,
                    .to = to,
                    .opening = opening,
                });
            }
        }
    }
    return replayed;
}

/// Checks, settles, and applies `candidate` at `validator`, or returns why it refused.
fn evaluate(
    validator: *d.TestValidator,
    accounts: *const [users]m.PublicKey,
    candidate: *const w.Processed,
) !@FieldType(Replayed, "candidate") {
    const queue = candidate.queue();
    const close = try candidate.close.clone(gpa);
    var proposal = validator.verify(close, &queue) catch |err| {
        if (err == error.OutOfMemory or err == error.Canceled) return err;
        return .{ .refused = err };
    };
    defer proposal.deinit(gpa);
    const summary = proposal.summary;
    validator.apply(&proposal, &summary.digest()) catch |err| {
        if (err == error.OutOfMemory or err == error.Canceled) return err;
        return .{ .refused = err };
    };
    var balances: [users]u64 = undefined;
    for (accounts, &balances) |*account, *balance| balance.* = try validator.balance(account);
    return .{ .settled = .{ .summary = summary, .balances = balances } };
}
