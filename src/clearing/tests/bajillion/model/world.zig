//! What the deployment and the network hold in one state of the model, with the model's own
//! record of it (commonware `model.rs` `World`, `Sent`, `Reply`, `Processed`, `Posted`,
//! `Candidate`, `Budget`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const bajillion = @import("../../../bajillion/mod.zig");
const m = @import("../main.zig");
const d = @import("../deployment.zig");
const map = m.roles.map;

const gpa = m.gpa;
const Epoch = m.Epoch;

/// The users of every workload, each a sender and a receiver.
pub const users = 2;

/// Whether the optional `index` is `value`.
pub fn holds(index: ?usize, value: usize) bool {
    return if (index) |held| held == value else false;
}

pub const Request = m.TestSender.Request;
pub const Challenge = d.TestLedger.Challenge;
pub const Signature = m.PublicKey.Signature;

/// How much the workload may still do.
pub const Budget = struct {
    /// Payments the users may still attempt.
    sends: usize = 0,
    /// Copies of a pending request a sender may still send again.
    duplicates: usize = 0,
    /// Replies the network may still lose.
    losses: usize = 0,
    /// Copies the network may still put back in flight, each of a request its sender does not
    /// await. A second request of the same sender can sign the same state as such a copy, and
    /// the model would mispredict the copy's reply, so a budget with replays allows one send.
    replays: usize = 0,
    /// Deposits the users may still make.
    deposits: usize = 0,
    /// Soft withdrawals the users may still ask the operator for.
    soft: usize = 0,
    /// Forced withdrawals the users may still ask the ledger for.
    forced: usize = 0,
    /// Admissions the operator may still forget at a cut.
    omissions: usize = 0,
    /// Halts the deployment's policy may still order.
    halts: usize = 0,
};

/// A request the sender signed.
pub const Sent = struct {
    /// The user that signed it.
    user: usize,
    request: Request,
    /// How many copies the sender sent.
    copies: usize,
};

/// The operator's reply to one delivery of a request.
pub const Reply = struct {
    /// Index of the request in the sent requests.
    request: usize,
    /// The epoch the operator admitted in and its acknowledgement, or null for a refusal.
    acknowledgement: ?struct { epoch: Epoch, signature: Signature },
};

/// A close with the requests it processes. Owns them.
pub const Processed = struct {
    close: m.TestClose,
    deposits: []m.Deposit,
    forced: []m.Forced,

    pub fn deinit(self: *Processed) void {
        self.close.deinit(gpa);
        gpa.free(self.deposits);
        gpa.free(self.forced);
        self.* = undefined;
    }

    pub fn clone(self: *const Processed) !Processed {
        var close = try self.close.clone(gpa);
        errdefer close.deinit(gpa);
        const deposits = try gpa.dupe(m.Deposit, self.deposits);
        errdefer gpa.free(deposits);
        const forced = try gpa.dupe(m.Forced, self.forced);
        return .{ .close = close, .deposits = deposits, .forced = forced };
    }

    /// The queue the close processed, with each required count its length. Borrows.
    pub fn queue(self: *const Processed) m.Queue {
        return .{
            .epoch = self.close.epoch,
            .deposits = self.deposits,
            .required_deposits = self.deposits.len,
            .forced_withdrawals = self.forced,
            .required_forced_withdrawals = self.forced.len,
        };
    }

    /// Feeds the encodings of the close and of its requests to `hasher`.
    pub fn digest_into(self: *const Processed, hasher: *m.Sha256) !void {
        inline for (.{
            .{ m.TestClose, self.close },
            .{ []const m.Deposit, @as([]const m.Deposit, self.deposits) },
            .{ []const m.Forced, @as([]const m.Forced, self.forced) },
        }) |pair| {
            const bytes = try codec.encode(pair[0], gpa, pair[1]);
            defer gpa.free(bytes);
            hasher.update(bytes);
        }
    }
};

/// A posted close with its summary.
pub const Posted = struct { processed: Processed, summary: d.Summary };

/// A close the operator released and the committee certified, before it posts. The committee's
/// certificate is a deterministic function of the summary, so the post certifies it again.
pub const Candidate = struct {
    processed: Processed,
    summary: d.Summary,
    /// Every user's balance once the close applies, as the committee settled it.
    balances: [users]u64,
    /// Length of the forced withdrawal queue at the cut.
    forced_queued: usize,
};

fn order_pair(a: *const [2]u64, b: *const [2]u64) std.math.Order {
    return std.mem.order(u64, a, b);
}

fn order_triple(a: *const [3]u64, b: *const [3]u64) std.math.Order {
    return std.mem.order(u64, a, b);
}

/// A sorted set of pairs, such as (request, epoch) or (epoch, user).
pub const Pairs = map.Map([2]u64, void, order_pair);
/// The largest amount each receiver kept a receipt for, by (receiver, epoch, sender).
pub const Held = map.Map([3]u64, u64, order_triple);

/// Everything the deployment and the network hold, with the model's record of it.
pub const World = struct {
    ledger: d.TestLedger,
    operator: m.TestOperator,
    senders: [users]m.TestSender,
    receivers: [users]m.TestReceiver,
    /// The posted closes, in epoch order.
    posted: std.ArrayList(Posted) = .empty,
    /// The close the operator released and the committee certified, until it posts.
    candidate: ?Candidate = null,
    /// Copies of sent requests in flight to the operator, in request order.
    requests: std.ArrayList(usize) = .empty,
    /// Replies in flight to senders.
    replies: std.ArrayList(Reply) = .empty,
    /// Challenges in flight to the ledger.
    challenges: std.ArrayList(Challenge) = .empty,
    /// Every request signed, in order.
    sent: std.ArrayList(Sent) = .empty,
    /// The request each sender awaits an answer to.
    pending: [users]?usize = @splat(null),
    /// Requests the operator admitted as new states, as (request, epoch admitted in).
    admitted: Pairs = .{},
    /// Requests whose state the sender holds as countersigned, as (request, state's epoch).
    countersigned: Pairs = .{},
    held: Held = .{},
    /// Last epoch whose post each sender resolved.
    resolved: [users]Epoch = @splat(0),
    /// Admissions the operator forgot at a cut, as (epoch, user).
    omitted: Pairs = .{},
    /// Every deposit, in queue order, as (user, amount).
    deposited: std.ArrayList([2]u64) = .empty,
    halted: bool = false,
    /// Users that claimed their balance, and their deposits, after the halt.
    claimed: [users]bool = @splat(false),
    claimed_deposits: [users]bool = @splat(false),
    /// Payouts paid, as (epoch, user).
    withdrawn: Pairs = .{},
    /// Users whose withdrawal request, forced or soft, the halt dropped unprocessed.
    dropped: [users]bool = @splat(false),
    /// The first step whose outcome was not the predicted one, if any.
    violation: ?[]const u8 = null,
    budget: Budget,

    pub fn deinit(self: *World, _: Allocator) void {
        self.ledger.deinit();
        self.operator.deinit();
        for (&self.senders) |*sender| sender.deinit();
        for (&self.receivers) |*receiver| receiver.deinit();
        for (self.posted.items) |*p| p.processed.deinit();
        self.posted.deinit(gpa);
        if (self.candidate) |*candidate| candidate.processed.deinit();
        self.requests.deinit(gpa);
        self.replies.deinit(gpa);
        for (self.challenges.items) |*challenge| challenge.deinit(gpa);
        self.challenges.deinit(gpa);
        for (self.sent.items) |*sent| sent.request.deinit(gpa);
        self.sent.deinit(gpa);
        const sets = .{ &self.admitted, &self.countersigned, &self.omitted, &self.withdrawn };
        inline for (sets) |set| {
            set.deinit(gpa);
        }
        self.held.deinit(gpa);
        self.deposited.deinit(gpa);
        self.* = undefined;
    }

    /// A deep copy. The roles restart from copies of what they persisted.
    pub fn clone(self: *const World) !World {
        var copy: World = .{
            .ledger = try self.ledger.clone(),
            .operator = undefined,
            .senders = undefined,
            .receivers = undefined,
            .budget = self.budget,
        };
        errdefer copy.ledger.deinit();
        copy.operator = try self.operator.clone();
        errdefer copy.operator.deinit();
        for (&copy.senders, &self.senders, 0..) |*to, *from, index| {
            errdefer for (copy.senders[0..index]) |*made| made.deinit();
            to.* = try from.clone();
        }
        errdefer for (&copy.senders) |*sender| sender.deinit();
        for (&copy.receivers, &self.receivers, 0..) |*to, *from, index| {
            errdefer for (copy.receivers[0..index]) |*made| made.deinit();
            to.* = try from.clone();
        }
        errdefer for (&copy.receivers) |*receiver| receiver.deinit();
        try self.clone_records(&copy);
        return copy;
    }

    /// Copies the model's records and the messages in flight into `copy`, whose roles are set.
    /// Leaves `copy` whole on error, so the caller's cleanup can run.
    fn clone_records(self: *const World, copy: *World) !void {
        errdefer copy.drop_records();
        for (self.posted.items) |*p| {
            try copy.posted.ensureUnusedCapacity(gpa, 1);
            const processed = try p.processed.clone();
            copy.posted.appendAssumeCapacity(.{ .processed = processed, .summary = p.summary });
        }
        if (self.candidate) |*candidate| {
            copy.candidate = candidate.*;
            copy.candidate.?.processed = try candidate.processed.clone();
        }
        copy.requests = try self.requests.clone(gpa);
        copy.replies = try self.replies.clone(gpa);
        for (self.challenges.items) |*challenge| {
            try copy.challenges.ensureUnusedCapacity(gpa, 1);
            copy.challenges.appendAssumeCapacity(try clone_challenge(challenge));
        }
        for (self.sent.items) |*sent| {
            try copy.sent.ensureUnusedCapacity(gpa, 1);
            var request = try sent.request.clone(gpa);
            errdefer request.deinit(gpa);
            copy.sent.appendAssumeCapacity(.{
                .user = sent.user,
                .request = request,
                .copies = sent.copies,
            });
        }
        copy.admitted = try self.admitted.clone_shallow(gpa);
        copy.countersigned = try self.countersigned.clone_shallow(gpa);
        copy.omitted = try self.omitted.clone_shallow(gpa);
        copy.withdrawn = try self.withdrawn.clone_shallow(gpa);
        copy.held = try self.held.clone_shallow(gpa);
        copy.deposited = try self.deposited.clone(gpa);
        copy.pending = self.pending;
        copy.resolved = self.resolved;
        copy.halted = self.halted;
        copy.claimed = self.claimed;
        copy.claimed_deposits = self.claimed_deposits;
        copy.dropped = self.dropped;
        copy.violation = self.violation;
    }

    /// Frees the records `clone_records` copied and resets them, keeping the roles.
    fn drop_records(self: *World) void {
        for (self.posted.items) |*p| p.processed.deinit();
        self.posted.deinit(gpa);
        if (self.candidate) |*candidate| candidate.processed.deinit();
        self.candidate = null;
        self.requests.deinit(gpa);
        self.replies.deinit(gpa);
        for (self.challenges.items) |*challenge| challenge.deinit(gpa);
        self.challenges.deinit(gpa);
        for (self.sent.items) |*sent| sent.request.deinit(gpa);
        self.sent.deinit(gpa);
        const sets = .{ &self.admitted, &self.countersigned, &self.omitted, &self.withdrawn };
        inline for (sets) |set| {
            set.deinit(gpa);
            set.* = .{};
        }
        self.held.deinit(gpa);
        self.held = .{};
        self.deposited.deinit(gpa);
        self.posted = .empty;
        self.requests = .empty;
        self.replies = .empty;
        self.challenges = .empty;
        self.sent = .empty;
        self.deposited = .empty;
    }

    /// Records the first outcome that was not the predicted one.
    pub fn fail(self: *World, step: []const u8) void {
        if (self.violation == null) self.violation = step;
    }

    /// The epoch of the last post, or zero before the first.
    pub fn last_posted(self: *const World) Epoch {
        return self.posted.items.len;
    }

    /// The post of the close of `epoch`, if it posted.
    pub fn post(self: *const World, epoch: Epoch) ?*const Posted {
        if (epoch == 0 or epoch > self.posted.items.len) return null;
        return &self.posted.items[epoch - 1];
    }

    /// The state's identity: every role's persisted records, the messages in flight, and the
    /// model's records (Stateright's derived `Hash` of `World`).
    pub fn fingerprint(self: *const World) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hash(&hasher, self.ledger.persisted);
        hash(&hasher, self.operator.persisted);
        for (&self.senders) |*sender| hash(&hasher, sender.persisted);
        for (&self.receivers) |*receiver| hash(&hasher, receiver.persisted);
        for (self.posted.items) |*p| hash(&hasher, p.summary.digest().bytes);
        if (self.candidate) |*candidate| hash(&hasher, candidate.summary.digest().bytes);
        hasher.update(&.{@intFromBool(self.candidate != null)});
        inline for (.{
            "requests",  "replies",       "challenges", "sent",             "pending",
            "admitted",  "countersigned", "held",       "resolved",         "omitted",
            "deposited", "halted",        "claimed",    "claimed_deposits", "withdrawn",
            "dropped",   "violation",     "budget",
        }) |field| hash(&hasher, @field(self, field));
        return hasher.final();
    }
};

fn clone_challenge(challenge: *const Challenge) !Challenge {
    var receipt = try challenge.receipt.clone(gpa);
    errdefer receipt.deinit(gpa);
    return .{ .receipt = receipt, .opening = try challenge.opening.clone(gpa) };
}

/// Hashes `value` by its structure: every field, following slices and single pointers. A list
/// hashes its items only, so its spare capacity does not change the hash, and the operator's
/// read counters are left out. Recursion here follows the type's nesting, which is bounded at
/// compile time.
pub fn hash(hasher: *std.hash.Wyhash, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .void => {},
        .int, .bool, .@"enum" => std.hash.autoHash(hasher, value),
        .array => for (value) |item| hash(hasher, item),
        .optional => if (value) |inner| {
            hasher.update(&.{1});
            hash(hasher, inner);
        } else hasher.update(&.{0}),
        .pointer => |info| switch (info.size) {
            .slice => {
                std.hash.autoHash(hasher, @as(u64, value.len));
                for (value) |item| hash(hasher, item);
            },
            .one => hash(hasher, value.*),
            else => @compileError("cannot fingerprint " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            const list = @hasField(T, "items") and @hasField(T, "capacity");
            if (list) return hash(hasher, value.items);
            inline for (info.field_names) |name| {
                if (comptime std.mem.eql(u8, name, "reads")) continue;
                hash(hasher, @field(value, name));
            }
        },
        .@"union" => {
            std.hash.autoHash(hasher, std.meta.activeTag(value));
            switch (value) {
                inline else => |payload| hash(hasher, payload),
            }
        },
        else => @compileError("cannot fingerprint " ++ @typeName(T)),
    }
}

comptime {
    assert(users == 2);
}
