//! Tests of `transfers` with effects (commonware `glue/src/transfers/tests.rs`, the nonced
//! accounts): each key's effects apply in transfer order, a refused effect rejects a batch,
//! and a selection undoes the effects of the candidates it drops.

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const transfers = @import("mod.zig");
const support = @import("transfers_test.zig");

const gpa = testing.allocator;
const explore = parallel.mocks.explore;
const Explorer = parallel.mocks.Explorer;
const Address = support.Address;
const Rejection = support.Rejection;
const Prng = std.Random.DefaultPrng;
const key = support.key;
const max = support.max;
const rejected_by = support.rejected_by;

/// The balance of an account the database does not hold.
pub const default_balance: u64 = 100;
/// How far above its lowest unused nonce an account tracks consumed nonces.
const nonce_window: u64 = 64;

/// An account whose transfers each consume one of its nonces, in any order within a window
/// above its lowest unused nonce.
pub const Nonced = struct {
    /// The balance transfers debit and credit.
    value: u64,
    /// The lowest unused nonce.
    base: u64,
    /// The consumed nonces above `base`, bit `i` for nonce `base + 1 + i`.
    bitmap: u64,

    pub const Amount = u64;
    pub const default: Nonced = .{ .value = default_balance, .base = 0, .bitmap = 0 };

    /// Each effect reads or changes the account's nonces or balance.
    pub const Effect = union(enum) {
        /// Consumes a nonce.
        nonce: u64,
        /// Requires a balance of at least the amount.
        floor: u64,
        /// Consumes a nonce and then refuses.
        refuse_after_nonce: u64,
        /// Empties the balance.
        burn,
    };

    pub fn balance(self: *const Nonced) u64 {
        return self.value;
    }

    pub fn set_balance(self: *Nonced, value: u64) void {
        self.value = value;
    }

    pub fn apply(self: *Nonced, effect: Effect) bool {
        switch (effect) {
            .nonce => |nonce| return self.consume(nonce),
            .floor => |floor| return self.value >= floor,
            .refuse_after_nonce => |nonce| {
                _ = self.consume(nonce);
                return false;
            },
            .burn => {
                self.value = 0;
                return true;
            },
        }
    }

    /// Consumes `nonce`, returning whether it was unused.
    fn consume(self: *Nonced, nonce: u64) bool {
        // A nonce below the base is already consumed, and the base cannot move past the max.
        if (nonce < self.base or nonce == max) return false;
        const delta = nonce - self.base;
        if (delta == 0) {
            // Consuming the base moves it past the run of consumed nonces right after it.
            const advance: u64 = @as(u64, @ctz(~self.bitmap)) + 1;
            self.base = std.math.add(u64, self.base, advance) catch return false;
            self.bitmap = if (advance >= 64) 0 else self.bitmap >> @intCast(advance);
        } else if (delta > nonce_window) {
            // A nonce past the window moves the base past it and forgets the window.
            self.base = nonce + 1;
            self.bitmap = 0;
        } else {
            // A nonce within the window is consumed once.
            const bit = @as(u64, 1) << @intCast(delta - 1);
            if (self.bitmap & bit != 0) return false;
            self.bitmap |= bit;
        }
        return true;
    }
};

pub fn nonced(value: u64, base: u64, bitmap: u64) Nonced {
    return .{ .value = value, .base = base, .bitmap = bitmap };
}

const Change = transfers.Change(Nonced);
pub const NoncedMulti = support.MultiOf(Nonced);
pub const Ledger = support.Ledger(Nonced);

/// A payment that consumes one of its sender's nonces.
const Signed = struct {
    pub const Key = Address;
    pub const Account = Nonced;
    const Entry = transfers.Entry(Address, Nonced);

    from: Address,
    to: Address,
    amount: u64,
    nonce: u64,

    pub fn changes(self: *const Signed) Changes {
        return .{ .signed = self };
    }

    /// A self-transfer moves nothing, but its sender must hold the amount. The sender's change
    /// comes last, so a selection that refuses its nonce must undo the transfer's other changes.
    pub const Changes = struct {
        signed: *const Signed,
        index: u8 = 0,

        pub fn next(it: *Changes) ?Entry {
            defer it.index += 1;
            const payment = it.signed;
            const nonce: Nonced.Effect = .{ .nonce = payment.nonce };
            const floor: Nonced.Effect = .{ .floor = payment.amount };
            const debit = Change.debiting(payment.amount).with_effect(nonce);
            const to_self = payment.from.eql(payment.to);
            return switch (it.index) {
                0 => if (to_self)
                    .{ .key = &payment.from, .change = .applying(floor) }
                else
                    .{ .key = &payment.to, .change = .crediting(payment.amount) },
                1 => if (to_self)
                    .{ .key = &payment.from, .change = .applying(nonce) }
                else
                    .{ .key = &payment.from, .change = debit },
                else => null,
            };
        }
    };
};

fn signed(from: u64, to: u64, amount: u64, nonce: u64) Signed {
    return .{ .from = key(from), .to = key(to), .amount = amount, .nonce = nonce };
}

pub fn held(n: u64, account: Nonced) support.Held(Nonced) {
    return .{ .key = key(n), .account = account };
}

/// Settles `list` from `ledger` under every shape and returns key `n`'s account.
fn settled_account(ledger: *const Ledger, list: anytype, n: u64) !Nonced {
    var outcome = try support.explore_settle(ledger, list);
    defer outcome.deinit();
    return (try outcome.ledger()).get(key(n)).?;
}

test "transfers: settle consumes nonces in transfer order" {
    // Key 1 has consumed every nonce below 3. Nonce 70 is past its window, so consuming it
    // moves the base past it, and nonce 3 cannot be consumed after it.
    var ledger = try Ledger.init(&.{held(1, nonced(10, 3, 0))});
    defer ledger.deinit();
    const forward = [_]Signed{ signed(1, 2, 1, 3), signed(1, 2, 1, 70) };
    const backward = [_]Signed{ signed(1, 2, 1, 70), signed(1, 2, 1, 3) };
    var settled = try support.explore_settle(&ledger, @as([]const Signed, &forward));
    defer settled.deinit();
    var want = try Ledger.init(&.{
        held(1, nonced(8, 71, 0)),
        held(2, nonced(default_balance + 2, 0, 0)),
    });
    defer want.deinit();
    try (try settled.ledger()).expect_equal(&want);
    const refused = try support.explore_settle(&ledger, @as([]const Signed, &backward));
    try refused.expect_rejected(.refused, key(1));

    // Between the two, key 0 pays enough fresh keys that a strategy splitting the hashing
    // hashes the two in different batches. Key 0 consumes its own nonces in order.
    const filler: u64 = 2 * transfers.hash_batch_min;
    try ledger.put(key(0), nonced(filler, 0, 0));
    for ([_][2]Signed{ forward, backward }, [_]bool{ true, false }) |pair, settles| {
        const apart = try gpa.alloc(Signed, filler + 2);
        defer gpa.free(apart);
        apart[0] = pair[0];
        for (apart[1 .. filler + 1], 0..) |*transfer, n| transfer.* = signed(0, n + 3, 1, n);
        apart[filler + 1] = pair[1];
        // Every execution shape keeps each key's effects in transfer order.
        var outcome = try support.explore_settle(&ledger, @as([]const Signed, apart));
        defer outcome.deinit();
        if (!settles) {
            try outcome.expect_rejected(.refused, key(1));
            continue;
        }
        const accounts = try outcome.ledger();
        try testing.expectEqual(nonced(0, filler, 0), accounts.get(key(0)).?);
        try testing.expectEqual(nonced(8, 71, 0), accounts.get(key(1)).?);
        var reference = try support.expected(&ledger, @as([]const Signed, apart));
        defer reference.deinit();
        try testing.expect(reference.eql(&outcome));
    }
}

/// A hasher that places key `n` in partition `n` for `n` below `transfers.partitions`, so a
/// test chooses the shard each key falls in.
const ByKey = struct {
    /// The lowest hash bit `utils.handles.partition` reads to place a key.
    const shift = 48;

    pub fn hash(_: ByKey, bytes: []const u8) u64 {
        return @as(u64, bytes[bytes.len - 1]) << shift;
    }
};

comptime {
    const partition = @import("utils").handles.partition;
    std.debug.assert(partition(1 << ByKey.shift, transfers.partitions) == 1);
}

/// The slots of a plan by key, or its rejection.
const Slots = union(enum) {
    slots: []support.Held(transfers.Slot(Nonced)),
    rejected: Rejection,

    fn deinit(self: Slots) void {
        switch (self) {
            .slots => |slots| gpa.free(slots),
            .rejected => {},
        }
    }
};

/// Plans `list` with `ByKey` and settles it from absent keys, under every shape.
const SettleByKey = struct {
    list: []const NoncedMulti,

    pub fn run(op: SettleByKey, explorer: Explorer) !Slots {
        var rejection: Rejection = undefined;
        var plan = transfers.Plan(Address, Nonced).init_with_hasher(
            gpa,
            op.list,
            ByKey{},
            explorer,
            &rejection,
        ) catch |err| return if (err == error.Rejected) .{ .rejected = rejection } else err;
        defer plan.deinit(gpa);
        const reads = try gpa.alloc(?Nonced, plan.len());
        defer gpa.free(reads);
        @memset(reads, null);
        const slots = plan.settle(gpa, reads, explorer, &rejection) catch |err|
            return if (err == error.Rejected) .{ .rejected = rejection } else err;
        defer gpa.free(slots);
        const by_key = try gpa.alloc(support.Held(transfers.Slot(Nonced)), plan.len());
        for (by_key, plan.keys, slots) |*entry, k, slot| entry.* = .{ .key = k, .account = slot };
        std.mem.sort(support.Held(transfers.Slot(Nonced)), by_key, {}, held_less);
        return .{ .slots = by_key };
    }

    const HeldSlot = support.Held(transfers.Slot(Nonced));

    fn held_less(_: void, a: HeldSlot, b: HeldSlot) bool {
        return a.key.order(b.key) == .lt;
    }

    pub fn eql(_: SettleByKey, a: Slots, b: Slots) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .slots => |slots| slots.len == b.slots.len and for (slots, b.slots) |x, y| {
                if (!std.meta.eql(x, y)) break false;
            } else true,
            .rejected => |rejection| std.meta.eql(rejection, b.rejected),
        };
    }

    pub fn discard(_: SettleByKey, value: Slots) void {
        value.deinit();
    }
};

/// Pads `pair` with transfers without changes, so every split shape buckets its hashing.
fn settle_padded(pair: [2]NoncedMulti) !Slots {
    const padded = try gpa.alloc(NoncedMulti, 3 * transfers.hash_batch_min);
    defer gpa.free(padded);
    @memset(padded, .{ .items = &.{} });
    padded[0] = pair[0];
    padded[1] = pair[1];
    return explore(gpa, testing.io, SettleByKey{ .list = padded });
}

test "transfers: plan keeps effects in order across shards" {
    // Keys 0, 64, and 224 fall in partitions 0, 64, and 224, so the most parallel split puts
    // them in three shards. Key 64 has only a credit, so its shard holds a key without effects,
    // and the effect ends of key 224's shard must be shifted past key 0's effects. Nonce 70 is
    // past the window above nonce 0, so consuming it first refuses nonce 0.
    const pair = [2]NoncedMulti{
        .{ .items = &.{
            .{ .key = key(224), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(0), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(64), .change = .crediting(1) },
        } },
        .{ .items = &.{
            .{ .key = key(0), .change = .applying(.{ .nonce = 70 }) },
            .{ .key = key(224), .change = .applying(.{ .nonce = 70 }) },
        } },
    };
    const settled = try settle_padded(pair);
    defer settled.deinit();
    try testing.expect(settled == .slots);
    const Slot = transfers.Slot(Nonced);
    try testing.expectEqualSlices(support.Held(Slot), &.{
        .{ .key = key(0), .account = .{ .put = nonced(default_balance, 71, 0) } },
        .{ .key = key(64), .account = .{ .put = nonced(default_balance + 1, 0, 0) } },
        .{ .key = key(224), .account = .{ .put = nonced(default_balance, 71, 0) } },
    }, settled.slots);

    // Swapping the transfers refuses nonce 0 on keys 0 and 224. Key 0 is reported, since it
    // comes first in every shape's plan: its partition comes first, and the whole input
    // touches it first.
    const swapped = try settle_padded(.{ pair[1], pair[0] });
    try testing.expectEqual(Slots{ .rejected = rejected_by(.refused, key(0)) }, swapped);
}

test "transfers: settle applies each key's effects in every range" {
    // Enough keys for every execution shape to split the settle into several ranges. Each key
    // consumes a nonce of its own past the window, so its settled base shows which effect it
    // got.
    const keys: u64 = 3 * transfers.settle_batch_min;
    const items = try gpa.alloc(NoncedMulti.Item, keys);
    defer gpa.free(items);
    const list = try gpa.alloc(NoncedMulti, keys);
    defer gpa.free(list);
    for (items, list, 0..) |*item, *transfer, n| {
        item.* = .{ .key = key(n), .change = .applying(.{ .nonce = nonce_window + 1 + n }) };
        transfer.* = .{ .items = item[0..1] };
    }
    // Every shape settles each key from its own effect, as the sequential reference does.
    var empty: Ledger = .{};
    var settled = try support.explore_settle(&empty, @as([]const NoncedMulti, list));
    defer settled.deinit();
    var reference = try support.expected(&empty, @as([]const NoncedMulti, list));
    defer reference.deinit();
    try testing.expect(reference.eql(&settled));
    const last = (try settled.ledger()).get(key(keys - 1)).?;
    try testing.expectEqual(nonced(default_balance, nonce_window + keys + 1, 0), last);
}

test "transfers: settle refuses replayed nonces" {
    // Key 1 has consumed every nonce below 3, and nonce 5 ahead of them.
    var ledger = try Ledger.init(&.{held(1, nonced(10, 3, 1 << 1))});
    defer ledger.deinit();

    // A nonce below the base, one consumed ahead of it, or one repeated within the batch is
    // refused, even by a transfer that moves nothing.
    const bodies = [_][]const Signed{
        &.{signed(1, 2, 0, 2)},
        &.{signed(1, 2, 0, 5)},
        &.{ signed(1, 2, 1, 4), signed(1, 2, 1, 4) },
    };
    for (bodies) |list| {
        const refused = try support.explore_settle(&ledger, list);
        try refused.expect_rejected(.refused, key(1));
    }

    // Consuming the base and then nonce 4 moves the base past nonce 5.
    const list = [_]Signed{ signed(1, 2, 1, 3), signed(1, 2, 1, 4) };
    const account = try settled_account(&ledger, @as([]const Signed, &list), 1);
    try testing.expectEqual(nonced(8, 6, 0), account);
}

test "transfers: settle deletes only accounts settled to the default" {
    var ledger = try Ledger.init(&.{
        held(1, nonced(10, 0, 0)),
        held(3, nonced(default_balance - 10, 0, 0)),
    });
    defer ledger.deinit();

    // Key 1 spends its whole balance but has consumed a nonce, so it is kept. Key 3 is refilled
    // to the default account and deleted. Absent keys spend from the default balance and
    // receive on top of it.
    const list = [_]Signed{ signed(1, 2, 10, 0), signed(4, 3, 10, 0), signed(5, 6, 30, 0) };
    var settled = try support.explore_settle(&ledger, @as([]const Signed, &list));
    defer settled.deinit();
    var want = try Ledger.init(&.{
        held(1, nonced(0, 1, 0)),
        held(2, nonced(default_balance + 10, 0, 0)),
        held(4, nonced(default_balance - 10, 1, 0)),
        held(5, nonced(default_balance - 30, 1, 0)),
        held(6, nonced(default_balance + 30, 0, 0)),
    });
    defer want.deinit();
    try (try settled.ledger()).expect_equal(&want);

    // An absent key cannot spend past the default balance.
    const over = [_]Signed{signed(5, 6, default_balance + 1, 0)};
    const short = try support.explore_settle(&ledger, @as([]const Signed, &over));
    try short.expect_rejected(.insufficient, key(5));
}

test "transfers: settle checks self transfers against the starting balance" {
    var ledger = try Ledger.init(&.{held(1, nonced(10, 0, 0))});
    defer ledger.deinit();

    // A self-transfer moves nothing and needs its amount only in the starting balance, even
    // when the batch debits all of it.
    const spent = [_]Signed{ signed(1, 1, 10, 0), signed(1, 2, 10, 1) };
    const account = try settled_account(&ledger, @as([]const Signed, &spent), 1);
    try testing.expectEqual(nonced(0, 2, 0), account);

    // A credit in the same batch cannot cover a self-transfer.
    const covered = [_]Signed{ signed(2, 1, 5, 0), signed(1, 1, 11, 0) };
    const refused = try support.explore_settle(&ledger, @as([]const Signed, &covered));
    try refused.expect_rejected(.refused, key(1));
}

test "transfers: settle replaces a balance an effect sets" {
    var ledger = try Ledger.init(&.{held(1, nonced(10, 0, 0))});
    defer ledger.deinit();

    // An effect empties key 1's balance, but its debit still comes off the starting balance,
    // and the batch replaces the emptied balance with 10 - 4. A verifier and a proposer agree.
    const list = [_]NoncedMulti{.{ .items = &.{
        .{ .key = key(1), .change = .applying(.burn) },
        .{ .key = key(1), .change = .debiting(4) },
        .{ .key = key(2), .change = .crediting(4) },
    } }};
    const account = try settled_account(&ledger, @as([]const NoncedMulti, &list), 1);
    try testing.expectEqual(nonced(6, 0, 0), account);
    var selected = try support.explore_select(&ledger, @as([]const NoncedMulti, &list), 1);
    defer selected.deinit();
    try testing.expectEqualSlices(bool, &.{true}, selected.accepted);
    try testing.expectEqual(nonced(6, 0, 0), selected.settled.get(key(1)).?);

    // A later effect on the key sees the balance an earlier effect set, in the same transfer
    // or a later one. A batch refuses the floor after the burn, and a proposer drops the
    // candidate that carries the floor.
    const together = [_]NoncedMulti{.{ .items = &.{
        .{ .key = key(1), .change = .applying(.burn) },
        .{ .key = key(1), .change = .applying(.{ .floor = 1 }) },
    } }};
    const apart = [_]NoncedMulti{
        .{ .items = &.{.{ .key = key(1), .change = .applying(.burn) }} },
        .{ .items = &.{.{ .key = key(1), .change = .applying(.{ .floor = 1 }) }} },
    };
    const cases = [_]struct { []const NoncedMulti, []const bool }{
        .{ &together, &.{false} },
        .{ &apart, &.{ true, false } },
    };
    for (cases) |case| {
        const candidates, const accepted = case;
        const refused = try support.explore_settle(&ledger, candidates);
        try refused.expect_rejected(.refused, key(1));
        var dropped = try support.explore_select(&ledger, candidates, 1);
        defer dropped.deinit();
        try testing.expectEqualSlices(bool, accepted, dropped.accepted);
        try ledger.expect_equal(&dropped.settled);
    }
}

test "transfers: selection undoes the effects of dropped candidates" {
    var ledger = try Ledger.init(&.{held(1, nonced(10, 0, 0))});
    defer ledger.deinit();
    const candidates = [_]Signed{
        // Fits: key 1 has 10.
        signed(1, 2, 6, 0),
        // Dropped: key 1 has only 4 left to spend, so nonce 1 stays unused.
        signed(1, 3, 5, 1),
        // Dropped: nonce 0 is consumed, so the debit and credit applied before it are undone.
        signed(1, 3, 4, 0),
        // Fits: nonce 1 is unused, and key 1 still has 4 to spend.
        signed(1, 3, 4, 1),
        // Dropped: key 2 starts at the default balance, and the credit it received cannot
        // cover a self-transfer.
        signed(2, 2, default_balance + 1, 0),
        // Fits: key 2 starts with the amount, and the dropped self-transfer left nonce 0 unused.
        signed(2, 2, default_balance, 0),
        // Fits: key 3 spends its whole default balance.
        signed(3, 1, default_balance, 0),
    };
    const list: []const Signed = &candidates;
    var selected = try support.explore_select(&ledger, list, 2);
    defer selected.deinit();
    try testing.expectEqualSlices(
        bool,
        &.{ true, false, false, true, false, true, true },
        selected.accepted,
    );
    var want = try Ledger.init(&.{
        held(1, nonced(default_balance, 2, 0)),
        held(2, nonced(default_balance + 6, 1, 0)),
        held(3, nonced(4, 1, 0)),
    });
    defer want.deinit();
    try want.expect_equal(&selected.settled);

    // The accepted candidates settle as a batch to the same accounts.
    const accepted = try support.body(Signed, list, selected.accepted);
    defer gpa.free(accepted);
    const body: []const Signed = accepted;
    var settled = try support.settle_all(parallel.sequential, &ledger, body);
    defer settled.deinit();
    try (try settled.ledger()).expect_equal(&want);
}

test "transfers: selection undoes applied effects when a sum overflows" {
    var selection = transfers.Selection(Address, Nonced).init(0);
    defer selection.deinit(gpa);
    const candidates = [_]NoncedMulti{
        .{ .items = &.{.{ .key = key(2), .change = .crediting(max - default_balance) }} },
        .{ .items = &.{
            .{ .key = key(1), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(1), .change = .debiting(5) },
            .{ .key = key(2), .change = .crediting(default_balance + 1) },
        } },
        .{ .items = &.{
            .{ .key = key(1), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(1), .change = .debiting(10) },
        } },
    };
    const list: []const NoncedMulti = &candidates;
    const touched = try selection.touch(gpa, list);
    try testing.expectEqual(parallel.Range.init(0, 2), touched);
    try selection.register(gpa, &.{ null, nonced(10, 0, 0) });

    // The second candidate's credit would push key 2's credit sum past the max, so the nonce
    // and debit it applied to key 1 before that are undone. The third candidate can then
    // consume the nonce and spend key 1's whole balance.
    var accepted: [3]bool = undefined;
    try selection.apply(gpa, list, &accepted);
    try testing.expectEqualSlices(bool, &.{ true, false, true }, &accepted);
    const slots = try selection.settle(gpa, parallel.sequential);
    defer gpa.free(slots);
    try testing.expectEqualSlices(transfers.Slot(Nonced), &.{
        .{ .put = nonced(max, 0, 0) },
        .{ .put = nonced(0, 1, 0) },
    }, slots);
}

test "transfers: selection restores repeated effects and mutating refusals" {
    var ledger = try Ledger.init(&.{held(1, nonced(10, 0, 0))});
    defer ledger.deinit();
    var want = try Ledger.init(&.{held(1, nonced(0, 1, 0))});
    defer want.deinit();

    // Each dropped candidate changes key 1 through its effects and is then dropped. One
    // consumes two nonces and cannot afford its debit, and the other consumes a nonce in an
    // effect that then refuses. Key 1 must be restored to its starting account, so the
    // candidate after it can consume nonce 0 and spend the whole balance.
    const dropped = [_][]const NoncedMulti.Item{
        &.{
            .{ .key = key(1), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(1), .change = .crediting(0) },
            .{ .key = key(1), .change = .applying(.{ .nonce = 1 }) },
            .{ .key = key(1), .change = .debiting(11) },
        },
        &.{
            .{ .key = key(1), .change = .crediting(5) },
            .{ .key = key(1), .change = .applying(.{ .refuse_after_nonce = 0 }) },
            .{ .key = key(1), .change = .debiting(1) },
        },
    };
    for (dropped) |items| {
        const candidates = [_]NoncedMulti{ .{ .items = items }, .{ .items = &.{
            .{ .key = key(1), .change = .applying(.{ .nonce = 0 }) },
            .{ .key = key(1), .change = .debiting(10) },
        } } };
        const list: []const NoncedMulti = &candidates;
        for ([_]usize{ 1, 2 }) |round| {
            var selected = try support.explore_select(&ledger, list, round);
            defer selected.deinit();
            try testing.expectEqualSlices(bool, &.{ false, true }, selected.accepted);
            try want.expect_equal(&selected.settled);
            var settled = try support.settle_all(parallel.sequential, &ledger, list[1..]);
            defer settled.deinit();
            try (try settled.ledger()).expect_equal(&want);
        }
    }
}

test "transfers: selection settles as the plan of the accepted signed candidates" {
    // Random candidates from accounts that have consumed nonce 0, with nonces close enough to
    // collide and amounts large enough that many do not fit.
    var prng: Prng = .init(29);
    const random = prng.random();
    const keys: u64 = 64;
    var ledger: Ledger = .{};
    defer ledger.deinit();
    for (0..keys) |n| {
        if (random.float(f64) < 0.7) {
            try ledger.put(key(n), nonced(random.uintLessThan(u64, 50), 1, 0));
        }
    }
    const candidates = try gpa.alloc(Signed, 2_000);
    defer gpa.free(candidates);
    for (candidates) |*candidate| {
        const from = random.uintLessThan(u64, keys);
        const to = random.uintLessThan(u64, keys);
        candidate.* = signed(from, to, random.uintLessThan(u64, 20), random.uintLessThan(u64, 80));
    }
    try support.expect_selection_matches_plan(&ledger, @as([]const Signed, candidates));
}
