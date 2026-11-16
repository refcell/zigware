//! Tests of `transfers` (commonware `glue/src/transfers/tests.rs`) that need no database: plans,
//! settling, and selection, checked against a one-key-at-a-time reference under every
//! execution shape `parallel.mocks.explore` runs.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const utils = @import("utils");
const transfers = @import("mod.zig");

const gpa = testing.allocator;
const explore = parallel.mocks.explore;
const Explorer = parallel.mocks.Explorer;
const Sequential = parallel.Sequential;
pub const Address = utils.sequence.FixedBytes(8);
pub const Rejection = transfers.Rejection(Address);
const Prng = std.Random.DefaultPrng;
pub const max = std.math.maxInt(u64);

pub fn rejected_by(reason: transfers.Reason, k: Address) Rejection {
    return .{ .reason = reason, .key = k };
}

/// Plans `list` sequentially with seed 0.
fn plan_sequential(list: anytype) !transfers.Plan(Address, Account(@TypeOf(list))) {
    var rejection: Rejection = undefined;
    return transfers.Plan(Address, Account(@TypeOf(list))).init(
        gpa,
        list,
        0,
        parallel.sequential,
        &rejection,
    );
}

pub fn key(n: u64) Address {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, n, .big);
    return .init(bytes);
}

/// An account that holds only a balance, so a key spent to zero is deleted.
pub const Balance = struct {
    value: u64,

    pub const Amount = u64;
    pub const Effect = enum {};
    pub const default: Balance = .{ .value = 0 };

    pub fn balance(self: *const Balance) u64 {
        return self.value;
    }

    pub fn set_balance(self: *Balance, value: u64) void {
        self.value = value;
    }

    pub fn apply(_: *Balance, effect: Effect) bool {
        switch (effect) {}
    }
};

pub fn bal(value: u64) Balance {
    return .{ .value = value };
}

/// A payment from one key to another.
pub fn PaymentOf(comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Key = Address;
        pub const Account = A;
        const Entry = transfers.Entry(Address, A);

        from: Address,
        to: Address,
        amount: A.Amount,

        pub fn changes(self: *const Self) Changes {
            return .{ .payment = self };
        }

        pub const Changes = struct {
            payment: *const Self,
            next_index: u8 = 0,

            pub fn next(it: *Changes) ?Entry {
                defer it.next_index += 1;
                const payment = it.payment;
                return switch (it.next_index) {
                    0 => .{ .key = &payment.from, .change = .debiting(payment.amount) },
                    1 => .{ .key = &payment.to, .change = .crediting(payment.amount) },
                    else => null,
                };
            }
        };
    };
}

const Payment = PaymentOf(Balance);

pub fn pay(from: u64, to: u64, amount: u64) Payment {
    return .{ .from = key(from), .to = key(to), .amount = amount };
}

/// A transfer with any number of changes, including repeated keys.
pub fn MultiOf(comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Key = Address;
        pub const Account = A;
        pub const Item = struct { key: Address, change: transfers.Change(A) };
        const Entry = transfers.Entry(Address, A);

        items: []const Item,

        pub fn changes(self: *const Self) Changes {
            return .{ .items = self.items };
        }

        pub const Changes = struct {
            items: []const Item,
            index: usize = 0,

            pub fn next(it: *Changes) ?Entry {
                if (it.index == it.items.len) return null;
                defer it.index += 1;
                return .{ .key = &it.items[it.index].key, .change = it.items[it.index].change };
            }
        };
    };
}

const Multi = MultiOf(Balance);
const Change = transfers.Change(Balance);

/// One account of a ledger.
pub fn Held(comptime A: type) type {
    return struct { key: Address, account: A };
}

/// Accounts by key, kept sorted, so two ledgers compare as slices.
pub fn Ledger(comptime A: type) type {
    return struct {
        const Self = @This();

        entries: std.ArrayList(Held(A)) = .empty,

        pub fn init(entries: []const Held(A)) !Self {
            var ledger: Self = .{};
            errdefer ledger.deinit();
            for (entries) |entry| try ledger.put(entry.key, entry.account);
            return ledger;
        }

        pub fn deinit(self: *Self) void {
            self.entries.deinit(gpa);
        }

        pub fn clone(self: *const Self) !Self {
            return .{ .entries = try self.entries.clone(gpa) };
        }

        fn search(self: *const Self, k: Address) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = self.entries.items.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                switch (self.entries.items[mid].key.order(k)) {
                    .eq => return .{ mid, true },
                    .lt => low = mid + 1,
                    .gt => high = mid,
                }
            }
            return .{ low, false };
        }

        pub fn get(self: *const Self, k: Address) ?A {
            const index, const found = self.search(k);
            return if (found) self.entries.items[index].account else null;
        }

        pub fn put(self: *Self, k: Address, account: A) !void {
            const index, const found = self.search(k);
            if (found) {
                self.entries.items[index].account = account;
            } else {
                try self.entries.insert(gpa, index, .{ .key = k, .account = account });
            }
        }

        pub fn remove(self: *Self, k: Address) void {
            const index, const found = self.search(k);
            if (found) _ = self.entries.orderedRemove(index);
        }

        pub fn apply(self: *Self, k: Address, slot: transfers.Slot(A)) !void {
            switch (slot) {
                .keep => {},
                .put => |account| try self.put(k, account),
                .delete => self.remove(k),
            }
        }

        pub fn expect_equal(self: *const Self, other: *const Self) !void {
            try testing.expectEqualSlices(Held(A), self.entries.items, other.entries.items);
        }
    };
}

/// Whether two ledgers hold the same accounts.
pub fn ledgers_eql(comptime A: type, a: *const Ledger(A), b: *const Ledger(A)) bool {
    if (a.entries.items.len != b.entries.items.len) return false;
    for (a.entries.items, b.entries.items) |x, y| {
        if (!std.meta.eql(x, y)) return false;
    }
    return true;
}

/// A settle's outcome: the ledger it leaves, or the rejection.
pub fn Outcome(comptime A: type) type {
    return union(enum) {
        const Self = @This();

        settled: Ledger(A),
        rejected: Rejection,

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .settled => |*settled| settled.deinit(),
                .rejected => {},
            }
        }

        pub fn ledger(self: *const Self) !*const Ledger(A) {
            return switch (self.*) {
                .settled => |*settled| settled,
                .rejected => error.TestUnexpectedRejection,
            };
        }

        pub fn expect_rejected(self: *const Self, reason: transfers.Reason, k: Address) !void {
            try testing.expect(self.* == .rejected);
            try testing.expectEqual(reason, self.rejected.reason);
            try testing.expect(self.rejected.key.eql(k));
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
            return switch (a.*) {
                .settled => |*settled| ledgers_eql(A, settled, &b.settled),
                .rejected => |rejection| std.meta.eql(rejection, b.rejected),
            };
        }
    };
}

pub fn Account(comptime List: type) type {
    return @typeInfo(List).pointer.child.Account;
}

/// Plans and settles `list` from `ledger` under `strategy`, returning what it leaves.
pub fn settle_all(
    strategy: anytype,
    ledger: anytype,
    list: anytype,
) !Outcome(Account(@TypeOf(list))) {
    const A = Account(@TypeOf(list));
    var rejection: Rejection = undefined;
    var plan = transfers.Plan(Address, A).init(gpa, list, 1, strategy, &rejection) catch |err|
        return if (err == error.Rejected) .{ .rejected = rejection } else err;
    defer plan.deinit(gpa);
    const reads = try gpa.alloc(?A, plan.len());
    defer gpa.free(reads);
    for (reads, plan.keys) |*read, k| read.* = ledger.get(k);
    const slots = plan.settle(gpa, reads, strategy, &rejection) catch |err|
        return if (err == error.Rejected) .{ .rejected = rejection } else err;
    defer gpa.free(slots);
    var settled = try ledger.clone();
    errdefer settled.deinit();
    for (plan.keys, slots) |k, slot| try settled.apply(k, slot);
    return .{ .settled = settled };
}

/// `settle_all` under every execution shape.
fn SettleAll(comptime List: type) type {
    const A = Account(List);
    return struct {
        ledger: *const Ledger(A),
        list: List,

        pub fn run(op: @This(), explorer: Explorer) !Outcome(A) {
            return settle_all(explorer, op.ledger, op.list);
        }

        pub fn eql(_: @This(), a: Outcome(A), b: Outcome(A)) bool {
            return a.eql(&b);
        }

        pub fn discard(_: @This(), value: Outcome(A)) void {
            var owned = value;
            owned.deinit();
        }
    };
}

pub fn explore_settle(ledger: anytype, list: anytype) !Outcome(Account(@TypeOf(list))) {
    return explore(gpa, testing.io, SettleAll(@TypeOf(list)){ .ledger = ledger, .list = list });
}

/// Per-key reference state: summed debits and credits and the effects in order.
fn Reference(comptime A: type) type {
    return struct {
        debit: A.Amount = 0,
        credit: A.Amount = 0,
        effects: std.ArrayList(transfers.StoredEffect(A)) = .empty,
    };
}

/// What settling `list` from `ledger` must leave, computed one key at a time over each change's
/// effect, then debit, then credit.
pub fn expected(ledger: anytype, list: anytype) !Outcome(Account(@TypeOf(list))) {
    const A = Account(@TypeOf(list));
    var keys: Ledger(Reference(A)) = .{};
    defer {
        for (keys.entries.items) |*entry| entry.account.effects.deinit(gpa);
        keys.deinit();
    }
    for (list) |*transfer| {
        var changes = transfer.changes();
        while (changes.next()) |entry| {
            if (entry.change.is_empty()) continue;
            var state = keys.get(entry.key.*) orelse Reference(A){};
            if (comptime transfers.has_effects(A)) {
                if (entry.change.effect) |effect| try state.effects.append(gpa, effect);
            }
            // Store the state before any rejection, so the deferred cleanup frees its effects.
            try keys.put(entry.key.*, state);
            const change = entry.change;
            const debit = utils.amount.checked_add(A.Amount, state.debit, change.debit) orelse
                return .{ .rejected = rejected_by(.insufficient, entry.key.*) };
            const credit = utils.amount.checked_add(A.Amount, state.credit, change.credit) orelse
                return .{ .rejected = rejected_by(.overflow, entry.key.*) };
            state.debit = debit;
            state.credit = credit;
            try keys.put(entry.key.*, state);
        }
    }
    var settled = try ledger.clone();
    errdefer settled.deinit();
    for (keys.entries.items) |entry| {
        if (try settle_reference(A, &settled, ledger, entry.key, &entry.account)) |rejection| {
            settled.deinit();
            return .{ .rejected = rejection };
        }
    }
    return .{ .settled = settled };
}

fn settle_reference(
    comptime A: type,
    settled: *Ledger(A),
    ledger: anytype,
    k: Address,
    state: *const Reference(A),
) !?Rejection {
    const start: A = ledger.get(k) orelse A.default;
    var account = start;
    if (comptime transfers.has_effects(A)) {
        for (state.effects.items) |effect| {
            if (!account.apply(effect)) return .{ .reason = .refused, .key = k };
        }
    }
    const remaining = utils.amount.checked_sub(A.Amount, start.balance(), state.debit) orelse
        return .{ .reason = .insufficient, .key = k };
    const final = utils.amount.checked_add(A.Amount, remaining, state.credit) orelse
        return .{ .reason = .overflow, .key = k };
    account.set_balance(final);
    if (transfers.account_eql(A, &account, &start)) return null;
    if (transfers.account_eql(A, &account, &A.default)) {
        settled.remove(k);
    } else {
        try settled.put(k, account);
    }
    return null;
}

/// A plan's debit and credit sums for one key.
const Sum = struct { key: Address, debit: u64, credit: u64 };

/// A plan's sums by key, independent of its key order, or its rejection.
const Planned = union(enum) {
    sums: []Sum,
    rejected: Rejection,

    fn deinit(self: Planned) void {
        switch (self) {
            .sums => |sums| gpa.free(sums),
            .rejected => {},
        }
    }

    fn expect_sums(self: Planned, want: []const Sum) !void {
        try testing.expect(self == .sums);
        try testing.expectEqualSlices(Sum, want, self.sums);
    }
};

fn sum_less(_: void, a: Sum, b: Sum) bool {
    return a.key.order(b.key) == .lt;
}

fn sums_of(plan: *const transfers.Plan(Address, Balance)) ![]Sum {
    const sums = try gpa.alloc(Sum, plan.len());
    for (sums, plan.keys, plan.debits, plan.credits) |*sum, k, debit, credit| {
        sum.* = .{ .key = k, .debit = debit, .credit = credit };
    }
    std.mem.sort(Sum, sums, {}, sum_less);
    return sums;
}

/// Plans `list` with `hasher` under every execution shape.
fn PlanSums(comptime List: type, comptime H: type) type {
    return struct {
        list: List,
        hasher: H,

        pub fn run(op: @This(), explorer: Explorer) !Planned {
            var rejection: Rejection = undefined;
            var plan = transfers.Plan(Address, Balance).init_with_hasher(
                gpa,
                op.list,
                op.hasher,
                explorer,
                &rejection,
            ) catch |err| return if (err == error.Rejected) .{ .rejected = rejection } else err;
            defer plan.deinit(gpa);
            return .{ .sums = try sums_of(&plan) };
        }

        pub fn eql(_: @This(), a: Planned, b: Planned) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .sums => |sums| std.mem.eql(
                    u8,
                    std.mem.sliceAsBytes(sums),
                    std.mem.sliceAsBytes(b.sums),
                ),
                .rejected => |rejection| std.meta.eql(rejection, b.rejected),
            };
        }

        pub fn discard(_: @This(), value: Planned) void {
            value.deinit();
        }
    };
}

fn explore_sums(list: anytype, hasher: anytype) !Planned {
    const Op = PlanSums(@TypeOf(list), @TypeOf(hasher));
    return explore(gpa, testing.io, Op{ .list = list, .hasher = hasher });
}

const seeded: transfers.SeededHasher = .{ .seed = 1 };

test "transfers: plan sums changes per key" {
    // Each key's debits and credits are summed across transfers, including a payment to itself.
    const payments = [_]Payment{ pay(1, 2, 10), pay(2, 3, 5), pay(1, 3, 7), pay(3, 3, 2) };
    const planned = try explore_sums(@as([]const Payment, &payments), seeded);
    defer planned.deinit();
    try planned.expect_sums(&.{
        .{ .key = key(1), .debit = 17, .credit = 0 },
        .{ .key = key(2), .debit = 5, .credit = 10 },
        .{ .key = key(3), .debit = 2, .credit = 14 },
    });
}

test "transfers: plan sums repeated keys within a transfer" {
    // A key repeated within one transfer sums every change, and an empty transfer adds nothing.
    const list = [_]Multi{
        .{ .items = &.{
            .{ .key = key(1), .change = .debiting(3) },
            .{ .key = key(1), .change = .crediting(4) },
            .{ .key = key(1), .change = .debiting(5) },
        } },
        .{ .items = &.{} },
        .{ .items = &.{.{ .key = key(2), .change = .crediting(1) }} },
    };
    const planned = try explore_sums(@as([]const Multi, &list), seeded);
    defer planned.deinit();
    try planned.expect_sums(&.{
        .{ .key = key(1), .debit = 8, .credit = 4 },
        .{ .key = key(2), .debit = 0, .credit = 1 },
    });
}

test "transfers: plan of nothing is empty" {
    // No transfers plan and settle nothing.
    var rejection: Rejection = undefined;
    var plan = try plan_sequential(@as([]const Payment, &.{}));
    defer plan.deinit(gpa);
    try testing.expect(plan.is_empty());
    const slots = try plan.settle(gpa, &.{}, parallel.sequential, &rejection);
    defer gpa.free(slots);
    try testing.expectEqual(0, slots.len);

    // A transfer without changes plans nothing.
    const empty_list = [_]Multi{.{ .items = &.{} }};
    var empty = try plan_sequential(@as([]const Multi, &empty_list));
    defer empty.deinit(gpa);
    try testing.expect(empty.is_empty());
}

test "transfers: plan rejects overflowing sums" {
    // Debits that sum past `u64::MAX` are unaffordable.
    const debits = [_]Payment{ pay(1, 2, max), pay(1, 3, 1) };
    const rejected_debits = try explore_sums(@as([]const Payment, &debits), seeded);
    const short: Planned = .{ .rejected = rejected_by(.insufficient, key(1)) };
    try testing.expectEqual(short, rejected_debits);

    // Credits that sum past `u64::MAX` overflow.
    const credits = [_]Payment{ pay(1, 3, max), pay(2, 3, 1) };
    const rejected_credits = try explore_sums(@as([]const Payment, &credits), seeded);
    const over: Planned = .{ .rejected = rejected_by(.overflow, key(3)) };
    try testing.expectEqual(over, rejected_credits);
}

test "transfers: plan leaves out keys touched only by zero" {
    // Key 1 sees only a zero debit and is left out, and a zero self-payment adds nothing to key 3.
    const payments = [_]Payment{ pay(1, 2, 0), pay(2, 3, 5), pay(3, 3, 0) };
    const planned = try explore_sums(@as([]const Payment, &payments), seeded);
    defer planned.deinit();
    try planned.expect_sums(&.{
        .{ .key = key(2), .debit = 5, .credit = 0 },
        .{ .key = key(3), .debit = 0, .credit = 5 },
    });
}

fn random_payments(prng: *Prng, count: usize, keys: u64, amount_max: u64) ![]Payment {
    const random = prng.random();
    const payments = try gpa.alloc(Payment, count);
    for (payments) |*payment| {
        const from = random.uintLessThan(u64, keys);
        const to = random.uintLessThan(u64, keys);
        payment.* = pay(from, to, random.uintLessThan(u64, amount_max));
    }
    return payments;
}

test "transfers: settle matches sequential reference" {
    // Random affordable payments, and a zero payment from a key held at zero, settle to the
    // reference balances under every execution shape.
    var prng: Prng = .init(7);
    const keys: u64 = 512;
    var ledger: Ledger(Balance) = .{};
    defer ledger.deinit();
    for (0..keys) |n| try ledger.put(key(n), bal(100 + prng.random().uintLessThan(u64, 900)));
    try ledger.put(key(keys + 1), bal(0));
    const payments = try random_payments(&prng, 4_097, keys, 4);
    defer gpa.free(payments);
    payments[4_096] = pay(keys + 1, 0, 0);
    var want = try expected(&ledger, @as([]const Payment, payments));
    defer want.deinit();
    var got = try explore_settle(&ledger, @as([]const Payment, payments));
    defer got.deinit();
    try testing.expect(want == .settled);
    try testing.expect(got.eql(&want));

    // Keys the database does not hold afford nothing, so one more payment from such a key
    // rejects the batch and names that key.
    const rejected = try gpa.alloc(Payment, payments.len + 1);
    defer gpa.free(rejected);
    @memcpy(rejected[0..payments.len], payments);
    rejected[payments.len] = pay(keys, 0, 1);
    const outcome = try explore_settle(&ledger, @as([]const Payment, rejected));
    try outcome.expect_rejected(.insufficient, key(keys));
}

test "transfers: settle rejects unaffordable and overflowing keys" {
    // A key whose debits exceed its balance is rejected.
    var funded = try Ledger(Balance).init(&.{.{ .key = key(1), .account = bal(10) }});
    defer funded.deinit();
    const unaffordable = [_]Payment{ pay(1, 2, 6), pay(1, 3, 5) };
    const short = try explore_settle(&funded, @as([]const Payment, &unaffordable));
    try short.expect_rejected(.insufficient, key(1));

    // A key whose final balance exceeds `u64::MAX` is rejected.
    var ledger = try Ledger(Balance).init(&.{
        .{ .key = key(1), .account = bal(10) },
        .{ .key = key(2), .account = bal(max) },
    });
    defer ledger.deinit();
    const overflowing = [_]Payment{pay(1, 2, 1)};
    const over = try explore_settle(&ledger, @as([]const Payment, &overflowing));
    try over.expect_rejected(.overflow, key(2));

    // Each key's debits come off before its credits are added, so a key can spend its whole
    // balance and be refilled up to `u64::MAX`.
    const refilled = [_]Payment{ pay(2, 1, max), pay(1, 2, 10) };
    var got = try explore_settle(&ledger, @as([]const Payment, &refilled));
    defer got.deinit();
    var want = try Ledger(Balance).init(&.{
        .{ .key = key(1), .account = bal(max) },
        .{ .key = key(2), .account = bal(10) },
    });
    defer want.deinit();
    try (try got.ledger()).expect_equal(&want);
}

/// The slot `plan` settles each key to, by key.
fn slot_of(
    plan: anytype,
    slots: []const transfers.Slot(Balance),
    k: Address,
) transfers.Slot(Balance) {
    for (plan.keys, slots) |planned, slot| if (planned.eql(k)) return slot;
    unreachable; // Every key the test asks for is planned.
}

test "transfers: settle deletes zero balances and keeps unchanged keys" {
    var ledger = try Ledger(Balance).init(&.{
        .{ .key = key(1), .account = bal(10) },
        .{ .key = key(2), .account = bal(5) },
        .{ .key = key(5), .account = bal(7) },
    });
    defer ledger.deinit();
    const payments = [_]Payment{ pay(1, 2, 10), pay(2, 3, 5), pay(4, 4, 0), pay(5, 5, 7) };
    var rejection: Rejection = undefined;
    var plan = try plan_sequential(@as([]const Payment, &payments));
    defer plan.deinit(gpa);
    const reads = try gpa.alloc(?Balance, plan.len());
    defer gpa.free(reads);
    for (reads, plan.keys) |*read, k| read.* = ledger.get(k);
    const slots = try plan.settle(gpa, reads, parallel.sequential, &rejection);
    defer gpa.free(slots);

    // Key 1 is drained and deleted, key 2 spends its 5 and receives 10, key 3 is created, and
    // key 5 pays itself its whole balance and keeps it. Key 4 pays itself nothing, so the plan
    // leaves it out.
    try testing.expectEqual(4, plan.len());
    const Slot = transfers.Slot(Balance);
    try testing.expectEqual(Slot.delete, slot_of(&plan, slots, key(1)));
    try testing.expectEqual(Slot{ .put = bal(10) }, slot_of(&plan, slots, key(2)));
    try testing.expectEqual(Slot{ .put = bal(5) }, slot_of(&plan, slots, key(3)));
    try testing.expectEqual(Slot.keep, slot_of(&plan, slots, key(5)));
}

/// The slots, or the rejection, of settling a plan.
const Settled = union(enum) {
    slots: []transfers.Slot(Balance),
    rejected: Rejection,

    fn deinit(self: Settled) void {
        switch (self) {
            .slots => |slots| gpa.free(slots),
            .rejected => {},
        }
    }
};

/// Settles `plan` against `reads` under every execution shape.
const SettlePlan = struct {
    plan: *const transfers.Plan(Address, Balance),
    reads: []const ?Balance,

    pub fn run(op: SettlePlan, explorer: Explorer) !Settled {
        var rejection: Rejection = undefined;
        const slots = op.plan.settle(gpa, op.reads, explorer, &rejection) catch |err|
            return if (err == error.Rejected) .{ .rejected = rejection } else err;
        return .{ .slots = slots };
    }

    pub fn eql(_: SettlePlan, a: Settled, b: Settled) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .slots => |slots| slots.len == b.slots.len and for (slots, b.slots) |x, y| {
                if (!std.meta.eql(x, y)) break false;
            } else true,
            .rejected => |rejection| std.meta.eql(rejection, b.rejected),
        };
    }

    pub fn discard(_: SettlePlan, value: Settled) void {
        value.deinit();
    }
};

fn settle_fixed(debits: []const u64, credits: []const u64) !Settled {
    var keys: [6]Address = undefined;
    for (&keys, 0..) |*k, n| k.* = key(n);
    var debits_copy: [6]u64 = undefined;
    var credits_copy: [6]u64 = undefined;
    @memcpy(&debits_copy, debits);
    @memcpy(&credits_copy, credits);
    const plan: transfers.Plan(Address, Balance) = .{
        .keys = &keys,
        .debits = &debits_copy,
        .credits = &credits_copy,
        .effect_offsets = &.{},
        .effects = &.{},
    };
    const reads = [_]?Balance{ bal(10), bal(0), bal(7), null, bal(0), bal(1) };
    return explore(gpa, testing.io, SettlePlan{ .plan = &plan, .reads = &reads });
}

test "transfers: settle marks each kind of slot and reports offenders" {
    // In key order, spending everything deletes, a credit to a held zero puts, and an even
    // exchange, an absent key, a held zero left at zero, and an untouched key all keep.
    const settled = try settle_fixed(&.{ 10, 0, 2, 0, 0, 0 }, &.{ 0, 3, 2, 0, 0, 0 });
    defer settled.deinit();
    try testing.expect(settled == .slots);
    try testing.expectEqualSlices(transfers.Slot(Balance), &.{
        .delete, .{ .put = bal(3) }, .keep, .keep, .keep, .keep,
    }, settled.slots);

    // A rejected batch reports the key that cannot afford its debits or whose final balance
    // overflows.
    const short = try settle_fixed(&.{ 10, 0, 8, 0, 0, 0 }, &.{ 0, 3, 2, 0, 0, 0 });
    try testing.expectEqual(Settled{ .rejected = rejected_by(.insufficient, key(2)) }, short);
    const over = try settle_fixed(&.{ 10, 0, 2, 0, 0, 0 }, &.{ 0, 3, 2, 0, 0, max });
    try testing.expectEqual(Settled{ .rejected = .{ .reason = .overflow, .key = key(5) } }, over);
}

test "transfers: settle slots are identical across strategies" {
    // Enough keys for every execution shape to split the settle into several ranges.
    var prng: Prng = .init(3);
    const keys: u64 = 3 * transfers.settle_batch_min;
    const payments = try gpa.alloc(Payment, keys);
    defer gpa.free(payments);
    for (payments, 0..) |*payment, n| payment.* = pay(n, prng.random().uintLessThan(u64, keys), 1);
    var plan = try plan_sequential(@as([]const Payment, payments));
    defer plan.deinit(gpa);
    try testing.expectEqual(keys, plan.len());
    const reads = try gpa.alloc(?Balance, plan.len());
    defer gpa.free(reads);
    @memset(reads, bal(100));

    // Every shape returns the same slot per key, matching a direct computation.
    const settled = try explore(gpa, testing.io, SettlePlan{ .plan = &plan, .reads = reads });
    defer settled.deinit();
    for (settled.slots, plan.debits, plan.credits) |slot, debit, credit| {
        const value = 100 - debit + credit;
        const want: transfers.Slot(Balance) = if (value == 100) .keep else .{ .put = bal(value) };
        try testing.expectEqual(want, slot);
    }

    // One key in the last range cannot afford its debit, whichever shape settles it.
    reads[plan.len() - 1] = null;
    const offender = plan.keys[plan.len() - 1];
    const rejected = try explore(gpa, testing.io, SettlePlan{ .plan = &plan, .reads = reads });
    try testing.expectEqual(Settled{ .rejected = rejected_by(.insufficient, offender) }, rejected);
}

/// A hasher that places every key in the same slot of the same partition.
const Collide = struct {
    pub fn hash(_: Collide, _: []const u8) u64 {
        return std.math.maxInt(u64);
    }
};

fn count_sums(payments: []const Payment) ![]Sum {
    var ledger: Ledger(Sum) = .{};
    defer ledger.deinit();
    for (payments) |payment| {
        var from = ledger.get(payment.from) orelse
            Sum{ .key = payment.from, .debit = 0, .credit = 0 };
        from.debit += 1;
        try ledger.put(payment.from, from);
        var to = ledger.get(payment.to) orelse Sum{ .key = payment.to, .debit = 0, .credit = 0 };
        to.credit += 1;
        try ledger.put(payment.to, to);
    }
    const sums = try gpa.alloc(Sum, ledger.entries.items.len);
    for (sums, ledger.entries.items) |*sum, entry| sum.* = entry.account;
    return sums;
}

test "transfers: plan deduplicates keys whose hashes collide" {
    // Every key shares a fingerprint and starts probing at the last slot, so only the key
    // comparison tells keys apart and probes wrap around the table.
    var prng: Prng = .init(9);
    const payments = try random_payments(&prng, 2_000, 200, 1);
    defer gpa.free(payments);
    for (payments) |*payment| payment.amount = 1;
    const want = try count_sums(payments);
    defer gpa.free(want);
    const planned = try explore_sums(@as([]const Payment, payments), Collide{});
    defer planned.deinit();
    try planned.expect_sums(want);
}

test "transfers: plan deduplicates many keys" {
    // Touch each key about ten times on average, with keys in every partition, under every
    // execution shape.
    var prng: Prng = .init(5);
    const payments = try random_payments(&prng, 100_000, 20_000, 1);
    defer gpa.free(payments);
    for (payments) |*payment| payment.amount = 1;
    const want = try count_sums(payments);
    defer gpa.free(want);
    const planned = try explore_sums(@as([]const Payment, payments), seeded);
    defer planned.deinit();
    try planned.expect_sums(want);
}

/// Which candidates a selection accepted, and the accounts the accepted ones leave.
pub fn Selected(comptime A: type) type {
    return struct {
        const Self = @This();

        accepted: []bool,
        settled: Ledger(A),

        pub fn deinit(self: *Self) void {
            gpa.free(self.accepted);
            self.settled.deinit();
        }
    };
}

/// Selects `list` in rounds of `round` transfers against `ledger` (each round touches its
/// candidates' keys, reads the new ones, and applies the round), then settles the accepted
/// candidates into a copy of the ledger.
pub fn select_all(
    strategy: anytype,
    ledger: anytype,
    list: anytype,
    round: usize,
) !Selected(Account(@TypeOf(list))) {
    const A = Account(@TypeOf(list));
    var selection = transfers.Selection(Address, A).init(1);
    defer selection.deinit(gpa);
    const accepted = try gpa.alloc(bool, list.len);
    errdefer gpa.free(accepted);
    var start: usize = 0;
    while (start < list.len) : (start += @max(round, 1)) {
        const end = @min(start + @max(round, 1), list.len);
        const touched = try selection.touch(gpa, list[start..end]);
        const reads = try gpa.alloc(?A, touched.end - touched.start);
        defer gpa.free(reads);
        for (reads, selection.keys()[touched.start..touched.end]) |*read, k| read.* = ledger.get(k);
        try selection.register(gpa, reads);
        try selection.apply(gpa, list[start..end], accepted[start..end]);
    }
    const slots = try selection.settle(gpa, strategy);
    defer gpa.free(slots);
    var settled = try ledger.clone();
    errdefer settled.deinit();
    for (selection.keys(), slots) |k, slot| try settled.apply(k, slot);
    return .{ .accepted = accepted, .settled = settled };
}

/// `select_all` under every execution shape.
fn SelectAll(comptime List: type) type {
    const A = Account(List);
    return struct {
        ledger: *const Ledger(A),
        list: List,
        round: usize,

        pub fn run(op: @This(), explorer: Explorer) !Selected(A) {
            return select_all(explorer, op.ledger, op.list, op.round);
        }

        pub fn eql(_: @This(), a: Selected(A), b: Selected(A)) bool {
            return std.mem.eql(bool, a.accepted, b.accepted) and
                ledgers_eql(A, &a.settled, &b.settled);
        }

        pub fn discard(_: @This(), value: Selected(A)) void {
            var owned = value;
            owned.deinit();
        }
    };
}

pub fn explore_select(
    ledger: anytype,
    list: anytype,
    round: usize,
) !Selected(Account(@TypeOf(list))) {
    const Op = SelectAll(@TypeOf(list));
    return explore(gpa, testing.io, Op{ .ledger = ledger, .list = list, .round = round });
}

/// The candidates `accepted` marks, in order.
pub fn body(comptime T: type, candidates: []const T, accepted: []const bool) ![]T {
    var result: std.ArrayList(T) = .empty;
    errdefer result.deinit(gpa);
    for (candidates, accepted) |candidate, keep| if (keep) try result.append(gpa, candidate);
    return result.toOwnedSlice(gpa);
}

/// Selects `candidates` against `ledger` in rounds of several sizes, checking that some but not
/// all are accepted and that the accepted ones settle as a batch to the accounts the selection
/// leaves.
pub fn expect_selection_matches_plan(ledger: anytype, candidates: anytype) !void {
    const T = @typeInfo(@TypeOf(candidates)).pointer.child;
    for ([_]usize{ 1, 7, 500, 2_000 }) |round| {
        var selected = try explore_select(ledger, candidates, round);
        defer selected.deinit();
        try testing.expect(std.mem.indexOfScalar(bool, selected.accepted, true) != null);
        try testing.expect(std.mem.indexOfScalar(bool, selected.accepted, false) != null);
        const accepted = try body(T, candidates, selected.accepted);
        defer gpa.free(accepted);
        var want = try expected(ledger, @as([]const T, accepted));
        defer want.deinit();
        try (try want.ledger()).expect_equal(&selected.settled);
        var got = try settle_all(parallel.sequential, ledger, @as([]const T, accepted));
        defer got.deinit();
        try (try got.ledger()).expect_equal(&selected.settled);
    }
}

test "transfers: selection drops candidates that do not fit in order" {
    var ledger = try Ledger(Balance).init(&.{
        .{ .key = key(1), .account = bal(10) },
        .{ .key = key(5), .account = bal(max) },
        .{ .key = key(6), .account = bal(1) },
        .{ .key = key(7), .account = bal(0) },
    });
    defer ledger.deinit();
    const candidates = [_]Payment{
        // Fits: key 1 has 10.
        pay(1, 2, 6),
        // Dropped: key 1 has only 4 left to spend.
        pay(1, 3, 5),
        // Dropped: key 2 starts at zero, since the credit it received cannot fund it.
        pay(2, 1, 6),
        // Fits: a self-payment needs the amount at the start and nets to nothing.
        pay(1, 1, 4),
        // Fits: a zero credit cannot overflow key 5.
        pay(1, 5, 0),
        // Dropped: key 2 starts at zero, so it cannot pay key 5.
        pay(2, 5, 1),
        // Dropped: the credit overflows key 5.
        pay(6, 5, 1),
        // Fits: a zero payment always does, and a held zero it touches is left alone.
        pay(7, 4, 0),
    };
    var selected = try explore_select(&ledger, @as([]const Payment, &candidates), 3);
    defer selected.deinit();
    try testing.expectEqualSlices(
        bool,
        &.{ true, false, false, true, true, false, false, true },
        selected.accepted,
    );
    var want = try Ledger(Balance).init(&.{
        .{ .key = key(1), .account = bal(4) },
        .{ .key = key(2), .account = bal(6) },
        .{ .key = key(5), .account = bal(max) },
        .{ .key = key(6), .account = bal(1) },
        .{ .key = key(7), .account = bal(0) },
    });
    defer want.deinit();
    try want.expect_equal(&selected.settled);
}

/// Touches, registers, and applies `candidates` as one round, writing whether each was
/// accepted, and returns the settled slots.
fn select_round(
    selection: *transfers.Selection(Address, Balance),
    candidates: []const Multi,
    reads: []const ?Balance,
    touched_count: usize,
    accepted: []bool,
) ![]transfers.Slot(Balance) {
    const touched = try selection.touch(gpa, candidates);
    try testing.expectEqual(parallel.Range.init(0, touched_count), touched);
    try selection.register(gpa, reads);
    try selection.apply(gpa, candidates, accepted);
    return selection.settle(gpa, parallel.sequential);
}

test "transfers: selection undoes a transfer whose later change does not fit" {
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    const candidates = [_]Multi{
        .{ .items = &.{
            .{ .key = key(1), .change = .crediting(5) },
            .{ .key = key(1), .change = .debiting(11) },
        } },
        .{ .items = &.{.{ .key = key(1), .change = .debiting(10) }} },
    };
    // The first candidate's debit does not fit, so its credit is undone. The second spends the
    // whole starting balance, and with no credit left behind, the key is deleted.
    var accepted: [2]bool = undefined;
    const slots = try select_round(&selection, &candidates, &.{bal(10)}, 1, &accepted);
    defer gpa.free(slots);
    try testing.expectEqualSlices(bool, &.{ false, true }, &accepted);
    try testing.expectEqualSlices(transfers.Slot(Balance), &.{.delete}, slots);
}

test "transfers: selection nets a transfer's changes to one key" {
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    const candidates = [_]Multi{
        .{ .items = &.{
            .{ .key = key(1), .change = .crediting(10) },
            .{ .key = key(1), .change = .debiting(10) },
        } },
        .{ .items = &.{
            .{ .key = key(1), .change = .debiting(10) },
            .{ .key = key(1), .change = .crediting(10) },
        } },
        .{ .items = &.{
            .{ .key = key(1), .change = .crediting(10) },
            .{ .key = key(1), .change = .debiting(4) },
        } },
    };
    const start = bal(max - 5);
    // A credit that would overflow the key on its own is accepted with the same transfer's
    // debit of the key, in either order, since a batch adds a key's credits after subtracting
    // all its debits. The third transfer would still leave the key past `u64::MAX`.
    var accepted: [3]bool = undefined;
    const slots = try select_round(&selection, &candidates, &.{start}, 1, &accepted);
    defer gpa.free(slots);
    try testing.expectEqualSlices(bool, &.{ true, true, false }, &accepted);
    try testing.expectEqualSlices(transfers.Slot(Balance), &.{.keep}, slots);

    // The plan agrees. The first two candidates settle as a batch, and the third cannot join.
    var ledger = try Ledger(Balance).init(&.{.{ .key = key(1), .account = start }});
    defer ledger.deinit();
    var two = try settle_all(parallel.sequential, &ledger, @as([]const Multi, candidates[0..2]));
    defer two.deinit();
    try testing.expect(two == .settled);
    const three = try settle_all(parallel.sequential, &ledger, @as([]const Multi, &candidates));
    try three.expect_rejected(.overflow, key(1));
}

test "transfers: selection undoes applied changes when a sum overflows" {
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    const candidates = [_]Multi{
        .{ .items = &.{.{ .key = key(1), .change = .crediting(max) }} },
        .{ .items = &.{
            .{ .key = key(2), .change = .crediting(5) },
            .{ .key = key(1), .change = .crediting(1) },
            .{ .key = key(3), .change = .crediting(7) },
        } },
    };
    // The second candidate's credit to key 1 would push its credit sum past `u64::MAX`, so the
    // credit to key 2 applied before it is undone and the credit to key 3 after it is never
    // applied. Key 1 keeps exactly the first candidate's credit.
    var accepted: [2]bool = undefined;
    const slots = try select_round(&selection, &candidates, &.{ null, null, null }, 3, &accepted);
    defer gpa.free(slots);
    try testing.expectEqualSlices(bool, &.{ true, false }, &accepted);
    try testing.expectEqualSlices(
        transfers.Slot(Balance),
        &.{ .{ .put = bal(max) }, .keep, .keep },
        slots,
    );
}

test "transfers: selection settles as the plan of the accepted candidates" {
    // Random candidates with amounts large enough that many do not fit.
    var prng: Prng = .init(17);
    const keys: u64 = 64;
    var ledger: Ledger(Balance) = .{};
    defer ledger.deinit();
    for (0..keys) |n| {
        if (prng.random().float(f64) < 0.7) {
            try ledger.put(key(n), bal(prng.random().uintLessThan(u64, 50)));
        }
    }
    const candidates = try random_payments(&prng, 2_000, keys, 20);
    defer gpa.free(candidates);
    try expect_selection_matches_plan(&ledger, @as([]const Payment, candidates));
}
