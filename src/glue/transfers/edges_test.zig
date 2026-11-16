//! Tests of `transfers` edge cases (commonware `glue/src/transfers/tests.rs`, from
//! `selection_leaves_zero_only_keys_unstaged`): empty and repeated changes, cached indices,
//! seeded key orders, bucketing, random batches against their flat entries, and wide amounts.

const std = @import("std");
const testing = std.testing;
const parallel = @import("parallel");
const transfers = @import("mod.zig");
const support = @import("transfers_test.zig");
const nonced_support = @import("nonced_test.zig");

const gpa = testing.allocator;
const explore = parallel.mocks.explore;
const Explorer = parallel.mocks.Explorer;
const Address = support.Address;
const Balance = support.Balance;
const Payment = support.PaymentOf(Balance);
const Multi = support.MultiOf(Balance);
const Nonced = nonced_support.Nonced;
const NoncedMulti = nonced_support.NoncedMulti;
const Prng = std.Random.DefaultPrng;
const key = support.key;
const max = support.max;
const pay = support.pay;
const bal = support.bal;
const nonced = nonced_support.nonced;
const held = nonced_support.held;
const default_balance = nonced_support.default_balance;

test "transfers: selection leaves zero only keys unstaged" {
    // A zero payment moves nothing, so neither of its keys is touched or staged, and applying
    // it accepts it without changing any account.
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    const list = [_]Payment{pay(1, 2, 0)};
    const touched = try selection.touch(gpa, @as([]const Payment, &list));
    try testing.expectEqual(parallel.Range.init(0, 0), touched);
    try selection.register(gpa, &.{});
    var accepted: [1]bool = undefined;
    try selection.apply(gpa, @as([]const Payment, &list), &accepted);
    try testing.expect(accepted[0]);
    const slots = try selection.settle(gpa, parallel.sequential);
    defer gpa.free(slots);
    try testing.expectEqual(0, slots.len);
}

test "transfers: selection applies transfers other than the last touched" {
    // The touched round caches the index of each of its changes, in order.
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    const touched_list = [_]Payment{ pay(1, 2, 2), pay(3, 4, 3) };
    const touched = try selection.touch(gpa, @as([]const Payment, &touched_list));
    try testing.expectEqual(parallel.Range.init(0, 4), touched);
    try selection.register(gpa, &.{ bal(10), bal(10), bal(10), bal(10) });

    // Different transfers over the same keys match the cache only in places and look up the
    // rest, reaching the same accounts as settling them as a batch.
    const applied = [_]Payment{ pay(4, 1, 3), pay(2, 3, 2), pay(1, 2, 1) };
    var accepted: [3]bool = undefined;
    try selection.apply(gpa, @as([]const Payment, &applied), &accepted);
    try testing.expectEqualSlices(bool, &.{ true, true, true }, &accepted);
    const slots = try selection.settle(gpa, parallel.sequential);
    defer gpa.free(slots);
    try testing.expectEqualSlices(transfers.Slot(Balance), &.{
        .{ .put = bal(12) }, .{ .put = bal(9) }, .{ .put = bal(12) }, .{ .put = bal(7) },
    }, slots);
}

/// Plans `list` twice with the same seed under one shape and checks the key orders agree.
const SamePlanOrder = struct {
    list: []const Payment,

    pub fn run(op: SamePlanOrder, explorer: Explorer) !void {
        var rejection: support.Rejection = undefined;
        const Plan = transfers.Plan(Address, Balance);
        var first = try Plan.init(gpa, op.list, 42, explorer, &rejection);
        defer first.deinit(gpa);
        var second = try Plan.init(gpa, op.list, 42, explorer, &rejection);
        defer second.deinit(gpa);
        try testing.expectEqualSlices(Address, first.keys, second.keys);
    }
};

test "transfers: seeded plans and selections reproduce their key order" {
    // Enough transfers for every execution shape to split the hashing.
    const count = 3 * transfers.hash_batch_min;
    const list = try gpa.alloc(Payment, count);
    defer gpa.free(list);
    for (list, 0..) |*payment, n| payment.* = pay(n % 257, (n + 1) % 257, 1);

    // Two plans with the same seed order their keys alike under the same shape. Different
    // shapes may order them differently, so each shape compares only its own plans.
    try explore(gpa, testing.io, SamePlanOrder{ .list = list });

    // Two selections with the same seed touch the same keys in the same order, round by round.
    var first = transfers.Selection(Address, Balance).init(42);
    defer first.deinit(gpa);
    var second = transfers.Selection(Address, Balance).init(42);
    defer second.deinit(gpa);
    var start: usize = 0;
    while (start < count) : (start += 17) {
        const round: []const Payment = list[start..@min(start + 17, count)];
        try testing.expectEqual(try first.touch(gpa, round), try second.touch(gpa, round));
    }
    try testing.expectEqualSlices(Address, first.keys(), second.keys());
}

/// One key's plan entry: its sums and the nonces of its effects in order.
const KeyNonces = struct { key: Address, debit: u64, credit: u64, nonces: []u64 };

fn free_key_nonces(entries: []KeyNonces) void {
    for (entries) |entry| gpa.free(entry.nonces);
    gpa.free(entries);
}

/// Plans `list` and lists each key's sums and nonces, sorted by key.
const PlanNonces = struct {
    list: []const NoncedMulti,

    pub fn run(op: PlanNonces, explorer: Explorer) ![]KeyNonces {
        var rejection: support.Rejection = undefined;
        var plan = try transfers.Plan(Address, Nonced).init(gpa, op.list, 3, explorer, &rejection);
        defer plan.deinit(gpa);
        var entries: std.ArrayList(KeyNonces) = .empty;
        errdefer {
            for (entries.items) |entry| gpa.free(entry.nonces);
            entries.deinit(gpa);
        }
        for (plan.keys, plan.debits, plan.credits, 0..) |k, debit, credit, index| {
            const effects = plan.effects_of(index);
            const nonces = try gpa.alloc(u64, effects.len);
            for (nonces, effects) |*nonce, effect| nonce.* = effect.nonce;
            try entries.append(gpa, .{
                .key = k,
                .debit = debit,
                .credit = credit,
                .nonces = nonces,
            });
        }
        std.mem.sort(KeyNonces, entries.items, {}, key_nonces_less);
        return entries.toOwnedSlice(gpa);
    }

    fn key_nonces_less(_: void, a: KeyNonces, b: KeyNonces) bool {
        return a.key.order(b.key) == .lt;
    }

    pub fn eql(_: PlanNonces, a: []KeyNonces, b: []KeyNonces) bool {
        if (a.len != b.len) return false;
        for (a, b) |x, y| {
            if (!x.key.eql(y.key) or x.debit != y.debit or x.credit != y.credit) return false;
            if (!std.mem.eql(u64, x.nonces, y.nonces)) return false;
        }
        return true;
    }

    pub fn discard(_: PlanNonces, value: []KeyNonces) void {
        free_key_nonces(value);
    }
};

test "transfers: plan keeps sums and effect order with and without buckets" {
    // Each of 32 keys consumes its nonces in order, one per transfer, debits 1, and credits the
    // next key 2. One hash batch of transfers is hashed on the calling thread and bucketed by
    // partition only when a shape splits its deduplication, while three are hashed in batches
    // and always bucketed.
    for ([_]usize{ transfers.hash_batch_min, 3 * transfers.hash_batch_min }) |len| {
        const items = try gpa.alloc(NoncedMulti.Item, 3 * len);
        defer gpa.free(items);
        const list = try gpa.alloc(NoncedMulti, len);
        defer gpa.free(list);
        for (list, 0..) |*transfer, n| {
            const changes = items[3 * n ..][0..3];
            changes[0] = .{ .key = key(n % 32), .change = .applying(.{ .nonce = n / 32 }) };
            changes[1] = .{ .key = key(n % 32), .change = .debiting(1) };
            changes[2] = .{ .key = key((n + 1) % 32), .change = .crediting(2) };
            transfer.* = .{ .items = changes };
        }
        // Every shape gives each key the same sums and its nonces in transfer order.
        const entries = try explore(gpa, testing.io, PlanNonces{ .list = list });
        defer free_key_nonces(entries);
        const rounds = len / 32;
        try testing.expectEqual(32, entries.len);
        for (entries, 0..) |entry, n| {
            try testing.expect(entry.key.eql(key(n)));
            try testing.expectEqual(rounds, entry.debit);
            try testing.expectEqual(2 * rounds, entry.credit);
            for (entry.nonces, 0..) |nonce, index| try testing.expectEqual(index, nonce);
            try testing.expectEqual(rounds, entry.nonces.len);
        }
    }
}

test "transfers: estimated changes samples the first transfer" {
    // Payments have two changes each, and no transfers expect none.
    const payments = [_]Payment{ pay(1, 2, 1), pay(2, 3, 1) };
    try testing.expectEqual(4, transfers.estimated_changes(@as([]const Payment, &payments)));
    try testing.expectEqual(0, transfers.estimated_changes(@as([]const Payment, &.{})));

    // A first transfer without changes still reserves one per transfer, and one with many
    // changes reserves at most the sampled maximum per transfer.
    var list: [10]Multi = @splat(.{ .items = &.{} });
    try testing.expectEqual(10, transfers.estimated_changes(@as([]const Multi, &list)));
    const many: [1_000]Multi.Item = @splat(.{ .key = key(1), .change = .crediting(1) });
    list[0] = .{ .items = &many };
    const sampled = 10 * transfers.sampled_changes_max;
    try testing.expectEqual(sampled, transfers.estimated_changes(@as([]const Multi, &list)));
}

/// A random batch of transfers between nonced accounts, owning its changes.
const Batch = struct {
    items: []NoncedMulti.Item,
    list: []NoncedMulti,

    fn deinit(batch: Batch) void {
        gpa.free(batch.items);
        gpa.free(batch.list);
    }
};

/// An amount: often zero, otherwise small, and with `edges` sometimes at the edge of `u64`.
fn random_amount(random: std.Random, edges: bool) u64 {
    const roll = random.uintLessThan(u64, 200);
    if (edges and roll == 0) return max;
    if (edges and roll == 1) return max - random.uintLessThan(u64, 2 * default_balance);
    if (roll < 62) return 0;
    return random.uintLessThan(u64, default_balance / 4);
}

fn random_effect(random: std.Random, last: u64, nonces: ?[]u64) ?Nonced.Effect {
    const edges = nonces == null;
    const roll = random.uintLessThan(u64, 100);
    if (roll < 10) {
        const list = nonces orelse return .{ .nonce = random.uintLessThan(u64, 32) };
        list[last] += 1;
        return .{ .nonce = list[last] - 1 };
    }
    if (edges and roll < 12) return .{ .floor = random.uintLessThan(u64, 2 * default_balance) };
    if (edges and roll == 12) return .{ .refuse_after_nonce = random.uintLessThan(u64, 3) };
    if (roll >= 12 and roll < 15) return .burn;
    return null;
}

/// Returns `count` transfers between nonced accounts below key `keys`, with one to four changes
/// each. Changes often name the key of the change before them or both debit and credit one key,
/// and include empty changes. With `nonces`, every effect is one an account accepts and nonces
/// are taken from it in order per key, so the batch settles from accounts with large balances.
/// Without it, some effects are refused and some amounts sit at the edge of `u64`.
fn random_batch(random: std.Random, keys: u64, count: usize, nonces: ?[]u64) !Batch {
    const items = try gpa.alloc(NoncedMulti.Item, 4 * count);
    errdefer gpa.free(items);
    const list = try gpa.alloc(NoncedMulti, count);
    var used: usize = 0;
    for (list) |*transfer| {
        var last = random.uintLessThan(u64, keys);
        const changes = 1 + random.uintLessThan(usize, 4);
        for (items[used..][0..changes]) |*item| {
            if (random.float(f64) < 0.6) last = random.uintLessThan(u64, keys);
            const effect = random_effect(random, last, nonces);
            const debit = random_amount(random, nonces == null);
            const credit = random_amount(random, nonces == null);
            item.* = .{
                .key = key(last),
                .change = .{ .debit = debit, .credit = credit, .effect = effect },
            };
        }
        transfer.* = .{ .items = items[used..][0..changes] };
        used += changes;
    }
    return .{ .items = items, .list = list };
}

/// Whether two outcomes agree on settling: both reject, or both leave the same accounts.
fn same_ok(a: *const support.Outcome(Nonced), b: *const support.Outcome(Nonced)) bool {
    if (a.* == .rejected or b.* == .rejected) return a.* == .rejected and b.* == .rejected;
    return support.ledgers_eql(Nonced, &a.settled, &b.settled);
}

fn non_empty_changes(list: []const NoncedMulti) usize {
    var count: usize = 0;
    for (list) |transfer| {
        for (transfer.items) |item| count += @intFromBool(!item.change.is_empty());
    }
    return count;
}

/// A few keys, some absent, some starting near the max, and some with consumed nonces.
fn random_accounts(random: std.Random, keys: u64) !nonced_support.Ledger {
    var ledger: nonced_support.Ledger = .{};
    errdefer ledger.deinit();
    for (0..keys) |n| {
        if (random.float(f64) < 0.3) continue;
        const value = if (random.float(f64) < 0.2)
            max - random.uintLessThan(u64, default_balance)
        else
            random.uintLessThan(u64, 2 * default_balance);
        try ledger.put(key(n), nonced(value, random.uintLessThan(u64, 2), 0));
    }
    return ledger;
}

/// Every small batch settles under every shape exactly when its flat entries do, and to the
/// same accounts. Returns how many settled.
fn check_small_batches(random: std.Random, ledger: *const nonced_support.Ledger) !usize {
    var settled: usize = 0;
    for (0..40) |_| {
        const batch = try random_batch(random, 6, 1 + random.uintLessThan(usize, 5), null);
        defer batch.deinit();
        const list: []const NoncedMulti = batch.list;
        var want = try support.expected(ledger, list);
        defer want.deinit();
        settled += @intFromBool(want == .settled);
        var got = try support.explore_settle(ledger, list);
        defer got.deinit();
        try testing.expect(same_ok(&got, &want));
    }
    return settled;
}

/// A batch with more touches than a plan deduplicates on the calling thread settles the same
/// way under every shape, and a selection accepts every candidate in it.
fn check_large_batch(random: std.Random, rich: *const nonced_support.Ledger) !void {
    var nonces: [256]u64 = @splat(0);
    const batch = try random_batch(random, 256, 1_200, &nonces);
    defer batch.deinit();
    const list: []const NoncedMulti = batch.list;
    try testing.expect(non_empty_changes(list) > transfers.split_touches_min);
    var want = try support.expected(rich, list);
    defer want.deinit();
    try testing.expect(want == .settled);
    var got = try support.explore_settle(rich, list);
    defer got.deinit();
    try testing.expect(got.eql(&want));
    var selected = try support.explore_select(rich, list, 300);
    defer selected.deinit();
    try testing.expect(std.mem.indexOfScalar(bool, selected.accepted, false) == null);
    try want.settled.expect_equal(&selected.settled);
}

/// A selection accepts exactly the candidates whose flat entries settle with those accepted
/// before them, in rounds of every size, and leaves the accounts that body settles to.
fn check_selection(random: std.Random, ledger: *const nonced_support.Ledger) !void {
    const batch = try random_batch(random, 6, 120, null);
    defer batch.deinit();
    var body: std.ArrayList(NoncedMulti) = .empty;
    defer body.deinit(gpa);
    var want: [120]bool = undefined;
    for (batch.list, &want) |candidate, *fits| {
        try body.append(gpa, candidate);
        var outcome = try support.expected(ledger, @as([]const NoncedMulti, body.items));
        defer outcome.deinit();
        fits.* = outcome == .settled;
        if (!fits.*) _ = body.pop();
    }
    try testing.expect(std.mem.indexOfScalar(bool, &want, true) != null);
    try testing.expect(std.mem.indexOfScalar(bool, &want, false) != null);
    var reference = try support.expected(ledger, @as([]const NoncedMulti, body.items));
    defer reference.deinit();
    for ([_]usize{ 1, 7, 120 }) |round| {
        const list: []const NoncedMulti = batch.list;
        var selected = try support.explore_select(ledger, list, round);
        defer selected.deinit();
        try testing.expectEqualSlices(bool, &want, selected.accepted);
        try (try reference.ledger()).expect_equal(&selected.settled);
    }
}

test "transfers: changes settle and select as their flat entries" {
    // Large batches run over enough keys to spread across partitions, from rich accounts.
    var rich: nonced_support.Ledger = .{};
    defer rich.deinit();
    for (0..256) |n| try rich.put(key(n), nonced(1 << 40, 0, 0));
    var settled: usize = 0;
    var small: usize = 0;
    for (0..16) |seed| {
        var prng: Prng = .init(seed);
        const random = prng.random();
        var ledger = try random_accounts(random, 6);
        defer ledger.deinit();
        settled += try check_small_batches(random, &ledger);
        small += 40;
        try check_large_batch(random, &rich);
        try check_selection(random, &ledger);
    }
    // Most small batches settle, so the comparison covers settled accounts and not only
    // rejections.
    try testing.expect(2 * settled >= small);
}

test "transfers: a key named twice settles as one change" {
    // Key 1 is named twice by one transfer and once by another with the same debit, credit,
    // and effect.
    var ledger = try nonced_support.Ledger.init(&.{held(1, nonced(10, 0, 0))});
    defer ledger.deinit();
    const NoncedChange = transfers.Change(Nonced);
    const twice = [_]NoncedMulti{.{ .items = &.{
        .{ .key = key(1), .change = NoncedChange.debiting(3).with_effect(.{ .nonce = 0 }) },
        .{ .key = key(1), .change = .crediting(4) },
    } }};
    const once = [_]NoncedMulti{.{ .items = &.{
        .{ .key = key(1), .change = .{ .debit = 3, .credit = 4, .effect = .{ .nonce = 0 } } },
    } }};
    // Both plan and select to the same account.
    var want = try nonced_support.Ledger.init(&.{held(1, nonced(11, 1, 0))});
    defer want.deinit();
    for ([_][]const NoncedMulti{ &twice, &once }) |list| {
        var settled = try support.explore_settle(&ledger, list);
        defer settled.deinit();
        try (try settled.ledger()).expect_equal(&want);
        var selected = try support.explore_select(&ledger, list, 1);
        defer selected.deinit();
        try testing.expectEqualSlices(bool, &.{true}, selected.accepted);
        try want.expect_equal(&selected.settled);
    }
}

test "transfers: a self transfer change debits the starting balance" {
    // Key 1 pays itself 6 in one change and then debits 5, which together pass its balance of
    // 10, since the credit cannot fund the debit.
    var ledger = try support.Ledger(Balance).init(&.{.{ .key = key(1), .account = bal(10) }});
    defer ledger.deinit();
    const candidates = [_]Multi{
        .{ .items = &.{.{ .key = key(1), .change = .{ .debit = 6, .credit = 6 } }} },
        .{ .items = &.{.{ .key = key(1), .change = .debiting(5) }} },
    };
    const list: []const Multi = &candidates;
    const rejected = try support.explore_settle(&ledger, list);
    try rejected.expect_rejected(.insufficient, key(1));

    // A selection accepts the self-transfer, which leaves the key as it was, and drops the
    // debit.
    var selected = try support.explore_select(&ledger, list, 2);
    defer selected.deinit();
    try testing.expectEqualSlices(bool, &.{ true, false }, selected.accepted);
    try ledger.expect_equal(&selected.settled);
}

/// Whether the plan of `list` is empty under one shape.
const PlansNothing = struct {
    list: []const Multi,

    pub fn run(op: PlansNothing, explorer: Explorer) !bool {
        var rejection: support.Rejection = undefined;
        var plan = try transfers.Plan(Address, Balance).init(gpa, op.list, 0, explorer, &rejection);
        defer plan.deinit(gpa);
        return plan.is_empty();
    }
};

test "transfers: an empty change is left out" {
    // Neither key is touched, so nothing is planned or staged and the transfer is accepted.
    const candidates = [_]Multi{.{ .items = &.{
        .{ .key = key(1), .change = .{} },
        .{ .key = key(2), .change = .debiting(0) },
    } }};
    const list: []const Multi = &candidates;
    try testing.expect(try explore(gpa, testing.io, PlansNothing{ .list = list }));
    var selection = transfers.Selection(Address, Balance).init(0);
    defer selection.deinit(gpa);
    try testing.expectEqual(parallel.Range.init(0, 0), try selection.touch(gpa, list));
    try selection.register(gpa, &.{});
    var accepted: [1]bool = undefined;
    try selection.apply(gpa, list, &accepted);
    try testing.expect(accepted[0]);
    const slots = try selection.settle(gpa, parallel.sequential);
    defer gpa.free(slots);
    try testing.expectEqual(0, slots.len);
}

test "transfers: an effect only change touches its key" {
    // A change with only an effect plans its key with no debit or credit and consumes the
    // nonce of the default account it reads.
    const candidates = [_]NoncedMulti{.{ .items = &.{
        .{ .key = key(1), .change = .applying(.{ .nonce = 0 }) },
    } }};
    var rejection: support.Rejection = undefined;
    const list: []const NoncedMulti = &candidates;
    const Plan = transfers.Plan(Address, Nonced);
    var plan = try Plan.init(gpa, list, 0, parallel.sequential, &rejection);
    defer plan.deinit(gpa);
    try testing.expectEqualSlices(Address, &.{key(1)}, plan.keys);
    try testing.expectEqual(0, plan.debits[0]);
    try testing.expectEqual(0, plan.credits[0]);
    const slots = try plan.settle(gpa, &.{null}, parallel.sequential, &rejection);
    defer gpa.free(slots);
    try testing.expectEqualSlices(
        transfers.Slot(Nonced),
        &.{.{ .put = nonced(default_balance, 1, 0) }},
        slots,
    );
}

/// An account that holds only a 256-bit balance.
const Wide = struct {
    value: u256,

    pub const Amount = u256;
    pub const Effect = enum {};
    pub const default: Wide = .{ .value = 0 };

    pub fn balance(self: *const Wide) u256 {
        return self.value;
    }

    pub fn set_balance(self: *Wide, value: u256) void {
        self.value = value;
    }

    pub fn apply(_: *Wide, effect: Effect) bool {
        switch (effect) {}
    }
};

const WidePayment = support.PaymentOf(Wide);

fn pay_wide(from: u64, to: u64, amount: u256) WidePayment {
    return .{ .from = key(from), .to = key(to), .amount = amount };
}

fn wide(n: u64, value: u256) support.Held(Wide) {
    return .{ .key = key(n), .account = .{ .value = value } };
}

test "transfers: amounts wider than a u64 settle and select" {
    // Key 1 holds more than any `u64`, and key 2 holds the largest amount.
    const half: u256 = 1 << 199;
    const whole: u256 = 1 << 200;
    const top = std.math.maxInt(u256);
    var ledger = try support.Ledger(Wide).init(&.{ wide(1, whole), wide(2, top) });
    defer ledger.deinit();

    // A batch is rejected when a key's debits pass its balance by one, or when a credit takes a
    // balance past the largest amount. Debits or credits that sum past the largest amount are
    // rejected when planned.
    const rejections = [_]struct { []const WidePayment, transfers.Reason, u64 }{
        .{ &.{ pay_wide(1, 3, whole), pay_wide(1, 4, 1) }, .insufficient, 1 },
        .{ &.{pay_wide(1, 2, 1)}, .overflow, 2 },
        .{ &.{ pay_wide(2, 3, top), pay_wide(2, 4, 1) }, .insufficient, 2 },
        .{ &.{ pay_wide(2, 3, top), pay_wide(1, 3, 1) }, .overflow, 3 },
    };
    for (rejections) |case| {
        const list, const reason, const offender = case;
        const outcome = try support.explore_settle(&ledger, list);
        try outcome.expect_rejected(reason, key(offender));
    }

    const candidates = [_]WidePayment{
        // Fits: key 1 holds twice the amount.
        pay_wide(1, 3, half),
        // Dropped: key 1 has only half its balance left to spend.
        pay_wide(1, 4, whole),
        // Dropped: the credit takes key 2 past the largest amount.
        pay_wide(1, 2, 1),
        // Fits: key 2 spends the largest amount, and key 5 starts at zero.
        pay_wide(2, 5, top),
        // Dropped: key 5's credits would sum past the largest amount, so the debit already
        // applied to key 1 is undone.
        pay_wide(1, 5, 1),
        // Fits: key 1 spends the other half of its balance.
        pay_wide(1, 3, half),
    };
    const list: []const WidePayment = &candidates;
    var selected = try support.explore_select(&ledger, list, 2);
    defer selected.deinit();
    const want_accepted = [_]bool{ true, false, false, true, false, true };
    try testing.expectEqualSlices(bool, &want_accepted, selected.accepted);

    // Keys 1 and 2 are spent to zero and deleted, and keys 3 and 5 are created.
    var want = try support.Ledger(Wide).init(&.{ wide(3, whole), wide(5, top) });
    defer want.deinit();
    try want.expect_equal(&selected.settled);

    // The accepted candidates settle as a batch to the same accounts, and so does the
    // sequential reference.
    const body = try support.body(WidePayment, list, selected.accepted);
    defer gpa.free(body);
    var reference = try support.expected(&ledger, @as([]const WidePayment, body));
    defer reference.deinit();
    try (try reference.ledger()).expect_equal(&want);
    var settled = try support.explore_settle(&ledger, @as([]const WidePayment, body));
    defer settled.deinit();
    try (try settled.ledger()).expect_equal(&want);
}
