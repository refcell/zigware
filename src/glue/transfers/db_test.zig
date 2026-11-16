//! Transfers settled and selected through qmdb `any` staged batches, ported from commonware
//! `glue/src/transfers/tests.rs` (`execute`, `select`, and the tests over `AnyUnordered` and
//! `NoncedAny`).
//!
//! The execute tests run on unordered and ordered `any` and `current` databases.
//! `NoncedAny` (an unordered variable database in commonware) runs on the fixed layout, which
//! stores the same accounts.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");

const transfers = @import("mod.zig");
const support = @import("transfers_test.zig");
const nonced_support = @import("nonced_test.zig");
const stateful_db = @import("../stateful/db/mod.zig");

const gpa = testing.allocator;
const qmdb = storage.qmdb;
const metrics = runtime.telemetry.metrics;
const rng_mod = utils.rng;
const sequential = parallel.sequential;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Address = support.Address;
const Rejection = support.Rejection;
const Balance = support.Balance;
const Nonced = nonced_support.Nonced;
const Payment = support.PaymentOf(Balance);
const Multi = support.MultiOf(Balance);
const Signed = nonced_support.Signed;
const key = support.key;
const pay = support.pay;
const bal = support.bal;
const signed = nonced_support.signed;
const nonced = nonced_support.nonced;
const default_balance = nonced_support.default_balance;

/// The parts of a fixed database of `A` accounts under `Address` keys with a `TwoCap` index,
/// unordered or `ordered`.
fn Parts(comptime A: type, comptime ordered: bool) type {
    const Encoding = qmdb.value.Fixed(A);
    const operation = qmdb.any.operation;
    const translator = storage.translator.TwoCap;
    return struct {
        const Family = storage.mmr.Family;
        const Operation = if (ordered)
            operation.Ordered(Family, Address, Encoding)
        else
            operation.Unordered(Family, Address, Encoding);
        const Journal = storage.journal.contiguous.fixed.Journal(Operation);
        const Update = if (ordered)
            operation.update.Ordered(Address, Encoding)
        else
            operation.update.Unordered(Address, Encoding);
        const Index = if (ordered)
            storage.index.ordered.Index(translator, u64)
        else
            storage.index.unordered.Index(translator, u64);
    };
}

/// A fixed `any` database: unordered (commonware's `AnyUnordered` and `NoncedAny`) or
/// `ordered` (`AnyOrdered`).
fn Any(comptime A: type, comptime ordered: bool) type {
    const P = Parts(A, ordered);
    return qmdb.any.Db(P.Family, P.Update, P.Journal, P.Index, Sha256, 64);
}

fn AnyUnordered(comptime A: type) type {
    return Any(A, false);
}

/// A fixed `current` database with 32-byte bitmap chunks (commonware's `CurrentUnordered`
/// and `CurrentOrdered`).
fn Current(comptime A: type, comptime ordered: bool) type {
    const P = Parts(A, ordered);
    return qmdb.current.Db(P.Family, P.Update, P.Journal, P.Index, Sha256, 32);
}

/// commonware's `NoncedCurrent`: nonced accounts in an ordered fixed `current` database.
const NoncedCurrent = Current(Nonced, true);

/// Storage, a page cache, and metrics for the databases one test opens.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(harness: *Harness) void {
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    /// Opens a database of `D` in partitions named after `suffix` (commonware's `any_config`).
    fn open(harness: *Harness, comptime D: type, comptime suffix: []const u8) !D {
        const AnyCfg = if (@hasDecl(D, "Any")) D.Any.Cfg else D.Cfg;
        const base: AnyCfg = .{
            .merkle = .{
                .journal_partition = "transfers-journal-" ++ suffix,
                .metadata_partition = "transfers-metadata-" ++ suffix,
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "transfers-log-" ++ suffix,
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 1024,
        };
        // A `current` database adds its grafted tree's metadata (commonware `current_config`).
        const config: D.Cfg = if (comptime @hasDecl(D, "Any")) .{
            .merkle = base.merkle,
            .log = base.log,
            .grafted_metadata_partition = "transfers-grafted-" ++ suffix,
            .translator = .{},
            .init_cache = base.init_cache,
        } else base;
        const label = comptime label: {
            var buffer: [suffix.len]u8 = suffix[0..suffix.len].*;
            std.mem.replaceScalar(u8, &buffer, '-', '_');
            const final = buffer;
            break :label &final;
        };
        const scope = metrics.Scope.init(&harness.registry).child(label);
        return D.init(gpa, harness.storage.interface(), scope, config, null);
    }
};

fn Account(comptime List: type) type {
    return @typeInfo(List).pointer.child.Account;
}

/// Plans and settles `list` on a new batch of `db`, returning the merkleized batch (commonware
/// `execute`). Fails with `error.Rejected`, filling `rejection`, before anything is written.
fn execute(db: anytype, list: anytype, rejection: *Rejection) !*@TypeOf(db.*).MerkleizedBatch {
    const A = Account(@TypeOf(list));
    var plan = try transfers.Plan(Address, A).init(gpa, list, 1, sequential, rejection);
    defer plan.deinit(gpa);
    const reads = try gpa.alloc(?A, plan.len());
    defer gpa.free(reads);
    var batch = try db.new_batch();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(plan.keys, db, reads);
    };
    const slots = plan.settle(gpa, reads, sequential, rejection) catch |err| {
        staged.deinit();
        return err;
    };
    defer gpa.free(slots);
    assert(slots.len == staged.len());
    return staged.merkleize(slots, &.{}, db) catch |err| {
        staged.deinit();
        return err;
    };
}

/// Selects from `candidates` on a new batch of `db`, writing whether each was accepted to
/// `accepted`, and returns the merkleized batch (commonware `select`).
fn select(db: anytype, candidates: anytype, accepted: []bool) !*@TypeOf(db.*).MerkleizedBatch {
    const A = Account(@TypeOf(candidates));
    var selection = transfers.Selection(Address, A).init(2);
    defer selection.deinit(gpa);
    const touched = try selection.touch(gpa, candidates);
    const reads = try gpa.alloc(?A, touched.end - touched.start);
    defer gpa.free(reads);
    var batch = try db.new_batch();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(selection.keys()[touched.start..touched.end], db, reads);
    };
    errdefer staged.deinit();
    try selection.register(gpa, reads);
    try selection.apply(gpa, candidates, accepted);
    const slots = try selection.settle(gpa, sequential);
    defer gpa.free(slots);
    return staged.merkleize(slots, &.{}, db);
}

/// Applies and commits `merkleized` (released) to `db`, returning its root.
fn commit(db: anytype, merkleized: anytype) !Digest {
    defer merkleized.release();
    const root = merkleized.root();
    try db.apply_batch(merkleized);
    try db.commit();
    return root;
}

/// Executes `list` on `db` and commits it, returning the batch root (commonware `run`).
fn run(db: anytype, list: anytype) !Digest {
    var rejection: Rejection = undefined;
    return commit(db, try execute(db, list, &rejection));
}

/// The accounts `db` holds among keys `0..keys`.
fn accounts(comptime A: type, db: anytype, keys: u64) !support.Ledger(A) {
    var ledger: support.Ledger(A) = .{};
    errdefer ledger.deinit();
    for (0..keys) |n| {
        const account = try db.get(&key(n)) orelse continue;
        try ledger.put(key(n), account);
    }
    return ledger;
}

fn expect_accounts(db: anytype, keys: u64, want: []const support.Held(Balance)) !void {
    var got = try accounts(Balance, db, keys);
    defer got.deinit();
    var expected = try support.Ledger(Balance).init(want);
    defer expected.deinit();
    try got.expect_equal(&expected);
}

fn held(n: u64, value: u64) support.Held(Balance) {
    return .{ .key = key(n), .account = bal(value) };
}

fn mint_item(n: u64, value: u64) Multi.Item {
    return .{ .key = key(n), .change = .crediting(value) };
}

/// Mints, rejects, settles, and deletes balances on a database of `D` (commonware
/// `exercise`).
fn exercise(comptime D: type, comptime suffix: []const u8) !void {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var db = try harness.open(D, suffix);
    defer db.deinit();

    // Mint balances into an empty database.
    const items = [_]Multi.Item{ mint_item(1, 100), mint_item(2, 150) };
    _ = try run(&db, @as([]const Multi, &.{.{ .items = &items }}));
    try expect_accounts(&db, 5, &.{ held(1, 100), held(2, 150) });

    // A rejected batch leaves the database unchanged.
    const before = db.root();
    var rejection: Rejection = undefined;
    const rejected = [_]Payment{ pay(1, 3, 60), pay(1, 4, 41) };
    const result = execute(&db, @as([]const Payment, &rejected), &rejection);
    try testing.expectError(error.Rejected, result);
    try testing.expectEqual(support.rejected_by(.insufficient, key(1)), rejection);
    try testing.expect(db.root().eql(before));
    try expect_accounts(&db, 5, &.{ held(1, 100), held(2, 150) });

    // A settled batch writes the changed balances. Key 1 spends its whole starting balance
    // and is refilled by key 2. Key 2 also pays itself.
    const payments = [_]Payment{ pay(1, 3, 60), pay(1, 4, 40), pay(2, 1, 50), pay(2, 2, 100) };
    const root = try run(&db, @as([]const Payment, &payments));
    try testing.expect(!root.eql(before));
    try expect_accounts(&db, 5, &.{ held(1, 50), held(2, 100), held(3, 60), held(4, 40) });

    // Spending everything deletes the key.
    _ = try run(&db, @as([]const Payment, &.{pay(1, 2, 50)}));
    try expect_accounts(&db, 5, &.{ held(2, 150), held(3, 60), held(4, 40) });
}

test "transfers: execute settles batches against any unordered" {
    try exercise(Any(Balance, false), "any-unordered");
}

test "transfers: execute settles batches against any ordered" {
    try exercise(Any(Balance, true), "any-ordered");
}

test "transfers: execute settles batches against current unordered" {
    try exercise(Current(Balance, false), "current-unordered");
}

test "transfers: execute settles batches against current ordered" {
    try exercise(Current(Balance, true), "current-ordered");
}

/// Mint credits for keys `0..keys`, each drawn from `100..1_000`.
fn draw_mint(rng: *rng_mod.TestRng, items: []Multi.Item, mint: []Multi) void {
    assert(items.len == mint.len);
    for (items, mint, 0..) |*item, *transfer, n| {
        item.* = mint_item(n, rng_mod.range_less_than(rng, u64, 100, 1_000));
        transfer.* = .{ .items = item[0..1] };
    }
}

/// Settles the same random payments in two orders on two fresh databases of `D`: the plan's
/// key order varies with its hash key, so the root must depend on neither it nor the order
/// (commonware `order_independence`).
fn order_independence(comptime D: type) !void {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var rng = rng_mod.TestRng.init(11);
    const keys = 300;
    var items: [keys]Multi.Item = undefined;
    var mint: [keys]Multi = undefined;
    draw_mint(&rng, &items, &mint);

    // Random payments among minted keys 2 and up, then key 0 drained to a fresh key (a delete
    // and a create) and key 1 drained into key 2 (a delete).
    var payments: [2_002]Payment = undefined;
    for (payments[0..2_000]) |*payment| {
        const from = rng_mod.range_less_than(&rng, u64, 2, keys);
        const to = rng_mod.range_less_than(&rng, u64, 2, keys);
        payment.* = pay(from, to, rng_mod.range_less_than(&rng, u64, 0, 3));
    }
    payments[2_000] = pay(0, keys, items[0].change.credit);
    payments[2_001] = pay(1, 2, items[1].change.credit);

    // The second order shuffles the first (`swap(i, random_range(0..=i))` from the end).
    var shuffled = payments;
    var i: usize = shuffled.len - 1;
    while (i > 0) : (i -= 1) {
        std.mem.swap(Payment, &shuffled[i], &shuffled[rng_mod.range_at_most(&rng, usize, 0, i)]);
    }

    var ordered_db = try harness.open(D, "ordered");
    defer ordered_db.deinit();
    var shuffled_db = try harness.open(D, "shuffled");
    defer shuffled_db.deinit();
    _ = try run(&ordered_db, @as([]const Multi, &mint));
    _ = try run(&shuffled_db, @as([]const Multi, &mint));
    const root = try run(&ordered_db, @as([]const Payment, &payments));
    try testing.expect(root.eql(try run(&shuffled_db, @as([]const Payment, &shuffled))));

    // Both orders reach the same balances, which match the sequential reference. The drained
    // keys are deleted, and the fresh key holds key 0's mint.
    var settled = try accounts(Balance, &ordered_db, keys + 1);
    defer settled.deinit();
    var other = try accounts(Balance, &shuffled_db, keys + 1);
    defer other.deinit();
    try settled.expect_equal(&other);
    try testing.expect(settled.get(key(0)) == null and settled.get(key(1)) == null);
    try testing.expectEqual(items[0].change.credit, settled.get(key(keys)).?.value);
    var minted: support.Ledger(Balance) = .{};
    defer minted.deinit();
    for (items) |item| try minted.put(item.key, bal(item.change.credit));
    var want = try support.expected(&minted, @as([]const Payment, &payments));
    defer want.deinit();
    try settled.expect_equal(try want.ledger());
}

test "transfers: execute roots do not depend on order in any unordered" {
    try order_independence(Any(Balance, false));
}

test "transfers: execute roots do not depend on order in any ordered" {
    try order_independence(Any(Balance, true));
}

test "transfers: execute roots do not depend on order in current unordered" {
    try order_independence(Current(Balance, false));
}

test "transfers: execute roots do not depend on order in current ordered" {
    try order_independence(Current(Balance, true));
}

/// Selects from `candidates` on a proposer's database holding the accounts `setup` leaves,
/// then executes exactly the accepted body on a verifier's database with the same setup,
/// checking that both reach the same root and accounts among keys `0..keys` (commonware
/// `select_matches_execute`).
fn select_matches_execute(
    harness: *Harness,
    comptime D: type,
    setup: anytype,
    candidates: anytype,
    keys: u64,
) !void {
    const A = D.Value;
    const T = @typeInfo(@TypeOf(candidates)).pointer.child;
    var proposer = try harness.open(D, "proposer");
    defer proposer.deinit();
    var verifier = try harness.open(D, "verifier");
    defer verifier.deinit();

    // A proposer selects a body from the candidates on the state the setup leaves.
    _ = try run(&proposer, setup);
    const accepted = try gpa.alloc(bool, candidates.len);
    defer gpa.free(accepted);
    const proposed = try commit(&proposer, try select(&proposer, candidates, accepted));
    var proposed_accounts = try accounts(A, &proposer, keys);
    defer proposed_accounts.deinit();

    // A verifier executes exactly the accepted body on the same state and reaches the same
    // root and accounts.
    const body = try support.body(T, candidates, accepted);
    defer gpa.free(body);
    try testing.expect(body.len < candidates.len);
    _ = try run(&verifier, setup);
    try testing.expect(proposed.eql(try run(&verifier, @as([]const T, body))));
    var verified_accounts = try accounts(A, &verifier, keys);
    defer verified_accounts.deinit();
    try verified_accounts.expect_equal(&proposed_accounts);
}

test "transfers: select merkleizes the accepted candidates" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var rng = rng_mod.TestRng.init(23);
    const keys = 100;

    // Each key is minted a small balance, and candidates also pay from ten unminted keys, so
    // some do not fit.
    var items: [keys]Multi.Item = undefined;
    var mint: [keys]Multi = undefined;
    for (&items, &mint, 0..) |*item, *transfer, n| {
        item.* = mint_item(n, rng_mod.range_less_than(&rng, u64, 1, 30));
        transfer.* = .{ .items = item[0..1] };
    }
    var candidates: [600]Payment = undefined;
    for (&candidates) |*candidate| {
        const from = rng_mod.range_less_than(&rng, u64, 0, keys + 10);
        const to = rng_mod.range_less_than(&rng, u64, 0, keys + 10);
        candidate.* = pay(from, to, rng_mod.range_less_than(&rng, u64, 0, 10));
    }
    const setup: []const Multi = &mint;
    const list: []const Payment = &candidates;
    try select_matches_execute(&harness, AnyUnordered(Balance), setup, list, keys + 10);
}

test "transfers: selection reads later rounds through expand" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const Db = AnyUnordered(Balance);
    var proposer = try harness.open(Db, "proposer");
    defer proposer.deinit();
    var verifier = try harness.open(Db, "verifier");
    defer verifier.deinit();

    // The proposer and the verifier start from the same minted accounts.
    const items = [_]Multi.Item{ mint_item(1, 10), mint_item(2, 5) };
    const mint: []const Multi = &.{.{ .items = &items }};
    _ = try run(&proposer, mint);
    _ = try run(&verifier, mint);

    // The first round reads its keys with `stage`, and each later round reads its new keys with
    // `expand` into the range `touch` returned for them. Key 3 is touched only by a dropped
    // candidate, key 4 only by a zero credit, and the second round touches no key.
    const all = [_]Payment{
        pay(1, 2, 6), pay(3, 1, 1), pay(1, 4, 0),
        pay(2, 5, 5), pay(1, 5, 4), pay(2, 3, 1),
    };
    const rounds = [_][]const Payment{ all[0..3], all[3..3], all[3..6] };
    var accepted: [all.len]bool = undefined;
    var selection = transfers.Selection(Address, Balance).init(3);
    defer selection.deinit(gpa);
    var reads: [8]?Balance = undefined;
    var touched = try selection.touch(gpa, rounds[0]);
    var batch = try proposer.new_batch();
    var staged = staged: {
        errdefer batch.deinit();
        const first = selection.keys()[touched.start..touched.end];
        break :staged try batch.stage(first, &proposer, reads[0..first.len]);
    };
    errdefer staged.deinit();
    try selection.register(gpa, reads[0 .. touched.end - touched.start]);
    try selection.apply(gpa, rounds[0], accepted[0..3]);
    var applied: usize = 3;
    for (rounds[1..]) |round| {
        touched = try selection.touch(gpa, round);
        const fresh = selection.keys()[touched.start..touched.end];
        const range = try staged.expand(fresh, &proposer, reads[0..fresh.len]);
        try testing.expectEqual(touched.start, range.start);
        try testing.expectEqual(touched.end, range.end);
        try selection.register(gpa, reads[0..fresh.len]);
        try selection.apply(gpa, round, accepted[applied..][0..round.len]);
        applied += round.len;
    }
    try testing.expectEqualSlices(bool, &.{ true, false, true, true, true, false }, &accepted);

    // Settling yields one slot per staged key, in staging order. Key 1 is drained and deleted,
    // key 2 is refilled, key 5 is created, and key 3 stays absent. Key 4 is never staged.
    const slots = try selection.settle(gpa, sequential);
    defer gpa.free(slots);
    const Slot = transfers.Slot(Balance);
    const want = [_]Slot{ .delete, .{ .put = bal(6) }, .keep, .{ .put = bal(9) } };
    try testing.expectEqualSlices(Slot, &want, slots);
    const proposed = try commit(&proposer, try staged.merkleize(slots, &.{}, &proposer));

    // A verifier executing the accepted body reaches the same root and accounts.
    const body = try support.body(Payment, &all, &accepted);
    defer gpa.free(body);
    try testing.expect(proposed.eql(try run(&verifier, @as([]const Payment, body))));
    var proposed_accounts = try accounts(Balance, &proposer, 6);
    defer proposed_accounts.deinit();
    var verified_accounts = try accounts(Balance, &verifier, 6);
    defer verified_accounts.deinit();
    try verified_accounts.expect_equal(&proposed_accounts);
}

test "transfers: execute carries nonces across batches" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var db = try harness.open(AnyUnordered(Nonced), "nonced");
    defer db.deinit();
    const Ledger = nonced_support.Ledger;

    // Key 1 spends its whole default balance with nonce 0 and keeps its key.
    _ = try run(&db, @as([]const Signed, &.{signed(1, 2, default_balance, 0)}));
    {
        var got = try accounts(Nonced, &db, 3);
        defer got.deinit();
        var want = try Ledger.init(&.{
            nonced_support.held(1, nonced(0, 1, 0)),
            nonced_support.held(2, nonced(2 * default_balance, 0, 0)),
        });
        defer want.deinit();
        try got.expect_equal(&want);
    }

    // A later batch that replays nonce 0 is refused, though its transfer moves nothing, and
    // leaves the database unchanged.
    const before = db.root();
    var rejection: Rejection = undefined;
    const replay = [_]Signed{signed(1, 2, 0, 0)};
    try testing.expectError(error.Rejected, execute(&db, @as([]const Signed, &replay), &rejection));
    try testing.expectEqual(support.rejected_by(.refused, key(1)), rejection);
    try testing.expect(db.root().eql(before));

    // Key 1 consumes its next nonce while key 2 consumes its first to refill key 1.
    _ = try run(&db, @as([]const Signed, &.{ signed(1, 1, 0, 1), signed(2, 1, 50, 0) }));
    var got = try accounts(Nonced, &db, 3);
    defer got.deinit();
    var want = try Ledger.init(&.{
        nonced_support.held(1, nonced(50, 2, 0)),
        nonced_support.held(2, nonced(2 * default_balance - 50, 1, 0)),
    });
    defer want.deinit();
    try got.expect_equal(&want);
}

test "transfers: select merkleizes the accepted signed candidates" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var rng = rng_mod.TestRng.init(31);
    const keys = 100;

    // Every key consumes nonce 0 paying the next one, so candidates that replay it are refused.
    var setup: [keys]Signed = undefined;
    for (&setup, 0..) |*transfer, n| {
        const amount = rng_mod.range_less_than(&rng, u64, 0, default_balance);
        transfer.* = signed(n, (n + 1) % keys, amount, 0);
    }
    var candidates: [600]Signed = undefined;
    for (&candidates) |*candidate| {
        const from = rng_mod.range_less_than(&rng, u64, 0, keys + 10);
        const to = rng_mod.range_less_than(&rng, u64, 0, keys + 10);
        const amount = rng_mod.range_less_than(&rng, u64, 0, 60);
        candidate.* = signed(from, to, amount, rng_mod.range_less_than(&rng, u64, 0, 8));
    }
    const list: []const Signed = &candidates;
    const setup_list: []const Signed = &setup;
    try select_matches_execute(&harness, NoncedCurrent, setup_list, list, keys + 10);
}

/// Plans and settles `list` through the stateful wrapper `shared` (commonware
/// `StatefulDb::execute`).
fn stateful_execute(shared: anytype, list: anytype) !@TypeOf(shared).Merkleized {
    const A = Account(@TypeOf(list));
    var rejection: Rejection = undefined;
    var plan = try transfers.Plan(Address, A).init(gpa, list, 1, sequential, &rejection);
    defer plan.deinit(gpa);
    const reads = try gpa.alloc(?A, plan.len());
    defer gpa.free(reads);
    var batch = try shared.new_batches();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(plan.keys, reads);
    };
    const slots = plan.settle(gpa, reads, sequential, &rejection) catch |err| {
        staged.deinit();
        return err;
    };
    defer gpa.free(slots);
    assert(slots.len == staged.len());
    return staged.merkleize(slots, &.{});
}

/// Selects from `rounds` in order through the stateful wrapper `shared`, reading the first
/// round's keys with `stage` and each later round's new keys with `expand`, writing whether
/// each candidate was accepted to `accepted` (commonware `StatefulDb::select`).
fn stateful_select(
    shared: anytype,
    comptime T: type,
    rounds: []const []const T,
    accepted: []bool,
) !@TypeOf(shared).Merkleized {
    const A = T.Account;
    var selection = transfers.Selection(Address, A).init(2);
    defer selection.deinit(gpa);
    var touched = try selection.touch(gpa, rounds[0]);
    const first = try gpa.alloc(?A, touched.end - touched.start);
    defer gpa.free(first);
    var batch = try shared.new_batches();
    var staged = staged: {
        errdefer batch.deinit();
        break :staged try batch.stage(selection.keys()[touched.start..touched.end], first);
    };
    errdefer staged.deinit();
    try selection.register(gpa, first);
    try selection.apply(gpa, rounds[0], accepted[0..rounds[0].len]);
    var applied: usize = rounds[0].len;
    // Each later round's new keys must land in the range `touch` returned, so the slots line
    // up with the selection's keys.
    for (rounds[1..]) |round| {
        touched = try selection.touch(gpa, round);
        const reads = try gpa.alloc(?A, touched.end - touched.start);
        defer gpa.free(reads);
        const range = try staged.expand(selection.keys()[touched.start..touched.end], reads);
        try testing.expectEqual(touched.start, range.start);
        try testing.expectEqual(touched.end, range.end);
        try selection.register(gpa, reads);
        try selection.apply(gpa, round, accepted[applied..][0..round.len]);
        applied += round.len;
    }
    assert(applied == accepted.len);
    const slots = try selection.settle(gpa, sequential);
    defer gpa.free(slots);
    return staged.merkleize(slots, &.{});
}

/// The accounts the wrapped database of `shared` holds among keys `0..keys`.
fn shared_accounts(comptime A: type, shared: anytype, keys: u64) !support.Ledger(A) {
    var guard = try shared.read();
    defer guard.deinit();
    return accounts(A, &guard.get().inner, keys);
}

/// Selects candidates through the stateful wrapper of a proposer's database, then executes the
/// accepted body through the wrapper of a verifier's database and directly on a twin database,
/// all three holding the accounts `setup` leaves. Checks that the three reach the same root
/// and that both wrapped databases hold the reference's accounts among keys `0..keys`. The
/// candidates arrive in four rounds: `first`, a replay of `first`, an empty round, and `last`
/// (commonware `stateful_select_matches_execute`).
fn stateful_select_matches_execute(
    comptime D: type,
    setup: anytype,
    comptime T: type,
    first: []const T,
    last: []const T,
    keys: u64,
) !void {
    const A = D.Value;
    const Wrapped = stateful_db.current.Current(D).Shared;
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var proposer_db = try harness.open(D, "proposer");
    _ = run(&proposer_db, setup) catch |err| {
        proposer_db.deinit();
        return err;
    };
    const proposer = try Wrapped.init(gpa, testing.io, "proposer", .{ .inner = proposer_db });
    defer proposer.deinit();
    var verifier_db = try harness.open(D, "verifier");
    _ = run(&verifier_db, setup) catch |err| {
        verifier_db.deinit();
        return err;
    };
    const verifier = try Wrapped.init(gpa, testing.io, "verifier", .{ .inner = verifier_db });
    defer verifier.deinit();
    var twin = try harness.open(D, "twin");
    defer twin.deinit();
    _ = try run(&twin, setup);
    var start = try accounts(A, &twin, keys);
    defer start.deinit();

    // The proposer selects a body in rounds and applies it.
    const rounds = [_][]const T{ first, first, &.{}, last };
    const candidates = try std.mem.concat(gpa, T, &rounds);
    defer gpa.free(candidates);
    const accepted = try gpa.alloc(bool, candidates.len);
    defer gpa.free(accepted);
    var proposed_batch = try stateful_select(proposer, T, &rounds, accepted);
    defer proposed_batch.deinit();
    const proposed = proposed_batch.root();
    try proposer.apply(&proposed_batch);

    // The verifier executes exactly the accepted body through its wrapper, and the twin
    // executes it directly.
    const body = try support.body(T, candidates, accepted);
    defer gpa.free(body);
    try testing.expect(body.len > 0 and body.len < candidates.len);
    var verified_batch = try stateful_execute(verifier, @as([]const T, body));
    defer verified_batch.deinit();
    try testing.expect(verified_batch.root().eql(proposed));
    try verifier.apply(&verified_batch);
    try testing.expect((try run(&twin, @as([]const T, body))).eql(proposed));

    // Both wrapped databases hold the accounts the reference settles the body to.
    var want = try support.expected(&start, @as([]const T, body));
    defer want.deinit();
    var proposed_accounts = try shared_accounts(A, proposer, keys);
    defer proposed_accounts.deinit();
    try proposed_accounts.expect_equal(try want.ledger());
    var verified_accounts = try shared_accounts(A, verifier, keys);
    defer verified_accounts.deinit();
    try verified_accounts.expect_equal(try want.ledger());
}

/// 200 signed candidates among keys `0..count` (commonware's `candidates` closure).
fn signed_candidates(rng: *rng_mod.TestRng, out: []Signed, count: u64) void {
    for (out) |*candidate| {
        const from = rng_mod.range_less_than(rng, u64, 0, count);
        const to = rng_mod.range_less_than(rng, u64, 0, count);
        const amount = rng_mod.range_less_than(rng, u64, 0, 60);
        candidate.* = signed(from, to, amount, rng_mod.range_less_than(rng, u64, 0, 8));
    }
}

test "transfers: stateful current batches select and execute signed candidates" {
    // Every key consumes nonce 0 paying the next one, so candidates that reuse it are refused,
    // as are replayed candidates whose nonces an earlier round consumed. The last round also
    // pays from ten keys the database does not hold that no earlier round touches.
    var rng = rng_mod.TestRng.init(41);
    const keys = 50;
    var setup: [keys]Signed = undefined;
    for (&setup, 0..) |*transfer, n| {
        const amount = rng_mod.range_less_than(&rng, u64, 0, default_balance);
        transfer.* = signed(n, (n + 1) % keys, amount, 0);
    }
    var first: [200]Signed = undefined;
    signed_candidates(&rng, &first, keys);
    var last: [200]Signed = undefined;
    signed_candidates(&rng, &last, keys + 10);
    const setup_list: []const Signed = &setup;
    const count = keys + 10;
    try stateful_select_matches_execute(NoncedCurrent, setup_list, Signed, &first, &last, count);
}
