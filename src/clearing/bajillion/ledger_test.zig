//! The test vector for implementations of the ledger (commonware `bajillion/tests.rs`
//! `test_ledger_vector`): the digests, roots, and encodings an implementation must compute for
//! SHA-256, Ed25519 keys, and `u64` amounts.
//!
//! Alice pays bob 5 and carol 7 in epoch 1. The close of epoch 1 settles her map, processes
//! bob's deposit of 5 and alice's of 20, and pays out 3 to bob and 4 to carol on their forced
//! withdrawals. The close of epoch 2 pays out 1 to alice and 2 to bob, and the payout log then
//! has three peaks.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const parallel = @import("parallel");
const mod = @import("mod.zig");
const payment = @import("payment.zig");
const validator = @import("validator.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const Digest = t.Digest;
const PublicKey = t.PublicKey;
const Store = t.Store(t.DefaultIndex);
const Payout = validator.Payout(PublicKey, u64);
const PayoutProof = validator.PayoutProof(PublicKey, Digest, u64);
const TestRequest = payment.Request(PublicKey, Digest, u64);
const TestReceipt = payment.Receipt(PublicKey, PublicKey, Digest, u64);
const TestOpening = mod.Opening(PublicKey, Digest, u64);
const gpa = testing.allocator;

/// The largest encoding the vector pins.
const max_hex_bytes = 512;

fn expect_hex(actual: []const u8, comptime expected: []const u8) !void {
    comptime std.debug.assert(expected.len % 2 == 0);
    comptime std.debug.assert(expected.len / 2 <= max_hex_bytes);
    var buffer: [expected.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&buffer, expected) catch unreachable; // Proof: valid test hex.
    try testing.expectEqualSlices(u8, &buffer, actual);
}

fn expect_encoding(comptime T: type, value: T, comptime expected: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try expect_hex(encoded, expected);
}

test "ledger: vector" {
    var harness = try t.Harness.init();
    defer harness.deinit();
    var store = try harness.open(t.DefaultIndex, .{});
    defer store.deinit();

    // The empty balances database and payout log, and the summary before the first close.
    var start = try t.genesis(store.balances.root());
    defer start.deinit();
    const genesis = start.summary;
    try expect_hex(&store.balances.root().bytes, "4e051a8ba89ab421a291d4b906848b2e" ++
        "0f80402175824a056cc3cc00efc4cc65");
    try testing.expect(genesis.payouts.root.eql(store.log.root()));
    try testing.expectEqual(genesis.payouts.size, store.log.bounds().end);
    try expect_hex(&store.log.root().bytes, "97f9a47536a9ff3eda91ef4e53351d36" ++
        "5e104280df46dbcc5dddc7adfabcef2c");
    try expect_hex(&genesis.digest().bytes, "dc78896a8eab075c7672d704b58798ff" ++
        "2687447dc6132852a86f007847bf5af0");

    // The deposit queue's running hash after bob's deposit, chained from genesis. The queues
    // of epoch 1 also hold alice's deposit after bob's and the forced withdrawals of bob and
    // carol.
    const deposits = [_]t.Deposit{
        .{ .account = t.account(1), .amount = 5 },
        .{ .account = t.account(0), .amount = 20 },
    };
    const forced = [_]t.Forced{
        .{ .account = t.account(1), .amount = 3 },
        .{ .account = t.account(2), .amount = 4 },
    };
    const queued = t.queue(1, &deposits, &forced);
    const chained = genesis.deposits.next(Sha256, t.Deposit, deposits[0..1]);
    try expect_hex(&chained.hash.bytes, "e3a81ed35a6c131dc7ea391436b14bc6" ++
        "bc9882a0cf7d815fbd936179601427b4");

    try expect_receipt();
    const close = try expect_openings();
    const first = try expect_first_close(&store, &start, close, &queued);
    defer {
        var owned = first;
        owned.deinit();
    }
    try expect_second_close(&store, &first);
}

/// Bob's receipt, with alice's signature and the operator's countersignature.
fn expect_receipt() !void {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const batch = try t.amounts(gpa, &.{ .{ 1, 5 }, .{ 2, 7 } });
    var states = try TestRequest.states(Sha256, gpa, 1, t.account(0), batch, null, t.empty_root());
    defer states.deinit(gpa);
    const alice = t.user(0);
    const operator = t.operator_key();
    const receipts = (try TestReceipt.issue(
        Sha256,
        gpa,
        states.current,
        states.current.sign(&alice, &namespace),
        states.current.acknowledge(&operator, &namespace),
        &states.payments,
        &.{t.account(1)},
    )).?;
    defer {
        for (receipts) |*receipt| receipt.deinit(gpa);
        gpa.free(receipts);
    }
    const receipt = &receipts[0];
    const operator_public = operator.public_key();
    try testing.expect(receipt.verify(Sha256, &namespace, &operator_public));
    try expect_encoding(TestReceipt, receipt.*, "0000000000000001edd0f6de342a1e6a" ++
        "7236d6244f23d83eedfcecd059a386c85055701498e7703316004c952b79b61f" ++
        "079ea03f168e671ba4ef1b92b99f648b947f1d130bdbf77dd4f280154cb1f1ec" ++
        "ee668774e73759cdff911f869b36bb77a89b2e1d91166e63f3a702485e545330" ++
        "ff175028de6ebf13eb6d26206e9f9197b921356a0ba71203c9aa2291e5add7d3" ++
        "b7c73857894f99e31e210a03cd3c15a00eba08c03fdff20fb8c05e67fbb03bd0" ++
        "bbc88c2e51683e9b7cb260bf4550c9b7c34bb2c8b649ca6988d0e278349baabb" ++
        "dd2a1198645179ff95503ccbdf54815d1644f4ed9e157c0b478b8e507e0bb2b1" ++
        "8c0f9e0824769e8562d10df9abe2e774896f82b4b44052660000000000000005" ++
        "0000000000000002014b496c9d7a3218e471ff8ecd0f2eb2c0e482a17687241d" ++
        "bac72334d783f33b47");
}

/// Openings of bob's entry and of dave's absent one in alice's row of the close of epoch 1,
/// which processes both queues in full. Returns the close.
fn expect_openings() !t.TestClose {
    const operator = t.operator_key();
    const alice_row = try t.row(1, 0, &.{ .{ 1, 5 }, .{ 2, 7 } }, t.empty_root());
    var close = try t.sign_close(&operator, 1, &.{alice_row}, &.{}, 2, 2);
    errdefer close.deinit(gpa);
    var matrix = try close.matrix(Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    const alice = t.account(0);
    const bob = t.account(1);
    const dave = t.account(3);
    var member = try matrix.open(gpa, &alice, &bob);
    defer member.deinit(gpa);
    var absent = try matrix.open(gpa, &alice, &dave);
    defer absent.deinit(gpa);
    const root = matrix.root();
    try testing.expectEqual(@as(u64, 5), try member.verify(Sha256, &root, &alice, &bob));
    try testing.expectEqual(@as(u64, 0), try absent.verify(Sha256, &root, &alice, &dave));
    try expect_hex(&root.bytes, "bb7e4f8026a16dea4b1b699ee9a17fa3" ++
        "61272f269a044f0532c3fae7729b059c");
    try expect_encoding(TestOpening, member, "000000000016004c952b79b61f079ea0" ++
        "3f168e671ba4ef1b92b99f648b947f1d130bdbf77d0000000100010000000000" ++
        "000000000000000500000002014b496c9d7a3218e471ff8ecd0f2eb2c0e482a1" ++
        "7687241dbac72334d783f33b47");
    try expect_encoding(TestOpening, absent, "000000000016004c952b79b61f079ea0" ++
        "3f168e671ba4ef1b92b99f648b947f1d130bdbf77d0000000100010100000002" ++
        "015925ba86e2189444a6c3b437b25d2ef35daecd1abf82c5fb36060f9fc0af42" ++
        "8c0000000000000007000000000201ed446b5e41b60f4b9747cf253e918e823d" ++
        "1c2db3c7f50b6e47b6f6336cfefb7c");
    return close;
}

/// Posts the close of epoch 1, and checks its summary, bob's balance proof under its balances
/// root, and the proof of bob's payout at index 1. Returns the close's checkpoint.
fn expect_first_close(
    store: *Store,
    start: *const t.Checkpoint,
    close: t.TestClose,
    queued: *const t.Queue,
) !t.Checkpoint {
    var first = try store.post(start, close, queued);
    errdefer first.deinit();
    try expect_encoding(t.TestSummary, first.summary, "0000000000000001dc78896a8eab075c" ++
        "7672d704b58798ff2687447dc6132852a86f007847bf5af0bb7e4f8026a16dea" ++
        "4b1b699ee9a17fa361272f269a044f0532c3fae7729b059ccbeaa33ee0fadca4" ++
        "0a7a84e3ef4538a6d5a9225c44b2e85fc27c58fc0dde40f50451b5519948527b" ++
        "730a86197f813f51283fa3545ca2b6c74ca20596b4f4461fec02f90c99746c6d" ++
        "c051366862ffe2d129f1729cb9134387158fe590c943d69f55e902e9e2c7b054" ++
        "fce05131d767f27fe4b9b130cf6fd44114d394fbf97853f27ef05d");
    try expect_hex(&first.summary.digest().bytes, "4ea46f121bbf323e7dd93e6c34665a9c" ++
        "c8f3b0cd117b950586426d44729165ae");

    // Bob's balance under the balances root of that summary, as a claim after a halt proves.
    const bob = t.account(1);
    const proved = try store.balances.key_value_proof(&bob);
    var balance: t.BalanceProof = .{ .balance = proved.value, .proof = proved.proof };
    defer balance.deinit(gpa);
    try testing.expect(balance.verify(Sha256, PublicKey, &first.summary.balances, bob));
    try testing.expectEqual(@as(u64, 7), balance.balance);
    try expect_encoding(t.BalanceProof, balance, "0000000000000007043c000000000000" ++
        "00000000000000000000000000000000000000000000000000060002e8deb066" ++
        "466eaf1b04f892d6986303eb407d463a51b4739a8c2513ac826becca71e1ff83" ++
        "de02f877f9e2c800a2502f61e761b10a0432c6703d620d79f7a9318c00011aee" ++
        "11ebaa71f4483e3129068f72caf28d4c1b4faa01f6b925e7fe97c2493636199f" ++
        "565a0c239b645ac33ac70a041ffda7cf66adc2e76d88454be81900cd252a");

    // The payout log after that close, and the proof of bob's payout at index 1.
    const payouts = first.summary.payouts;
    var early = try payout_proof(&store.log, 1, .{ .account = bob, .amount = 3 });
    defer early.deinit(gpa);
    try testing.expect(early.verify(Sha256, &payouts.root));
    try testing.expectEqual(@as(u64, 4), payouts.size);
    try expect_hex(&payouts.root.bytes, "51b5519948527b730a86197f813f5128" ++
        "3fa3545ca2b6c74ca20596b4f4461fec");
    try expect_encoding(PayoutProof, early, "01478b8e507e0bb2b18c0f9e0824769e" ++
        "8562d10df9abe2e774896f82b4b4405266000000000000000304000266b4a8b2" ++
        "a17f0463f7427c0239106eaf710ea7129f42d184a58c50cdff614ba4c9b32f58" ++
        "d153a4f26cb6078783a7d3a6cfab16d8f6fcedaa19ed63c338e2a9ce");
    return first;
}

/// Posts the close of epoch 2, which pays out 1 to alice and 2 to bob, so the log holds three
/// peaks. The proof of bob's first payout under the new root folds the two later peaks.
fn expect_second_close(store: *Store, first: *const t.Checkpoint) !void {
    const bob = t.account(1);
    var early = try payout_proof(&store.log, 1, .{ .account = bob, .amount = 3 });
    defer early.deinit(gpa);
    const forced = [_]t.Forced{
        .{ .account = t.account(0), .amount = 1 },
        .{ .account = t.account(1), .amount = 2 },
    };
    const queued = t.queue(2, &.{}, &forced);
    const operator = t.operator_key();
    const close = try t.sign_close(&operator, 2, &.{}, &.{}, 0, 2);
    var second = try store.post(first, close, &queued);
    defer second.deinit();
    const payouts = second.summary.payouts;
    var late = try payout_proof(&store.log, 1, .{ .account = bob, .amount = 3 });
    defer late.deinit(gpa);
    try testing.expect(late.verify(Sha256, &payouts.root));
    try testing.expect(!early.verify(Sha256, &payouts.root));
    try testing.expectEqual(@as(u64, 7), payouts.size);
    try expect_hex(&payouts.root.bytes, "540a194296da3b72974ec85cba28b56c" ++
        "e0cae59481844b2480db323061d7554d");
    try expect_encoding(PayoutProof, late, "01478b8e507e0bb2b18c0f9e0824769e" ++
        "8562d10df9abe2e774896f82b4b44052660000000000000003070003" ++
        "8a4c9a9db0462d62f8c5467b7d7ae30b90514a347f1abb4265e7184ec9052e42" ++
        "66b4a8b2a17f0463f7427c0239106eaf710ea7129f42d184a58c50cdff614ba4" ++
        "c9b32f58d153a4f26cb6078783a7d3a6cfab16d8f6fcedaa19ed63c338e2a9ce");
}

/// The proof that `log` holds `payout` at `index`, under its current root.
fn payout_proof(log: *t.Log, index: u64, payout: Payout) !PayoutProof {
    const items = try log.proof(index, 1);
    defer codec.free_items(t.Log.Operation, gpa, items.items);
    defer gpa.free(items.items);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expect(items.items[0].append.eql(payout));
    return .{ .index = index, .payout = payout, .proof = items.proof };
}
