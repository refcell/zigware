//! Tests of `close.zig` (commonware `bajillion/close.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const parallel = @import("parallel");
const close = @import("close.zig");
const mod = @import("mod.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const PublicKey = t.PublicKey;
const PrivateKey = t.PrivateKey;
const TestClose = close.Close(PublicKey, PublicKey, u64);
const Row = TestClose.RowType;
const Withdrawal = TestClose.WithdrawalType;
const Queue = TestClose.QueueType;
const Deposit = close.Deposit(PublicKey, u64);
const Forced = close.ForcedWithdrawal(PublicKey, u64);
const gpa = testing.allocator;

const limits: close.Limits = .{ .rows = 4, .receivers = 4, .withdrawals = 4 };

/// A row of `signer` paying `receiver` 1, with a placeholder signature.
fn row(signer: *const PrivateKey, receiver: *const PrivateKey) !Row {
    return .{
        .account = signer.public_key(),
        .payments = try t.TestAmounts.init(gpa, &.{.{ receiver.public_key(), 1 }}),
        .signature = signer.sign("row", "row"),
    };
}

/// Encodes a close of epoch 1 processing two deposits and three forced withdrawals.
fn encode(rows: []const Row, withdrawals: []const Withdrawal) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const operator = t.operator_key();
    const signature = operator.sign("close", "close");
    const size = 8 + codec.encode_size([]const Row, rows) +
        codec.encode_size([]const Withdrawal, withdrawals) + 2 + 64;
    try list.resize(gpa, size);
    var writer = codec.Writer.init(list.items);
    codec.write(u64, 1, &writer);
    codec.write([]const Row, rows, &writer);
    codec.write([]const Withdrawal, withdrawals, &writer);
    codec.varint.write(u64, 2, &writer);
    codec.varint.write(u64, 3, &writer);
    signature.write(&writer);
    try testing.expectEqual(size, writer.written().len);
    return list.toOwnedSlice(gpa);
}

fn expect_decode_error(bytes: []const u8, cfg: close.Limits) !void {
    if (codec.decode_cfg(TestClose, gpa, bytes, cfg)) |decoded| {
        var copy = decoded;
        copy.deinit(gpa);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

// A withdrawal verifies only under its account's signature over its exact fields, in its
// namespace, and for a nonzero amount.
test "close: withdrawal signature" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signer = t.user(0);
    const withdrawal = Withdrawal.sign(&signer, &namespace, 3, 10, 7);
    try testing.expect(withdrawal.account.eql(signer.public_key()));
    try testing.expect(withdrawal.verify(&namespace));
    var other = try mod.Namespace.init(gpa, "other");
    defer other.deinit(gpa);
    try testing.expect(!withdrawal.verify(&other));

    // Every signed field is bound by the signature.
    var tampered: [4]Withdrawal = @splat(withdrawal);
    tampered[0].epoch = 4;
    tampered[1].amount = 11;
    tampered[2].tag = 8;
    tampered[3].account = t.account(1);
    for (&tampered) |*forged| try testing.expect(!forged.verify(&namespace));

    // A zero amount never verifies.
    try testing.expect(!Withdrawal.sign(&signer, &namespace, 3, 0, 7).verify(&namespace));
}

// A canonical close round-trips. Decoding refuses unsorted or repeated rows, a row that pays no
// one, a repeated withdrawal request, and rows, receivers, or withdrawals over the limits.
test "close: decode rejects non-canonical close" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signers = t.users(3);
    var rows = [_]Row{ try row(&signers[0], &signers[2]), try row(&signers[1], &signers[2]) };
    defer for (&rows) |*r| r.deinit(gpa);
    const withdrawal = Withdrawal.sign(&signers[0], &namespace, 1, 5, 0);

    // A canonical close decodes with its rows, withdrawals, and counts, and encodes back.
    const canonical = try encode(&rows, &.{withdrawal});
    defer gpa.free(canonical);
    var decoded = try codec.decode_cfg(TestClose, gpa, canonical, limits);
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), decoded.rows.len);
    for (decoded.rows, &rows) |*a, *b| try testing.expect(a.eql(b));
    try testing.expect(decoded.withdrawals[0].eql(withdrawal));
    try testing.expectEqual(@as(u64, 2), decoded.deposits);
    try testing.expectEqual(@as(u64, 3), decoded.forced_withdrawals);
    const again = try codec.encode(TestClose, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, canonical, again);

    // Rows must be strictly increasing by account.
    for ([_][2]Row{ .{ rows[1], rows[0] }, .{ rows[0], rows[0] } }) |pair| {
        const bytes = try encode(&pair, &.{});
        defer gpa.free(bytes);
        try expect_decode_error(bytes, limits);
    }

    // A row must pay someone.
    var empty = rows[0];
    empty.payments = t.TestAmounts.empty;
    const unpaid = try encode(&.{empty}, &.{});
    defer gpa.free(unpaid);
    try expect_decode_error(unpaid, limits);

    // The same request cannot appear twice, even under different signatures.
    var resigned = withdrawal;
    resigned.signature = signers[1].sign("other", "other");
    const repeated = try encode(&rows, &.{ withdrawal, resigned });
    defer gpa.free(repeated);
    try expect_decode_error(repeated, limits);

    // Rows, receivers per row, and withdrawals are each bounded.
    var paying_two = rows[0];
    paying_two.payments = try t.TestAmounts.init(gpa, &.{
        .{ signers[1].public_key(), 1 },
        .{ signers[2].public_key(), 1 },
    });
    defer paying_two.payments.deinit(gpa);
    const wide = try encode(&.{paying_two}, &.{});
    defer gpa.free(wide);
    var wide_close = try codec.decode_cfg(TestClose, gpa, wide, limits);
    wide_close.deinit(gpa);
    try expect_decode_error(canonical, .{ .rows = 1, .receivers = 4, .withdrawals = 4 });
    try expect_decode_error(wide, .{ .rows = 4, .receivers = 1, .withdrawals = 4 });
    try expect_decode_error(canonical, .{ .rows = 4, .receivers = 4, .withdrawals = 0 });
}

// A prefix holds the oldest requests of each queue, at least the required count and at most the
// queue's length.
test "close: queue prefix" {
    const account = t.account(0);
    const deposits = [_]Deposit{
        .{ .account = account, .amount = 1 },
        .{ .account = account, .amount = 2 },
    };
    const forced = [_]Forced{
        .{ .account = account, .amount = 3 },
        .{ .account = account, .amount = 4 },
    };
    const queue: Queue = .{
        .epoch = 1,
        .deposits = &deposits,
        .required_deposits = 1,
        .forced_withdrawals = &forced,
        .required_forced_withdrawals = 0,
    };
    const first = queue.prefix(1, 0).?;
    try testing.expectEqual(@as(usize, 1), first.deposits.len);
    try testing.expectEqual(@as(usize, 0), first.forced_withdrawals.len);
    const second = queue.prefix(1, 1).?;
    try testing.expect(second.deposits[0].eql(deposits[0]));
    try testing.expect(second.forced_withdrawals[0].eql(forced[0]));
    const all = queue.prefix(2, 2).?;
    try testing.expectEqual(@as(usize, 2), all.deposits.len);
    try testing.expectEqual(@as(usize, 2), all.forced_withdrawals.len);
    for ([_][2]u64{ .{ 0, 0 }, .{ 3, 0 }, .{ 1, 3 } }) |counts| {
        try testing.expectEqual(null, queue.prefix(counts[0], counts[1]));
    }
}

// An account signs the epoch, account, amount, and tag in their fixed encodings, in that order,
// in the withdrawal namespace.
test "close: withdrawal message is what the account signs" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signer = t.user(0);
    const account = signer.public_key();
    const withdrawal = Withdrawal.sign(&signer, &namespace, 3, 10, 7);
    const message = Withdrawal.message(3, &account, 10, 7);
    var expected: [8 + 32 + 8 + 8]u8 = undefined;
    std.mem.writeInt(u64, expected[0..8], 3, .big);
    @memcpy(expected[8..40], account.as_slice());
    std.mem.writeInt(u64, expected[40..48], 10, .big);
    std.mem.writeInt(u64, expected[48..56], 7, .big);
    try testing.expectEqualSlices(u8, &expected, &message);
    try testing.expect(signer.sign(namespace.withdrawal, &message).eql(withdrawal.signature));
}

// Deposits and forced withdrawals encode at their fixed size and round-trip.
test "close: queued requests have fixed encodings" {
    const deposit: Deposit = .{ .account = t.account(0), .amount = 7 };
    const forced: Forced = .{ .account = t.account(0), .amount = 9 };
    const deposit_bytes = codec.encode_fixed(Deposit, deposit);
    const forced_bytes = codec.encode_fixed(Forced, forced);
    try testing.expectEqual(@as(usize, 40), deposit_bytes.len);
    try testing.expectEqual(@as(usize, 40), forced_bytes.len);
    try testing.expect((try codec.decode(Deposit, gpa, &deposit_bytes)).eql(deposit));
    try testing.expect((try codec.decode(Forced, gpa, &forced_bytes)).eql(forced));
}

fn owned_rows(rows: []const Row) ![]Row {
    const result = try gpa.alloc(Row, rows.len);
    for (rows, result) |*from, *to| to.* = try from.clone(gpa);
    return result;
}

fn assemble(
    queue: *const Queue,
    rows: []const Row,
    withdrawals: []const Withdrawal,
    deposits: u64,
    forced: u64,
) !TestClose.Assembled {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const operator = t.operator_key();
    return TestClose.assemble(
        Sha256,
        gpa,
        &operator,
        &namespace,
        queue,
        try owned_rows(rows),
        try gpa.dupe(Withdrawal, withdrawals),
        deposits,
        forced,
        parallel.sequential,
    );
}

// Assembly orders rows and withdrawals itself, recomputes every root, and signs the close.
test "close: assembly is independent of order" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signers = t.users(3);
    var rows = [_]Row{ try row(&signers[0], &signers[2]), try row(&signers[1], &signers[2]) };
    defer for (&rows) |*r| r.deinit(gpa);
    const withdrawals = [_]Withdrawal{
        Withdrawal.sign(&signers[0], &namespace, 1, 5, 0),
        Withdrawal.sign(&signers[1], &namespace, 1, 5, 0),
    };
    const deposits = [_]Deposit{.{ .account = signers[2].public_key(), .amount = 4 }};
    const queue: Queue = .{
        .epoch = 1,
        .deposits = &deposits,
        .required_deposits = 0,
        .forced_withdrawals = &.{},
        .required_forced_withdrawals = 0,
    };
    var assembled = try assemble(&queue, &rows, &withdrawals, 1, 0);
    defer assembled.deinit(gpa);
    const backwards = [_]Withdrawal{ withdrawals[1], withdrawals[0] };
    var reversed = try assemble(&queue, &.{ rows[1], rows[0] }, &backwards, 1, 0);
    defer reversed.deinit(gpa);
    try testing.expect(assembled.close.eql(&reversed.close));
    const Entry = TestClose.Flows.Entry;
    try testing.expectEqualSlices(Entry, assembled.flows.flows, reversed.flows.flows);
    for (assembled.close.rows, &rows) |*a, *b| try testing.expect(a.eql(b));
    for (assembled.close.withdrawals, withdrawals) |a, b| try testing.expect(a.eql(b));

    // The operator signs the epoch, the matrix root of the rows, the withdrawals, and both counts
    // as varints. The flows sum every account's part of the close.
    var matrix = try assembled.close.matrix(Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    const root = matrix.root();
    const signed = assembled.close.withdrawals;
    const message = try TestClose.message(t.Digest, gpa, 1, &root, signed, 1, 0);
    defer gpa.free(message);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);
    var epoch: [8]u8 = undefined;
    std.mem.writeInt(u64, &epoch, 1, .big);
    try expected.appendSlice(gpa, &epoch);
    try expected.appendSlice(gpa, &root.bytes);
    const encoded = try codec.encode([]const Withdrawal, gpa, assembled.close.withdrawals);
    defer gpa.free(encoded);
    try expected.appendSlice(gpa, encoded);
    try expected.appendSlice(gpa, &.{ 1, 0 });
    try testing.expectEqualSlices(u8, expected.items, message);
    const operator = t.operator_key().public_key();
    try testing.expect(operator.verify(namespace.close, message, &assembled.close.signature));
    const flows = assembled.flows.flows;
    try testing.expectEqual(@as(usize, 3), flows.len);
    for (flows[0 .. flows.len - 1], flows[1..]) |a, b| try testing.expect(a[0].order(b[0]) == .lt);
    const settled = struct {
        fn of(entries: []const TestClose.Flows.Entry, key: PublicKey, before: u64) ![2]u64 {
            for (entries) |entry| if (entry[0].eql(key)) {
                const result = try entry[1].settle(before);
                return .{ result.balance, result.payout };
            };
            return error.TestUnexpectedResult;
        }
    }.of;
    try testing.expectEqual([2]u64{ 4, 5 }, try settled(flows, signers[0].public_key(), 10));
    try testing.expectEqual([2]u64{ 6, 0 }, try settled(flows, signers[2].public_key(), 0));
}

// Assembly refuses a second row of an account, a repeated request, and a count outside the
// queue's bounds.
test "close: assembly refuses repeats and counts" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signers = t.users(3);
    const deposits = [_]Deposit{.{ .account = t.account(2), .amount = 4 }};
    const queue: Queue = .{
        .epoch = 1,
        .deposits = &deposits,
        .required_deposits = 1,
        .forced_withdrawals = &.{},
        .required_forced_withdrawals = 0,
    };

    // An account has at most one row, and a request appears at most once, even under different
    // signatures.
    var first = try row(&signers[0], &signers[2]);
    defer first.deinit(gpa);
    var repeated = try row(&signers[0], &signers[2]);
    defer repeated.deinit(gpa);
    repeated.payments.deinit(gpa);
    repeated.payments = try t.TestAmounts.init(gpa, &.{.{ signers[1].public_key(), 2 }});
    try testing.expectError(error.Duplicate, assemble(&queue, &.{ first, repeated }, &.{}, 1, 0));
    const withdrawal = Withdrawal.sign(&signers[0], &namespace, 1, 5, 0);
    var resigned = withdrawal;
    resigned.signature = signers[1].sign("other", "other");
    const twice = assemble(&queue, &.{}, &.{ withdrawal, resigned }, 1, 0);
    try testing.expectError(error.Duplicate, twice);

    // The close processes at least the required requests and at most those queued.
    for ([_]u64{ 0, 2 }) |count| {
        try testing.expectError(error.InvalidCount, assemble(&queue, &.{}, &.{}, count, 0));
    }
    var assembled = try assemble(&queue, &.{}, &.{withdrawal}, 1, 0);
    assembled.deinit(gpa);
}

// Assembly refuses a row that pays no receiver and a soft withdrawal of another epoch.
test "close: assembly refuses rows and withdrawals validators reject" {
    var namespace = try t.namespace(gpa);
    defer namespace.deinit(gpa);
    const signers = t.users(3);
    const queue: Queue = .{
        .epoch = 1,
        .deposits = &.{},
        .required_deposits = 0,
        .forced_withdrawals = &.{},
        .required_forced_withdrawals = 0,
    };
    var empty = try row(&signers[0], &signers[2]);
    defer empty.deinit(gpa);
    var unpaid = empty;
    unpaid.payments = t.TestAmounts.empty;
    try testing.expectError(error.NoReceivers, assemble(&queue, &.{unpaid}, &.{}, 0, 0));
    const late = Withdrawal.sign(&signers[1], &namespace, 2, 5, 0);
    try testing.expectError(error.WrongEpoch, assemble(&queue, &.{}, &.{late}, 0, 0));
}
