//! Verify fuzz for every bajillion proof (commonware `clearing/fuzz/fuzz_targets/verify.rs`).
//!
//! Arbitrary openings, receipts, challenges, and payout proofs must be judged without a crash,
//! whatever they are checked against. A payments case builds the honest proofs of four
//! accounts' promised and posted payments in one epoch, checks them, and then checks that no
//! proof spliced from two honest ones, and no change to the bytes of one sender and receiver's
//! proofs, verifies as anything the case does not hold. Each input runs in its own arena.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const bajillion = @import("../bajillion/mod.zig");
const arb = @import("../bajillion/arbitrary.zig");
const bytes = @import("bytes.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Amounts = bajillion.Amounts(PublicKey, u64);
const State = bajillion.State(PublicKey, Digest);
const Opening = bajillion.Opening(PublicKey, Digest, u64);
const Receipt = bajillion.Receipt(PublicKey, PublicKey, Digest, u64);
const Challenge = bajillion.Challenge(PublicKey, PublicKey, Digest, u64);
const PayoutProof = bajillion.PayoutProof(PublicKey, Digest, u64);
const BalanceProof = bajillion.BalanceProof(Digest, u64);
const Close = bajillion.Close(PublicKey, PublicKey, u64);
const Matrix = bajillion.Matrix(PublicKey, Sha256, u64);

/// The number of accounts that pay and are paid in a case.
const accounts_count = 4;
/// The epoch of a case's states and of the close that settles them.
const epoch: bajillion.Epoch = 2;
/// The most changes a case applies to its proofs.
const mutations_max = 8;
/// The deployment namespace every case signs in.
const namespace_bytes = "_COMMONWARE_CLEARING_BAJILLION_FUZZ";

const Grid = [accounts_count][accounts_count]u64;

fn user(index: usize) PrivateKey {
    return PrivateKey.from_seed(index);
}

fn operator_key() PrivateKey {
    return PrivateKey.from_seed(std.math.maxInt(u64));
}

/// A change to the bytes of an encoded proof.
const Mutation = struct {
    kind: enum { flip, insert, delete, replace, swap },
    position: u16,
    second: u16,
    value: u8,

    fn read(reader: *bytes.Reader) Mutation {
        return .{
            .kind = @fromBackingInt(@intCast(reader.below(5))),
            .position = reader.int(u16),
            .second = reader.int(u16),
            .value = reader.int(u8),
        };
    }

    /// Changes the encoding of `value` and returns what the changed bytes decode to, if
    /// anything.
    fn apply(self: Mutation, comptime T: type, arena: Allocator, value: *const T) !?T {
        const encoded = try codec.encode(T, arena, value.*);
        var list: std.ArrayList(u8) = .fromOwnedSlice(encoded);
        const len = list.items.len;
        if (self.kind == .insert) {
            try list.insert(arena, self.position % (len + 1), self.value);
        } else {
            if (len == 0) return null;
            const at = self.position % len;
            switch (self.kind) {
                .flip => list.items[at] ^= @as(u8, 1) << @intCast(self.value % 8),
                .delete => _ = list.orderedRemove(at),
                .replace => list.items[at] = self.value,
                .swap => std.mem.swap(u8, &list.items[at], &list.items[self.second % len]),
                .insert => unreachable,
            }
        }
        return codec.decode_cfg(T, arena, list.items, {}) catch |err| switch (err) {
            error.OutOfMemory => err,
            else => null,
        };
    }
};

/// What the senders of a case promised and what its close posted. Whatever verifies must
/// agree with it.
const Case = struct {
    namespace: bajillion.Namespace,
    operator: PublicKey,
    /// The accounts, in the order the amounts below index them.
    accounts: [accounts_count]PublicKey,
    /// The countersigned state of each sender, or null if its map pays no one.
    states: [accounts_count]?State,
    promised: Grid,
    posted: Grid,
    /// The root of each sender's row in the posted matrix, if it has one.
    rows: [accounts_count]?Digest,
    /// The root of the posted matrix.
    root: Digest,

    /// The index of `account`; a verified proof must name one of the case's accounts.
    fn index(self: *const Case, account: *const PublicKey) !usize {
        for (self.accounts, 0..) |candidate, position| {
            if (candidate.eql(account.*)) return position;
        }
        return error.UnknownAccount;
    }

    /// Checks that `opening` verifies for any sender only as that sender's posted row, and for
    /// any pair only as what the close credits that pair.
    fn check_opening(self: *const Case, opening: *const Opening) !void {
        for (&self.accounts, 0..) |*account, sender| {
            if (opening.verify_row(Sha256, &self.root, account)) |row| {
                try expect_equal_row(row, self.rows[sender]);
            } else |_| {}
            for (&self.accounts, 0..) |*paid, receiver| {
                const credited = opening.verify(Sha256, &self.root, account, paid) catch continue;
                try testing.expectEqual(self.posted[sender][receiver], credited);
            }
        }
    }

    /// Whether `receipt` verifies. A receipt that verifies must carry its sender's
    /// countersigned state, both signatures over it, and the amount the sender promised.
    fn check_receipt(self: *const Case, receipt: *const Receipt) !bool {
        if (!receipt.verify(Sha256, &self.namespace, &self.operator)) return false;
        const state = receipt.state;
        const message = state.message();
        const account = state.account;
        try testing.expect(account.verify(self.namespace.state, &message, &receipt.signature));
        const ack = &receipt.acknowledgement;
        try testing.expect(self.operator.verify(self.namespace.acknowledgement, &message, ack));
        const sender = try self.index(&state.account);
        const receiver = try self.index(&receipt.receiver);
        try testing.expect(self.states[sender] != null);
        try testing.expect(self.states[sender].?.eql(state));
        try testing.expectEqual(self.promised[sender][receiver], receipt.amount);
        try testing.expect(receipt.amount != 0);
        return true;
    }

    /// Checks that `challenge` verifies against the posted matrix only with a receipt its
    /// sender issued for more than the close credits.
    fn check_challenge(self: *const Case, challenge: *const Challenge) !void {
        challenge.verify(Sha256, &self.namespace, &self.operator, epoch, &self.root) catch
            return;
        const receipt = &challenge.receipt;
        try testing.expect(try self.check_receipt(receipt));
        const sender = try self.index(&receipt.state.account);
        const receiver = try self.index(&receipt.receiver);
        try testing.expect(self.posted[sender][receiver] < receipt.amount);
    }
};

fn expect_equal_row(found: ?Digest, expected: ?Digest) !void {
    try testing.expectEqual(expected != null, found != null);
    if (expected) |digest| try testing.expect(digest.eql(found.?));
}

/// The amounts of `row` paid to the matching accounts, without zeros.
fn amounts(arena: Allocator, accounts: *const [accounts_count]PublicKey, row: [4]u64) !Amounts {
    var entries: [accounts_count]Amounts.Entry = undefined;
    var count: usize = 0;
    for (accounts, row) |account, amount| {
        if (amount == 0) continue;
        entries[count] = .{ account, amount };
        count += 1;
    }
    return Amounts.init(arena, entries[0..count]);
}

fn read_grid(reader: *bytes.Reader) Grid {
    var grid: Grid = undefined;
    for (&grid) |*row| {
        for (row) |*amount| amount.* = reader.int(u8);
    }
    return grid;
}

/// The receipts each sender whose map pays anyone issues to its receivers, after signing its
/// state and having the operator countersign it.
fn issue_receipts(arena: Allocator, case: *Case) ![]Receipt {
    const operator = operator_key();
    const previous = Amounts.empty.root(Sha256);
    var receipts: std.ArrayList(Receipt) = .empty;
    for (case.promised, 0..) |row, sender| {
        const payments = try amounts(arena, &case.accounts, row);
        case.states[sender] = null;
        if (payments.is_empty()) continue;
        const state: State = .{
            .epoch = epoch,
            .account = case.accounts[sender],
            .payments = payments.root(Sha256),
            .previous = previous,
        };
        const signer = user(sender);
        const signature = state.sign(&signer, &case.namespace);
        const acknowledgement = state.acknowledge(&operator, &case.namespace);
        const receivers = try arena.alloc(PublicKey, payments.len());
        for (payments.entries, receivers) |entry, *receiver| receiver.* = entry[0];
        const issued = try Receipt.issue(
            Sha256,
            arena,
            state,
            signature,
            acknowledgement,
            &payments,
            receivers,
        ) orelse return error.UnopenedReceiver;
        try receipts.appendSlice(arena, issued);
        case.states[sender] = state;
    }
    return receipts.items;
}

/// The posted matrix: the close settles the posted rows, whatever the senders signed. Assembly
/// checks no row's signature, so every row carries the same one.
fn post(arena: Allocator, case: *Case) !Matrix {
    const operator = operator_key();
    const signature = operator.sign(case.namespace.state, "");
    var rows: std.ArrayList(bajillion.Row(PublicKey, u64)) = .empty;
    for (case.posted, &case.accounts) |row, account| {
        const payments = try amounts(arena, &case.accounts, row);
        if (payments.is_empty()) continue;
        const posted: bajillion.Row(PublicKey, u64) = .{
            .account = account,
            .payments = payments,
            .signature = signature,
        };
        try rows.append(arena, posted);
    }
    const queue: bajillion.Queue(PublicKey, u64) = .{
        .epoch = epoch,
        .deposits = &.{},
        .required_deposits = 0,
        .forced_withdrawals = &.{},
        .required_forced_withdrawals = 0,
    };
    const assembled = try Close.assemble(
        Sha256,
        arena,
        &operator,
        &case.namespace,
        &queue,
        try rows.toOwnedSlice(arena),
        try arena.alloc(Close.WithdrawalType, 0),
        0,
        0,
        parallel.sequential,
    );
    const matrix = try assembled.close.matrix(Sha256, arena, parallel.sequential);
    for (&case.accounts, &case.rows) |*account, *row| row.* = matrix.payments_root(account);
    case.root = matrix.root();
    return matrix;
}

/// The opening of every sender and receiver verifies as what the close credits them.
fn check_honest_openings(arena: Allocator, case: *const Case, matrix: *const Matrix) !void {
    for (&case.accounts, 0..) |*account, sender| {
        for (&case.accounts, 0..) |*paid, receiver| {
            const opening = try matrix.open(arena, account, paid);
            const row = try opening.verify_row(Sha256, &case.root, account);
            try expect_equal_row(row, case.rows[sender]);
            const credited = try opening.verify(Sha256, &case.root, account, paid);
            try testing.expectEqual(case.posted[sender][receiver], credited);
            try case.check_opening(&opening);
        }
    }
}

/// A sender and receiver's indices, the opening of their entry, and the receipt the sender
/// issued the receiver, if any.
const Pair = struct {
    sender: usize,
    receiver: usize,
    opening: Opening,
    receipt: ?Receipt,

    fn pick(
        arena: Allocator,
        reader: *bytes.Reader,
        case: *const Case,
        matrix: *const Matrix,
        receipts: []const Receipt,
    ) !Pair {
        const sender = reader.int(u8) % accounts_count;
        const receiver = reader.int(u8) % accounts_count;
        const account = &case.accounts[sender];
        const paid = &case.accounts[receiver];
        var found: ?Receipt = null;
        for (receipts) |receipt| {
            if (receipt.state.account.eql(account.*) and receipt.receiver.eql(paid.*)) {
                found = receipt;
            }
        }
        const opening = try matrix.open(arena, account, paid);
        return .{ .sender = sender, .receiver = receiver, .opening = opening, .receipt = found };
    }
};

/// A receipt the sender issued verifies. With the opening of its sender and receiver, it is a
/// challenge exactly when the close credits less than it promises, and only for its epoch.
fn check_pair(case: *const Case, pair: *const Pair) !void {
    const receipt = pair.receipt orelse return;
    try testing.expect(try case.check_receipt(&receipt));
    const challenge: Challenge = .{ .receipt = receipt, .opening = pair.opening };
    const promised = case.promised[pair.sender][pair.receiver];
    const contradicted = case.posted[pair.sender][pair.receiver] < promised;
    const ns = &case.namespace;
    const verified = challenge.verify(Sha256, ns, &case.operator, epoch, &case.root);
    try testing.expectEqual(contradicted, std.meta.isError(verified) == false);
    for ([_]bajillion.Epoch{ epoch - 1, epoch + 1 }) |other| {
        const result = challenge.verify(Sha256, ns, &case.operator, other, &case.root);
        try testing.expectError(error.WrongEpoch, result);
    }
}

/// Proofs spliced from the parts of two honest ones verify only as the case holds.
fn check_spliced(case: *const Case, pair: *const Pair, other: *const Pair) !void {
    const spliced = [_]Opening{
        .{ .row = pair.opening.row, .entry = other.opening.entry },
        .{ .row = other.opening.row, .entry = pair.opening.entry },
        .{ .row = pair.opening.row, .entry = null },
    };
    for (&spliced) |*opening| {
        try case.check_opening(opening);
        if (pair.receipt) |receipt| {
            try case.check_challenge(&.{ .receipt = receipt, .opening = opening.* });
        }
    }
    const receipt = pair.receipt orelse return;
    const issued = other.receipt orelse return;
    var amount = receipt;
    amount.amount = issued.amount;
    _ = try case.check_receipt(&amount);
    var state = receipt;
    state.state = issued.state;
    state.signature = issued.signature;
    state.acknowledgement = issued.acknowledgement;
    _ = try case.check_receipt(&state);
}

/// Each change to bytes keeps what still decodes, and whatever then verifies must agree with
/// the case.
fn check_mutations(arena: Allocator, reader: *bytes.Reader, case: *const Case, pair: *Pair) !void {
    const count = reader.below(mutations_max + 1);
    for (0..count) |_| {
        const mutation = Mutation.read(reader);
        if (try mutation.apply(Opening, arena, &pair.opening)) |changed| pair.opening = changed;
        try case.check_opening(&pair.opening);
        const receipt = &(pair.receipt orelse continue);
        if (try mutation.apply(Receipt, arena, receipt)) |changed| pair.receipt = changed;
        _ = try case.check_receipt(&pair.receipt.?);
        const challenge: Challenge = .{ .receipt = pair.receipt.?, .opening = pair.opening };
        try case.check_challenge(&challenge);
        if (try mutation.apply(Challenge, arena, &challenge)) |changed| {
            try case.check_challenge(&changed);
        }
    }
}

/// Builds the honest proofs of a case and checks them, then checks that no change to the
/// proofs of one sender and receiver makes them verify as anything the case does not hold.
fn check_payments(arena: Allocator, reader: *bytes.Reader) !void {
    var case: Case = .{
        .namespace = try bajillion.Namespace.init(arena, namespace_bytes),
        .operator = operator_key().public_key(),
        .accounts = undefined,
        .states = undefined,
        .promised = read_grid(reader),
        .posted = read_grid(reader),
        .rows = undefined,
        .root = undefined,
    };
    for (&case.accounts, 0..) |*account, index| account.* = user(index).public_key();
    const receipts = try issue_receipts(arena, &case);
    const matrix = try post(arena, &case);
    try check_honest_openings(arena, &case, &matrix);
    var pair = try Pair.pick(arena, reader, &case, &matrix, receipts);
    try check_pair(&case, &pair);
    const other = try Pair.pick(arena, reader, &case, &matrix, receipts);
    try check_spliced(&case, &pair, &other);
    try check_mutations(arena, reader, &case, &pair);
}

fn Generated(comptime T: type) type {
    return struct {
        fn generate(allocator: Allocator, u: *arb.Unstructured) arb.Error!T {
            return arb.value(T, allocator, u);
        }
    };
}

fn generate(comptime T: type, arena: Allocator, seed: u64) !?T {
    return codec.arbitrary.generate(T, Generated(T).generate, arena, seed) catch |err|
        switch (err) {
            error.OutOfMemory => err,
            else => null,
        };
}

/// Arbitrary proofs must be judged without a crash, whatever they are checked against.
fn arbitrary_proof(arena: Allocator, choice: u64, seed: u64, namespace: anytype) !void {
    switch (choice) {
        0 => {
            const opening, const root, const sender, const receiver =
                try generate(struct { Opening, Digest, PublicKey, PublicKey }, arena, seed) orelse
                return;
            _ = opening.verify_row(Sha256, &root, &sender) catch null;
            _ = opening.verify(Sha256, &root, &sender, &receiver) catch 0;
        },
        1 => {
            const receipt, const operator =
                try generate(struct { Receipt, PublicKey }, arena, seed) orelse return;
            _ = receipt.verify(Sha256, namespace, &operator);
        },
        2 => {
            const challenge, const operator, const root =
                try generate(struct { Challenge, PublicKey, Digest }, arena, seed) orelse return;
            const at = challenge.receipt.state.epoch;
            challenge.verify(Sha256, namespace, &operator, at, &root) catch {};
        },
        3 => {
            const proof, const root =
                try generate(struct { PayoutProof, Digest }, arena, seed) orelse return;
            _ = proof.verify(Sha256, &root);
        },
        4 => {
            const proof, const root, const account =
                try generate(struct { BalanceProof, Digest, PublicKey }, arena, seed) orelse
                return;
            _ = proof.verify(Sha256, PublicKey, &root, account);
        },
        else => unreachable,
    }
}

/// One fuzz input: an arbitrary proof, or a payments case.
pub fn run_one(input: []const u8) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var reader = bytes.Reader.init(input);
    const choice = reader.below(6);
    if (choice == 5) return check_payments(arena, &reader);
    const namespace = try bajillion.Namespace.init(arena, namespace_bytes);
    try arbitrary_proof(arena, choice, reader.int(u32), &namespace);
}

test "fuzz clearing verifiers (seeded)" {
    // Signatures and key derivation dominate; Debug runs a few cases, ReleaseSafe many more.
    const iterations: u32 = if (builtin.mode == .debug) 8 else 256;
    try bytes.seeded(160, 0x636c_6561_7276_6572, iterations, run_one);
}

test "fuzz clearing verifiers" {
    try testing.fuzz({}, bytes.smith(512, run_one), .{});
}
