//! Benchmarks of clearing's hot paths. commonware's clearing crate has no benches, so these
//! are zigware's own: the root of a payment map, opening and verifying one payment in a
//! matrix, and the validators' check of a close (dominated by its signatures).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const clearing = @import("clearing");
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const bajillion = clearing.bajillion;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Amounts = bajillion.Amounts(PublicKey, u64);
const Matrix = bajillion.Matrix(PublicKey, Sha256, u64);
const Close = bajillion.Close(PublicKey, PublicKey, u64);
const Row = Close.RowType;
const Checked = bajillion.Checked(PublicKey, Sha256, u64);
const Checkpoint = bajillion.Checkpoint(PublicKey, Sha256, u64);

const namespace_bytes = "_COMMONWARE_CLEARING_BAJILLION_BENCH";
const epoch: bajillion.Epoch = 1;

fn key_less(_: void, a: PrivateKey, b: PrivateKey) bool {
    return a.public_key().order(b.public_key()) == .lt;
}

/// `count` signing keys, in increasing order of their accounts.
fn keys(gpa: Allocator, count: usize) ![]PrivateKey {
    const result = try gpa.alloc(PrivateKey, count);
    for (result, 0..) |*key, index| key.* = PrivateKey.from_seed(index);
    std.mem.sort(PrivateKey, result, {}, key_less);
    return result;
}

/// The root of a payment map with `len` receivers.
const RootWorkload = struct {
    payments: *const Amounts,

    pub fn iter(workload: *RootWorkload) Digest {
        return workload.payments.root(Sha256);
    }
};

/// Opens and verifies the payment of one sender to its receiver, cycling through the senders.
const OpenWorkload = struct {
    gpa: Allocator,
    matrix: *const Matrix,
    accounts: []const PublicKey,
    root: Digest,
    next: usize = 0,

    pub fn iter(workload: *OpenWorkload) !u64 {
        const count = workload.accounts.len;
        const sender = &workload.accounts[workload.next];
        const receiver = &workload.accounts[(workload.next + 1) % count];
        workload.next = (workload.next + 1) % count;
        var opening = try workload.matrix.open(workload.gpa, sender, receiver);
        defer opening.deinit(workload.gpa);
        const amount = try opening.verify(Sha256, &workload.root, sender, receiver);
        assert(amount == 1);
        return amount;
    }
};

/// The validators' check of a close of `rows` senders, each paying the next one.
const CheckWorkload = struct {
    gpa: Allocator,
    close: *const Close,
    namespace: *const bajillion.Namespace,
    operator: PublicKey,
    parent: *const Checkpoint,
    queue: bajillion.Queue(PublicKey, u64),

    pub fn iter(workload: *CheckWorkload) !u64 {
        var checked = try Checked.check(
            PublicKey,
            workload.gpa,
            workload.close,
            workload.namespace,
            &workload.operator,
            workload.parent,
            &workload.queue,
            parallel.sequential,
        );
        defer checked.deinit(workload.gpa);
        return checked.matrix.rows().len;
    }
};

/// Signed rows of `users`, each paying the next user 1 on top of the empty map.
fn rows_of(
    gpa: Allocator,
    users: []const PrivateKey,
    namespace: *const bajillion.Namespace,
) ![]Row {
    const rows = try gpa.alloc(Row, users.len);
    var built: usize = 0;
    errdefer {
        for (rows[0..built]) |*row| row.deinit(gpa);
        gpa.free(rows);
    }
    const previous = Amounts.empty.root(Sha256);
    for (users, rows, 0..) |*signer, *row, index| {
        const receiver = users[(index + 1) % users.len].public_key();
        const payments = try Amounts.init(gpa, &.{.{ receiver, 1 }});
        const state: bajillion.State(PublicKey, Digest) = .{
            .epoch = epoch,
            .account = signer.public_key(),
            .payments = payments.root(Sha256),
            .previous = previous,
        };
        row.* = .{
            .account = state.account,
            .payments = payments,
            .signature = state.sign(signer, namespace),
        };
        built += 1;
    }
    return rows;
}

fn run_root(runner: *bench.Runner, users: []const PrivateKey) !void {
    const gpa = runner.allocator;
    const entries = try gpa.alloc(Amounts.Entry, users.len);
    defer gpa.free(entries);
    for (users, entries) |*key, *entry| entry.* = .{ key.public_key(), 1 };
    var payments = try Amounts.init(gpa, entries);
    defer payments.deinit(gpa);
    var workload: RootWorkload = .{ .payments = &payments };
    const name = bench.Benchmark.init("clearing::amounts_root").with_param("len", users.len);
    try runner.run(name, &workload);
}

fn run_close(runner: *bench.Runner, users: []const PrivateKey) !void {
    const gpa = runner.allocator;
    var namespace = try bajillion.Namespace.init(gpa, namespace_bytes);
    defer namespace.deinit(gpa);
    const operator = PrivateKey.from_seed(std.math.maxInt(u64));
    var close = try Close.sign(
        Sha256,
        gpa,
        &operator,
        &namespace,
        epoch,
        try rows_of(gpa, users, &namespace),
        try gpa.alloc(Close.WithdrawalType, 0),
        0,
        0,
        parallel.sequential,
    );
    defer close.deinit(gpa);
    var matrix = try close.matrix(Sha256, gpa, parallel.sequential);
    defer matrix.deinit();
    const accounts = try gpa.alloc(PublicKey, users.len);
    defer gpa.free(accounts);
    for (users, accounts) |*key, *account| account.* = key.public_key();

    var open: OpenWorkload = .{
        .gpa = gpa,
        .matrix = &matrix,
        .accounts = accounts,
        .root = matrix.root(),
    };
    const open_name = bench.Benchmark.init("clearing::matrix_open").with_param("rows", users.len);
    try runner.run(open_name, &open);

    var parent: Checkpoint = .{
        .summary = .genesis(PublicKey, u64, Sha256.hash(&.{"balances"})),
        .matrix = try Matrix.empty(gpa),
    };
    defer parent.deinit();
    var check: CheckWorkload = .{
        .gpa = gpa,
        .close = &close,
        .namespace = &namespace,
        .operator = operator.public_key(),
        .parent = &parent,
        .queue = .{
            .epoch = epoch,
            .deposits = &.{},
            .required_deposits = 0,
            .forced_withdrawals = &.{},
            .required_forced_withdrawals = 0,
        },
    };
    const check_name = bench.Benchmark.init("clearing::close_check").with_param("rows", users.len);
    try runner.run(check_name, &check);
}

pub fn run(runner: *bench.Runner) !void {
    const count = runner.inputs.pick(usize, 4, 256, 4_096);
    const users = try keys(runner.allocator, count);
    defer runner.allocator.free(users);
    assert(users.len == count);
    try run_root(runner, users);
    try run_close(runner, users);
}
