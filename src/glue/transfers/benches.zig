//! Benchmarks of transfers' CPU stages over batches of payments, ported from commonware
//! `glue/src/transfers/benches` with its names (`transfers::plan`, `transfers::settle`, and
//! `transfers::select`, each `/transfers=N accounts=M effects=E conc=C`) and constants.
//!
//! Each batch's payments come from a fresh `test_rng`, like the reference's `payments`. The
//! parallel rows run on a pool of `conc` threads (the caller and `conc - 1` workers). Plans and
//! selections key their hash with seed 0, where the reference keys each one randomly; the
//! key order they produce does not change their cost.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const bench = @import("bench");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const transfers = @import("glue").transfers;

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const rng_mod = utils.rng;

/// Workers in the pool behind the parallel rows, the caller included.
const concurrency = 8;
/// Payments per benchmarked batch.
const transfer_counts = [_]usize{ 16, 1_024, 32_768, 131_072 };
/// Numbers of distinct keys the payments draw from.
const account_counts = [_]u64{ 128, 4_096, 1_000_000 };
/// Starting balance of every account, more than any key's debits in a batch.
const start_balance: u64 = 1 << 40;
/// The hash key of every plan and selection.
const seed = 0;

/// An account that holds only a balance.
const Balance = struct {
    value: u64,

    pub const Amount = u64;
    pub const Effect = enum {};
    pub const default: Balance = .{ .value = 0 };
    const start: Balance = .{ .value = start_balance };

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

/// An account that holds a balance and the next nonce its payments consume.
const Nonced = struct {
    value: u64,
    nonce: u64,

    pub const Amount = u64;
    pub const Effect = u64;
    pub const default: Nonced = .{ .value = 0, .nonce = 0 };
    const start: Nonced = .{ .value = start_balance, .nonce = 0 };

    pub fn balance(self: *const Nonced) u64 {
        return self.value;
    }

    pub fn set_balance(self: *Nonced, value: u64) void {
        self.value = value;
    }

    pub fn apply(self: *Nonced, nonce: u64) bool {
        if (nonce != self.nonce) return false;
        self.nonce += 1;
        return true;
    }
};

/// A payment from one key to another; with `Nonced` accounts its sender also consumes `nonce`.
fn PaymentOf(comptime A: type) type {
    return struct {
        const Self = @This();
        pub const Key = Digest;
        pub const Account = A;
        const Entry = transfers.Entry(Digest, A);

        from: Digest,
        to: Digest,
        amount: u64,
        nonce: u64 = 0,

        pub fn changes(self: *const Self) Changes {
            return .{ .payment = self };
        }

        pub const Changes = struct {
            payment: *const Self,
            index: u8 = 0,

            pub fn next(it: *Changes) ?Entry {
                defer it.index += 1;
                const payment = it.payment;
                const debit: transfers.Change(A) = .debiting(payment.amount);
                const sender = if (A == Nonced) debit.with_effect(payment.nonce) else debit;
                return switch (it.index) {
                    0 => .{ .key = &payment.from, .change = sender },
                    1 => .{ .key = &payment.to, .change = .crediting(payment.amount) },
                    else => null,
                };
            }
        };
    };
}

const Payment = PaymentOf(Balance);
const Signed = PaymentOf(Nonced);

/// The key of account `index`.
fn key(index: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, index, .big);
    return Sha256.hash(&.{&bytes});
}

/// `count` payments between random keys among the first `accounts`, from a fresh `test_rng`.
fn payments(gpa: Allocator, count: usize, accounts: u64) ![]Payment {
    var rng = rng_mod.test_rng();
    const result = try gpa.alloc(Payment, count);
    for (result) |*payment| {
        const from = rng_mod.range_less_than(&rng, u64, 0, accounts);
        const to = rng_mod.range_less_than(&rng, u64, 0, accounts);
        const amount = rng_mod.range_less_than(&rng, u64, 1, 10);
        payment.* = .{ .from = key(from), .to = key(to), .amount = amount };
    }
    return result;
}

/// `list` with each sender's nonces assigned in order from zero.
fn signed(gpa: Allocator, list: []const Payment) ![]Signed {
    var nonces: std.AutoHashMapUnmanaged(Digest, u64) = .empty;
    defer nonces.deinit(gpa);
    const result = try gpa.alloc(Signed, list.len);
    errdefer gpa.free(result);
    for (list, result) |payment, *out| {
        const entry = try nonces.getOrPut(gpa, payment.from);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        out.* = .{
            .from = payment.from,
            .to = payment.to,
            .amount = payment.amount,
            .nonce = entry.value_ptr.*,
        };
        entry.value_ptr.* += 1;
    }
    return result;
}

const Stage = enum { plan, settle, select };

/// Plans, settles, or selects `list` each iteration on `strategy`.
fn Workload(comptime T: type, comptime Strategy: type) type {
    const A = T.Account;
    const Plan = transfers.Plan(T.Key, A);
    return struct {
        const Self = @This();

        gpa: Allocator,
        stage: Stage,
        list: []const T,
        strategy: Strategy,
        /// The plan `settle` settles, built untimed.
        plan: ?Plan = null,
        /// Every planned key's starting account, for `settle`.
        reads: []?A = &.{},
        accepted: []bool = &.{},

        pub fn setup(self: *Self) !void {
            self.accepted = try self.gpa.alloc(bool, self.list.len);
            if (self.stage != .settle) return;
            var rejection: Plan.Rejection = undefined;
            self.plan = try Plan.init(self.gpa, self.list, seed, parallel.sequential, &rejection);
            self.reads = try self.gpa.alloc(?A, self.plan.?.len());
            @memset(self.reads, A.start);
        }

        pub fn iter(self: *Self) !usize {
            return switch (self.stage) {
                .plan => self.iter_plan(),
                .settle => self.iter_settle(),
                .select => self.iter_select(),
            };
        }

        fn iter_plan(self: *Self) !usize {
            var rejection: Plan.Rejection = undefined;
            var plan = try Plan.init(self.gpa, self.list, seed, self.strategy, &rejection);
            defer plan.deinit(self.gpa);
            assert(plan.len() > 0);
            return plan.len();
        }

        fn iter_settle(self: *Self) !usize {
            const plan = &self.plan.?;
            var rejection: Plan.Rejection = undefined;
            const slots = try plan.settle(self.gpa, self.reads, self.strategy, &rejection);
            defer self.gpa.free(slots);
            assert(slots.len == plan.len());
            return slots.len;
        }

        /// Selects every transfer in one round from keys that all start at `A.start` and
        /// accept every transfer.
        fn iter_select(self: *Self) !usize {
            const gpa = self.gpa;
            var selection = transfers.Selection(T.Key, A).init(seed);
            defer selection.deinit(gpa);
            const touched = try selection.touch(gpa, self.list);
            const reads = try gpa.alloc(?A, touched.len());
            defer gpa.free(reads);
            @memset(reads, A.start);
            try selection.register(gpa, reads);
            try selection.apply(gpa, self.list, self.accepted);
            const slots = try selection.settle(gpa, self.strategy);
            defer gpa.free(slots);
            assert(slots.len == touched.len());
            return slots.len;
        }

        pub fn teardown(self: *Self) void {
            if (self.plan) |*plan| plan.deinit(self.gpa);
            self.gpa.free(self.reads);
            self.gpa.free(self.accepted);
            self.plan = null;
            self.reads = &.{};
            self.accepted = &.{};
        }
    };
}

const Case = struct { transfers: usize, accounts: u64, conc: usize };

fn bench_list(
    runner: *bench.Runner,
    stage: Stage,
    case: Case,
    list: anytype,
    strategy: anytype,
) !void {
    const T = @typeInfo(@TypeOf(list)).pointer.child;
    var workload: Workload(T, @TypeOf(strategy)) = .{
        .gpa = runner.allocator,
        .stage = stage,
        .list = list,
        .strategy = strategy,
    };
    const benchmark = bench.Benchmark.init(switch (stage) {
        .plan => "transfers::plan",
        .settle => "transfers::settle",
        .select => "transfers::select",
    })
        .with_param("transfers", case.transfers)
        .with_param("accounts", case.accounts)
        .with_param("effects", if (T == Signed) "nonce" else "none")
        .with_param("conc", case.conc);
    try runner.run(benchmark, &workload);
}

/// Runs one stage over `case`'s payments and the same payments with nonces, on one thread and
/// on a pool of `concurrency` threads.
fn bench_case(
    runner: *bench.Runner,
    stage: Stage,
    case: Case,
    list: []const Payment,
    nonced: []const Signed,
) !void {
    assert(list.len == case.transfers and nonced.len == case.transfers);
    const pool = try parallel.ThreadPool.create(runner.allocator, runner.io, .{
        .threads = concurrency - 1,
    });
    defer pool.destroy();
    const strategy = parallel.Rayon.init(pool);
    var pooled = case;
    pooled.conc = concurrency;
    try bench_list(runner, stage, case, list, parallel.sequential);
    try bench_list(runner, stage, pooled, list, strategy);
    try bench_list(runner, stage, case, nonced, parallel.sequential);
    try bench_list(runner, stage, pooled, nonced, strategy);
}

pub fn run(runner: *bench.Runner) !void {
    const gpa = runner.allocator;
    const inputs = runner.inputs;
    const counts = inputs.pick([]const usize, &.{16}, transfer_counts[0..3], &transfer_counts);
    const accounts_list = inputs.pick([]const u64, &.{128}, &account_counts, &account_counts);
    // The reference runs every plan bench, then every settle bench, then every select bench.
    for ([_]Stage{ .plan, .settle, .select }) |stage| {
        for (counts) |count| for (accounts_list) |accounts| {
            const list = try payments(gpa, count, accounts);
            defer gpa.free(list);
            const nonced = try signed(gpa, list);
            defer gpa.free(nonced);
            const case: Case = .{ .transfers = count, .accounts = accounts, .conc = 1 };
            try bench_case(runner, stage, case, list, nonced);
        };
    }
}
