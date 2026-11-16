//! Helpers shared by the unit tests (commonware `bajillion/tests.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const mod = @import("mod.zig");
const summary = @import("summary.zig");
const validator = @import("validator.zig");
const metrics = runtime.telemetry.metrics;
const test_gpa = std.testing.allocator;

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const PrivateKey = cryptography.ed25519.PrivateKey;
pub const PublicKey = cryptography.ed25519.PublicKey;
pub const Signature = cryptography.ed25519.Signature;
pub const TestAmounts = mod.Amounts(PublicKey, u64);
pub const TestClose = mod.Close(PublicKey, PublicKey, u64);
pub const Row = TestClose.RowType;
pub const Withdrawal = TestClose.WithdrawalType;
pub const Queue = TestClose.QueueType;
pub const Deposit = mod.Deposit(PublicKey, u64);
pub const Forced = mod.ForcedWithdrawal(PublicKey, u64);
pub const Checkpoint = validator.Checkpoint(PublicKey, Sha256, u64);
pub const Checked = validator.Checked(PublicKey, Sha256, u64);
pub const TestSummary = summary.Summary(Sha256);
pub const Log = validator.Payouts(PublicKey, Sha256, u64);
pub const BalanceProof = validator.BalanceProof(Digest, u64);
/// The plain unordered index over translator `T` that a balances database may use.
pub fn Index(comptime T: type) type {
    return storage.index.unordered.Index(T, u64);
}
/// The balances database over the index `I`.
pub fn Db(comptime I: type) type {
    return validator.Balances(PublicKey, Sha256, I, u64);
}
/// The balances database commonware's tests use by default.
pub const DefaultIndex = Index(storage.translator.EightCap);

/// Namespace of the deployment under test.
pub const namespace_bytes = "_COMMONWARE_CLEARING_BAJILLION_TEST";

/// Returns the signature namespaces of the deployment under test.
pub fn namespace(gpa: Allocator) !mod.Namespace {
    return mod.Namespace.init(gpa, namespace_bytes);
}

/// Returns the signing key of user `index`.
pub fn user(index: u64) PrivateKey {
    return PrivateKey.from_seed(index);
}

/// Returns the account of user `index`.
pub fn account(index: u64) PublicKey {
    return user(index).public_key();
}

/// Returns the operator's signing key.
pub fn operator_key() PrivateKey {
    return PrivateKey.from_seed(1_000);
}

fn key_less(_: void, a: PrivateKey, b: PrivateKey) bool {
    return a.public_key().order(b.public_key()) == .lt;
}

/// Returns the signing keys of users `0..count`, in increasing order of their accounts.
pub fn users(comptime count: usize) [count]PrivateKey {
    var result: [count]PrivateKey = undefined;
    for (&result, 0..) |*key, index| key.* = user(index);
    std.mem.sort(PrivateKey, &result, {}, key_less);
    return result;
}

/// Returns the accounts of users `0..count` in increasing order.
pub fn accounts(comptime count: usize) [count]PublicKey {
    var result: [count]PublicKey = undefined;
    for (users(count), &result) |key, *public_key| public_key.* = key.public_key();
    for (result[0..count -| 1], result[@min(1, count)..]) |a, b| assert(a.order(b) == .lt);
    return result;
}

/// Returns amounts paying user `index` its `amount` for each `{ index, amount }`.
pub fn amounts(gpa: Allocator, entries: []const [2]u64) !TestAmounts {
    var list: std.ArrayList(TestAmounts.Entry) = .empty;
    defer list.deinit(gpa);
    for (entries) |entry| try list.append(gpa, .{ account(entry[0]), entry[1] });
    return TestAmounts.init(gpa, list.items);
}

/// Returns the root of the empty payment map.
pub fn empty_root() Digest {
    return TestAmounts.empty.root(Sha256);
}

/// Returns a row of `sender` for `epoch` paying `entries`, signed on top of `previous`.
pub fn row(epoch: u64, sender: u64, entries: []const [2]u64, previous: Digest) !Row {
    var derived = try namespace(test_gpa);
    defer derived.deinit(test_gpa);
    const payments = try amounts(test_gpa, entries);
    const state: mod.State(PublicKey, Digest) = .{
        .epoch = epoch,
        .account = account(sender),
        .payments = payments.root(Sha256),
        .previous = previous,
    };
    const signer = user(sender);
    return .{
        .account = account(sender),
        .payments = payments,
        .signature = state.sign(&signer, &derived),
    };
}

pub fn less_row(_: void, a: Row, b: Row) bool {
    return a.account.order(b.account) == .lt;
}

/// Signs a close of `rows` and `withdrawals` as `operator`, without checking its contents.
/// Takes ownership of the rows.
pub fn sign_close(
    operator: *const PrivateKey,
    epoch: u64,
    rows: []const Row,
    withdrawals: []const Withdrawal,
    deposits: u64,
    forced_withdrawals: u64,
) !TestClose {
    var derived = try namespace(test_gpa);
    defer derived.deinit(test_gpa);
    const owned_rows = try test_gpa.dupe(Row, rows);
    std.mem.sort(Row, owned_rows, {}, less_row);
    const owned_withdrawals = try test_gpa.dupe(Withdrawal, withdrawals);
    return TestClose.sign(
        Sha256,
        test_gpa,
        operator,
        &derived,
        epoch,
        owned_rows,
        owned_withdrawals,
        deposits,
        forced_withdrawals,
        parallel.sequential,
    );
}

pub fn queue(
    epoch: u64,
    deposits: []const Deposit,
    forced: []const Forced,
) Queue {
    return .{
        .epoch = epoch,
        .deposits = deposits,
        .required_deposits = 0,
        .forced_withdrawals = forced,
        .required_forced_withdrawals = 0,
    };
}

/// Checks `close` as the successor of `parent` against `queue`, then frees the close.
pub fn check(close: TestClose, parent: *const Checkpoint, ledger: *const Queue) !Checked {
    var owned = close;
    defer owned.deinit(test_gpa);
    var derived = try namespace(test_gpa);
    defer derived.deinit(test_gpa);
    const operator = operator_key().public_key();
    return Checked.check(
        PublicKey,
        test_gpa,
        &owned,
        &derived,
        &operator,
        parent,
        ledger,
        parallel.sequential,
    );
}

/// Returns `hash` extended by `H(hash || request)` for each of `requests`.
pub fn chain(comptime R: type, hash: Digest, requests: []const R) Digest {
    var result = hash;
    for (requests) |request| {
        const encoded = codec.encode_fixed(R, request);
        result = Sha256.hash(&.{ &result.bytes, &encoded });
    }
    return result;
}

/// Returns the checkpoint before the first close, on top of a balances database with root
/// `balances`.
pub fn genesis(balances: Digest) !Checkpoint {
    return .{
        .summary = TestSummary.genesis(PublicKey, u64, balances),
        .matrix = try mod.Matrix(PublicKey, Sha256, u64).empty(test_gpa),
    };
}

/// In-memory storage for a validator's balances database and payout log (commonware's `open`
/// on the deterministic runtime). Each database registers its metrics afresh when it opens.
pub const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    balances_registry: metrics.Registry,
    log_registry: metrics.Registry,

    pub fn init() !Harness {
        return .{
            .storage = .init(test_gpa),
            .cache_ref = try .init(test_gpa, 101, 11),
            .balances_registry = metrics.Registry.init(test_gpa),
            .log_registry = metrics.Registry.init(test_gpa),
        };
    }

    pub fn deinit(self: *Harness) void {
        self.log_registry.deinit();
        self.balances_registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    /// Opens the payout log at its latest commit with at most `size` operations if given.
    pub fn open_log(self: *Harness, size: ?u64) !Log {
        const cfg: Log.Cfg = .{
            .merkle = self.merkle_config("payouts-merkle-journal", "payouts-merkle-metadata"),
            .log = self.log_config("payouts-log"),
        };
        self.log_registry.deinit();
        self.log_registry = metrics.Registry.init(test_gpa);
        const scope = metrics.Scope.init(&self.log_registry).child("log");
        return Log.init(test_gpa, self.storage.interface(), scope, cfg, size);
    }

    /// Opens the balances database over the index `I` with `translator` at its latest commit
    /// with at most `size` operations if given.
    pub fn open_balances(
        self: *Harness,
        comptime I: type,
        translator: I.Translator,
        size: ?u64,
    ) !Db(I) {
        const cfg: Db(I).Cfg = .{
            .merkle = self.merkle_config("balances-merkle-journal", "balances-merkle-metadata"),
            .log = self.log_config("balances-log"),
            .grafted_metadata_partition = "balances-grafted-metadata",
            .translator = translator,
        };
        self.balances_registry.deinit();
        self.balances_registry = metrics.Registry.init(test_gpa);
        const scope = metrics.Scope.init(&self.balances_registry).child("balances");
        return Db(I).init(test_gpa, self.storage.interface(), scope, cfg, size);
    }

    /// Opens both databases, the balances over the index `I` with `translator`.
    pub fn open(self: *Harness, comptime I: type, translator: I.Translator) !Store(I) {
        var balances = try self.open_balances(I, translator, null);
        errdefer balances.deinit();
        return .{ .balances = balances, .log = try self.open_log(null) };
    }

    fn merkle_config(
        self: *Harness,
        journal: []const u8,
        metadata: []const u8,
    ) storage.merkle.full.Config {
        return .{
            .journal_partition = journal,
            .metadata_partition = metadata,
            .items_per_blob = 7,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &self.cache_ref,
        };
    }

    fn log_config(self: *Harness, partition: []const u8) storage.journal.contiguous.fixed.Config {
        return .{
            .partition = partition,
            .items_per_blob = 7,
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
    }
};

/// A validator's balances database over the index `I`, with its payout log.
pub fn Store(comptime I: type) type {
    return struct {
        const Self = @This();
        pub const Proposal = validator.Proposal(PublicKey, Sha256, u64, Db(I));

        balances: Db(I),
        log: Log,

        pub fn deinit(self: *Self) void {
            self.log.deinit();
            self.balances.deinit();
            self.* = undefined;
        }

        /// Settles `checked` on both databases.
        pub fn settle(self: *Self, checked: *const Checked) !Proposal {
            return checked.settle(test_gpa, &self.balances, &self.log);
        }

        /// Applies `proposal` to both databases as the posted close with digest `posted`.
        pub fn apply(self: *Self, proposal: *const Proposal, posted: *const Digest) !Checkpoint {
            return proposal.apply(&self.balances, &self.log, posted);
        }

        /// Makes the balance writes durable. The log is durable once a close applies.
        pub fn commit(self: *Self) !void {
            try self.balances.commit();
        }

        /// The roots of the balances database and the payout log.
        pub fn roots(self: *const Self) [2]Digest {
            return .{ self.balances.root(), self.log.root() };
        }

        /// Checks, settles, and applies `close` on top of `parent` as its posted successor,
        /// and returns the close's checkpoint. Frees the close.
        pub fn post(
            self: *Self,
            parent: *const Checkpoint,
            close: TestClose,
            ledger: *const Queue,
        ) !Checkpoint {
            var checked = try check(close, parent, ledger);
            defer checked.deinit(test_gpa);
            var proposal = try self.settle(&checked);
            defer proposal.deinit(test_gpa);
            const posted = proposal.summary.digest();
            return self.apply(&proposal, &posted);
        }
    };
}
