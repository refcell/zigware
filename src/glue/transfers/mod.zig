//! Settle batches of balance transfers against a QMDB database (commonware
//! `glue/src/transfers`).
//!
//! Each key holds an account: a balance and any state the application keeps beside it, such
//! as a nonce. A transfer lists the accounts it changes, each with a `Change` holding how much
//! it debits and credits the account and any effect on the account's own state. A batch of
//! transfers settles against its starting accounts, read for its keys before any of its
//! transfers apply.
//!
//! Each key's final balance is its starting balance less the batch's debits plus the batch's
//! credits. Credits never fund debits in the same batch, even within one transfer, so whether
//! a batch settles depends only on its transfers and starting balances, never on their order.
//! Each key's effects apply to its starting account in the order of the transfers and of their
//! changes; an account may refuse an effect. A batch settles all or nothing: a refused effect,
//! an unaffordable debit, or an overflowing balance rejects it with a `Rejection`.
//!
//! A key the database does not hold reads as the default account, and settling an account to
//! the default deletes its key.
//!
//! `Plan` settles a verifier's batch; `Selection` (`select.zig`) chooses a builder's batch
//! candidate by candidate. Both produce one `Slot` per staged key for the batch to merkleize.
//!
//! Contracts (commonware's traits, duck-typed at comptime):
//! - An account type `A` declares `Amount` (an unsigned integer), `Effect` (an empty
//!   `enum {}` when it has none), `pub const default: A`, `balance(*const A) Amount`,
//!   `set_balance(*A, Amount)`, and `apply(*A, Effect) bool`; optionally `eql`, else accounts
//!   compare field by field. Accounts are plain values: a copy is independent of its original.
//! - A transfer type `T` declares `Key` (a type with a unique byte representation, such as
//!   `utils.sequence.FixedBytes(N)`), `Account`, and `changes(*const T) Iterator`, where
//!   `Iterator.next` returns `?Entry(Key, Account)` with keys pointing into the transfer.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const parallel = @import("parallel");
const storage = @import("storage");
const utils = @import("utils");
const handles = utils.handles;
const amount = utils.amount;
const Lookahead = utils.prefetch.Lookahead;

pub const select = @import("select.zig");
pub const Selection = select.Selection;

const max_chunks = parallel.max_chunks;

/// What a staged merkleize does with the key of one staged read: keep, put, or delete
/// (commonware `qmdb::any::batch::Slot`).
pub const Slot = storage.qmdb.any.batch.Slot;

/// Why a batch cannot settle.
pub const Reason = enum {
    /// The key's account refuses one of its effects.
    refused,
    /// The key's debits exceed its starting balance.
    insufficient,
    /// The key's final balance exceeds the largest amount.
    overflow,
};

/// A key that keeps a batch from settling (commonware `Rejection<K>`). When several keys
/// offend, any may be reported, so the key must not enter consensus-visible data.
pub fn Rejection(comptime K: type) type {
    return struct { reason: Reason, key: K };
}

/// `error.Rejected` fills the caller's `Rejection`.
pub const Error = error{Rejected} || Allocator.Error;

/// Asserts that `A` is an account type.
pub fn assert_account(comptime A: type) void {
    comptime {
        amount.assert_amount(A.Amount);
        assert(@TypeOf(A.Effect) == type);
        for ([_][]const u8{ "default", "balance", "set_balance", "apply" }) |decl| {
            if (!@hasDecl(A, decl)) @compileError("account type lacks " ++ decl);
        }
    }
}

/// Whether `A` has effects. An account without them declares an uninhabited `Effect` (an empty
/// `enum {}`, commonware's `Infallible`), which Zig cannot allocate, so plans store `void`.
pub fn has_effects(comptime A: type) bool {
    return switch (@typeInfo(A.Effect)) {
        .@"enum" => |info| info.field_names.len > 0 or info.mode == .nonexhaustive,
        .noreturn => false,
        else => true,
    };
}

/// The storable form of `A.Effect`: `void` for an account without effects.
pub fn StoredEffect(comptime A: type) type {
    return if (has_effects(A)) A.Effect else void;
}

/// Whether two accounts are equal: `A.eql` if declared, else field by field.
pub fn account_eql(comptime A: type, a: *const A, b: *const A) bool {
    if (comptime @hasDecl(A, "eql")) return A.eql(a, b);
    return std.meta.eql(a.*, b.*);
}

/// The change one transfer makes to one account of type `A` (commonware `Change<A>`). The
/// debit comes off the starting balance and the credit is added after every debit of the
/// batch. A change with no debit, credit, or effect is empty and is left out.
pub fn Change(comptime A: type) type {
    assert_account(A);
    return struct {
        const Self = @This();

        /// Value removed from the balance.
        debit: A.Amount = 0,
        /// Value added to the balance.
        credit: A.Amount = 0,
        /// A change to the account's own state, such as consuming a nonce.
        effect: ?A.Effect = null,

        /// A change that only removes `value` from the balance (commonware `Change::debit`).
        pub fn debiting(value: A.Amount) Self {
            return .{ .debit = value };
        }

        /// A change that only adds `value` to the balance (commonware `Change::credit`).
        pub fn crediting(value: A.Amount) Self {
            return .{ .credit = value };
        }

        /// A change that only applies `effect` (commonware `Change::effect`).
        pub fn applying(effect: A.Effect) Self {
            return .{ .effect = effect };
        }

        /// This change with `effect` in place of any effect it has.
        pub fn with_effect(self: Self, effect: A.Effect) Self {
            var result = self;
            result.effect = effect;
            return result;
        }

        /// Whether the change moves no value and has no effect.
        pub fn is_empty(self: *const Self) bool {
            return self.debit == 0 and self.credit == 0 and self.effect == null;
        }
    };
}

/// One change a transfer lists: the key it changes, which points into the transfer.
pub fn Entry(comptime K: type, comptime A: type) type {
    return struct { key: *const K, change: Change(A) };
}

/// Places keys in partitions and table slots by a hash keyed with `seed` (commonware keys
/// `ahash` the same way; the hash never leaves the process). `Plan.init` and
/// `Selection.init` take the seed, so a deterministic run draws it from the runtime and a
/// production one from a random source adversaries cannot predict.
pub const SeededHasher = struct {
    seed: u64,

    pub fn hash(self: SeededHasher, bytes: []const u8) u64 {
        return std.hash.Wyhash.hash(self.seed, bytes);
    }
};

/// The bytes a key is hashed and compared by.
pub fn key_bytes(comptime K: type, key: *const K) []const u8 {
    comptime assert(std.meta.hasUniqueRepresentation(K));
    return std.mem.asBytes(key);
}

pub fn key_eql(comptime K: type, a: *const K, b: *const K) bool {
    return std.mem.eql(u8, key_bytes(K, a), key_bytes(K, b));
}

/// Partitions of the key hash space that the plan's workers split among themselves.
pub const partitions: usize = 256;
/// Fewest transfers a worker hashes on its own.
pub const hash_batch_min: usize = 1 << 12;
/// Most changes per transfer that sizing extrapolates from a batch's first transfer.
pub const sampled_changes_max: usize = 4;
/// Each bucket reserves its even share divided by this as a margin for uneven hashing.
pub const bucket_margin_divisor: usize = 4;
/// Capacity each bucket reserves beyond its share and margin.
pub const bucket_spare: usize = 4;
/// Fewest partitions a worker deduplicates on its own.
pub const partition_batch_min: usize = partitions / 16;
/// Fewest touches for which a plan too short to split its hashing splits its deduplication.
pub const split_touches_min: usize = 1 << 11;
/// Fewest keys a worker settles on its own.
pub const settle_batch_min: usize = 1 << 14;
/// Distance, in lookups, from the lookup in progress to the one whose slot is prefetched.
pub const prefetch_distance: usize = 16;

comptime {
    assert(partition_batch_min > 0);
    assert(std.math.isPowerOfTwo(partitions));
}

/// One non-empty change of a batch, with its key's hash.
pub fn Touch(comptime K: type, comptime A: type) type {
    return struct { hash: u64, key: *const K, change: Change(A) };
}

/// Calls `sink.touch(touch)` with each non-empty change of `transfers`, in order.
pub fn for_each_touch(transfers: anytype, hasher: anytype, sink: anytype) !void {
    const T = @typeInfo(@TypeOf(transfers)).pointer.child;
    for (transfers) |*transfer| {
        var changes = transfer.changes();
        while (changes.next()) |entry| {
            if (entry.change.is_empty()) continue;
            try sink.touch(Touch(T.Key, T.Account){
                .hash = hasher.hash(key_bytes(T.Key, entry.key)),
                .key = entry.key,
                .change = entry.change,
            });
        }
    }
}

/// Estimates the changes in `transfers` from the first transfer's count, between one and
/// `sampled_changes_max` per transfer.
pub fn estimated_changes(transfers: anytype) usize {
    if (transfers.len == 0) return 0;
    var changes = transfers[0].changes();
    var count: usize = 0;
    while (count < sampled_changes_max) : (count += 1) {
        if (changes.next() == null) break;
    }
    assert(count <= sampled_changes_max);
    return transfers.len * @max(count, 1);
}

/// Every key placed so far, each once, with a table from each key's hash to its position.
pub fn KeyIndex(comptime K: type) type {
    return struct {
        const Self = @This();

        table: handles.Table(u32) = .empty,
        keys: std.ArrayList(K) = .empty,

        pub const empty: Self = .{};

        /// An index that holds `capacity` keys without growing.
        pub fn init_capacity(gpa: Allocator, capacity: usize) Allocator.Error!Self {
            var table = try handles.Table(u32).init_capacity(gpa, capacity);
            errdefer table.deinit(gpa);
            const keys = try std.ArrayList(K).initCapacity(gpa, capacity);
            return .{ .table = table, .keys = keys };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.table.deinit(gpa);
            self.keys.deinit(gpa);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            return self.keys.items.len;
        }

        pub fn prefetch(self: *const Self, hash: u64) void {
            self.table.prefetch(hash);
        }

        /// The position of `key` if it is placed, given its `hash`.
        pub fn find(self: *const Self, key: *const K, hash: u64) ?usize {
            var candidates = self.table.get(hash);
            while (candidates.next()) |position| {
                if (key_eql(K, &self.keys.items[position], key)) return position;
            }
            return null;
        }

        /// The position of `key` given its `hash`, placing it last if it is new, and whether
        /// it was placed. A growing table rehashes the placed keys through `hasher`.
        pub fn find_or_insert(
            self: *Self,
            gpa: Allocator,
            key: *const K,
            hash: u64,
            hasher: anytype,
        ) Allocator.Error!struct { usize, bool } {
            const next = std.math.cast(u32, self.keys.items.len) orelse
                @panic("an index must hold at most u32::MAX keys");
            try self.keys.ensureUnusedCapacity(gpa, 1);
            const matcher: Matcher = .{ .keys = self.keys.items, .key = key };
            const rehash: Rehash(@TypeOf(hasher)) = .{ .keys = self.keys.items, .hasher = hasher };
            const found = try self.table.find_or_insert(gpa, hash, matcher, next, rehash);
            if (found.inserted) self.keys.appendAssumeCapacity(key.*);
            assert(found.handle < self.keys.items.len);
            return .{ found.handle, found.inserted };
        }

        /// Grows the index, if needed, to place `additional` more keys without growing.
        pub fn reserve(self: *Self, gpa: Allocator, additional: usize, hasher: anytype) !void {
            // Headroom for half the existing keys makes the table grow at a lower load.
            const rehash: Rehash(@TypeOf(hasher)) = .{ .keys = self.keys.items, .hasher = hasher };
            try self.table.reserve(gpa, additional + self.keys.items.len / 2, rehash);
            try self.keys.ensureUnusedCapacity(gpa, additional);
        }

        const Matcher = struct {
            keys: []const K,
            key: *const K,

            pub fn matches(matcher: Matcher, position: u32) bool {
                return key_eql(K, &matcher.keys[position], matcher.key);
            }
        };

        fn Rehash(comptime H: type) type {
            return struct {
                keys: []const K,
                hasher: H,

                pub fn rehash(context: @This(), position: u32) u64 {
                    return context.hasher.hash(key_bytes(K, &context.keys[position]));
                }
            };
        }
    };
}

/// Sets `account`'s settled `balance` and returns its slot: a keep for an account left as it
/// started, a delete for one settled to the default, and a put otherwise.
pub fn settled_slot(comptime A: type, account: A, balance: A.Amount, start: *const A) Slot(A) {
    var settled = account;
    settled.set_balance(balance);
    if (account_eql(A, &settled, start)) return .keep;
    if (account_eql(A, &settled, &A.default)) return .delete;
    return .{ .put = settled };
}

/// Returns `len` slots, splitting them among `strategy`'s workers: `op.settle(index, range,
/// slots)` fills the slots of batch `index`'s range of keys.
pub fn settle_batches(
    comptime A: type,
    gpa: Allocator,
    strategy: anytype,
    len: usize,
    op: anytype,
) (SettleError(@TypeOf(op)) || Allocator.Error)![]Slot(A) {
    const slots = try gpa.alloc(Slot(A), len);
    errdefer gpa.free(slots);
    @memset(slots, .keep);
    const Op = @TypeOf(op);
    const Runner = struct {
        op: Op,
        slots: []Slot(A),

        pub fn run(runner: @This(), batches: anytype) SettleError(Op)!void {
            var out: [max_chunks]void = undefined;
            return batches.try_map_collect(out[0..batches.count()], runner);
        }

        pub fn map(runner: @This(), index: usize, range: parallel.Range) SettleError(Op)!void {
            return runner.op.settle(index, range, runner.slots[range.start..range.end]);
        }
    };
    try strategy.try_run_batches(len, settle_batch_min, 1, Runner{ .op = op, .slots = slots });
    return slots;
}

fn SettleError(comptime Op: type) type {
    const R = @typeInfo(@TypeOf(Op.settle)).@"fn".return_type.?;
    return @typeInfo(R).error_union.error_set;
}

/// Records the rejection of the batch with index `index`; `first` picks the first in batch
/// order once every batch returned.
pub fn Rejections(comptime K: type) type {
    return struct {
        const Self = @This();

        slots: [max_chunks]?Rejection(K) = @splat(null),

        pub fn reject(self: *Self, index: usize, reason: Reason, key: K) error{Rejected} {
            assert(index < max_chunks);
            self.slots[index] = .{ .reason = reason, .key = key };
            return error.Rejected;
        }

        pub fn first(self: *const Self) Rejection(K) {
            for (self.slots) |slot| if (slot) |rejection| return rejection;
            unreachable; // `error.Rejected` is returned only after `reject` recorded one.
        }
    };
}

pub const plan = @import("plan.zig");
pub const Plan = plan.Plan;

test {
    std.testing.refAllDecls(@This());
    _ = @import("transfers_test.zig");
    _ = @import("nonced_test.zig");
    _ = @import("edges_test.zig");
    _ = @import("db_test.zig");
}
