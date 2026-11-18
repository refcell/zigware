//! A reference validator that checks closes, applies the posted ones to its balances and
//! payout log, and serves the closes it attested and the payouts they owe (commonware
//! `clearing/tests/bajillion/roles/validator.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const parallel = @import("parallel");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const bajillion = @import("../../../bajillion/mod.zig");
const map = @import("map.zig");

const Epoch = bajillion.Epoch;
const Namespace = bajillion.Namespace;
const Limits = bajillion.Limits;
const metrics = runtime.telemetry.metrics;

/// Why the validator refused, besides the check, settle, apply, and database errors.
pub const Refusal = error{
    /// The databases and the records do not agree on a posted close.
    InvalidCheckpoint,
};

/// Storage the validators of a test share, as the deterministic runtime's: the in-memory
/// backend under `runtime.storage.faulty` (commonware's `FaultConfig`), drawing faults from a
/// seeded RNG. Each validator keeps its databases in partitions named after it. Lives in place:
/// the fault wrapper points into it.
pub const Env = struct {
    pub const Faulty = runtime.storage.faulty.Storage(utils.rng.TestRng);

    gpa: Allocator,
    memory: runtime.storage.memory.Storage,
    rng: utils.rng.TestRng,
    faults: Faulty,
    cache_ref: runtime.buffer.paged.CacheRef,

    pub fn init(self: *Env, gpa: Allocator, seed: u64) !void {
        self.gpa = gpa;
        self.memory = .init(gpa);
        errdefer self.memory.deinit();
        self.rng = utils.rng.TestRng.init(seed);
        self.faults = .init(gpa, &self.memory, &self.rng, .{});
        self.cache_ref = try .init(gpa, 1024, 8);
    }

    pub fn deinit(self: *Env) void {
        self.cache_ref.deinit();
        self.faults.deinit();
        self.memory.deinit();
        self.* = undefined;
    }

    pub fn storage(self: *Env) runtime.storage.Storage {
        return self.faults.storage();
    }

    /// Crashes: unsynced writes keep what their retention selects, and open handles can no
    /// longer publish (commonware's `start_and_recover`). Faults stop after the crash.
    pub fn crash(self: *Env) !void {
        try self.faults.crash();
        self.memory.crash();
        self.faults.config = .{};
    }
};

/// The partitions of one validator's databases, named after it.
pub const Partitions = struct {
    buffer: []u8,
    balances_journal: []const u8,
    balances_metadata: []const u8,
    balances_log: []const u8,
    balances_grafted: []const u8,
    payouts_journal: []const u8,
    payouts_metadata: []const u8,
    payouts_log: []const u8,

    const suffixes = [_][]const u8{
        "-merkle-journal",
        "-merkle-metadata",
        "-log",
        "-grafted-metadata",
        "-payouts-merkle-journal",
        "-payouts-merkle-metadata",
        "-payouts-log",
    };

    pub fn init(gpa: Allocator, name: []const u8) Allocator.Error!Partitions {
        var size: usize = 0;
        for (suffixes) |suffix| size += name.len + suffix.len;
        const buffer = try gpa.alloc(u8, size);
        var parts: [suffixes.len][]const u8 = undefined;
        var at: usize = 0;
        for (suffixes, &parts) |suffix, *part| {
            @memcpy(buffer[at..][0..name.len], name);
            @memcpy(buffer[at + name.len ..][0..suffix.len], suffix);
            part.* = buffer[at..][0 .. name.len + suffix.len];
            at += name.len + suffix.len;
        }
        assert(at == size);
        return .{
            .buffer = buffer,
            .balances_journal = parts[0],
            .balances_metadata = parts[1],
            .balances_log = parts[2],
            .balances_grafted = parts[3],
            .payouts_journal = parts[4],
            .payouts_metadata = parts[5],
            .payouts_log = parts[6],
        };
    }

    pub fn deinit(self: *Partitions, gpa: Allocator) void {
        gpa.free(self.buffer);
        self.* = undefined;
    }
};

/// A validator with user keys `P`, operator key `O`, hasher `H`, translator `T`, and amounts
/// `A`, over the plain unordered index.
pub fn Validator(P: type, O: type, H: type, T: type, A: type) type {
    return struct {
        const Self = @This();
        pub const D = H.Digest;
        pub const Index = storage.index.unordered.Index(T, u64);
        pub const Balances = bajillion.Balances(P, H, Index, A);
        pub const Log = bajillion.Payouts(P, H, A);
        pub const Close = bajillion.Close(P, O, A);
        pub const Queue = Close.QueueType;
        pub const Deposit = bajillion.Deposit(P, A);
        pub const Forced = bajillion.ForcedWithdrawal(P, A);
        pub const Summary = bajillion.Summary(H);
        pub const Checkpoint = bajillion.Checkpoint(P, H, A);
        pub const Checked = bajillion.Checked(P, H, A);
        pub const Proposal = bajillion.Proposal(P, H, A, Balances);
        pub const Matrix = bajillion.Matrix(P, H, A);
        pub const Opening = bajillion.Opening(P, D, A);
        pub const BalanceProof = bajillion.BalanceProof(D, A);
        pub const PayoutProof = bajillion.PayoutProof(P, D, A);

        /// The configuration of a validator.
        pub const Config = struct {
            /// Borrowed during `init` only; the validator keeps a copy.
            namespace: *const Namespace,
            operator: O,
            limits: Limits,
            /// The prefix of the validator's partitions.
            name: []const u8,
        };

        /// What a validator persists about a close it attested (V4): the close, the requests
        /// it processes, and its summary, each encoded. Owns its bytes.
        pub const Record = struct {
            close: []u8,
            deposits: []u8,
            forced_withdrawals: []u8,
            summary: []u8,

            fn deinit(self: *Record, gpa: Allocator) void {
                gpa.free(self.close);
                gpa.free(self.deposits);
                gpa.free(self.forced_withdrawals);
                gpa.free(self.summary);
                self.* = undefined;
            }

            fn clone(self: *const Record, gpa: Allocator) Allocator.Error!Record {
                var copy: Record = undefined;
                copy.close = try gpa.dupe(u8, self.close);
                errdefer gpa.free(copy.close);
                copy.deposits = try gpa.dupe(u8, self.deposits);
                errdefer gpa.free(copy.deposits);
                copy.forced_withdrawals = try gpa.dupe(u8, self.forced_withdrawals);
                errdefer gpa.free(copy.forced_withdrawals);
                copy.summary = try gpa.dupe(u8, self.summary);
                return copy;
            }

            fn eql(a: *const Record, b: *const Record) bool {
                return std.mem.eql(u8, a.close, b.close) and
                    std.mem.eql(u8, a.deposits, b.deposits) and
                    std.mem.eql(u8, a.forced_withdrawals, b.forced_withdrawals) and
                    std.mem.eql(u8, a.summary, b.summary);
            }

            /// The summary the record holds.
            pub fn decoded_summary(self: *const Record, gpa: Allocator) Summary {
                return codec.decode(Summary, gpa, self.summary) catch
                    unreachable; // Proof: the validator encoded it.
            }
        };

        fn order_digest(a: *const D, b: *const D) std.math.Order {
            return std.mem.order(u8, &a.bytes, &b.bytes);
        }

        /// What the validator persists: the closes it attested, by summary digest.
        pub const Persisted = struct {
            attested: map.Map(D, Record, order_digest) = .{},

            pub fn deinit(self: *Persisted, gpa: Allocator) void {
                for (self.attested.items()) |*entry| entry.value.deinit(gpa);
                self.attested.deinit(gpa);
                self.* = undefined;
            }

            pub fn clone(self: *const Persisted, gpa: Allocator) Allocator.Error!Persisted {
                var copy: Persisted = .{};
                errdefer copy.deinit(gpa);
                for (self.attested.items()) |*entry| {
                    var copied = try entry.value.clone(gpa);
                    errdefer copied.deinit(gpa);
                    _ = try copy.attested.put(gpa, entry.key, copied);
                }
                return copy;
            }

            pub fn eql(a: *const Persisted, b: *const Persisted) bool {
                if (a.attested.count() != b.attested.count()) return false;
                for (a.attested.items(), b.attested.items()) |*x, *y| {
                    if (!x.key.eql(y.key) or !x.value.eql(&y.value)) return false;
                }
                return true;
            }
        };

        gpa: Allocator,
        env: *Env,
        config: Config,
        namespace: Namespace,
        partitions: Partitions,
        /// Each database registers its metrics afresh when it opens. Heap-allocated so the
        /// scopes the databases hold stay valid when the validator moves.
        balances_registry: *metrics.Registry,
        log_registry: *metrics.Registry,
        /// Null after a failed apply: the validator must restart.
        balances: ?Balances,
        log: ?Log,
        persisted: Persisted,
        parent: Checkpoint,

        /// Opens the validator's databases and resumes from `persisted` (taken), walking the
        /// persisted summaries back from the ledger's last post `posted` to the first whose
        /// balances root the database holds (V2). Only a database that applied no close
        /// falls back to genesis. The payout log reopens at the chosen summary's payouts size.
        pub fn init(
            gpa: Allocator,
            env: *Env,
            config: Config,
            persisted: Persisted,
            posted: ?*const D,
        ) !Self {
            var owned = persisted;
            errdefer owned.deinit(gpa);
            var self: Self = .{
                .gpa = gpa,
                .env = env,
                .config = config,
                .namespace = try config.namespace.clone(gpa),
                .partitions = undefined,
                .balances_registry = undefined,
                .log_registry = undefined,
                .balances = null,
                .log = null,
                .persisted = owned,
                .parent = undefined,
            };
            errdefer self.namespace.deinit(gpa);
            self.partitions = try Partitions.init(gpa, config.name);
            errdefer self.partitions.deinit(gpa);
            self.balances_registry = try gpa.create(metrics.Registry);
            self.balances_registry.* = metrics.Registry.init(gpa);
            errdefer destroy_registry(gpa, self.balances_registry);
            self.log_registry = try gpa.create(metrics.Registry);
            self.log_registry.* = metrics.Registry.init(gpa);
            errdefer destroy_registry(gpa, self.log_registry);
            self.balances = try self.open_balances();
            errdefer self.balances.?.deinit();
            self.parent = try self.resume_parent(posted);
            errdefer self.parent.deinit();
            self.log = try self.open_log(&self.parent.summary);
            return self;
        }

        fn destroy_registry(gpa: Allocator, registry: *metrics.Registry) void {
            registry.deinit();
            gpa.destroy(registry);
        }

        pub fn deinit(self: *Self) void {
            if (self.log) |*log| log.deinit();
            if (self.balances) |*balances| balances.deinit();
            self.parent.deinit();
            self.persisted.deinit(self.gpa);
            destroy_registry(self.gpa, self.log_registry);
            destroy_registry(self.gpa, self.balances_registry);
            self.partitions.deinit(self.gpa);
            self.namespace.deinit(self.gpa);
            self.* = undefined;
        }

        fn merkle_config(
            self: *Self,
            journal: []const u8,
            metadata: []const u8,
        ) storage.merkle.full.Config {
            return .{
                .journal_partition = journal,
                .metadata_partition = metadata,
                .items_per_blob = 16,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.env.cache_ref,
            };
        }

        fn log_config(self: *Self, partition: []const u8) storage.journal.contiguous.fixed.Config {
            return .{
                .partition = partition,
                .items_per_blob = 16,
                .cache_ref = &self.env.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            };
        }

        fn open_balances(self: *Self) !Balances {
            const p = &self.partitions;
            const cfg: Balances.Cfg = .{
                .merkle = self.merkle_config(p.balances_journal, p.balances_metadata),
                .log = self.log_config(p.balances_log),
                .grafted_metadata_partition = p.balances_grafted,
                .translator = .{},
            };
            self.balances_registry.deinit();
            self.balances_registry.* = metrics.Registry.init(self.gpa);
            const scope = metrics.Scope.init(self.balances_registry).child("balances");
            return Balances.init(self.gpa, self.env.storage(), scope, cfg, null);
        }

        /// Opens the payout log at `summary`'s payouts size and checks its root.
        fn open_log(self: *Self, at: *const Summary) !Log {
            var log = try self.open_log_at(at.payouts.size);
            errdefer log.deinit();
            if (!log.root().eql(at.payouts.root)) return error.InvalidCheckpoint;
            return log;
        }

        /// Opens the payout log rewound to `size` operations, or whole if null.
        fn open_log_at(self: *Self, size: ?u64) !Log {
            const p = &self.partitions;
            const cfg: Log.Cfg = .{
                .merkle = self.merkle_config(p.payouts_journal, p.payouts_metadata),
                .log = self.log_config(p.payouts_log),
            };
            self.log_registry.deinit();
            self.log_registry.* = metrics.Registry.init(self.gpa);
            const scope = metrics.Scope.init(self.log_registry).child("payouts");
            return Log.init(self.gpa, self.env.storage(), scope, cfg, size);
        }

        /// Closes the payout log and reopens it rewound to `size` operations (whole if null)
        /// without checking its root, as a crash or a lost write would leave it: commonware's
        /// tests open the log's partitions directly. The validator must restart afterwards.
        pub fn reopen_log(self: *Self, size: ?u64) !*Log {
            if (self.log) |*log| log.deinit();
            self.log = null;
            self.log = try self.open_log_at(size);
            return &self.log.?;
        }

        fn resume_parent(self: *Self, posted: ?*const D) !Checkpoint {
            const balances = &self.balances.?;
            const applied = try balances.get_metadata() != null;
            const root = balances.root();
            var digest: ?D = if (posted) |d| d.* else null;
            while (digest) |at| {
                const found = self.persisted.attested.get(&at) orelse break;
                const s = found.decoded_summary(self.gpa);
                if (s.balances.eql(root)) {
                    return .{ .summary = s, .matrix = try self.matrix_of(found) };
                }
                digest = s.parent;
            }
            if (applied) return error.InvalidCheckpoint;
            return .{
                .summary = Summary.genesis(P, A, root),
                .matrix = try Matrix.empty(self.gpa),
            };
        }

        fn close_of(self: *const Self, found: *const Record) !Close {
            return codec.decode_cfg(Close, self.gpa, found.close, self.config.limits);
        }

        fn matrix_of(self: *const Self, found: *const Record) !Matrix {
            var close = try self.close_of(found);
            defer close.deinit(self.gpa);
            return close.matrix(H, self.gpa, parallel.sequential);
        }

        /// The summary of the last close applied.
        pub fn summary(self: *const Self) *const Summary {
            return &self.parent.summary;
        }

        /// The payment matrix of the last close applied.
        pub fn matrix(self: *const Self) *const Matrix {
            return &self.parent.matrix;
        }

        /// The account's balance after the last close applied.
        pub fn balance(self: *Self, account: *const P) !A {
            return try self.balances.?.get(account) orelse 0;
        }

        /// The proof of the account's balance under the last balances root, or null for a
        /// zero balance (V6). The caller frees it.
        pub fn prove(self: *Self, account: *const P) !?BalanceProof {
            const proved = self.balances.?.key_value_proof(account) catch |err| switch (err) {
                error.KeyNotFound => return null,
                else => return err,
            };
            return .{ .balance = proved.value, .proof = proved.proof };
        }

        /// The record of the close of `epoch` along the chain of applied closes.
        fn record_at(self: *const Self, epoch: Epoch) ?*const Record {
            var digest = self.parent.summary.digest();
            while (self.persisted.attested.get(&digest)) |found| {
                const s = found.decoded_summary(self.gpa);
                if (s.epoch == epoch) return found;
                digest = s.parent;
            }
            return null;
        }

        /// Opens the payment from `sender` to `receiver` in the applied close of `epoch` (V6).
        /// The caller frees it.
        pub fn open(self: *const Self, epoch: Epoch, from: *const P, to: *const P) !?Opening {
            const found = self.record_at(epoch) orelse return null;
            var m = try self.matrix_of(found);
            defer m.deinit();
            return try m.open(self.gpa, from, to);
        }

        /// The proof of the payout the applied close of `epoch` owes `account`, under the last
        /// payouts root, or null if it owes none (V6). The caller frees it.
        pub fn prove_payout(self: *Self, epoch: Epoch, account: *const P) !?PayoutProof {
            const found = self.record_at(epoch) orelse return null;
            const s = found.decoded_summary(self.gpa);
            // The close's payouts start at its parent's payouts size; the parent of epoch 1
            // is the genesis summary.
            const start = if (self.persisted.attested.get(&s.parent)) |parent_record|
                parent_record.decoded_summary(self.gpa).payouts.size
            else if (epoch == 1)
                Summary.genesis(P, A, .empty).payouts.size
            else
                return error.InvalidCheckpoint;
            const log = &self.log.?;
            var low = start;
            var high = s.payouts.size - 1;
            while (low < high) {
                const index = low + (high - low) / 2;
                const payout = (try log.get(index)).?; // A close's payouts precede its commit.
                switch (payout.account.order(account.*)) {
                    .lt => low = index + 1,
                    .gt => high = index,
                    .eq => {
                        const proved = try log.proof(index, 1);
                        defer codec.free_items(Log.Operation, self.gpa, proved.items);
                        defer self.gpa.free(proved.items);
                        return .{ .index = index, .payout = payout, .proof = proved.proof };
                    },
                }
            }
            return null;
        }

        /// Checks `close` (taken) against `queue` and settles it (V1, V3), persisting the
        /// close, the requests it processes, and its summary before the attestation is
        /// released (V4). The caller frees the proposal.
        pub fn verify(self: *Self, close: Close, queue: *const Queue) !Proposal {
            var owned = close;
            defer owned.deinit(self.gpa);
            var checked = try Checked.check(
                O,
                self.gpa,
                &owned,
                &self.namespace,
                &self.config.operator,
                &self.parent,
                queue,
                parallel.sequential,
            );
            defer checked.deinit(self.gpa);
            var proposal = try checked.settle(self.gpa, &self.balances.?, &self.log.?);
            errdefer proposal.deinit(self.gpa);
            const digest = proposal.summary.digest();
            if (self.persisted.attested.contains(&digest)) return proposal;
            const prefix = queue.prefix(owned.deposits, owned.forced_withdrawals).?;
            var made = try self.record_of(&owned, prefix, &proposal.summary);
            errdefer made.deinit(self.gpa);
            _ = try self.persisted.attested.put(self.gpa, digest, made);
            return proposal;
        }

        fn record_of(self: *Self, close: *const Close, prefix: anytype, s: *const Summary) !Record {
            var made: Record = undefined;
            made.close = try codec.encode(Close, self.gpa, close.*);
            errdefer self.gpa.free(made.close);
            made.deposits = try codec.encode([]const Deposit, self.gpa, prefix.deposits);
            errdefer self.gpa.free(made.deposits);
            const forced = prefix.forced_withdrawals;
            made.forced_withdrawals = try codec.encode([]const Forced, self.gpa, forced);
            errdefer self.gpa.free(made.forced_withdrawals);
            made.summary = try codec.encode(Summary, self.gpa, s.*);
            return made;
        }

        /// Applies `proposal` as the posted close with digest `posted`, commits the balances,
        /// and prunes them to their sync boundary (V5). The proposal stays the caller's. After
        /// an error the validator holds no database and must restart.
        pub fn apply(self: *Self, proposal: *const Proposal, posted: *const D) !void {
            errdefer {
                if (self.log) |*log| log.deinit();
                if (self.balances) |*balances| balances.deinit();
                self.log = null;
                self.balances = null;
            }
            const balances = &self.balances.?;
            var checkpoint = try proposal.apply(balances, &self.log.?, posted);
            errdefer checkpoint.deinit();
            // The log is durable once the close applies, so committing the balances makes the
            // close durable. The balances then prune their history up to the sync boundary.
            try balances.commit();
            try balances.prune(balances.sync_boundary());
            self.parent.deinit();
            self.parent = checkpoint;
        }

        /// Replays the persisted closes from the last close applied up to the ledger's last
        /// post `posted`, and returns how many it applied.
        pub fn catch_up(self: *Self, posted: *const D) !usize {
            const applied = self.parent.summary.digest();
            var missing: std.ArrayList(D) = .empty;
            defer missing.deinit(self.gpa);
            var digest = posted.*;
            while (!digest.eql(applied)) {
                const found = self.persisted.attested.get(&digest) orelse
                    return error.InvalidCheckpoint;
                const s = found.decoded_summary(self.gpa);
                if (s.epoch <= self.parent.summary.epoch) return error.InvalidCheckpoint;
                try missing.append(self.gpa, digest);
                digest = s.parent;
            }
            var index = missing.items.len;
            while (index > 0) {
                index -= 1;
                try self.replay(&missing.items[index]);
            }
            return missing.items.len;
        }

        /// Checks and applies the persisted close whose summary has digest `digest` against a
        /// queue holding exactly the persisted prefix, each required count its length.
        fn replay(self: *Self, digest: *const D) !void {
            var found = try self.persisted.attested.get(digest).?.clone(self.gpa);
            defer found.deinit(self.gpa);
            const expected = found.decoded_summary(self.gpa);
            const cfg_deposits: codec.Cfg([]const Deposit) = .{ .range = .full() };
            const deposits =
                try codec.decode_cfg([]const Deposit, self.gpa, found.deposits, cfg_deposits);
            defer self.gpa.free(deposits);
            const cfg_forced: codec.Cfg([]const Forced) = .{ .range = .full() };
            const encoded_forced = found.forced_withdrawals;
            const forced =
                try codec.decode_cfg([]const Forced, self.gpa, encoded_forced, cfg_forced);
            defer self.gpa.free(forced);
            const queue: Queue = .{
                .epoch = expected.epoch,
                .deposits = deposits,
                .required_deposits = deposits.len,
                .forced_withdrawals = forced,
                .required_forced_withdrawals = forced.len,
            };
            var proposal = try self.verify(try self.close_of(&found), &queue);
            defer proposal.deinit(self.gpa);
            if (!proposal.summary.eql(expected)) return error.InvalidCheckpoint;
            try self.apply(&proposal, digest);
        }
    };
}
