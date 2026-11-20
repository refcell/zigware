//! Shared infrastructure of the QMDB benchmarks (commonware's `qmdb/benches/common.rs`): the
//! variant registry, database configurations, storage, and the seeding workloads.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bench = @import("bench");
const codec = @import("codec");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const parallel = @import("parallel");
const Sequential = parallel.Sequential;

const qmdb = storage.qmdb;
const merkle = storage.merkle;
const contiguous = storage.journal.contiguous;
const metrics = runtime.telemetry.metrics;
const paged = runtime.buffer.paged;
pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const TestRng = utils.TestRng;
pub const Translator = storage.translator.EightCap;

pub const items_per_blob: u64 = 50_000;
/// Bytes per activity-bitmap chunk (commonware's `CHUNK_SIZE`).
pub const chunk_bytes: usize = 32;
pub const page_size: u16 = paged.page_size(runtime.storage.blob_page_size);
const page_cache_size: u32 = 512;
pub const delete_frequency: u32 = 10;
const variable_value_max_len: u32 = 256;
const write_buffer_bytes: usize = 2 * 1024 * 1024;
const replay_buffer_bytes: usize = 2 * 1024 * 1024;
pub const init_cache_size: usize = 1 << 18;

pub const Bytes = []const u8;
pub const FixedDigest = qmdb.value.Fixed(Digest);
pub const VariableDigest = qmdb.value.Variable(Digest);
pub const VariableBytes = qmdb.value.Variable(Bytes);

pub const Order = enum { unordered, ordered };

/// Commonware's `any` database over `Digest` keys, `EightCap`, and SHA-256: a fixed log for
/// fixed values, a variable log otherwise.
pub fn AnyDb(comptime F: type, comptime order: Order, comptime E: type) type {
    const any = qmdb.any;
    const Op = switch (order) {
        .unordered => any.operation.Unordered(F, Digest, E),
        .ordered => any.operation.Ordered(F, Digest, E),
    };
    const U = switch (order) {
        .unordered => any.operation.update.Unordered(Digest, E),
        .ordered => any.operation.update.Ordered(Digest, E),
    };
    const I = switch (order) {
        .unordered => storage.index.unordered.Index(Translator, u64),
        .ordered => storage.index.ordered.Index(Translator, u64),
    };
    const C = if (E == FixedDigest)
        contiguous.fixed.Journal(Op)
    else
        contiguous.variable.Journal(Op);
    return any.Db(F, U, C, I, Sha256, chunk_bytes);
}

/// Commonware's `current` database over the same types as `AnyDb`, with `N`-byte chunks.
pub fn CurrentChunksDb(
    comptime F: type,
    comptime order: Order,
    comptime E: type,
    comptime N: usize,
) type {
    // The variant tuples build every database type in one comptime evaluation.
    @setEvalBranchQuota(100_000);
    const A = AnyDb(F, order, E);
    const any = qmdb.any;
    const U = switch (order) {
        .unordered => any.operation.update.Unordered(Digest, E),
        .ordered => any.operation.update.Ordered(Digest, E),
    };
    const I = switch (order) {
        .unordered => storage.index.unordered.Index(Translator, u64),
        .ordered => storage.index.ordered.Index(Translator, u64),
    };
    return qmdb.current.Db(F, U, @FieldType(A.Log, "journal"), I, Sha256, N);
}

pub fn CurrentDb(comptime F: type, comptime order: Order, comptime E: type) type {
    return CurrentChunksDb(F, order, E, chunk_bytes);
}

pub fn KeylessDb(comptime F: type) type {
    const C = contiguous.variable.Journal(qmdb.keyless.Operation(F, VariableBytes));
    return qmdb.keyless.Db(F, VariableBytes, C, Sha256);
}

pub const StoreDb = qmdb.store.Db(Digest, VariableBytes, Translator, Sequential);

/// A named database type of one benchmark variant.
pub fn Variant(comptime name_: []const u8, comptime D: type) type {
    return struct {
        pub const name = name_;
        pub const Db = D;
    };
}

pub const mmr = merkle.mmr.Family;
pub const mmb = merkle.mmb.Family;

/// Commonware's `define_fixed_variants` (digest values).
pub const fixed_variants = .{
    Variant("any::unordered::fixed::mmr", AnyDb(mmr, .unordered, FixedDigest)),
    Variant("any::unordered::fixed::mmb", AnyDb(mmb, .unordered, FixedDigest)),
    Variant("any::ordered::fixed::mmr", AnyDb(mmr, .ordered, FixedDigest)),
    Variant("any::ordered::fixed::mmb", AnyDb(mmb, .ordered, FixedDigest)),
    Variant("any::unordered::variable::mmr", AnyDb(mmr, .unordered, VariableDigest)),
    Variant("any::unordered::variable::mmb", AnyDb(mmb, .unordered, VariableDigest)),
    Variant("any::ordered::variable::mmr", AnyDb(mmr, .ordered, VariableDigest)),
    Variant("any::ordered::variable::mmb", AnyDb(mmb, .ordered, VariableDigest)),
    Variant("current::unordered::fixed::mmr", CurrentDb(mmr, .unordered, FixedDigest)),
    Variant("current::unordered::fixed::mmb", CurrentDb(mmb, .unordered, FixedDigest)),
    Variant("current::ordered::fixed::mmr", CurrentDb(mmr, .ordered, FixedDigest)),
    Variant("current::ordered::fixed::mmb", CurrentDb(mmb, .ordered, FixedDigest)),
    Variant("current::unordered::variable::mmr", CurrentDb(mmr, .unordered, VariableDigest)),
    Variant("current::unordered::variable::mmb", CurrentDb(mmb, .unordered, VariableDigest)),
    Variant("current::ordered::variable::mmr", CurrentDb(mmr, .ordered, VariableDigest)),
    Variant("current::ordered::variable::mmb", CurrentDb(mmb, .ordered, VariableDigest)),
};

/// Commonware's `define_vec_variants` (`Vec<u8>` values).
pub const vec_variants = .{
    Variant("any::unordered::variable-vec::mmr", AnyDb(mmr, .unordered, VariableBytes)),
    Variant("any::unordered::variable-vec::mmb", AnyDb(mmb, .unordered, VariableBytes)),
    Variant("any::ordered::variable-vec::mmr", AnyDb(mmr, .ordered, VariableBytes)),
    Variant("any::ordered::variable-vec::mmb", AnyDb(mmb, .ordered, VariableBytes)),
    Variant("current::unordered::variable-vec::mmr", CurrentDb(mmr, .unordered, VariableBytes)),
    Variant("current::unordered::variable-vec::mmb", CurrentDb(mmb, .unordered, VariableBytes)),
    Variant("current::ordered::variable-vec::mmr", CurrentDb(mmr, .ordered, VariableBytes)),
    Variant("current::ordered::variable-vec::mmb", CurrentDb(mmb, .ordered, VariableBytes)),
};

pub const keyless_variants = .{
    Variant("keyless::mmr", KeylessDb(mmr)),
    Variant("keyless::mmb", KeylessDb(mmb)),
};

/// Commonware's `Sha256::hash(&[&i.to_be_bytes()])`.
pub fn key_at(i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

/// Commonware's `make_fixed_value` or `make_var_value` (1 to 256 repeated bytes), by type.
pub fn make_value(comptime V: type, gpa: Allocator, rng: *TestRng) !V {
    if (V == Digest) {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, rng.next_u32(), .big);
        return Sha256.hash(&.{&bytes});
    }
    comptime assert(V == Bytes);
    const len = rng.next_u32() % variable_value_max_len + 1;
    const bytes = try gpa.alloc(u8, len);
    @memset(bytes, @truncate(rng.next_u32()));
    assert(bytes.len >= 1 and bytes.len <= variable_value_max_len);
    return bytes;
}

/// The codec configuration of an operation log: slices hold at most 10000 items, as
/// commonware's `(0..=10000).into()`.
fn codec_config(comptime C: type) C {
    if (comptime is_slice_cfg(C) or C == void) return leaf_config(C);
    var result: C = undefined;
    inline for (@typeInfo(C).@"struct".field_types, 0..) |field_type, index| {
        result[index] = leaf_config(field_type);
    }
    return result;
}

fn is_slice_cfg(comptime C: type) bool {
    return @typeInfo(C) == .@"struct" and @hasField(C, "range");
}

fn leaf_config(comptime C: type) C {
    if (comptime is_slice_cfg(C)) return .{ .range = .inclusive(0, 10000) };
    return codec.unit_cfg(C);
}

/// Commonware's `fix_log_cfg` or `var_log_cfg`, by the log's configuration type.
pub fn log_config(
    comptime LogCfg: type,
    comptime suffix: []const u8,
    cache: *paged.CacheRef,
    blob: u64,
) LogCfg {
    if (comptime @hasField(LogCfg, "items_per_section")) {
        return .{
            .partition = "log-journal-" ++ suffix,
            .items_per_section = blob,
            .codec_config = codec_config(@FieldType(LogCfg, "codec_config")),
            .cache_ref = cache,
            .write_buffer = write_buffer_bytes,
            .replay_buffer = replay_buffer_bytes,
        };
    }
    return .{
        .partition = "log-journal-" ++ suffix,
        .items_per_blob = blob,
        .cache_ref = cache,
        .write_buffer = write_buffer_bytes,
        .replay_buffer = replay_buffer_bytes,
    };
}

/// Commonware's `merkle_cfg`.
pub fn merkle_config(
    comptime suffix: []const u8,
    cache: *paged.CacheRef,
    blob: u64,
) merkle.full.Config {
    return .{
        .journal_partition = "journal-" ++ suffix,
        .metadata_partition = "metadata-" ++ suffix,
        .items_per_blob = blob,
        .write_buffer = write_buffer_bytes,
        .replay_buffer = replay_buffer_bytes,
        .cache_ref = cache,
    };
}

/// The partition suffix of a database's configuration (commonware's `PARTITION_*`).
pub fn partition(comptime D: type) []const u8 {
    if (D == StoreDb) return "bench-store";
    if (comptime @hasDecl(D, "Set")) return "bench-immutable";
    if (comptime @hasField(D, "snapshot") or @hasField(D, "grafted_tree")) {
        const variable = @hasField(@FieldType(D.Cfg, "log"), "items_per_section");
        return if (variable) "bench-variable" else "bench-fixed";
    }
    return "bench-keyless";
}

/// Production disk storage under a fresh directory of `.zig-cache/tmp`, removed on close. On
/// smoke inputs (`zig build test`) an in-memory storage stands in: every commit there would
/// otherwise wait on the disk.
pub const Disk = struct {
    io: Io,
    memory: bool,
    directory: [64]u8 = undefined,
    directory_len: usize = 0,
    backend: union {
        production: runtime.production.storage.WithRing,
        memory: runtime.storage.memory.Storage,
    } = undefined,
    opened: bool = false,
    /// A wrapper of the backend (such as a storage meter) that databases open through instead.
    override: ?runtime.storage.Storage = null,
    /// A directory the caller names (the CLI harnesses' `<dir>`), created if absent and kept
    /// on close.
    path: ?[]const u8 = null,

    pub fn init(runner: *const bench.Runner) Disk {
        return .{ .io = runner.io, .memory = runner.inputs == .smoke };
    }

    /// Production storage at `path`, kept on close.
    pub fn at(io: Io, path: []const u8) Disk {
        assert(path.len > 0);
        return .{ .io = io, .memory = false, .path = path };
    }

    pub fn open(disk: *Disk, gpa: Allocator) !void {
        assert(!disk.opened);
        if (disk.memory) {
            disk.backend = .{ .memory = .init(gpa) };
            disk.opened = true;
            return;
        }
        if (disk.path) |path| {
            const root = try Io.Dir.cwd().createDirPathOpen(disk.io, path, .{});
            disk.backend = .{ .production = .{} };
            try disk.backend.production.init(disk.io, gpa, root, bench.io_uring);
            disk.opened = true;
            return;
        }
        var nonce: [8]u8 = undefined;
        disk.io.random(&nonce);
        const name = try std.fmt.bufPrint(&disk.directory, ".zig-cache/tmp/qmdb-bench-{x}", .{
            std.mem.readInt(u64, &nonce, .little),
        });
        disk.directory_len = name.len;
        const root = try Io.Dir.cwd().createDirPathOpen(disk.io, name, .{});
        disk.backend = .{ .production = .{} };
        try disk.backend.production.init(disk.io, gpa, root, bench.io_uring);
        disk.opened = true;
        assert(disk.directory_len > 0);
    }

    pub fn storage(disk: *Disk) runtime.storage.Storage {
        assert(disk.opened);
        if (disk.override) |wrapper| return wrapper;
        if (disk.memory) return disk.backend.memory.storage();
        return disk.backend.production.storage.storage();
    }

    pub fn close(disk: *Disk) void {
        assert(disk.opened);
        disk.opened = false;
        if (disk.memory) return disk.backend.memory.deinit();
        disk.backend.production.deinit();
        if (disk.path != null) return;
        const name = disk.directory[0..disk.directory_len];
        Io.Dir.cwd().deleteTree(disk.io, name) catch |err|
            std.log.warn("qmdb benches: could not remove {s}: {t}", .{ name, err });
    }
};

/// How a session opens its database (commonware's `*_cfg_with` overrides).
pub const Options = struct {
    /// Items per log blob and Merkle journal blob.
    items_per_blob: u64 = items_per_blob,
    /// Entries of the init-time `location -> key` cache; null disables it.
    init_cache: ?usize = init_cache_size,
    /// Tasks the init snapshot build may use (commonware's `init_concurrency`).
    init_concurrency: usize = 1,
    /// Starts the threads of a parallel init build; it also times the duration metrics.
    init_io: ?std.Io = null,
    /// Pages of the page cache.
    page_cache_pages: u32 = page_cache_size,
    /// The page cache's logical page size (commonware's unaligned-layout override).
    logical_page_size: u16 = page_size,
    /// Partition names replacing the bench defaults (the CLI harnesses' own names).
    names: ?Names = null,
    /// The database's strategy (commonware's `ctx.strategy(THREADS)`); null is sequential.
    strategy: ?parallel.Rayon = null,
};

/// The partitions of one database.
pub const Names = struct {
    merkle_journal: []const u8,
    merkle_metadata: []const u8,
    log: []const u8,
    /// The grafted metadata partition of a `current` database, if not the default.
    grafted_metadata: ?[]const u8 = null,
};

/// One open database of type `D` with its page cache and metrics (commonware creates both
/// afresh with each config and context).
pub fn Session(comptime D: type) type {
    return struct {
        const Self = @This();

        cache: paged.CacheRef,
        registry: metrics.Registry,
        db: D,

        pub fn open(self: *Self, gpa: Allocator, disk: *Disk, options: Options) !void {
            assert(options.items_per_blob > 0);
            assert(options.logical_page_size > 0);
            self.cache = try .init(gpa, options.logical_page_size, options.page_cache_pages);
            errdefer self.cache.deinit();
            self.registry = .init(gpa);
            errdefer self.registry.deinit();
            const backend = disk.storage();
            const suffix = comptime partition(D);
            const blob = options.items_per_blob;
            var log = log_config(@FieldType(D.Cfg, "log"), suffix, &self.cache, blob);
            if (options.names) |names| log.partition = names.log;
            if (D == StoreDb) {
                const cfg: D.Cfg = .{
                    .log = log,
                    .translator = .{},
                    .init_cache = options.init_cache,
                    .strategy = .{},
                };
                self.db = try D.init(gpa, backend, cfg, null);
                return;
            }
            const scope = metrics.Scope.init(&self.registry).child("storage");
            var cfg: D.Cfg = undefined;
            cfg.merkle = merkle_config(suffix, &self.cache, blob);
            if (options.names) |names| {
                cfg.merkle.journal_partition = names.merkle_journal;
                cfg.merkle.metadata_partition = names.merkle_metadata;
            }
            cfg.log = log;
            if (comptime @hasField(D.Cfg, "translator")) {
                const T = @FieldType(D.Cfg, "translator");
                // A partitioned translator wraps the inner one.
                cfg.translator = if (comptime @hasField(T, "inner")) .init(.{}) else .{};
            }
            if (comptime @hasField(D.Cfg, "init_cache")) cfg.init_cache = options.init_cache;
            // Benches time themselves; only a parallel init needs the `Io`.
            if (comptime @hasField(D.Cfg, "io")) cfg.io = options.init_io;
            if (comptime @hasField(D.Cfg, "strategy")) cfg.strategy = options.strategy;
            if (comptime @hasField(D.Cfg, "init_concurrency")) {
                cfg.init_concurrency = options.init_concurrency;
            }
            if (comptime @hasField(D.Cfg, "grafted_metadata_partition")) {
                cfg.grafted_metadata_partition = "grafted-metadata-" ++ suffix;
                if (options.names) |names| {
                    if (names.grafted_metadata) |name| cfg.grafted_metadata_partition = name;
                }
            }
            self.db = try D.init(gpa, backend, scope, cfg, null);
            assert(self.db.bounds().end > 0);
        }

        /// Destroys the database and frees its cache and metrics.
        pub fn close(self: *Self) !void {
            defer self.free();
            try self.db.destroy();
        }

        /// Closes the database, keeping its storage, and frees its cache and metrics.
        pub fn shut(self: *Self) void {
            defer self.free();
            self.db.deinit();
        }

        fn free(self: *Self) void {
            self.registry.deinit();
            self.cache.deinit();
            self.* = undefined;
        }
    };
}

/// Writes `value` (or a delete) to `batch`, freeing `value` if the write fails.
pub fn write(comptime D: type, gpa: Allocator, batch: anytype, key: Digest, value: ?D.Value) !void {
    batch.write(key, value) catch |err| {
        codec.free(?D.Value, gpa, value);
        return err;
    };
}

/// Merkleizes the pending `batch` and applies it to `db`, committing if `commit`. With
/// `reopen`, leaves a fresh batch in `batch`; otherwise null. A batch is consumed only once
/// merkleized, so the caller frees a non-null `batch` on error.
pub fn flush(
    comptime D: type,
    db: *D,
    batch: *?D.UnmerkleizedBatch,
    commit: bool,
    reopen: bool,
) !void {
    const before = db.bounds().end;
    const merkleized = try batch.*.?.merkleize(db);
    batch.* = null;
    defer merkleized.release();
    try db.apply_batch(merkleized);
    if (commit) try db.commit();
    assert(db.bounds().end > before);
    if (reopen) batch.* = try db.new_batch();
    assert(reopen == (batch.* != null));
}

/// Commonware's `gen_random_kv` with uniform churn over the seeded keys: seeds `elements`
/// keys in one batch, then performs `operations` random updates and deletes (one in
/// `delete_frequency`), applying and committing after a write when the rng draws a multiple
/// of `commit_frequency`.
pub fn gen_random_kv(
    comptime D: type,
    gpa: Allocator,
    db: *D,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) !void {
    assert(elements > 0);
    assert(commit_frequency > 0);
    var rng: TestRng = .init(42);
    var batch: ?D.UnmerkleizedBatch = try db.new_batch();
    errdefer if (batch) |*pending| pending.deinit();
    for (0..elements) |i| {
        try write(D, gpa, &batch.?, key_at(i), try make_value(D.Value, gpa, &rng));
    }
    try flush(D, db, &batch, true, true);
    for (0..operations) |_| {
        const key = key_at(rng.next_u64() % elements);
        if (rng.next_u32() % delete_frequency == 0) {
            try write(D, gpa, &batch.?, key, null);
            continue;
        }
        try write(D, gpa, &batch.?, key, try make_value(D.Value, gpa, &rng));
        if (rng.next_u32() % commit_frequency == 0) try flush(D, db, &batch, true, true);
    }
    try flush(D, db, &batch, true, false);
}

/// Commonware's `gen_store_random_kv`: the same key, value, and commit sequence as
/// `gen_random_kv`, applied to a store as changesets.
pub fn gen_store_random_kv(
    gpa: Allocator,
    db: *StoreDb,
    elements: u64,
    operations: u64,
    commit_frequency: u32,
) !void {
    assert(elements > 0);
    assert(commit_frequency > 0);
    var rng: TestRng = .init(42);
    var writes: std.ArrayList(StoreDb.Write) = .empty;
    defer {
        for (writes.items) |w| codec.free(?Bytes, gpa, w.value);
        writes.deinit(gpa);
    }
    try writes.ensureTotalCapacity(gpa, elements);
    for (0..elements) |i| {
        const value = try make_value(Bytes, gpa, &rng);
        writes.appendAssumeCapacity(.{ .key = key_at(i), .value = value });
    }
    try store_apply_commit(gpa, db, &writes);
    for (0..operations) |_| {
        const key = key_at(rng.next_u64() % elements);
        if (rng.next_u32() % delete_frequency == 0) {
            try writes.append(gpa, .{ .key = key, .value = null });
            continue;
        }
        const value = try make_value(Bytes, gpa, &rng);
        writes.append(gpa, .{ .key = key, .value = value }) catch |err| {
            gpa.free(value);
            return err;
        };
        if (rng.next_u32() % commit_frequency == 0) try store_apply_commit(gpa, db, &writes);
    }
    try store_apply_commit(gpa, db, &writes);
    assert(writes.items.len == 0);
}

/// Applies `writes` (taken, leaving it empty) to the store as one changeset, and commits.
pub fn store_apply_commit(
    gpa: Allocator,
    db: *StoreDb,
    writes: *std.ArrayList(StoreDb.Write),
) !void {
    const before = db.bounds().end;
    var changeset = try StoreDb.Changeset.from_writes(gpa, writes);
    writes.* = .empty;
    try db.apply_batch(&changeset);
    try db.commit();
    assert(writes.items.len == 0);
    assert(db.bounds().end > before);
}

/// A fresh database per iteration on its own disk: opened before the iteration and destroyed
/// after it, untimed.
pub fn Fresh(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        disk: Disk,
        options: Options = .{},
        session: Session(D) = undefined,
        open: bool = false,

        pub fn setup(self: *Self) !void {
            assert(!self.open);
            try self.disk.open(self.gpa);
        }

        /// Destroys the previous iteration's database and opens the next one.
        pub fn next(self: *Self) !*D {
            try self.close();
            try self.session.open(self.gpa, &self.disk, self.options);
            self.open = true;
            return &self.session.db;
        }

        pub fn db(self: *Self) *D {
            assert(self.open);
            return &self.session.db;
        }

        pub fn teardown(self: *Self) !void {
            try self.close();
            self.disk.close();
            assert(!self.open);
        }

        pub fn close(self: *Self) !void {
            if (!self.open) return;
            self.open = false;
            try self.session.close();
        }
    };
}

/// Commonware's `seed_db`: `keys` keys with values drawn from `TestRng::new(42)`, committed.
pub fn seed_db(comptime D: type, db: *D, keys: u64) !void {
    var rng: TestRng = .init(42);
    var batch: ?D.UnmerkleizedBatch = try db.new_batch();
    errdefer if (batch) |*pending| pending.deinit();
    for (0..keys) |i| {
        try write(D, db.gpa, &batch.?, key_at(i), try make_value(D.Value, db.gpa, &rng));
    }
    try flush(D, db, &batch, true, false);
    assert(db.bounds().end > keys);
}

/// Commonware's `write_random_updates`: `updates` writes of keys below `keys`, sampled with
/// replacement, to fresh values.
pub fn write_random_updates(
    comptime D: type,
    batch: *D.UnmerkleizedBatch,
    updates: u64,
    keys: u64,
    rng: *TestRng,
) !void {
    assert(keys > 0);
    assert(updates > 0);
    for (0..updates) |_| {
        const key = key_at(rng.next_u64() % keys);
        try write(D, batch.gpa, batch, key, try make_value(D.Value, batch.gpa, rng));
    }
}
