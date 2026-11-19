//! Benchmarks of the QMDB databases (commonware `storage/src/qmdb/benches`), with commonware's
//! names, constants, and workloads, over the production disk storage as commonware's tokio
//! runtime runs them. This file holds the `any`, `keyless`, and `store` variants; `current`
//! adds its own (docs/lanes/storage-qmdb.md).
//!
//! - `qmdb::generate`: seed a database, churn it with random updates and deletes (committing
//!   periodically), then prune and sync it. Opening and destroying the database are untimed.

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

const qmdb = storage.qmdb;
const merkle = storage.merkle;
const contiguous = storage.journal.contiguous;
const metrics = runtime.telemetry.metrics;
const paged = runtime.buffer.paged;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const TestRng = utils.TestRng;
const Translator = storage.translator.EightCap;

const items_per_blob: u64 = 50_000;
const page_size: u16 = paged.page_size(runtime.storage.blob_page_size);
const page_cache_size: u32 = 512;
const delete_frequency: u32 = 10;
const variable_value_max_len: u32 = 256;
const write_buffer_bytes: usize = 2 * 1024 * 1024;
const replay_buffer_bytes: usize = 2 * 1024 * 1024;
const init_cache_size: usize = 1 << 18;

const Bytes = []const u8;
const FixedDigest = qmdb.value.Fixed(Digest);
const VariableDigest = qmdb.value.Variable(Digest);
const VariableBytes = qmdb.value.Variable(Bytes);

const Order = enum { unordered, ordered };

/// Commonware's `any` database over `Digest` keys, `EightCap`, and SHA-256: a fixed log for
/// fixed values, a variable log otherwise.
fn AnyDb(comptime F: type, comptime order: Order, comptime E: type) type {
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
    return any.Db(F, U, C, I, Sha256, 32);
}

fn KeylessDb(comptime F: type) type {
    const C = contiguous.variable.Journal(qmdb.keyless.Operation(F, VariableBytes));
    return qmdb.keyless.Db(F, VariableBytes, C, Sha256);
}

const StoreDb = qmdb.store.Db(Digest, VariableBytes, Translator);

/// A named database type of one benchmark variant.
fn Variant(comptime name_: []const u8, comptime D: type) type {
    return struct {
        pub const name = name_;
        pub const Db = D;
    };
}

const mmr = merkle.mmr.Family;
const mmb = merkle.mmb.Family;

/// Commonware's `define_fixed_variants` (digest values), without the `current` entries.
const fixed_variants = .{
    Variant("any::unordered::fixed::mmr", AnyDb(mmr, .unordered, FixedDigest)),
    Variant("any::unordered::fixed::mmb", AnyDb(mmb, .unordered, FixedDigest)),
    Variant("any::ordered::fixed::mmr", AnyDb(mmr, .ordered, FixedDigest)),
    Variant("any::ordered::fixed::mmb", AnyDb(mmb, .ordered, FixedDigest)),
    Variant("any::unordered::variable::mmr", AnyDb(mmr, .unordered, VariableDigest)),
    Variant("any::unordered::variable::mmb", AnyDb(mmb, .unordered, VariableDigest)),
    Variant("any::ordered::variable::mmr", AnyDb(mmr, .ordered, VariableDigest)),
    Variant("any::ordered::variable::mmb", AnyDb(mmb, .ordered, VariableDigest)),
};

/// Commonware's `define_vec_variants` (`Vec<u8>` values), without the `current` entries.
const vec_variants = .{
    Variant("any::unordered::variable-vec::mmr", AnyDb(mmr, .unordered, VariableBytes)),
    Variant("any::unordered::variable-vec::mmb", AnyDb(mmb, .unordered, VariableBytes)),
    Variant("any::ordered::variable-vec::mmr", AnyDb(mmr, .ordered, VariableBytes)),
    Variant("any::ordered::variable-vec::mmb", AnyDb(mmb, .ordered, VariableBytes)),
};

const keyless_variants = .{
    Variant("keyless::mmr", KeylessDb(mmr)),
    Variant("keyless::mmb", KeylessDb(mmb)),
};

pub fn run(runner: *bench.Runner) !void {
    try bench_generate(runner);
}

// ---------------------------------------------------------------------------------------------
// Shared infrastructure (commonware's `common.rs`).

/// Commonware's `Sha256::hash(&[&i.to_be_bytes()])`.
fn key_at(i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

/// Commonware's `make_fixed_value` or `make_var_value` (1 to 256 repeated bytes), by type.
fn make_value(comptime V: type, gpa: Allocator, rng: *TestRng) !V {
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
fn log_config(comptime LogCfg: type, comptime suffix: []const u8, cache: *paged.CacheRef) LogCfg {
    if (comptime @hasField(LogCfg, "items_per_section")) {
        return .{
            .partition = "log-journal-" ++ suffix,
            .items_per_section = items_per_blob,
            .codec_config = codec_config(@FieldType(LogCfg, "codec_config")),
            .cache_ref = cache,
            .write_buffer = write_buffer_bytes,
            .replay_buffer = replay_buffer_bytes,
        };
    }
    return .{
        .partition = "log-journal-" ++ suffix,
        .items_per_blob = items_per_blob,
        .cache_ref = cache,
        .write_buffer = write_buffer_bytes,
        .replay_buffer = replay_buffer_bytes,
    };
}

/// Commonware's `merkle_cfg`.
fn merkle_config(comptime suffix: []const u8, cache: *paged.CacheRef) merkle.full.Config {
    return .{
        .journal_partition = "journal-" ++ suffix,
        .metadata_partition = "metadata-" ++ suffix,
        .items_per_blob = items_per_blob,
        .write_buffer = write_buffer_bytes,
        .replay_buffer = replay_buffer_bytes,
        .cache_ref = cache,
    };
}

/// The partition suffix of a database's configuration (commonware's `PARTITION_*`).
fn partition(comptime D: type) []const u8 {
    if (D == StoreDb) return "bench-store";
    if (comptime @hasField(D, "snapshot")) {
        const variable = @hasField(@FieldType(D.Cfg, "log"), "items_per_section");
        return if (variable) "bench-variable" else "bench-fixed";
    }
    return "bench-keyless";
}

/// Production disk storage under a fresh directory of `.zig-cache/tmp`, removed on close. On
/// smoke inputs (`zig build test`) an in-memory storage stands in: every commit there would
/// otherwise wait on the disk.
const Disk = struct {
    io: Io,
    memory: bool,
    directory: [64]u8 = undefined,
    directory_len: usize = 0,
    backend: union {
        production: runtime.production.storage.Storage,
        memory: runtime.storage.memory.Storage,
    } = undefined,
    opened: bool = false,

    fn init(runner: *const bench.Runner) Disk {
        return .{ .io = runner.io, .memory = runner.inputs == .smoke };
    }

    fn open(disk: *Disk, gpa: Allocator) !void {
        assert(!disk.opened);
        if (disk.memory) {
            disk.backend = .{ .memory = .init(gpa) };
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
        disk.backend = .{ .production = try .init(disk.io, gpa, root, .{}) };
        disk.opened = true;
        assert(disk.directory_len > 0);
    }

    fn storage(disk: *Disk) runtime.storage.Storage {
        assert(disk.opened);
        if (disk.memory) return disk.backend.memory.storage();
        return disk.backend.production.storage();
    }

    fn close(disk: *Disk) void {
        assert(disk.opened);
        disk.opened = false;
        if (disk.memory) return disk.backend.memory.deinit();
        disk.backend.production.deinit();
        const name = disk.directory[0..disk.directory_len];
        Io.Dir.cwd().deleteTree(disk.io, name) catch |err|
            std.log.warn("qmdb benches: could not remove {s}: {t}", .{ name, err });
    }
};

/// One open database of type `D` with its page cache and metrics (commonware creates both
/// afresh with each config and context).
fn Session(comptime D: type) type {
    return struct {
        const Self = @This();

        cache: paged.CacheRef,
        registry: metrics.Registry,
        db: D,

        fn open(self: *Self, gpa: Allocator, disk: *Disk) !void {
            self.cache = try .init(gpa, page_size, page_cache_size);
            errdefer self.cache.deinit();
            self.registry = .init(gpa);
            errdefer self.registry.deinit();
            const backend = disk.storage();
            const suffix = comptime partition(D);
            const log = log_config(@FieldType(D.Cfg, "log"), suffix, &self.cache);
            if (D == StoreDb) {
                const cfg: D.Cfg = .{
                    .log = log,
                    .translator = .{},
                    .init_cache = init_cache_size,
                };
                self.db = try D.init(gpa, backend, cfg, null);
                return;
            }
            const scope = metrics.Scope.init(&self.registry).child("storage");
            var cfg: D.Cfg = undefined;
            cfg.merkle = merkle_config(suffix, &self.cache);
            cfg.log = log;
            if (comptime @hasField(D.Cfg, "translator")) {
                cfg.translator = .{};
                cfg.init_cache = init_cache_size;
            }
            self.db = try D.init(gpa, backend, scope, cfg, null);
            assert(self.db.bounds().end > 0);
        }

        /// Destroys the database and frees its cache and metrics.
        fn close(self: *Self) !void {
            defer self.registry.deinit();
            defer self.cache.deinit();
            try self.db.destroy();
        }
    };
}

/// Writes `value` (or a delete) to `batch`, freeing `value` if the write fails.
fn write(comptime D: type, gpa: Allocator, batch: anytype, key: Digest, value: ?D.Value) !void {
    batch.write(key, value) catch |err| {
        codec.free(?D.Value, gpa, value);
        return err;
    };
}

/// Merkleizes the pending `batch` and applies it to `db`, committing if `commit`. With
/// `reopen`, leaves a fresh batch in `batch`; otherwise null. A batch is consumed only once
/// merkleized, so the caller frees a non-null `batch` on error.
fn flush(comptime D: type, db: *D, batch: *?D.UnmerkleizedBatch, commit: bool, reopen: bool) !void {
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
fn gen_random_kv(
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
fn gen_store_random_kv(
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
fn store_apply_commit(gpa: Allocator, db: *StoreDb, writes: *std.ArrayList(StoreDb.Write)) !void {
    const before = db.bounds().end;
    var changeset = try StoreDb.Changeset.from_writes(gpa, writes);
    writes.* = .empty;
    try db.apply_batch(&changeset);
    try db.commit();
    assert(writes.items.len == 0);
    assert(db.bounds().end > before);
}

// ---------------------------------------------------------------------------------------------
// qmdb::generate (commonware's `generate.rs`).

const generate_elements: u64 = 1_000;
const generate_operations: u64 = 10_000;
const commits_per_iteration: u64 = 100;
const keyless_operations: u64 = 10_000;
const keyless_commit_frequency: u32 = 25;

/// A fresh database per iteration on its own disk: opened before the iteration and destroyed
/// after it, untimed.
fn Fresh(comptime D: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        disk: Disk,
        session: Session(D) = undefined,
        open: bool = false,

        fn setup(self: *Self) !void {
            assert(!self.open);
            try self.disk.open(self.gpa);
        }

        /// Destroys the previous iteration's database and opens the next one.
        fn next(self: *Self) !*D {
            try self.close();
            try self.session.open(self.gpa, &self.disk);
            self.open = true;
            return &self.session.db;
        }

        fn db(self: *Self) *D {
            assert(self.open);
            return &self.session.db;
        }

        fn teardown(self: *Self) !void {
            try self.close();
            self.disk.close();
            assert(!self.open);
        }

        fn close(self: *Self) !void {
            if (!self.open) return;
            self.open = false;
            try self.session.close();
        }
    };
}

/// Seeds and churns a fresh database per iteration, then prunes it to its sync boundary (the
/// store: its inactivity floor) and syncs it.
fn GenerateWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        elements: u64,
        operations: u64,

        pub fn setup(self: *Self) !void {
            try self.fresh.setup();
        }

        pub fn before_iter(self: *Self) !void {
            _ = try self.fresh.next();
        }

        pub fn iter(self: *Self) !u64 {
            const gpa = self.fresh.gpa;
            const db = self.fresh.db();
            const elements = self.elements;
            const operations = self.operations;
            const commit_frequency: u32 = @intCast(operations / commits_per_iteration);
            if (D == StoreDb) {
                try gen_store_random_kv(gpa, db, elements, operations, commit_frequency);
                try db.prune(db.inactivity_floor());
            } else {
                try gen_random_kv(D, gpa, db, elements, operations, commit_frequency);
                try db.prune(db.sync_boundary());
            }
            try db.sync();
            assert(db.bounds().end > elements);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            try self.fresh.teardown();
        }
    };
}

fn bench_generate(runner: *bench.Runner) !void {
    // Smoke inputs shrink the case: `zig build test` runs these in debug builds.
    const elements = runner.inputs.pick(u64, 100, generate_elements, generate_elements);
    const operations = runner.inputs.pick(u64, 1_000, generate_operations, generate_operations);
    inline for (fixed_variants ++ vec_variants) |V| {
        try run_generate(V, runner, elements, operations);
    }
    // The full run also measures the store at the init bench's population size.
    try run_generate(Variant("store::variable", StoreDb), runner, elements, operations);
    if (runner.inputs == .full) {
        const variant = Variant("store::variable", StoreDb);
        try run_generate(variant, runner, elements * 100, operations * 100);
    }
    const keyless_ops = runner.inputs.pick(u64, 1_000, keyless_operations, keyless_operations);
    for ([_]u64{ keyless_ops, keyless_ops * 2 }) |ops| {
        inline for (keyless_variants) |V| try run_keyless_generate(V, runner, ops);
    }
}

fn run_generate(comptime V: type, runner: *bench.Runner, elements: u64, operations: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::generate")
        .with_param("variant", V.name)
        .with_param("elements", elements)
        .with_param("operations", operations);
    if (!runner.matches(benchmark.name())) return;
    var workload: GenerateWorkload(V.Db) = .{
        .fresh = .{ .gpa = runner.allocator, .disk = .init(runner) },
        .elements = elements,
        .operations = operations,
    };
    try runner.run(benchmark, &workload);
}

/// Appends `operations` variable values to a fresh keyless database per iteration, applying
/// a batch whenever the rng draws a multiple of `keyless_commit_frequency`, then syncs.
fn KeylessGenerateWorkload(comptime D: type) type {
    return struct {
        const Self = @This();

        fresh: Fresh(D),
        operations: u64,

        pub fn setup(self: *Self) !void {
            try self.fresh.setup();
        }

        pub fn before_iter(self: *Self) !void {
            _ = try self.fresh.next();
        }

        pub fn iter(self: *Self) !u64 {
            const gpa = self.fresh.gpa;
            const db = self.fresh.db();
            var rng: TestRng = .init(42);
            var batch: ?D.UnmerkleizedBatch = try db.new_batch();
            errdefer if (batch) |*pending| pending.deinit();
            for (0..self.operations) |_| {
                const value = try make_value(Bytes, gpa, &rng);
                batch.?.append(value) catch |err| {
                    gpa.free(value);
                    return err;
                };
                if (rng.next_u32() % keyless_commit_frequency == 0) {
                    try flush(D, db, &batch, false, true);
                }
            }
            try flush(D, db, &batch, false, false);
            try db.sync();
            assert(db.bounds().end > self.operations);
            return db.bounds().end;
        }

        pub fn teardown(self: *Self) !void {
            try self.fresh.teardown();
        }
    };
}

fn run_keyless_generate(comptime V: type, runner: *bench.Runner, operations: u64) !void {
    const benchmark = bench.Benchmark.init("qmdb::generate")
        .with_param("variant", V.name)
        .with_param("operations", operations);
    if (!runner.matches(benchmark.name())) return;
    var workload: KeylessGenerateWorkload(V.Db) = .{
        .fresh = .{ .gpa = runner.allocator, .disk = .init(runner) },
        .operations = operations,
    };
    try runner.run(benchmark, &workload);
}
