//! The freezer's `freezer_recovery` fuzz target (commonware `storage/fuzz`): recovery across
//! partial-write crash cuts.
//!
//! The crash cuts either the put path (candidate writes past a checkpointed baseline) or the
//! resize path (a sync that writes both table regions while a bounded resize is in progress),
//! through failed writes that retain selected submitted bytes or successful writes left
//! volatile by a failed sync. The deepen arm first completes a table resize and rolls past one
//! value section, so recovery trims a multi-section value journal against a doubled table.
//! A chain of faulted recoveries follows. The supplied checkpoint is the authority: recovery
//! must restore exactly the checkpointed state, every cursor from the discarded candidates
//! must be unreadable, and a sentinel put, sync, and reopen must succeed.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const freezer = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const Faults = @import("../archive/faults.zig").Faults;

const gpa = testing.allocator;
const Probability = utils.Probability;
const Key = [32]u8;
const F = freezer.Freezer(Key, i32);
const table_size: u32 = 4;

const WritePath = enum { put, resize };
const CrashKind = enum { failed_write, unsynced_write };

const Input = struct {
    path: WritePath,
    crash: CrashKind,
    retention: u8,
    fail_second: bool,
    deepen: bool,
    seed: u64,
};

/// Pinned: `faults` must stay at one address.
const Harness = struct {
    faults: Faults,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(self: *Harness, seed: u64) !void {
        // A page size no key-record size divides, so boundary entries straddle pages.
        self.cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 72, 4);
        self.registry = metrics.Registry.init(gpa);
        self.faults.init(gpa, seed);
    }

    fn deinit(self: *Harness) void {
        self.faults.deinit();
        self.registry.deinit();
        self.cache_ref.deinit();
    }

    fn open(self: *Harness, checkpoint: ?freezer.Checkpoint) !F {
        const scope = metrics.Scope.init(&self.registry).child("freezer");
        return F.init(gpa, self.faults.interface(), scope, .{
            .key_partition = "freezer-recovery-index",
            .key_write_buffer = 1,
            .key_cache_ref = &self.cache_ref,
            .value_partition = "freezer-recovery-values",
            .value_write_buffer = 1,
            .value_target_size = 64,
            .table_partition = "freezer-recovery-table",
            .table_initial_size = table_size,
            .table_resize_frequency = 1,
            .table_resize_chunk_size = 1,
            .table_replay_buffer = 512,
            .codec_config = {},
        }, checkpoint);
    }
};

/// A deterministic key whose checksum maps to table `slot`.
fn key_for_slot(slot: u32, tag: u8) Key {
    assert(slot < table_size);
    for (0..10_000) |nonce| {
        var key: Key = @splat(0);
        key[0] = tag;
        std.mem.writeInt(u64, key[8..16], nonce, .big);
        if (cryptography.Crc32.checksum(&key) & (table_size - 1) == slot) return key;
    }
    unreachable; // Proof: a bounded search of 10,000 nonces covers every four-entry slot.
}

fn baseline_key(slot: u32) Key {
    return key_for_slot(slot, 0x10 + @as(u8, @intCast(slot)));
}

fn candidate_key() Key {
    return key_for_slot(1, 0x80);
}

fn sentinel_key() Key {
    return key_for_slot(3, 0xF0);
}

const Pair = struct { key: Key, value: i32 };
const Pairs = std.ArrayList(Pair);

/// Every scenario key exposes exactly the expected value and presence.
fn expect_values(store: *F, expected: []const Pair) !void {
    var keys: [20]Key = undefined;
    var count: usize = 0;
    for (0..table_size) |slot| {
        keys[count] = baseline_key(@intCast(slot));
        count += 1;
    }
    keys[count] = candidate_key();
    keys[count + 1] = sentinel_key();
    count += 2;
    assert(count + expected.len <= keys.len);
    for (expected) |pair| {
        keys[count] = pair.key;
        count += 1;
    }
    for (keys[0..count]) |key| {
        var want: ?i32 = null;
        for (expected) |pair| {
            if (std.mem.eql(u8, &pair.key, &key)) want = pair.value;
        }
        try testing.expectEqual(want, try store.get(.{ .key = &key }));
        try testing.expectEqual(want != null, try store.has(key));
    }
}

/// Builds the checkpointed baseline. The resize path leaves a bounded resize in progress so
/// the next sync writes both table regions.
fn build_baseline(store: *F, input: Input, baseline: *Pairs) !freezer.Checkpoint {
    if (input.deepen) {
        // Mark every slot, then advance the resize one chunk per sync until it completes,
        // doubling the table; eight values also roll past one value section.
        for (0..8) |round| {
            const slot: u32 = @intCast(round % table_size);
            const key = key_for_slot(slot, 0x30 + @as(u8, @intCast(round)));
            const value: i32 = 300 + @as(i32, @intCast(round));
            _ = try store.put(key, value);
            try baseline.append(gpa, .{ .key = key, .value = value });
        }
        for (0..4) |_| _ = try store.sync();
    }
    const slots: []const u32 = switch (input.path) {
        .put => &.{0},
        .resize => if (input.deepen) &.{ 0, 1, 2, 3 } else &.{ 0, 1, 2 },
    };
    for (slots) |slot| {
        const value: i32 = 100 + @as(i32, @intCast(slot));
        _ = try store.put(baseline_key(slot), value);
        try baseline.append(gpa, .{ .key = baseline_key(slot), .value = value });
    }
    const checkpoint = try store.sync();
    assert(!checkpoint.is_empty());
    return checkpoint;
}

/// Arms the crash faults and runs the candidate writes. Returns the cursors written.
fn write_candidates(
    harness: *Harness,
    store: *F,
    input: Input,
    mode: runtime.storage.faulty.PartialWriteMode,
    cursors: *std.ArrayList(freezer.Cursor),
) !void {
    const fail_second = input.path == .put and input.crash == .failed_write and
        input.fail_second;
    const fail_now = input.crash == .failed_write and !fail_second;
    const config = &harness.faults.layer.config;
    config.* = .{
        .write_rate = .{
            .failure_rate = if (fail_now) .one else .zero,
            .retention_rate = Probability.init(input.retention % 101, 100).?,
            .mode = mode,
        },
        .sync_rate = if (input.crash == .unsynced_write) .one else null,
    };
    switch (input.path) {
        .resize => try testing.expectError(error.Io, store.sync()),
        .put => {
            const updated = store.put(baseline_key(0), 900) catch {
                // Only an armed write failure can fail the first put.
                try testing.expect(fail_now);
                return;
            };
            try cursors.append(gpa, updated);
            if (fail_second) config.write_rate.?.failure_rate = .one;
            const inserted = store.put(candidate_key(), 901) catch {
                try testing.expect(input.crash == .failed_write);
                return;
            };
            try cursors.append(gpa, inserted);
            try testing.expect(std.meta.isError(store.sync()));
        },
    }
}

const Recover = struct { harness: *Harness, checkpoint: freezer.Checkpoint };

fn recover(context: Recover) anyerror!void {
    var store = try context.harness.open(context.checkpoint);
    store.deinit();
}

fn run(input: Input, mode: runtime.storage.faulty.PartialWriteMode) !void {
    var harness: Harness = undefined;
    try harness.init(input.seed);
    defer harness.deinit();
    var baseline: Pairs = .empty;
    defer baseline.deinit(gpa);
    var cursors: std.ArrayList(freezer.Cursor) = .empty;
    defer cursors.deinit(gpa);
    const checkpoint = checkpoint: {
        var store = try harness.open(null);
        defer store.deinit();
        const checkpoint = try build_baseline(&store, input, &baseline);
        try write_candidates(&harness, &store, input, mode, &cursors);
        harness.faults.disarm();
        try harness.faults.crash();
        break :checkpoint checkpoint;
    };
    const context: Recover = .{ .harness = &harness, .checkpoint = checkpoint };
    try harness.faults.faulted_recovery(context, recover);
    // The supplied checkpoint is the authority: exactly the baseline survives.
    var store = try harness.open(checkpoint);
    try expect_values(&store, baseline.items);
    // Cursor reads bypass the table, so discarded cursors must be unreadable too.
    for (cursors.items) |cursor| {
        try testing.expect(std.meta.isError(store.get(.{ .cursor = cursor })));
    }
    // The recovered freezer publishes a new checkpoint that survives a reopen.
    _ = try store.put(sentinel_key(), 999);
    try baseline.append(gpa, .{ .key = sentinel_key(), .value = 999 });
    const next = try store.sync();
    store.deinit();
    var reopened = try harness.open(next);
    try expect_values(&reopened, baseline.items);
    try reopened.destroy();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    const input: Input = .{
        .path = if (reader.boolean()) .put else .resize,
        .crash = if (reader.boolean()) .failed_write else .unsynced_write,
        .retention = reader.int(u8),
        .fail_second = reader.boolean(),
        .deepen = reader.boolean(),
        .seed = reader.int(u64),
    };
    // Recovery under both partial-write retention modes.
    try run(input, .prefix);
    try run(input, .subset);
}

test "fuzz freezer_recovery (seeded)" {
    try fuzz_bytes.seeded(32, 0x66727263, 64, recovery_run);
}

test "fuzz freezer_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(32, recovery_run), .{});
}
