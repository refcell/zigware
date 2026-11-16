//! The `metadata_recovery` fuzz target (commonware `storage/fuzz`): metadata recovery across
//! partial-write crash cuts, on `runtime.storage.faulty`.
//!
//! Rewrite, overwrite, and remove mutations are crossed with three crash kinds: a failed
//! write, an unsynced write, and an acknowledged sync. Recovery must yield the baseline or the
//! complete candidate, never a mixture; a crash after an acknowledged sync keeps the candidate;
//! and the first syncs after a repair survive reopen. Commonware parks the unsynced write at a
//! delayed durability barrier (`start_sync`); syncs complete at once here, so a failing blob
//! sync leaves the write unsynced for the crash to cut instead. A chain of faulted recovery
//! attempts (`faulted_recovery`) runs between the crash and the checked recovery.
//!
//! Also commonware's `test_overwrite_crash_during_background_sync` (`metadata/mod.rs`), on
//! the same faulty storage.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const metadata = @import("mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const Faults = @import("../archive/faults.zig").Faults;
const runtime = @import("runtime");
const utils = @import("utils");

const gpa = testing.allocator;
const Store = metadata.Metadata(u64, []const u8);
const Probability = utils.Probability;
const PartialWriteMode = runtime.storage.faulty.PartialWriteMode;

const config: metadata.Config([]const u8) = .{
    .partition = "metadata-recovery",
    .codec_config = .{ .range = .full(), .item = {} },
};

const sentinel_key: u64 = 99;
/// Every key the target writes; a recovered key outside these is fabricated.
const keys = [_]u64{ 0, 1, 2, sentinel_key };
/// Expected values by `keys` index.
const Model = [keys.len]?[]const u8;

const WritePath = enum { rewrite, overwrite, remove };
const CrashKind = enum { failed_write, unsynced_write, acked_sync };

const Input = struct {
    path: WritePath,
    crash: CrashKind,
    /// Crash retention rate in percent.
    retention: u8,
    payload: [32]u8,
    /// Seeds the fault RNG: fault sampling and the faulted recovery chain.
    seed: u64,

    fn decode(bytes: []const u8) Input {
        var reader = fuzz_bytes.Reader.init(bytes);
        var input: Input = .{
            .path = @fromBackingInt(@intCast(reader.below(3))),
            .crash = @fromBackingInt(@intCast(reader.below(3))),
            .retention = @intCast(reader.below(101)),
            .payload = undefined,
            .seed = 0,
        };
        for (&input.payload) |*byte| byte.* = reader.int(u8);
        input.seed = reader.int(u64);
        assert(input.retention <= 100);
        return input;
    }

    /// A value tagged per write path: the tag, then the payload.
    fn value(self: *const Input, tag: u8) [33]u8 {
        var bytes: [33]u8 = undefined;
        bytes[0] = tag;
        @memcpy(bytes[1..], &self.payload);
        return bytes;
    }
};

fn put(store: *Store, key: u64, bytes: []const u8) !void {
    const owned = try gpa.dupe(u8, bytes);
    errdefer gpa.free(owned);
    if (try store.put(key, owned)) |previous| gpa.free(previous);
}

/// Whether the store holds exactly `expected`, so a load that fabricates or misparses a key
/// diverges.
fn holds(store: *const Store, expected: *const Model) bool {
    var present: usize = 0;
    for (expected) |value| {
        if (value != null) present += 1;
    }
    if (store.count() != present) return false;
    for (store.items()) |entry| {
        const index = std.mem.indexOfScalar(u64, &keys, entry.key) orelse return false;
        const value = expected[index] orelse return false;
        if (!std.mem.eql(u8, value, entry.value)) return false;
    }
    return true;
}

fn reopen(faults: *Faults) !Store {
    return Store.init(gpa, faults.interface(), config);
}

/// A recovery attempt of the faulted chain; its result is discarded.
fn recover(faults: *Faults) !void {
    var store = try reopen(faults);
    store.deinit();
}

/// Writes the baseline to both copies, applies the mutation, and crashes at `input.crash`.
fn mutate_and_crash(
    faults: *Faults,
    input: *const Input,
    mode: PartialWriteMode,
    values: *const [4][33]u8,
    candidate: *Model,
) !void {
    var store = try reopen(faults);
    defer store.deinit();
    // The same baseline in both alternating copies, so the mutation can exercise an equal-size
    // overwrite, a growing rewrite, or a shrinking rewrite with a resize.
    try put(&store, 0, &values[0]);
    try put(&store, 1, &values[1]);
    try store.sync();
    try store.sync();
    switch (input.path) {
        .rewrite => {
            try put(&store, 2, &values[2]);
            candidate[2] = &values[2];
        },
        .overwrite => {
            try put(&store, 0, &values[3]);
            candidate[0] = &values[3];
        },
        .remove => {
            gpa.free(store.remove(1).?);
            candidate[1] = null;
        },
    }
    const failed = input.crash == .failed_write;
    faults.layer.config = .{
        .write_rate = .{
            .failure_rate = if (failed) .one else .zero,
            .retention_rate = Probability.init(input.retention, 100).?,
            .mode = mode,
        },
        .sync_rate = if (input.crash == .unsynced_write) .one else null,
    };
    switch (input.crash) {
        .failed_write, .unsynced_write => try testing.expect(std.meta.isError(store.sync())),
        .acked_sync => try store.sync(),
    }
    faults.disarm();
}

fn run(input: *const Input, mode: PartialWriteMode) !void {
    var faults: Faults = undefined;
    faults.init(gpa, input.seed);
    defer faults.deinit();
    const values = [4][33]u8{
        input.value(0x10), input.value(0x11), input.value(0x20), input.value(0x21),
    };
    const baseline: Model = .{ &values[0], &values[1], null, null };
    var candidate = baseline;
    try mutate_and_crash(&faults, input, mode, &values, &candidate);
    try faults.crash();
    try faults.faulted_recovery(&faults, recover);
    // The checksum makes each copy authoritative as a whole: the last durable copy or the
    // complete attempted one, never a mixture.
    var store = try reopen(&faults);
    var expected: Model = if (holds(&store, &candidate)) candidate else baseline;
    try testing.expect(holds(&store, &expected));
    // An acknowledged sync is durable; an unsynced write survives only as far as retention.
    if (input.crash == .acked_sync) try testing.expect(holds(&store, &candidate));
    if (input.crash == .unsynced_write and input.retention == 0) {
        try testing.expect(holds(&store, &baseline));
    }
    // Full retention gives a complete candidate unless it also needs an unsynced resize.
    if (input.crash == .unsynced_write and input.retention == 100 and input.path != .remove) {
        try testing.expect(holds(&store, &candidate));
    }
    // Shrink first: a sync after a repair lands on the repaired copy, and a shrunk state never
    // outgrows that copy's image, so a stale tail fails its checksum at reopen.
    if (store.remove(0)) |removed| gpa.free(removed);
    expected[0] = null;
    try store.sync();
    store.deinit();
    store = try reopen(&faults);
    try testing.expect(holds(&store, &expected));
    // The store stays writable, and a further sync survives a clean reopen.
    const sentinel: [32]u8 = @splat(0xEF);
    try put(&store, sentinel_key, &sentinel);
    expected[3] = &sentinel;
    try store.sync();
    store.deinit();
    store = try reopen(&faults);
    try testing.expect(holds(&store, &expected));
    try store.destroy();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    const input = Input.decode(bytes);
    for ([_]PartialWriteMode{ .prefix, .subset }) |mode| try run(&input, mode);
}

test "fuzz metadata_recovery (seeded)" {
    try fuzz_bytes.seeded(64, 0x6d657461, 64, recovery_run);
}

test "fuzz metadata_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(64, recovery_run), .{});
}

test "metadata_recovery covers every write path and crash kind" {
    // Every path and crash kind at no, partial, and full retention.
    for (0..3) |path| {
        for (0..3) |crash| {
            for ([_]u8{ 0, 37, 100 }) |retention| {
                // Each choice is a little-endian u64; then the payload and the seed.
                var bytes: [64]u8 = @splat(0);
                bytes[0] = @intCast(path);
                bytes[8] = @intCast(crash);
                bytes[16] = retention;
                @memset(bytes[24..56], 0x5a);
                bytes[56] = @intCast(path * 9 + crash * 3);
                try recovery_run(&bytes);
            }
        }
    }
}

/// Fills `len` bytes with `byte`, owned by the caller.
fn filled(byte: u8, len: usize) ![]u8 {
    const value = try gpa.alloc(u8, len);
    @memset(value, byte);
    return value;
}

const Retention = struct { mode: PartialWriteMode, rate: Probability, update_survives: bool };

fn overwrite_crash_during_sync(retention: Retention, store_len: u64, durable: u8) !void {
    // A second key (8-byte key, 1-byte length prefix, 8-byte value) never changes.
    const value_len: usize = @intCast(store_len - 8 - 8 - 2 - 4 - 17);
    const stable: [8]u8 = @splat(0xEE);
    var faults: Faults = undefined;
    faults.init(gpa, durable);
    defer faults.deinit();
    faults.layer.config = .{ .write_rate = .{
        .failure_rate = .zero,
        .retention_rate = retention.rate,
        .mode = retention.mode,
    } };
    var store = try reopen(&faults);
    try put(&store, 2, &stable);
    // Each sync makes one generation durable, alternating copies, so the copies hold
    // different generations and the update targets the older one.
    for (1..durable + 1) |generation| {
        if (try store.put(1, try filled(@intCast(generation), value_len))) |old| gpa.free(old);
        try store.sync();
    }
    if (try store.put(1, try filled(durable + 1, value_len))) |old| gpa.free(old);
    // The update's sync never completes, so the crash finds it unsynced and the retention
    // policy decides which of its bytes survive.
    faults.layer.config.sync_rate = .one;
    try testing.expect(std.meta.isError(store.sync()));
    store.deinit();
    faults.disarm();
    try faults.crash();
    store = try reopen(&faults);
    defer store.deinit();
    const expected: u8 = if (retention.update_survives) durable + 1 else durable;
    const value = store.get(1).?.*;
    try testing.expectEqual(value_len, value.len);
    for (value) |byte| try testing.expectEqual(expected, byte);
    try testing.expectEqualSlices(u8, &stable, store.get(2).?.*);
}

test "an overwrite cut before its sync completes recovers whole or not at all" {
    const page_size = runtime.storage.blob_page_size;
    const cases = [_]Retention{
        .{ .mode = .prefix, .rate = .zero, .update_survives = false }, // Lost.
        .{ .mode = .subset, .rate = .ratio(1, 2), .update_survives = false }, // Torn.
        .{ .mode = .prefix, .rate = .one, .update_survives = true }, // Retained.
    };
    for (cases) |retention| {
        for ([_]u64{ page_size, page_size + 1 }) |store_len| {
            for ([_]u8{ 2, 3 }) |durable| {
                try overwrite_crash_during_sync(retention, store_len, durable);
            }
        }
    }
}
