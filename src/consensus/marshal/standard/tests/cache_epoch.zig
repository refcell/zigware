//! Marshal's per-epoch caches across restarts (commonware `standard/mod.rs`, lines 1987-2543:
//! `test_cache_load_persisted_epochs_finds_blocks` through
//! `test_cache_start_sync_notarizations_covers_prior_write`, and `opened_cache_epochs`).
//!
//! zigware's cache syncs every put before returning (commonware returns a sync handle), so the
//! write handles commonware awaits or drops have no counterpart here.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const cache_api = @import("../../core/cache.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const soak = @import("../../mocks/soak.zig");
const Manager = cache_api.Manager(H.Variant, harness.S);
const Ctx = runtime.deterministic.Context;
const CacheRef = runtime.buffer.paged.CacheRef;
const MutationFaults = runtime.storage.mocks.MutationFaults;
const MutationFault = runtime.storage.mocks.MutationFault;
const Epoch = types.Epoch;
const Round = types.Round;

/// commonware's `Runner::timed(60s)`.
const timed: runtime.deterministic.Config = .{ .timeout_ns = 60 * std.time.ns_per_s };
const far_epoch: Epoch = .new(64);
/// Every partition of one epoch: three per archive.
const epoch_partitions = cache_api.archives.len * 3;
const partition_size_max = 192;

/// commonware's `make_cfg`, with `prefix` and the page cache the test owns.
fn config(prefix: []const u8, cache_ref: *CacheRef) cache_api.Config {
    return .{
        .partition_prefix = prefix,
        .prunable_items_per_section = 10,
        .replay_buffer = 1024,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .key_page_cache = cache_ref,
    };
}

/// A cache under metrics root `root`, before `load_persisted_epochs`.
fn init_manager(ctx: Ctx, root: []const u8, prefix: []const u8, cache_ref: *CacheRef) !Manager {
    const child = ctx.child(root);
    return Manager.init(gpa, child.storage, child.scope, config(prefix, cache_ref), {});
}

/// `init_manager`, then `load_persisted_epochs`.
fn open_manager(ctx: Ctx, root: []const u8, prefix: []const u8, cache_ref: *CacheRef) !Manager {
    var manager = try init_manager(ctx, root, prefix, cache_ref);
    errdefer manager.deinit();
    try manager.load_persisted_epochs();
    return manager;
}

fn new_cache_ref() !CacheRef {
    return CacheRef.init(gpa, harness.page_size, harness.page_cache_size);
}

/// Epochs whose cache archives are open under the metrics root `root`, ascending: each open
/// epoch's finalizations archive registers an `items_tracked` gauge labeled with the epoch
/// (commonware `opened_cache_epochs`).
fn opened_cache_epochs(ctx: Ctx, root: []const u8, out: []u64) ![]u64 {
    const text = try ctx.scope.encode(gpa);
    defer gpa.free(text);
    var needle_buffer: [partition_size_max]u8 = undefined;
    const needle = try std.fmt.bufPrint(
        &needle_buffer,
        "{s}_cache_finalizations_items_tracked{{",
        .{root},
    );
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, needle)) continue;
        const label = "epoch=\"";
        const start = (std.mem.indexOf(u8, line, label) orelse return error.TestNoEpoch) +
            label.len;
        const end = start + (std.mem.indexOfScalar(u8, line[start..], '"') orelse
            return error.TestNoEpoch);
        if (count == out.len) return error.TestTooManyEpochs;
        out[count] = try std.fmt.parseInt(u64, line[start..end], 10);
        count += 1;
    }
    std.sort.pdq(u64, out[0..count], {}, std.sort.asc(u64));
    return out[0..count];
}

fn expect_opened(ctx: Ctx, root: []const u8, expected: []const u64) !void {
    var buffer: [16]u64 = undefined;
    try testing.expectEqualSlices(u64, expected, try opened_cache_epochs(ctx, root, &buffer));
}

/// A raw block at `height` over the parent `Sha256(seed)`, stamped `timestamp`.
fn make_block(seed: []const u8, height: u64, timestamp: u64) !H.TestBlock {
    const parent = harness.Sha256.hash(&.{seed});
    const raw = try harness.make_raw_block(gpa, parent, .new(height), timestamp);
    return @import("../../mocks/block.zig").ready(harness.B, gpa, raw);
}

/// The quorum finalization of `digest` at `round`, over the previous view.
fn finalize(
    fixture: *const harness.Fixture,
    round: Round,
    digest: harness.D,
) !harness.Finalization {
    const proposal = harness.Proposal.init(round, .new(round.view.get() - 1), digest);
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

fn test_fixture() !harness.Fixture {
    var rng = utils.rng.test_rng();
    return harness.fixture(gpa, &rng);
}

/// Accepts every block.
const Any = struct {
    pub fn matches(_: Any, _: *const H.Variant.Block) bool {
        return true;
    }
};

fn load_persisted_epochs_finds_blocks_body(ctx: Ctx) anyerror!void {
    const prefix = "test-cache";
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var block = try make_block("", 1, 100);
    defer block.deinit();
    const digest = H.digest(&block);
    const round: Round = .new(.zero(), .new(1));

    // Write a block into the cache.
    {
        var manager = try init_manager(ctx, "write", prefix, &cache_ref);
        defer manager.deinit();
        try (try manager.put_notarized(round, digest, &block)).wait_release();
    }

    // Re-init the cache (simulating restart): find_block fails before loading persisted epochs.
    var manager = try init_manager(ctx, "read", prefix, &cache_ref);
    defer manager.deinit();
    try testing.expectEqual(null, try manager.find_block_matching(digest, Any{}));
    try manager.load_persisted_epochs();
    var found = (try manager.find_block_matching(digest, Any{})) orelse return error.TestNoBlock;
    defer found.deinit();
    // The digest commits to the whole block.
    try testing.expect(found.digest().eql(digest));
}

test "cache load persisted epochs finds blocks" {
    try soak.run(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    }, load_persisted_epochs_finds_blocks_body, .{});
}

/// A floor finalization cached at epoch 64 before its anchor block arrives is the cache's first
/// write, so it records the epoch range (0, 64). Reopening the cache must open only the epoch
/// that holds data.
fn far_epoch_write_body(ctx: Ctx) anyerror!void {
    const prefix = "test-cache-far-epoch";
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var block = try make_block("far", 1290, 100);
    defer block.deinit();
    const digest = H.digest(&block);
    const round: Round = .new(far_epoch, .new(1290));
    var finalization = try finalize(&fixture, round, digest);
    defer finalization.deinit(gpa);
    {
        var manager = try init_manager(ctx, "write", prefix, &cache_ref);
        defer manager.deinit();
        try manager.put_finalization(round, digest, &finalization);
    }

    var manager = try open_manager(ctx, "read", prefix, &cache_ref);
    defer manager.deinit();
    var cached = (try manager.get_finalization_for(digest)) orelse return error.TestNoFinalization;
    cached.deinit(gpa);
    // Reopen must open only the written epoch.
    try expect_opened(ctx, "read", &.{64});
}

test "cache restart after far epoch write reopens only written epochs" {
    try soak.run(gpa, timed, far_epoch_write_body, .{});
}

fn fetch_issued(resolver: common.RecordingResolver) bool {
    return resolver.fetch_count() > 0;
}

const Started = common.Started(harness.Provider, App, common.RecordingBuffer);

/// Starts the actor under `root` from `floor` (cloned) with a never-answering resolver, and
/// waits for its floor fetch.
fn start_from_floor(
    ctx: Ctx,
    root: []const u8,
    fixture: *const harness.Fixture,
    floor: *const harness.Finalization,
) !Started {
    const prefix = "start-floor-far-epoch-restart";
    const app: App = try .manual_ack(gpa, ctx.io());
    const buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    var started = try common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child(root),
        prefix,
        .init(&fixture.schemes[0]),
        app,
        buffer,
        .{ .floor = try floor.clone(gpa) },
    );
    errdefer started.crash();
    try common.wait_until(ctx, 5_000, "floor fetch issued", started.resolver, fetch_issued);
    return started;
}

/// A fresh node configured with a `Start::Floor` at epoch 64 caches the floor finalization while
/// the anchor block is still being fetched. A restart in that window must open only the floor's
/// epoch.
fn floor_restart_body(ctx: Ctx) anyerror!void {
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    // Height 1290 sits in epoch 64 of the 20-block test epocher.
    const floor_round: Round = .new(far_epoch, .new(1290));
    var floor_block = try make_block("floor-parent", 1290, 500);
    defer floor_block.deinit();
    var floor = try finalize(&fixture, floor_round, H.digest(&floor_block));
    defer floor.deinit(gpa);

    // The anchor is never served, so the floor stays pending.
    var first = try start_from_floor(ctx, "first", &fixture, &floor);
    expect_opened(ctx, "first_actor_cache", &.{64}) catch |err| {
        first.crash();
        return err;
    };
    first.crash();

    // The restart reissues the floor fetch with the same cache on disk.
    var restarted = try start_from_floor(ctx, "restarted", &fixture, &floor);
    defer restarted.crash();
    // Restart must open only the floor's epoch.
    try expect_opened(ctx, "restarted_actor_cache", &.{64});
}

test "standard start floor restart before anchor reopens only floor epoch" {
    try soak.run(gpa, timed, floor_restart_body, .{});
}

/// A restart skips the epochs in the metadata range that hold no data. A later write to one of
/// them initializes its cache on demand, and the next restart finds it.
fn skipped_epoch_body(ctx: Ctx) anyerror!void {
    const prefix = "test-cache-skipped-epoch";
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();

    // A write at epoch 64 widens the range to (0, 64).
    var far = try make_block("far", 1290, 100);
    defer far.deinit();
    const far_round: Round = .new(far_epoch, .new(1290));
    var far_finalization = try finalize(&fixture, far_round, H.digest(&far));
    defer far_finalization.deinit(gpa);
    {
        var manager = try init_manager(ctx, "write", prefix, &cache_ref);
        defer manager.deinit();
        try manager.put_finalization(far_round, H.digest(&far), &far_finalization);
    }

    // The restart skips the empty epochs below 64.
    var manager = try open_manager(ctx, "reopen", prefix, &cache_ref);
    try expect_opened(ctx, "reopen", &.{64});

    // A late notarization for skipped epoch 10 opens that epoch's cache.
    var old = try make_block("old", 210, 100);
    defer old.deinit();
    const old_round: Round = .new(.new(10), .new(210));
    const proposal = harness.Proposal.init(old_round, .new(209), H.digest(&old));
    var notarization = try harness.make_notarization(gpa, &fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    {
        defer manager.deinit();
        try (try manager.put_notarization(old_round, H.digest(&old), &notarization)).wait_release();
        try expect_notarization(&manager, old_round);
        try expect_opened(ctx, "reopen", &.{ 10, 64 });
    }

    // The next restart finds both written epochs.
    manager = try open_manager(ctx, "again", prefix, &cache_ref);
    defer manager.deinit();
    try expect_opened(ctx, "again", &.{ 10, 64 });
    try expect_notarization(&manager, old_round);
    var cached = (try manager.get_finalization_for(H.digest(&far))) orelse
        return error.TestNoFinalization;
    cached.deinit(gpa);
}

fn expect_notarization(manager: *Manager, round: Round) !void {
    var found = (try manager.get_notarization(round)) orelse return error.TestNoNotarization;
    found.deinit(gpa);
}

test "cache write to skipped epoch initializes on demand" {
    try soak.run(gpa, timed, skipped_epoch_body, .{});
}

/// Every partition of `epoch`'s archives (commonware `cache::ARCHIVES` through
/// `Manager::partitions`), formatted into `names`.
fn all_partitions(
    prefix: []const u8,
    epoch: Epoch,
    names: *[epoch_partitions][partition_size_max]u8,
    out: *[epoch_partitions][]const u8,
) void {
    var index: usize = 0;
    for (cache_api.archives) |archive| {
        for ([_][]const u8{ "metadata", "key", "value" }) |kind| {
            out[index] = cache_api.partition(&names[index], prefix, epoch, archive, kind);
            index += 1;
        }
    }
    assert(index == epoch_partitions);
}

/// The partitions of `partitions` that still exist, into `out`.
fn remaining(
    ctx: Ctx,
    partitions: []const []const u8,
    out: [][]const u8,
) ![]const []const u8 {
    var count: usize = 0;
    for (partitions) |partition| {
        const names = ctx.storage.scan(gpa, partition) catch |err| switch (err) {
            error.PartitionMissing => continue,
            else => return err,
        };
        names.deinit(gpa);
        out[count] = partition;
        count += 1;
    }
    return out[0..count];
}

const Survivor = struct { kind: []const u8, emptied: bool };

/// A prune destroys an epoch's archives one after another. Each archive empties and removes its
/// metadata partition, then destroys its two journals. A crash can therefore leave an empty
/// metadata partition or a single journal as the epoch's only partition. A restart must still
/// reopen that epoch so the next prune past it can finish retiring it.
fn interrupted_destroy_body(ctx: Ctx, survivor: Survivor) anyerror!void {
    const prefix = "test-cache-interrupted-destroy";
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var names: [epoch_partitions][partition_size_max]u8 = undefined;
    var partitions: [epoch_partitions][]const u8 = undefined;
    all_partitions(prefix, far_epoch, &names, &partitions);

    // Only the finalizations archive is written, so it is the only archive with journals.
    var block = try make_block("far", 1290, 100);
    defer block.deinit();
    const round: Round = .new(far_epoch, .new(1290));
    var finalization = try finalize(&fixture, round, H.digest(&block));
    defer finalization.deinit(gpa);
    {
        var manager = try init_manager(ctx, "write", prefix, &cache_ref);
        defer manager.deinit();
        try manager.put_finalization(round, H.digest(&block), &finalization);
    }

    // Simulate a destroy cut that leaves one finalizations partition. A cut partway through
    // destroying the metadata leaves its partition empty.
    var kept_name: [partition_size_max]u8 = undefined;
    const kept = cache_api.partition(&kept_name, prefix, far_epoch, "finalizations", survivor.kind);
    for (partitions) |partition| {
        if (std.mem.eql(u8, partition, kept)) continue;
        ctx.storage.remove(partition, null) catch |err| switch (err) {
            error.PartitionMissing => {},
            else => return err,
        };
    }
    if (survivor.emptied) try empty_partition(ctx, kept);
    var left: [epoch_partitions][]const u8 = undefined;
    const remnant = try remaining(ctx, &partitions, &left);
    try testing.expectEqual(1, remnant.len);
    try testing.expectEqualStrings(kept, remnant[0]);

    // The leftover partition is enough for a restart to reopen the epoch.
    var manager = try open_manager(ctx, "reopen", prefix, &cache_ref);
    defer manager.deinit();
    try expect_opened(ctx, "reopen", &.{64});

    // A prune past the epoch finishes retiring it.
    try manager.prune_by_view(.new(.new(65), .zero()));
    try testing.expectEqual(0, (try remaining(ctx, &partitions, &left)).len);
}

/// Removes every blob of `partition`, leaving it empty.
fn empty_partition(ctx: Ctx, partition: []const u8) !void {
    const blobs = try ctx.storage.scan(gpa, partition);
    defer blobs.deinit(gpa);
    for (blobs.items) |blob| try ctx.storage.remove(partition, blob);
    const after = try ctx.storage.scan(gpa, partition);
    defer after.deinit(gpa);
    try testing.expectEqual(0, after.items.len);
}

test "cache restart reopens epoch left by interrupted destroy" {
    const survivors = [_]Survivor{
        .{ .kind = "metadata", .emptied = true },
        .{ .kind = "key", .emptied = false },
        .{ .kind = "value", .emptied = false },
    };
    for (survivors) |survivor| {
        try soak.run(gpa, timed, interrupted_destroy_body, .{survivor});
    }
}

const interrupted_prefix = "test-cache-interrupted-prune";
const pruned_round: Round = .new(.new(65), .zero());

/// The prune `prune_until_parked` runs in its own task.
const Prune = struct {
    manager: *Manager,
    done: bool = false,

    fn run(_: Ctx, prune: *Prune) anyerror!void {
        try prune.manager.prune_by_view(pruned_round);
        prune.done = true;
    }
};

/// Writes a finalization into the epoch the prune retires, then prunes with every mutation after
/// the first `interrupted` parked. Returns whether the prune completed.
fn prune_until_parked(
    ctx: Ctx,
    finalization: *const harness.Finalization,
    digest: harness.D,
    interrupted: u64,
) anyerror!bool {
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var faults: MutationFaults = .init(ctx.io());
    var wrapper: MutationFault = .init(gpa, ctx.storage, &faults);
    var faulty = ctx;
    faulty.storage = wrapper.storage();
    var manager = try init_manager(faulty, "write", interrupted_prefix, &cache_ref);
    defer manager.deinit();
    try manager.put_finalization(.new(far_epoch, .new(1290)), digest, finalization);

    // A storage failure is fatal to the cache, so the prune is stopped by parking one of its
    // mutations and abandoning it.
    faults.park_after(interrupted);
    var prune: Prune = .{ .manager = &manager };
    const handle = try ctx.child("prune").spawn(Prune.run, .{&prune});
    while (!prune.done and !faults.parked()) try ctx.sleep(.fromMilliseconds(1));
    const completed = prune.done;
    if (completed) {
        try try handle.join();
    } else {
        if (handle.abort()) |_| {} else |_| {}
    }
    try testing.expectEqual(completed, !faults.parked());
    return completed;
}

/// A restart reopens what the prune left, and pruning again removes every partition of the
/// retired epoch.
fn prune_after_restart(ctx: Ctx, interrupted: u64) anyerror!void {
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var manager = try open_manager(ctx, "restart", interrupted_prefix, &cache_ref);
    defer manager.deinit();
    try manager.prune_by_view(pruned_round);
    var names: [epoch_partitions][partition_size_max]u8 = undefined;
    var partitions: [epoch_partitions][]const u8 = undefined;
    all_partitions(interrupted_prefix, far_epoch, &names, &partitions);
    for (partitions) |partition| {
        if (ctx.storage.scan(gpa, partition)) |names_left| {
            names_left.deinit(gpa);
            std.log.err("stopped after {d} mutations: {s} remains", .{ interrupted, partition });
            return error.TestPartitionRemains;
        } else |err| if (err != error.PartitionMissing) return err;
    }
}

// A prune destroys the archives of every epoch below its round and only then raises the
// persisted floor. A prune that stops inside those destroys leaves an epoch that is still at or
// above the floor, so a restart reopens it and the next prune finishes retiring it.
test "cache prune stopped inside epoch destroy finishes after restart" {
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    var block = try make_block("far", 1290, 100);
    defer block.deinit();
    const digest = H.digest(&block);
    var finalization = try finalize(&fixture, .new(far_epoch, .new(1290)), digest);
    defer finalization.deinit(gpa);

    // Stop the prune before its first mutation, then its second, and so on until one prune
    // completes.
    var interrupted: u64 = 0;
    while (true) : (interrupted += 1) {
        try testing.expect(interrupted < 1_000);
        var runner = try runtime.deterministic.Runner.init(gpa, timed);
        defer runner.deinit();
        const completed = try try runner.start_context(prune_until_parked, .{
            &finalization, digest, interrupted,
        });
        try try runner.start_context(prune_after_restart, .{interrupted});
        if (completed) break;
    }
    // Destroying the epoch removes the partitions of each of its archives, so the prune can stop
    // at least once before each.
    try testing.expect(interrupted >= epoch_partitions);
}

/// The certify barrier folds in notarization durability via `start_sync_notarizations`: after
/// it, the notarization written earlier is recoverable.
fn start_sync_notarizations_body(ctx: Ctx) anyerror!void {
    const prefix = "test-cache-notarizations";
    var fixture = try test_fixture();
    defer fixture.deinit(gpa);
    var cache_ref = try new_cache_ref();
    defer cache_ref.deinit();
    var block = try make_block("", 1, 100);
    defer block.deinit();
    const digest = H.digest(&block);
    const round: Round = .new(.zero(), .new(1));
    const proposal = harness.Proposal.init(round, .zero(), digest);
    var notarization = try harness.make_notarization(gpa, &fixture, proposal, harness.quorum);
    defer notarization.deinit(gpa);
    {
        var manager = try init_manager(ctx, "write", prefix, &cache_ref);
        defer manager.deinit();
        try (try manager.put_notarization(round, digest, &notarization)).wait_release();
        try (try manager.start_sync_notarizations(round)).wait_release();
    }

    var manager = try open_manager(ctx, "read", prefix, &cache_ref);
    defer manager.deinit();
    // The notarization covered by the barrier must be durable.
    try expect_notarization(&manager, round);
}

test "cache start sync notarizations covers prior write" {
    try soak.run(gpa, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    }, start_sync_notarizations_body, .{});
}
