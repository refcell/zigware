//! The `journal_contiguous_recovery` fuzz target (commonware `storage/fuzz`): contiguous
//! journal crash recovery across repeated crash/recover cycles, on `runtime.storage.faulty`.
//!
//! One input drives a fixed or variable journal through cycles. Each cycle recovers what the
//! previous crash left, checks it against the `Expected` bounds carried from that crash, runs
//! its ops under write, sync, and resize faults, and drops the journal (the crash). Between
//! cycles a chain of faulted recovery attempts runs, each crashing into the next. `Crash`
//! markers split the ops into cycles; `Reset` routes the next recovery through
//! `init_at_size` and `CrashAtMost` through `init_at_most`, whose faulted attempts run that
//! initializer so its staged clear or truncation can crash anywhere.
//!
//! A crash can land anywhere in a range, so `Expected` tracks conservative bounds: a durable
//! prefix plus size and pruning ceilings. Retained positions above the durable prefix are
//! still content-checked: every readable frame is CRC-gated, so a recovered item must be one
//! of the values recorded at that position.
//!
//! A held `start_sync` completion is waited for (the memory backend completes it at the
//! call), and a dropped one leaves the durable bounds unchanged. Snapshot readers are not
//! ported, so `Snapshot` does nothing.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const contiguous = @import("mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;

const gpa = testing.allocator;
const paged = runtime.buffer.paged;
const faulty = runtime.storage.faulty;
const Probability = utils.Probability;
const Bounds = contiguous.Bounds;

const item_size = 32;
const Item = [item_size]u8;
/// Buffer size of verification replays.
const verify_replay_buffer = 1024;
const max_operations = 128;
/// Reset targets are taken modulo this bound, keeping `Expected.values` small while still
/// spanning several sections at every `items_per_section`.
const max_reset_size = 256;
const partition = "crash-recovery";

const Operation = union(enum) {
    append: u8,
    read: u64,
    sync,
    start_sync: bool,
    snapshot,
    commit,
    reopen_at_most: u64,
    prune: u64,
    replay: struct { buffer: usize, start: u64 },
    crash,
    reset: struct { size: u64, complete: bool },
    crash_at_most: u64,

    /// Appends get five of sixteen draws so seeded inputs build journals worth recovering.
    fn decode(reader: *fuzz_bytes.Reader) Operation {
        const kind = reader.int(u8) % 16;
        return switch (kind) {
            0...4 => .{ .append = reader.int(u8) },
            5 => .{ .read = reader.int(u16) },
            6 => .sync,
            7 => .{ .start_sync = reader.boolean() },
            8 => .snapshot,
            9 => .commit,
            10 => .{ .reopen_at_most = reader.int(u16) },
            11 => .{ .prune = reader.int(u16) },
            12 => .{ .replay = .{ .buffer = 1 + reader.below(2048), .start = reader.int(u16) } },
            13 => .crash,
            14 => .{ .reset = .{ .size = reader.int(u16), .complete = reader.boolean() } },
            15 => .{ .crash_at_most = reader.int(u16) },
            else => unreachable, // Proof: `% 16` is in 0..16.
        };
    }

    fn is_durability(self: Operation) bool {
        return switch (self) {
            .sync, .commit, .reopen_at_most, .prune => true,
            else => false,
        };
    }
};

/// Journal geometry and fault rates, shared by every cycle.
const Params = struct {
    variable: bool,
    page_size: u16,
    page_cache_size: u32,
    items_per_section: u64,
    write_buffer: usize,
    replay_buffer: usize,
    write_config: faulty.WriteConfig,
    sync_rate: Probability,
    resize_rate: Probability,
    partial_resize_rate: Probability,
    remove_rate: Probability,

    /// The fault config of the operation phase.
    fn fault_config(self: *const Params) faulty.Config {
        return .{
            .write_rate = self.write_config,
            .sync_rate = self.sync_rate,
            .resize_rate = .{
                .failure_rate = self.resize_rate,
                .partial_rate = self.partial_resize_rate,
            },
        };
    }

    /// The fault config around each prune: the operation faults plus remove failures, so a
    /// prune can fail after removing only some of its blobs.
    fn prune_fault_config(self: *const Params) faulty.Config {
        var config = self.fault_config();
        config.remove_rate = self.remove_rate;
        return config;
    }
};

const Input = struct {
    params: Params,
    seed: u64,
    operations: [max_operations]Operation,
    operations_len: usize,

    fn decode(bytes: []const u8) Input {
        var reader = fuzz_bytes.Reader.init(bytes);
        var input: Input = .{
            .params = .{
                .variable = reader.boolean(),
                .page_size = @intCast(1 + reader.below(256)),
                .page_cache_size = @intCast(1 + reader.below(16)),
                .items_per_section = items_per_section(&reader),
                .write_buffer = 1 + reader.below(2048),
                .replay_buffer = 1 + reader.below(2048),
                .write_config = .{
                    .failure_rate = rate(&reader),
                    .retention_rate = Probability.init(reader.int(u8) % 101, 100).?,
                    .mode = if (reader.boolean()) .prefix else .subset,
                },
                .sync_rate = rate(&reader),
                .resize_rate = rate(&reader),
                .partial_resize_rate = Probability.init(reader.int(u8) % 101, 100).?,
                .remove_rate = rate(&reader),
            },
            .seed = reader.int(u64),
            .operations = undefined,
            .operations_len = 0,
        };
        const count = reader.below(max_operations + 1);
        while (input.operations_len < count) : (input.operations_len += 1) {
            input.operations[input.operations_len] = Operation.decode(&reader);
        }
        return input;
    }

    /// Items per section in 1..=64, biased toward small sections (quadratically) so seeded
    /// inputs fill sections and reach prunes.
    fn items_per_section(reader: *fuzz_bytes.Reader) u64 {
        const draw = reader.below(65);
        const result = 1 + draw * draw / 65;
        assert(result >= 1 and result <= 64);
        return result;
    }

    /// A failure rate of 0..=100 percent, biased toward low rates (cubically) so random inputs
    /// also reach deep states; every rate stays reachable.
    fn rate(reader: *fuzz_bytes.Reader) Probability {
        const draw: u64 = reader.int(u8) % 101;
        const biased = draw * draw * draw / 10_000;
        assert(biased <= 100);
        return Probability.init(biased, 100).?;
    }
};

const Candidate = struct { position: u64, item: Item };

/// Conservative bounds on what a recovery may produce after an unclean shutdown:
/// - positions `[0, durable_prune)` are pruned,
/// - positions `[max_prune, durable_len)` hold exactly `values[position]`,
/// - positions `[durable_len, max_size)` are absent or hold a value recorded there, the latest
///   append or a failed append's candidate,
/// - the recovered size is in `[durable_len, max_size]`, and its boundary in
///   `[durable_prune, max_prune]`.
const Expected = struct {
    durable_len: u64 = 0,
    max_size: u64 = 0,
    durable_prune: u64 = 0,
    max_prune: u64 = 0,
    /// Latest value appended at each position.
    values: std.ArrayList(Item) = .empty,
    /// Values whose append failed after possibly persisting.
    candidates: std.ArrayList(Candidate) = .empty,

    fn deinit(self: *Expected) void {
        self.values.deinit(gpa);
        self.candidates.deinit(gpa);
        self.* = undefined;
    }

    /// State after a completed `init_at_size(target)`: fully pruned at `target`.
    fn reset(target: u64) Expected {
        return .{
            .durable_len = target,
            .max_size = target,
            .durable_prune = target,
            .max_prune = target,
        };
    }

    /// A successful append is not durable until a barrier: only the ceiling rises.
    fn appended(self: *Expected, item: Item) !void {
        try self.values.append(gpa, item);
        self.max_size = @max(self.max_size, self.values.items.len);
    }

    /// A failed append may have partially persisted at the position it targeted.
    fn append_failed(self: *Expected, size_before: u64, item: Item) !void {
        self.max_size = @max(self.max_size, size_before + 1);
        try self.candidates.append(gpa, .{ .position = size_before, .item = item });
    }

    /// Sync pins size, content, and pruning boundary exactly.
    fn synced(self: *Expected, bounds: Bounds) void {
        self.durable_len = bounds.end;
        self.max_size = bounds.end;
        self.durable_prune = bounds.start;
        self.max_prune = bounds.start;
        self.candidates.clearRetainingCapacity();
    }

    /// A completed data barrier (commit, or the sync inside a prune) pins size and content.
    fn committed(self: *Expected, size: u64) void {
        self.durable_len = size;
        self.max_size = size;
        self.candidates.clearRetainingCapacity();
    }

    /// A completed `start_sync`: everything appended before the call is durable and exact.
    fn started_sync_completed(self: *Expected, size: u64) void {
        self.durable_len = @max(self.durable_len, size);
        var kept: usize = 0;
        for (self.candidates.items) |candidate| {
            if (candidate.position < size) continue;
            self.candidates.items[kept] = candidate;
            kept += 1;
        }
        self.candidates.items.len = kept;
    }

    /// A successful bounded initializer durably fixes the retained prefix.
    fn reopened(self: *Expected, end: u64) void {
        self.values.shrinkRetainingCapacity(@intCast(@min(end, self.values.items.len)));
        self.candidates.clearRetainingCapacity();
        self.durable_len = end;
        self.max_size = end;
    }

    /// A failed initialization may have truncated, but surviving positions keep their content.
    fn initialization_failed(self: *Expected, target: u64, size_before: u64) void {
        self.durable_len = @min(self.durable_len, target);
        self.max_size = @max(self.max_size, size_before);
    }

    /// A successful prune durably removes whole sections: the boundary is exact.
    fn pruned(self: *Expected, boundary: u64) void {
        self.durable_prune = boundary;
        self.max_prune = boundary;
    }

    /// A failed prune may have removed sections (oldest first) up to `ceiling`.
    fn prune_failed(self: *Expected, ceiling: u64) void {
        self.max_prune = @max(self.max_prune, ceiling);
    }

    /// The cap a `CrashAtMost` marker with raw `size` selects: at least the pruning ceiling
    /// and at most one past the size ceiling.
    fn bounded_target(self: *const Expected, size: u64) u64 {
        return self.max_prune + size % ((self.max_size -| self.max_prune) + 2);
    }

    /// Bounds after `init_at_most(target)` recovers the crashed image.
    fn capped(self: *const Expected, target: u64) !Expected {
        var result = self.*;
        result.values = try self.values.clone(gpa);
        result.candidates = try self.candidates.clone(gpa);
        result.durable_len = @min(self.durable_len, target);
        result.max_size = @min(self.max_size, target);
        return result;
    }

    fn admissible(self: *const Expected, position: u64, item: *const Item) bool {
        if (position < self.values.items.len) {
            if (std.mem.eql(u8, &self.values.items[@intCast(position)], item)) return true;
        }
        for (self.candidates.items) |candidate| {
            if (candidate.position != position) continue;
            if (std.mem.eql(u8, &candidate.item, item)) return true;
        }
        return false;
    }
};

/// How a cycle's clean recovery reopens the crashed journal.
const Recovery = union(enum) {
    /// Ordinary `init`.
    init,
    /// The faulted attempt ran `init_at_size(target)`. With `complete`, recovery reruns it
    /// and must land at exactly `target..target`; otherwise `init` must observe either the
    /// prior state or the completed reset, never a mix.
    reset: struct { target: u64, complete: bool },
    /// The faulted attempt ran `init_at_most`; recovery reruns it at the same cap.
    at_most: u64,
};

/// One crash cycle: how to recover, and the ops before the next crash.
const Cycle = struct { recovery: Recovery, start: usize, end: usize };

/// Splits the ops into cycles at each crash marker; always returns at least one cycle.
fn split_into_cycles(ops: []const Operation, out: *[max_operations + 1]Cycle) []const Cycle {
    var count: usize = 0;
    var start: usize = 0;
    var recovery: Recovery = .init;
    for (ops, 0..) |op, index| {
        const next: Recovery = switch (op) {
            .crash => .init,
            .reset => |reset| .{ .reset = .{
                .target = reset.size % max_reset_size,
                .complete = reset.complete,
            } },
            .crash_at_most => |size| .{ .at_most = size },
            else => continue,
        };
        out[count] = .{ .recovery = recovery, .start = start, .end = index };
        count += 1;
        start = index + 1;
        recovery = next;
    }
    out[count] = .{ .recovery = recovery, .start = start, .end = ops.len };
    count += 1;
    assert(count <= out.len);
    return out[0..count];
}

fn expect_not_corruption(err: anyerror) !void {
    if (err == error.OutOfMemory) return err;
    try testing.expect(err != error.Corruption);
}

const Harness = struct {
    faults: Faults,
    cache_ref: paged.CacheRef,
    params: Params,

    fn init(self: *Harness, params: Params, seed: u64) !void {
        self.faults.init(gpa, seed);
        errdefer self.faults.deinit();
        self.cache_ref = try paged.CacheRef.init(gpa, params.page_size, params.page_cache_size);
        self.params = params;
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.faults.deinit();
    }
};

/// The target's checks and cycle driver for journal type `J`.
fn Driver(comptime J: type) type {
    return struct {
        const variable = J == contiguous.variable.Journal(Item);
        comptime {
            assert(variable or J == contiguous.fixed.Journal(Item));
        }

        fn config(harness: *Harness) J.BackingConfig {
            const params = &harness.params;
            if (variable) return .{
                .partition = partition,
                .items_per_section = params.items_per_section,
                .codec_config = {},
                .cache_ref = &harness.cache_ref,
                .write_buffer = params.write_buffer,
                .replay_buffer = params.replay_buffer,
            };
            return .{
                .partition = partition,
                .items_per_blob = params.items_per_section,
                .cache_ref = &harness.cache_ref,
                .write_buffer = params.write_buffer,
                .replay_buffer = params.replay_buffer,
            };
        }

        fn open(harness: *Harness, initializer: Attempt) !J {
            const storage = harness.faults.interface();
            return switch (initializer) {
                .init => J.init(gpa, storage, config(harness)),
                .reset => |target| J.init_at_size(gpa, storage, config(harness), target),
                .at_most => |target| J.init_at_most(gpa, storage, config(harness), target),
            };
        }

        /// The items of `[start, end)` replayed in batches of about `buffer` bytes.
        fn collect(journal: *J, start: u64, buffer: usize, out: *std.ArrayList(Item)) !void {
            out.clearRetainingCapacity();
            var replay = try journal.replay(.{ .start = start, .end = journal.size() }, buffer);
            defer replay.deinit();
            var position = start;
            while (try replay.next()) |batch| {
                try testing.expectEqual(position, batch.start);
                try out.appendSlice(gpa, batch.items);
                position += batch.items.len;
            }
            try testing.expectEqual(journal.size(), position);
        }

        /// Verifies the recovered journal falls within `expected`.
        fn assert_matches(journal: *J, expected: *const Expected) !void {
            const bounds = journal.get_bounds();
            try testing.expect(bounds.end >= bounds.start);
            try testing.expect(bounds.end >= expected.durable_len);
            try testing.expect(bounds.end <= expected.max_size);
            try testing.expect(bounds.start >= expected.durable_prune);
            try testing.expect(bounds.start <= expected.max_prune);
            for (0..bounds.start) |position| {
                try testing.expectError(error.ItemPruned, journal.read(position));
            }
            var read_items: std.ArrayList(Item) = .empty;
            defer read_items.deinit(gpa);
            for (bounds.start..bounds.end) |position| {
                const item = try journal.read(position);
                if (position < expected.durable_len) {
                    try testing.expectEqualSlices(u8, &expected.values.items[position], &item);
                } else {
                    // The content was written at that position by this run.
                    try testing.expect(expected.admissible(position, &item));
                }
                try read_items.append(gpa, item);
            }
            var replayed: std.ArrayList(Item) = .empty;
            defer replayed.deinit(gpa);
            try collect(journal, bounds.start, verify_replay_buffer, &replayed);
            try testing.expectEqual(read_items.items.len, replayed.items.len);
            for (read_items.items, replayed.items) |read, replay| {
                try testing.expectEqualSlices(u8, &read, &replay);
            }
        }

        /// The recovered journal as an `Expected` pinned to exactly that state.
        fn to_expected(journal: *J) !Expected {
            const bounds = journal.get_bounds();
            var expected: Expected = .{
                .durable_len = bounds.end,
                .max_size = bounds.end,
                .durable_prune = bounds.start,
                .max_prune = bounds.start,
            };
            errdefer expected.deinit();
            try expected.values.appendNTimes(gpa, @splat(0), @intCast(bounds.end));
            var items: std.ArrayList(Item) = .empty;
            defer items.deinit(gpa);
            try collect(journal, bounds.start, verify_replay_buffer, &items);
            @memcpy(expected.values.items[@intCast(bounds.start)..], items.items);
            return expected;
        }

        /// Recovers per `recovery` with faults off and checks the result.
        fn recover(harness: *Harness, expected: *const Expected, recovery: Recovery) !J {
            harness.faults.disarm();
            switch (recovery) {
                .init => {
                    var journal = try open(harness, .init);
                    errdefer journal.deinit();
                    try assert_matches(&journal, expected);
                    return journal;
                },
                .reset => |reset| {
                    const initializer: Attempt = if (reset.complete)
                        .{ .reset = reset.target }
                    else
                        .init;
                    var journal = try open(harness, initializer);
                    errdefer journal.deinit();
                    const at_target = journal.get_bounds().start == reset.target and
                        journal.size() == reset.target;
                    if (reset.complete or at_target) {
                        var cleared = Expected.reset(reset.target);
                        defer cleared.deinit();
                        try assert_matches(&journal, &cleared);
                    } else {
                        try assert_matches(&journal, expected);
                    }
                    return journal;
                },
                .at_most => |size| {
                    const target = expected.bounded_target(size);
                    var journal = try open(harness, .{ .at_most = target });
                    errdefer journal.deinit();
                    var capped = try expected.capped(target);
                    defer capped.deinit();
                    try assert_matches(&journal, &capped);
                    return journal;
                },
            }
        }

        /// One cycle: recover, check, then run the ops under faults and drop the journal.
        fn run_cycle(
            harness: *Harness,
            expected: *Expected,
            cycle: Cycle,
            ops: []const Operation,
        ) !void {
            const journal = try recover(harness, expected, cycle.recovery);
            var state: Ops = .{ .harness = harness, .journal = journal, .expected = expected };
            defer if (state.alive) state.journal.deinit();
            // Rebase the cycle on the state the clean recovery verified.
            const next = try to_expected(&state.journal);
            expected.deinit();
            expected.* = next;
            harness.faults.layer.config = harness.params.fault_config();
            defer harness.faults.disarm();
            for (ops[cycle.start..cycle.end]) |op| {
                if (!try state.apply(op)) return;
            }
        }

        /// A faulted recovery attempt: the given initializer, then the journal is dropped.
        fn faulted_attempt(context: *const AttemptContext) !void {
            var journal = try open(context.harness, context.attempt);
            journal.deinit();
        }

        /// The cycle state of `run_ops`. A mutation error ends the cycle (the crash); reads
        /// and replays never fault, so a bad one fails the test.
        const Ops = struct {
            harness: *Harness,
            journal: J,
            alive: bool = true,
            expected: *Expected,

            fn apply(self: *Ops, op: Operation) !bool {
                return switch (op) {
                    .append => |byte| self.append(@splat(byte)),
                    .read => |position| self.read(position),
                    .sync => self.sync(),
                    .start_sync => |hold| self.start_sync(hold),
                    .snapshot => true,
                    .commit => self.commit(),
                    .reopen_at_most => |size| self.reopen_at_most(size),
                    .prune => |min| self.prune(min),
                    .replay => |args| self.replay(args.buffer, args.start),
                    // `split_into_cycles` strips the markers.
                    .crash, .reset, .crash_at_most => unreachable,
                };
            }

            fn append(self: *Ops, item: Item) !bool {
                const size_before = self.journal.size();
                const position = self.journal.append(item) catch |err| {
                    try expect_not_corruption(err);
                    try self.expected.append_failed(size_before, item);
                    return false;
                };
                try testing.expectEqual(size_before, position);
                try self.expected.appended(item);
                return true;
            }

            /// A clamped retained position reads; the raw one exercises bounds validation.
            fn read(self: *Ops, position: u64) !bool {
                const bounds = self.journal.get_bounds();
                if (bounds.end > bounds.start) {
                    const target = bounds.start + position % (bounds.end - bounds.start);
                    try self.expect_read(target, bounds);
                }
                try self.expect_read(position, bounds);
                return true;
            }

            fn expect_read(self: *Ops, position: u64, bounds: Bounds) !void {
                if (self.journal.read(position)) |_| {
                    try testing.expect(position >= bounds.start and position < bounds.end);
                } else |err| switch (err) {
                    error.ItemPruned => try testing.expect(position < bounds.start),
                    error.ItemOutOfRange => try testing.expect(position >= bounds.end),
                    else => return err,
                }
            }

            fn sync(self: *Ops) !bool {
                self.journal.sync() catch |err| {
                    try expect_not_corruption(err);
                    return false;
                };
                self.expected.synced(self.journal.get_bounds());
                return true;
            }

            /// A dropped handle leaves the durable bounds unchanged; a held one completed.
            fn start_sync(self: *Ops, hold: bool) !bool {
                const size = self.journal.size();
                const completion = self.journal.start_sync() catch |err| {
                    try expect_not_corruption(err);
                    return false;
                };
                defer completion.release();
                if (!hold) return true;
                completion.wait() catch |err| {
                    try expect_not_corruption(err);
                    return false;
                };
                self.expected.started_sync_completed(size);
                return true;
            }

            fn commit(self: *Ops) !bool {
                self.journal.commit() catch |err| {
                    try expect_not_corruption(err);
                    return false;
                };
                self.expected.committed(self.journal.size());
                return true;
            }

            /// Syncs, then reopens with a cap: usually clamped into the retained range,
            /// occasionally raw to exercise validation.
            fn reopen_at_most(self: *Ops, size: u64) !bool {
                const bounds = self.journal.get_bounds();
                if (bounds.end == bounds.start) return true;
                const use_raw = size % 8 == 0;
                const target = if (use_raw) size else bounds.start + size % (bounds.end -
                    bounds.start + 1);
                if (!try self.sync()) return false;
                self.expected.committed(bounds.end);
                self.journal.deinit();
                self.alive = false;
                self.journal = open(self.harness, .{ .at_most = target }) catch |err| {
                    if (err == error.ItemPruned) {
                        // Validation rejects before mutating, and only a raw target can.
                        try testing.expect(use_raw);
                        return false;
                    }
                    try expect_not_corruption(err);
                    self.expected.initialization_failed(@min(target, bounds.end), bounds.end);
                    return false;
                };
                self.alive = true;
                try testing.expectEqual(@min(target, bounds.end), self.journal.size());
                self.expected.reopened(self.journal.size());
                return true;
            }

            /// Prunes at a raw position (capped to the size inside `prune`) with remove
            /// faults armed.
            fn prune(self: *Ops, min: u64) !bool {
                const bounds = self.journal.get_bounds();
                const layer = &self.harness.faults.layer;
                layer.config = self.harness.params.prune_fault_config();
                const result = self.journal.prune(min);
                layer.config = self.harness.params.fault_config();
                const pruned = result catch |err| {
                    try expect_not_corruption(err);
                    // Removals run oldest first, so the boundary may stop at any blob
                    // boundary up to the section floor.
                    const per_section = self.harness.params.items_per_section;
                    const section_floor = @min(min, bounds.end) / per_section * per_section;
                    self.expected.prune_failed(section_floor);
                    return false;
                };
                const boundary = self.journal.get_bounds().start;
                try testing.expect(boundary >= bounds.start);
                try testing.expectEqual(boundary != bounds.start, pruned);
                // A completed prune syncs everything before removing a blob.
                if (pruned) self.expected.committed(bounds.end);
                self.expected.pruned(boundary);
                return true;
            }

            /// The clamped replay returns the whole suffix and matches `read`; the raw start
            /// exercises bounds validation.
            fn replay(self: *Ops, buffer: usize, start: u64) !bool {
                const bounds = self.journal.get_bounds();
                const clamped = bounds.start + start % (bounds.end - bounds.start + 1);
                var items: std.ArrayList(Item) = .empty;
                defer items.deinit(gpa);
                try collect(&self.journal, clamped, buffer, &items);
                try testing.expectEqual(bounds.end - clamped, items.items.len);
                for (items.items, clamped..) |item, position| {
                    const read_item = try self.journal.read(position);
                    try testing.expectEqualSlices(u8, &read_item, &item);
                }
                if (collect(&self.journal, start, buffer, &items)) |_| {
                    try testing.expect(start >= bounds.start and start <= bounds.end);
                } else |err| switch (err) {
                    error.ItemPruned => try testing.expect(start < bounds.start),
                    error.ItemOutOfRange => try testing.expect(start > bounds.end),
                    else => return err,
                }
                return true;
            }
        };

        /// Alternates clean recovery and modeled operations with faulted restart attempts,
        /// then appends, syncs, and reopens a sentinel.
        fn run(harness: *Harness, ops: []const Operation) !void {
            var cycles_buffer: [max_operations + 1]Cycle = undefined;
            const cycles = split_into_cycles(ops, &cycles_buffer);
            var expected: Expected = .{};
            defer expected.deinit();
            for (cycles, 0..) |cycle, index| {
                try run_cycle(harness, &expected, cycle, ops);
                try harness.faults.crash();
                // The attempt before a reset or bounded cycle runs that initializer itself.
                const next: Recovery = if (index + 1 == cycles.len)
                    .init
                else
                    cycles[index + 1].recovery;
                const attempt: Attempt = switch (next) {
                    .init => .init,
                    .reset => |reset| .{ .reset = reset.target },
                    .at_most => |size| .{ .at_most = expected.bounded_target(size) },
                };
                const context: AttemptContext = .{ .harness = harness, .attempt = attempt };
                try harness.faults.faulted_recovery(&context, faulted_attempt);
            }
            try verify_final(harness, &expected);
        }

        /// The fault-free final phase: the last recovery holds, and a synced sentinel
        /// survives a reopen.
        fn verify_final(harness: *Harness, expected_in: *const Expected) !void {
            var journal = try recover(harness, expected_in, .init);
            var expected = try to_expected(&journal);
            defer expected.deinit();
            const sentinel: Item = @splat(0xEF);
            const position = journal.size();
            {
                defer journal.deinit();
                try testing.expectEqual(position, try journal.append(sentinel));
                try expected.appended(sentinel);
                try journal.sync();
                expected.synced(journal.get_bounds());
            }
            journal = try recover(harness, &expected, .init);
            errdefer journal.deinit();
            try testing.expectEqualSlices(u8, &sentinel, &try journal.read(position));
            try journal.destroy();
        }
    };
}

/// Replay is a pure read: it serves buffered items without writing, so it cannot fail under
/// write faults or leave unsynced writes for a crash (found by this target).
fn expect_replay_writes_nothing(comptime J: type, variable: bool) !void {
    var harness: Harness = undefined;
    try harness.init(.{
        .variable = variable,
        .page_size = 16,
        .page_cache_size = 2,
        .items_per_section = 4,
        .write_buffer = 2048,
        .replay_buffer = 64,
        .write_config = .{ .failure_rate = .one, .retention_rate = .zero, .mode = .prefix },
        .sync_rate = .zero,
        .resize_rate = .zero,
        .partial_resize_rate = .zero,
        .remove_rate = .zero,
    }, 7);
    defer harness.deinit();
    const D = Driver(J);
    var journal = try D.open(&harness, .init);
    defer journal.deinit();
    for (0..10) |value| _ = try journal.append(@splat(@intCast(value)));
    harness.faults.layer.config = harness.params.fault_config();
    defer harness.faults.disarm();
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    try D.collect(&journal, 3, 40, &items);
    try testing.expectEqual(7, items.items.len);
    for (items.items, 3..) |item, value| {
        try testing.expectEqualSlices(u8, &@as(Item, @splat(@intCast(value))), &item);
    }
}

test "contiguous replay writes nothing" {
    try expect_replay_writes_nothing(contiguous.fixed.Journal(Item), false);
    try expect_replay_writes_nothing(contiguous.variable.Journal(Item), true);
}

/// The initializer a faulted attempt runs on the crashed image.
const Attempt = union(enum) { init, reset: u64, at_most: u64 };

const AttemptContext = struct { harness: *Harness, attempt: Attempt };

fn recovery_run(bytes: []const u8) anyerror!void {
    const input = Input.decode(bytes);
    var harness: Harness = undefined;
    try harness.init(input.params, input.seed);
    defer harness.deinit();
    const ops = input.operations[0..input.operations_len];
    if (input.params.variable) {
        try Driver(contiguous.variable.Journal(Item)).run(&harness, ops);
    } else {
        try Driver(contiguous.fixed.Journal(Item)).run(&harness, ops);
    }
}

test "fuzz journal_contiguous_recovery (seeded)" {
    try fuzz_bytes.seeded(512, 0x636f6e74, 64, recovery_run);
}

test "fuzz journal_contiguous_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(512, recovery_run), .{});
}
