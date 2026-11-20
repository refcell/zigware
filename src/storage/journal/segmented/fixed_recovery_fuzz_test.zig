//! A `journal_segmented_fixed_recovery` fuzz target (no commonware counterpart; modeled on
//! `journal_segmented_variable_recovery`): the segmented fixed journal under drawn write, sync,
//! remove, and resize faults (archive's `Faults`), crashed with torn unsynced writes, then a
//! chain of faulted recoveries and a clean reopen.
//!
//! The model keeps each section's issued appends and the count a completed sync covered. A clean
//! replay must hold, per section, a prefix of the issued stream (every recovered item is one that
//! was appended, at its position: nothing torn is half-visible), at least the synced count, and
//! no section a completed prune removed. A second reopen must replay the same, and a sentinel
//! appended at each section's tail must survive a sync and reopen.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const runtime = @import("runtime");
const fixed = @import("fixed.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;

const gpa = testing.allocator;
const paged = runtime.buffer.paged;
const J = fixed.Journal(u64);

const partition = "segmented-fixed-recovery";
/// Not a multiple of the 8-byte item, so items straddle pages and a torn page can leave a
/// partial trailing item for recovery to truncate.
const page_size: u16 = 60;
const sections = 4;
const max_steps = 48;
const sentinel: u64 = 0xDEAD_BEEF_0000_0001;

/// The value of the `id`th issued append: never zero and never the sentinel.
fn value_of(section: u64, id: usize) u64 {
    return (section << 32) | (@as(u64, id) + 1);
}

const Stream = struct {
    count: usize = 0,
    items: [max_steps]u64 = undefined,

    fn push(self: *Stream, item: u64) void {
        assert(self.count < max_steps);
        self.items[self.count] = item;
        self.count += 1;
    }
};

const Model = struct {
    issued: [sections]Stream = @splat(.{}),
    /// Items covered by a completed sync of the section.
    durable: [sections]usize = @splat(0),
    /// Sections a completed prune removed.
    pruned: [sections]bool = @splat(false),
    /// Sections a failed prune may have removed.
    doomed: [sections]bool = @splat(false),
    floor: u64 = 0,
};

/// A clean replay's contents, by section; null where the section is not open.
const Seen = struct {
    present: [sections]bool = @splat(false),
    streams: [sections]Stream = @splat(.{}),
};

const Harness = struct {
    faults: Faults,
    cache_ref: paged.CacheRef,

    fn init(self: *Harness, seed: u64) !void {
        self.faults.init(gpa, seed);
        self.cache_ref = try paged.CacheRef.init(gpa, page_size, 4);
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.faults.deinit();
    }

    fn config(self: *Harness) fixed.Config {
        return .{
            .partition = partition,
            .cache_ref = &self.cache_ref,
            .write_buffer = 96,
            .replay_buffer = 128,
        };
    }

    /// Replays every section into `seen`, requiring dense positions, and returns the journal.
    fn replay(self: *Harness, seen: *Seen) !J {
        var recovery = try J.preflight_floors(gpa, self.faults.interface(), self.config(), &.{});
        while (recovery.next() catch |err| {
            recovery.deinit();
            return err;
        }) |entry| {
            try testing.expect(entry.section < sections);
            const stream = &seen.streams[@intCast(entry.section)];
            try testing.expectEqual(@as(u64, stream.count), entry.position);
            stream.push(entry.item);
        }
        var journal = try recovery.finish();
        for (journal.open_sections()) |open| {
            try testing.expect(open.section < sections);
            seen.present[@intCast(open.section)] = true;
        }
        return journal;
    }
};

/// A faulted recovery attempt: a complete replay, then the journal is dropped.
fn recover_once(harness: *Harness) !void {
    var journal = try J.init(gpa, harness.faults.interface(), harness.config());
    journal.deinit();
}

/// One drawn step; false once a mutation failed (the journal is retired then).
fn step(journal: *J, model: *Model, reader: *fuzz_bytes.Reader, id: usize) bool {
    const op = reader.int(u8);
    var section: u64 = (op >> 4) % sections;
    if (section < model.floor) section = model.floor + section % (sections - model.floor);
    switch (op & 0x0f) {
        0...9 => {
            const item = value_of(section, id);
            // Counted before the append: a failed append may still have reached storage.
            model.issued[@intCast(section)].push(item);
            const position = journal.append(section, item) catch return false;
            assert(position + 1 == model.issued[@intCast(section)].count);
        },
        10, 11 => {
            journal.sync(&.{section}) catch return false;
            const index: usize = @intCast(section);
            model.durable[index] = model.issued[index].count;
        },
        12, 13 => {
            journal.sync_all() catch return false;
            for (0..sections) |index| model.durable[index] = model.issued[index].count;
        },
        else => {
            const min = (op >> 4) % sections;
            const pruned = journal.prune(min) catch {
                for (0..min) |index| model.doomed[index] = !model.pruned[index];
                return false;
            };
            if (pruned) for (0..min) |index| {
                model.pruned[index] = true;
            };
            model.floor = @max(model.floor, min);
        },
    }
    return true;
}

fn operation_phase(harness: *Harness, model: *Model, reader: *fuzz_bytes.Reader) !void {
    var journal = try J.init(gpa, harness.faults.interface(), harness.config());
    harness.faults.arm(reader);
    defer harness.faults.disarm();
    const steps = 1 + reader.below(max_steps);
    for (0..steps) |id| {
        if (!step(&journal, model, reader, id)) break;
    }
    journal.deinit();
}

fn check(seen: *const Seen, model: *const Model) !void {
    for (0..sections) |index| {
        const found = &seen.streams[index];
        const issued = &model.issued[index];
        if (issued.count == 0) try testing.expect(!seen.present[index]);
        if (model.pruned[index]) try testing.expect(!seen.present[index]);
        try testing.expect(found.count <= issued.count);
        const count = found.count;
        try testing.expectEqualSlices(u64, issued.items[0..count], found.items[0..count]);
        if (model.doomed[index] and !seen.present[index]) continue;
        if (model.pruned[index]) continue;
        try testing.expect(found.count >= model.durable[index]);
    }
}

/// Reopens to the same contents, then appends a sentinel at each tail and reopens again.
fn verify_repair(harness: *Harness, first: *const Seen) !void {
    var again: Seen = .{};
    var journal = try harness.replay(&again);
    errdefer journal.deinit();
    for (0..sections) |index| {
        try testing.expectEqual(first.present[index], again.present[index]);
        try testing.expectEqual(first.streams[index].count, again.streams[index].count);
    }
    for (0..sections) |index| {
        if (!again.present[index]) continue;
        const position = try journal.append(index, sentinel);
        try testing.expectEqual(@as(u64, again.streams[index].count), position);
    }
    try journal.sync_all();
    journal.deinit();
    var last: Seen = .{};
    journal = try harness.replay(&last);
    for (0..sections) |index| {
        if (!again.present[index]) continue;
        const stream = &last.streams[index];
        try testing.expectEqual(again.streams[index].count + 1, stream.count);
        try testing.expectEqual(sentinel, stream.items[stream.count - 1]);
    }
    try journal.destroy();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var harness: Harness = undefined;
    try harness.init(reader.int(u64));
    defer harness.deinit();
    var model: Model = .{};
    try operation_phase(&harness, &model, &reader);
    try harness.faults.crash();
    try harness.faults.faulted_recovery(&harness, recover_once);
    var seen: Seen = .{};
    var journal = try harness.replay(&seen);
    journal.deinit();
    try check(&seen, &model);
    try verify_repair(&harness, &seen);
}

test "fuzz journal_segmented_fixed_recovery (seeded)" {
    try fuzz_bytes.seeded(128, 0x73666978, 96, recovery_run);
}

test "fuzz journal_segmented_fixed_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(128, recovery_run), .{});
}
