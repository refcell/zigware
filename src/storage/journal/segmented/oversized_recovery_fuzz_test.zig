//! The `journal_oversized_recovery` fuzz target (commonware `storage/fuzz`): marker-tracked
//! oversized journal crash recovery under partial-write crash cuts, on
//! `runtime.storage.faulty`.
//!
//! The oracle derives each section's retained prefix from the raw crash image and its marker
//! floors (see `recover_expected`). It asserts that entries covered by a completed sync
//! survive, that recovery removes orphan value sections and truncates each value glob to the
//! last retained entry, that a second recovery mutates nothing, and that sentinel appends land
//! at the repaired tail and reopen intact.
//!
//! Syncs complete at once here, so commonware's pipelined and parked syncs map as follows. A
//! pipelined `start_sync` completes immediately, so its coverage is durable at once, and the
//! ops that release or settle parked completions do nothing. A sync interrupted behind the
//! armed gate becomes a sync whose first blob with work fails its blob sync after writing its
//! flush, while every other blob syncs. Abandoned `start_sync` handles become blob syncs that
//! all fail after writing their flushes, and a prune parked at its marker sync becomes a
//! prune whose syncs fail.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const Crc32 = @import("cryptography").crc32.Crc32;
const oversized = @import("oversized.zig");
const metadata_mod = @import("../../metadata/mod.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;

const gpa = testing.allocator;
const paged = runtime.buffer.paged;
const Probability = utils.Probability;

const index_partition = "fuzz-index";
const value_partition = "fuzz-values";
const marker_partition = "fuzz-markers";
const page_size = 128;
const physical_page_size = page_size + paged.checksum_size;
const value_checksum_size = 4;
const sections = 4;
const max_entries = 24;
/// Entries a section can hold: the script and a sentinel.
const max_section_entries = max_entries + 1;

/// Index entry that stores a u64 id and references a value.
const TestEntry = struct {
    id: u64,
    value_offset: u64 = 0,
    value_size: u32 = 0,

    pub const fixed_size: usize = 8 + 8 + 4;

    pub fn value_location(self: TestEntry) oversized.Location {
        return .{ .offset = self.value_offset, .size = self.value_size };
    }

    pub fn with_location(self: TestEntry, offset: u64, size: u32) TestEntry {
        return .{ .id = self.id, .value_offset = offset, .value_size = size };
    }

    pub fn encode_size(_: TestEntry) usize {
        return fixed_size;
    }

    pub fn write(self: TestEntry, writer: *codec.Writer) void {
        writer.write_int(u64, self.id);
        writer.write_int(u64, self.value_offset);
        writer.write_int(u32, self.value_size);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!TestEntry {
        return .{
            .id = try reader.read_int(u64),
            .value_offset = try reader.read_int(u64),
            .value_size = try reader.read_int(u32),
        };
    }

    fn decode(bytes: *const [fixed_size]u8) TestEntry {
        return .{
            .id = std.mem.readInt(u64, bytes[0..8], .big),
            .value_offset = std.mem.readInt(u64, bytes[8..16], .big),
            .value_size = std.mem.readInt(u32, bytes[16..20], .big),
        };
    }
};

const TestValue = [16]u8;
const Journal = oversized.Oversized(TestEntry, TestValue);
const Markers = metadata_mod.Metadata(u64, u64);

fn value_of(id: u64) TestValue {
    return @splat(@truncate(id));
}

const Input = struct {
    /// Number of entries to append (1..=24).
    count: u8,
    /// Crash retention rate (percent) for unsynced bytes.
    retention: u8,
    /// Partial-write mode: subset when set, prefix otherwise.
    subset: bool,
    /// Per-entry target section selector.
    routes: [max_entries]u8,
    /// Per-entry action after its append, in the low three bits: sync its section
    /// (pipelined or blocking), sync everything, flush nothing to publish marker debt, or
    /// prune below the section the top four bits select.
    ops: [max_entries]u8,
    /// Shape of the faulted crash: flush everything without syncing, interrupt a sync of
    /// every section, interrupt a sync of one section, or interrupt a prune.
    final_op: u8,
    /// Remove failure rate armed around every prune.
    remove_rate: Probability,
    seed: u64,

    /// The run's shape comes first and each route travels with its op, so short inputs
    /// still choose a crash shape and a scripted prefix.
    fn decode(bytes: []const u8) Input {
        var reader = fuzz_bytes.Reader.init(bytes);
        var input: Input = .{
            .count = reader.int(u8),
            // Biased toward full retention so lossless flushes are checked often; every
            // percentage stays reachable.
            .retention = @min(reader.int(u8) % 128, 100),
            .subset = reader.boolean(),
            .routes = undefined,
            .ops = undefined,
            .final_op = reader.int(u8),
            .remove_rate = .zero,
            .seed = reader.int(u64),
        };
        // Biased toward low rates (cubically) so random inputs also reach deep states.
        const draw: u64 = reader.int(u8) % 101;
        input.remove_rate = Probability.init(draw * draw * draw / 10_000, 100).?;
        for (&input.routes, &input.ops) |*selector, *op| {
            selector.* = reader.int(u8);
            op.* = reader.int(u8);
        }
        return input;
    }

    fn script_len(self: *const Input) usize {
        return @as(usize, self.count % max_entries) + 1;
    }

    fn route(self: *const Input, id: usize) u64 {
        return self.routes[id % self.routes.len] % sections;
    }
};

/// The ids at each position of a section.
const Ids = struct {
    len: usize = 0,
    items: [max_section_entries]u64 = undefined,

    fn push(self: *Ids, id: u64) void {
        assert(self.len < max_section_entries);
        self.items[self.len] = id;
        self.len += 1;
    }

    fn slice(self: *const Ids) []const u64 {
        return self.items[0..self.len];
    }
};

/// The operation phase's model, per section.
const Model = struct {
    /// Entries covered by a completed sync.
    durable: [sections]u64 = @splat(0),
    /// The intended stream after prune-aware routing, through appends and completed prunes.
    ids: [sections]Ids = @splat(.{}),

    fn sync_completed(self: *Model, section: usize) void {
        self.durable[section] = self.ids[section].len;
    }

    /// Durability claims below `min` are dropped: those sections may be partially removed.
    fn drop_durable_below(self: *Model, min: u64) void {
        for (0..min) |section| self.durable[section] = 0;
    }

    fn prune_completed(self: *Model, min: u64) void {
        self.drop_durable_below(min);
        for (0..min) |section| self.ids[section] = .{};
    }
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

    /// The fully-retained-section check relies on no buffer-fill flush before the fault
    /// window opens: at most 24 entries of 20 bytes stay under these 512-byte buffers.
    fn config(self: *Harness) Journal.Cfg {
        return .{
            .index_partition = index_partition,
            .value_partition = value_partition,
            .index_cache_ref = &self.cache_ref,
            .index_write_buffer = 512,
            .value_write_buffer = 512,
            .replay_buffer = 4096,
            .codec_config = {},
        };
    }

    /// The full tracked recovery: open the marker sidecar, drain the marker-aware replay, and
    /// finish.
    fn init_tracked(self: *Harness) !Journal {
        const storage = self.faults.interface();
        var recovery = try Journal.init_with_markers(gpa, storage, self.config(), marker_partition);
        try recovery.drain();
        return recovery.finish();
    }

    fn logical_blob(self: *Harness, partition: []const u8, section: u64) !?[]u8 {
        var name: [8]u8 = undefined;
        std.mem.writeInt(u64, &name, section, .big);
        return self.faults.inner.logical_blob(gpa, partition, &name);
    }
};

/// A faulted recovery attempt: a complete tracked recovery, then the journal is dropped.
fn recover_once(harness: *Harness) !void {
    var journal = try harness.init_tracked();
    journal.deinit();
}

/// One run's operation phase.
const Run = struct {
    harness: *Harness,
    input: *const Input,
    model: *Model,
    journal: *Journal,
    floor: u64 = 0,

    /// Routes appends above the prune floor: mutating a pruned section fails.
    fn above_floor(self: *const Run, section: u64) u64 {
        assert(self.floor < sections);
        if (section >= self.floor) return section;
        return self.floor + section % (sections - self.floor);
    }

    /// Applies the op after an append to `section`; returns false once a prune failed (the
    /// journal is retired then and the run crashes with nothing flushed by a final op).
    fn apply(self: *Run, op: u8, section: u64) !bool {
        const index: usize = @intCast(section);
        switch (op & 0x07) {
            1, 4 => {
                try self.journal.sync(&.{section});
                self.model.sync_completed(index);
            },
            5 => {
                try self.journal.sync_all();
                for (0..sections) |each| self.model.sync_completed(each);
            },
            // Empty flush: every settled durability proof publishes as a marker generation.
            6 => try self.journal.sync(&.{}),
            7 => return self.prune((op >> 4) % sections),
            // Releasing or settling parked completions: syncs here never park.
            else => {},
        }
        return true;
    }

    /// Prunes below `min` with remove faults armed: a fault can fail the prune between an
    /// index section's removal and its value section's, leaving an orphan for recovery.
    fn prune(self: *Run, min: u64) !bool {
        self.harness.faults.layer.config = .{ .remove_rate = self.input.remove_rate };
        const result = self.journal.prune(min);
        self.harness.faults.disarm();
        const pruned = result catch |err| {
            if (err == error.OutOfMemory) return err;
            self.model.drop_durable_below(min);
            return false;
        };
        if (pruned) {
            self.floor = @max(self.floor, min);
            self.model.prune_completed(min);
        }
        return true;
    }

    /// Syncs every buffer with work among the selected sections, oldest first and each
    /// section's two journals in the order `values_first` picks (barriers arrive in any
    /// order). With `fail_first`, the first one's blob sync fails after its flush is written
    /// while the others sync; with `fail_all`, every one fails that way.
    fn sync_buffers(
        self: *Run,
        only: ?u64,
        mode: enum { fail_first, fail_all },
        values_first: bool,
    ) !void {
        const layer = &self.harness.faults.layer;
        var parked = false;
        for (0..sections) |section| {
            if (only != null and only.? != section) continue;
            const index = self.journal.index.manager.get(section) catch null;
            const values = self.journal.values.manager.get(section) catch null;
            for (0..2) |turn| {
                if ((turn == 0) == values_first) {
                    if (values) |buffer| if (buffer.needs_sync()) {
                        try sync_buffer(layer, buffer, mode == .fail_all or !parked);
                        parked = true;
                    };
                } else if (index) |buffer| if (buffer.needs_sync()) {
                    try sync_buffer(layer, buffer, mode == .fail_all or !parked);
                    parked = true;
                };
            }
        }
    }

    /// The faulted crash shape; returns whether everything was flushed.
    fn final_op(self: *Run) !bool {
        const op = self.input.final_op;
        switch (op % 4) {
            1 => {
                // An interrupted sync of every section, or one that completed.
                if ((op >> 2) % 2 == 0) {
                    try self.sync_buffers(null, .fail_first, (op >> 3) % 2 == 1);
                    return false;
                }
                try self.journal.sync_all();
                for (0..sections) |each| self.model.sync_completed(each);
            },
            2 => {
                // An interrupted sync of one section above the floor, or one that completed.
                const section = self.above_floor((op >> 2) % sections);
                if ((op >> 5) % 2 == 0) {
                    try self.sync_buffers(section, .fail_first, (op >> 6) % 2 == 1);
                    return false;
                }
                try self.journal.sync(&.{section});
                self.model.sync_completed(@intCast(section));
            },
            3 => try self.interrupted_prune((op >> 2) % sections, (op >> 4) % 3),
            else => {
                // Flush every buffered append, then abandon the syncs: the crash samples the
                // writes and discards their barriers.
                try self.sync_buffers(null, .fail_all, false);
                return true;
            },
        }
        return false;
    }

    /// A prune abandoned before it first ran (`polls` 0), parked at its marker sync (1), or
    /// run to completion (2). The armed remove faults can fail it between section removals.
    fn interrupted_prune(self: *Run, min: u64, polls: u64) !void {
        assert(polls < 3);
        if (polls == 0) return;
        const layer = &self.harness.faults.layer;
        if (polls == 1) layer.config.sync_rate = .one;
        const result = self.journal.prune(min);
        layer.config.sync_rate = null;
        // The oracle must not depend on where a failed prune stopped, so durability claims
        // below the floor are dropped. The intended stream is kept: the sections may equally
        // have survived, and surviving records must stay authentic.
        const pruned = result catch |err| {
            if (err == error.OutOfMemory) return err;
            self.model.drop_durable_below(min);
            return;
        };
        if (pruned) self.model.prune_completed(min);
    }
};

/// Syncs one section buffer with work; when `fail`, its blob sync fails after the flush.
fn sync_buffer(layer: anytype, buffer: anytype, fail: bool) !void {
    assert(buffer.needs_sync());
    if (!fail) return buffer.sync();
    layer.config.sync_rate = .one;
    defer layer.config.sync_rate = null;
    if (buffer.sync()) |_| return error.TestUnexpectedResult else |err| {
        if (err == error.OutOfMemory) return err;
    }
    assert(buffer.failed);
}

/// Runs the script and the faulted final op; returns whether everything was flushed.
fn operation_phase(harness: *Harness, input: *const Input, model: *Model) !bool {
    var journal = try harness.init_tracked();
    defer journal.deinit();
    var run: Run = .{ .harness = harness, .input = input, .model = model, .journal = &journal };
    for (0..input.script_len()) |id| {
        const section = run.above_floor(input.route(id));
        _ = try journal.append(section, .{ .id = id }, value_of(id));
        model.ids[@intCast(section)].push(id);
        if (!try run.apply(input.ops[id % input.ops.len], section)) return false;
    }
    // Retention binds when a write is issued, so the window's writes tear at the crash.
    harness.faults.layer.config = .{
        .write_rate = .{
            .failure_rate = .zero,
            .retention_rate = Probability.init(input.retention, 100).?,
            .mode = if (input.subset) .subset else .prefix,
        },
        .remove_rate = input.remove_rate,
    };
    defer harness.faults.disarm();
    return run.final_op();
}

/// The marker sidecar's floors, read with the production parser before recovery reconciles
/// them: init adopts the newest valid marker generation and durably resets only a copy a
/// crash left torn, which the tracked recovery repeats identically.
fn read_floors(harness: *Harness) ![sections]u64 {
    var markers = try Markers.init(gpa, harness.faults.interface(), .{
        .partition = marker_partition,
        .codec_config = {},
    });
    defer markers.deinit();
    var floors: [sections]u64 = @splat(0);
    for (markers.items()) |entry| {
        try testing.expect(entry.key < sections);
        floors[@intCast(entry.key)] = entry.value;
    }
    return floors;
}

/// The whole records of an index blob's valid-page prefix.
const Records = struct {
    len: usize = 0,
    items: [max_section_entries]TestEntry = undefined,

    fn read(harness: *Harness, section: u64) !Records {
        var records: Records = .{};
        const raw = try harness.logical_blob(index_partition, section) orelse return records;
        defer gpa.free(raw);
        var logical: std.ArrayList(u8) = .empty;
        defer logical.deinit(gpa);
        for (0..raw.len / physical_page_size) |page_index| {
            const page = raw[page_index * physical_page_size ..][0..physical_page_size];
            const len = paged.page_len(page, page_size) orelse break;
            try logical.appendSlice(gpa, page[0..len]);
            if (len < page_size) break;
        }
        const count = logical.items.len / TestEntry.fixed_size;
        try testing.expect(count <= max_section_entries);
        for (0..count) |index| {
            const bytes = logical.items[index * TestEntry.fixed_size ..][0..TestEntry.fixed_size];
            records.items[index] = TestEntry.decode(bytes);
        }
        records.len = count;
        return records;
    }
};

/// Whether `entry` references an in-bounds value frame whose checksum verifies against the
/// raw value bytes.
fn frame_valid(harness: *Harness, section: u64, entry: TestEntry) !bool {
    const location = entry.value_location();
    if (location.size < value_checksum_size) return false;
    const end = try std.math.add(u64, location.offset, location.size);
    const raw = try harness.logical_blob(value_partition, section) orelse return false;
    defer gpa.free(raw);
    if (end > raw.len) return false;
    const frame = raw[@intCast(location.offset)..@intCast(end)];
    const data_len = frame.len - value_checksum_size;
    const stored = std.mem.readInt(u32, frame[data_len..][0..value_checksum_size], .big);
    return Crc32.checksum(frame[0..data_len]) == stored;
}

/// Each section's expected recovery outcome, derived from the raw crash image.
const Image = struct {
    /// The id at each retained position.
    retained: [sections]Ids = @splat(.{}),
    /// Each scanned section's terminal value end (zero when nothing is retained), which
    /// repair must truncate the glob to.
    value_end: [sections]?u64 = @splat(null),
};

/// Reconstructs each section's expected recovery from the raw crash image without repairing
/// it. Recovery adopts each section's marker floor without value checks and validates
/// forward from it, truncating at the first invalid value.
///
/// Markers trail durability. Under crash cuts a floor was published only after a completed
/// joint sync covered it, and prune durably removes markers before data can shrink, so a
/// floor never exceeds the section's durable record count and every frame below it is still
/// in bounds and checksum-valid. An in-model crash cut cannot forge a CRC-valid record, so
/// every retained record matches the intended stream.
fn recover_expected(harness: *Harness, model: *const Model, floors: *const [sections]u64) !Image {
    var image: Image = .{};
    var seen: [sections]bool = @splat(false);
    var names = try harness.faults.interface().scan(gpa, index_partition);
    defer names.deinit(gpa);
    for (names.items) |name| {
        try testing.expectEqual(8, name.len);
        const section = std.mem.readInt(u64, name[0..8], .big);
        try testing.expect(section < sections);
        seen[@intCast(section)] = true;
        try expect_section(harness, model, floors[@intCast(section)], section, &image);
    }
    // A positive marker proves its records durable, so its section must survive.
    for (floors, seen) |floor, found| try testing.expect(floor == 0 or found);
    return image;
}

fn expect_section(
    harness: *Harness,
    model: *const Model,
    floor: u64,
    section: u64,
    image: *Image,
) !void {
    const records = try Records.read(harness, section);
    var validity: [max_section_entries]bool = undefined;
    for (records.items[0..records.len], 0..) |record, index| {
        validity[index] = try frame_valid(harness, section, record);
    }
    // The marker trails the durable index and value boundaries.
    try testing.expect(floor <= records.len);
    for (validity[0..@intCast(floor)]) |valid| try testing.expect(valid);
    var retained: usize = @intCast(floor);
    while (retained < records.len and validity[retained]) retained += 1;
    const index: usize = @intCast(section);
    image.value_end[index] = 0;
    if (retained > 0) {
        const location = records.items[retained - 1].value_location();
        image.value_end[index] = location.offset + location.size;
    }
    const intended = model.ids[index].slice();
    for (records.items[0..retained], 0..) |record, position| {
        // The crash image retains no unauthentic index record.
        try testing.expect(position < intended.len);
        try testing.expectEqual(intended[position], record.id);
        image.retained[index].push(record.id);
    }
}

/// Asserts the journal serves the identity and value of every retained entry. When `sealed`,
/// nothing was appended past the recovered prefix, so reading one position past it fails.
fn assert_view(journal: *Journal, image: *const Image, sealed: bool) !void {
    for (0..sections) |section| {
        const ids = image.retained[section].slice();
        for (ids, 0..) |id, position| {
            const entry = try journal.get(section, position);
            try testing.expectEqual(id, entry.id);
            const location = entry.value_location();
            const value = try journal.get_value(section, location.offset, location.size);
            try testing.expectEqualSlices(u8, &value_of(id), &value);
        }
        if (!sealed) continue;
        if (journal.get(section, ids.len)) |_| return error.TestUnexpectedResult else |err| {
            switch (err) {
                error.ItemOutOfRange, error.SectionOutOfRange => {},
                else => return err,
            }
        }
    }
}

/// Every blob's logical size in both partitions.
const Sizes = struct {
    index: [sections]?u64 = @splat(null),
    values: [sections]?u64 = @splat(null),

    fn read(harness: *Harness) !Sizes {
        var sizes: Sizes = .{};
        inline for (.{ index_partition, value_partition }, .{ &sizes.index, &sizes.values }) |
            partition,
            out,
        | {
            var names = try harness.faults.interface().scan(gpa, partition);
            defer names.deinit(gpa);
            for (names.items) |name| {
                const section = std.mem.readInt(u64, name[0..8], .big);
                try testing.expect(section < sections);
                const logical = (try harness.logical_blob(partition, section)).?;
                defer gpa.free(logical);
                out[@intCast(section)] = logical.len;
            }
        }
        return sizes;
    }

    /// Repair pairs every index section with a glob truncated to the last retained entry's
    /// end and removes value sections with no index counterpart, so stale value bytes can
    /// never satisfy a later append's range.
    fn expect_repaired(self: *const Sizes, image: *const Image) !void {
        for (self.index, self.values, image.value_end) |index, values, value_end| {
            if (index != null) try testing.expect(values != null);
            const size = values orelse continue;
            try testing.expect(index != null);
            try testing.expectEqual(value_end.?, size);
        }
    }
};

/// Recovery is idempotent, and appends land at the repaired tail, survive a sync, and reopen
/// intact.
fn verify_reopen(harness: *Harness, image: *const Image, sizes: *const Sizes) !void {
    {
        var journal = try harness.init_tracked();
        defer journal.deinit();
        try testing.expectEqualDeep(sizes.*, try Sizes.read(harness));
        try assert_view(&journal, image, true);
        for (0..sections) |section| {
            const sentinel = std.math.maxInt(u64) - section;
            const appended = try journal.append(section, .{ .id = sentinel }, @splat(0xFF));
            try testing.expectEqual(image.retained[section].len, appended.position);
        }
        try journal.sync_all();
    }
    var reopened = try harness.init_tracked();
    errdefer reopened.deinit();
    try assert_view(&reopened, image, false);
    for (0..sections) |section| {
        const entry = try reopened.get(section, image.retained[section].len);
        try testing.expectEqual(std.math.maxInt(u64) - section, entry.id);
        const location = entry.value_location();
        const value = try reopened.get_value(section, location.offset, location.size);
        try testing.expectEqualSlices(u8, &@as(TestValue, @splat(0xFF)), &value);
    }
    try reopened.destroy();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    const input = Input.decode(bytes);
    var harness: Harness = undefined;
    try harness.init(input.seed);
    defer harness.deinit();
    var model: Model = .{};
    const flushed_all = try operation_phase(&harness, &input, &model);
    try harness.faults.crash();
    // A failed recovery instance is abandoned; its crash image must stay recoverable.
    try harness.faults.faulted_recovery(&harness, recover_once);
    const floors = try read_floors(&harness);
    const image = try recover_expected(&harness, &model, &floors);
    {
        var journal = try harness.init_tracked();
        defer journal.deinit();
        // Entries a completed sync covered survive, and a crash that retained every faulted
        // byte after flushing everything loses nothing at all.
        for (model.durable, image.retained, model.ids) |durable, retained, ids| {
            try testing.expect(retained.len >= durable);
            if (input.retention == 100 and flushed_all) {
                try testing.expectEqualSlices(u64, ids.slice(), retained.slice());
            }
        }
        try assert_view(&journal, &image, true);
    }
    const sizes = try Sizes.read(&harness);
    try sizes.expect_repaired(&image);
    try harness.faults.crash();
    try verify_reopen(&harness, &image, &sizes);
}

test "fuzz journal_oversized_recovery (seeded)" {
    try fuzz_bytes.seeded(64, 0x6f766572, 64, recovery_run);
}

test "fuzz journal_oversized_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(64, recovery_run), .{});
}
