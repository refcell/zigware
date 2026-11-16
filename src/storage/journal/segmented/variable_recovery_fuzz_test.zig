//! The `journal_segmented_variable_recovery` fuzz target (commonware `storage/fuzz`): segmented
//! variable journal crash recovery under partial-write crash cuts, on
//! `runtime.storage.faulty`.
//!
//! The oracle rebuilds each section's expected item prefix from the raw crash image (the
//! contiguous valid-page prefix, cut at the last whole frame), drains a recovery against it,
//! and reopens the repaired result. A section with no valid page recovers to size zero, so a
//! probe item appended to it lands at offset zero. Prunes run with remove faults armed: a
//! completed prune removed every section below its floor, and a failed one removed an
//! oldest-first prefix of them, leaving the section whose removal failed.
//!
//! Commonware interrupts the final `sync_all` by parking the first section's durability
//! barrier. Syncs complete at once here, so the interrupted run syncs every other section,
//! then fails the first section's blob sync, leaving its flushed bytes unsynced for the crash
//! to tear.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const runtime = @import("runtime");
const utils = @import("utils");
const variable = @import("variable.zig");
const fuzz_bytes = @import("../../fuzz_bytes.zig");
const Faults = @import("../../archive/faults.zig").Faults;

const gpa = testing.allocator;
const paged = runtime.buffer.paged;
const Probability = utils.Probability;
const Item = []const u8;
const Journal = variable.Journal(Item);

const partition = "segmented-variable-recovery";
const page_size = 128;
const physical_page_size = page_size + paged.checksum_size;
const max_item_len = 48;
const sections = 4;
const max_script = 32;
/// Frames a section can hold: the script, a probe, and a sentinel.
const max_frames = max_script + 2;

const Input = struct {
    count: u8,
    baseline: u8,
    retention: u8,
    subset: bool,
    routes: [32]u8,
    ops: [32]u8,
    remove_failure: u8,
    final_polls: u8,
    seed: u64,

    fn decode(bytes: []const u8) Input {
        var reader = fuzz_bytes.Reader.init(bytes);
        var input: Input = .{
            .count = reader.int(u8),
            .baseline = reader.int(u8),
            .retention = reader.int(u8),
            .subset = reader.boolean(),
            .routes = undefined,
            .ops = undefined,
            .remove_failure = 0,
            .final_polls = 0,
            .seed = 0,
        };
        for (&input.routes) |*selector| selector.* = reader.int(u8);
        for (&input.ops) |*op| op.* = reader.int(u8);
        input.remove_failure = reader.int(u8);
        input.final_polls = reader.int(u8);
        input.seed = reader.int(u64);
        return input;
    }

    fn script_len(self: *const Input) usize {
        return @as(usize, self.count % max_script) + 1;
    }

    /// The scripted item `id`: `(id * 7) % 48` bytes of `id`, routed to a section.
    fn route(self: *const Input, id: usize) u64 {
        return self.routes[id % self.routes.len] % sections;
    }
};

fn item_bytes(id: usize, out: *[max_item_len]u8) []u8 {
    const len = (id * 7) % max_item_len;
    @memset(out[0..len], @intCast(id));
    return out[0..len];
}

/// A section's frames: copies of item payloads in order.
const Frames = struct {
    count: usize = 0,
    lens: [max_frames]u8 = undefined,
    data: [max_frames][max_item_len]u8 = undefined,

    fn push(self: *Frames, bytes: []const u8) void {
        assert(self.count < max_frames);
        assert(bytes.len <= max_item_len);
        self.lens[self.count] = @intCast(bytes.len);
        @memcpy(self.data[self.count][0..bytes.len], bytes);
        self.count += 1;
    }

    fn get(self: *const Frames, index: usize) []const u8 {
        assert(index < self.count);
        return self.data[index][0..self.lens[index]];
    }

    /// Whether `self` is a prefix of `other`.
    fn prefix_of(self: *const Frames, other: *const Frames) bool {
        if (self.count > other.count) return false;
        for (0..self.count) |index| {
            if (!std.mem.eql(u8, self.get(index), other.get(index))) return false;
        }
        return true;
    }
};

/// A section's expected recovery: its logical size and frames.
const Expected = struct { size: u64, frames: Frames };

const Image = struct {
    sections: [sections]?Expected = @splat(null),
    /// The smallest section whose blob holds no valid page.
    empty: ?u64 = null,
};

/// The operation phase's model.
const Model = struct {
    /// Items covered by a completed sync, per live section.
    durable: [sections]?usize = @splat(null),
    /// The append streams issued after prune-aware routing.
    effective: [sections]Frames = @splat(.{}),
    appended: [sections]bool = @splat(false),
    /// Sections whose blobs exist.
    live: [sections]bool = @splat(false),
    /// Live sections a failed prune covered, oldest first.
    doomed: [sections]bool = @splat(false),
    doomed_any: bool = false,

    fn sync_all_succeeded(self: *Model) void {
        for (0..sections) |section| {
            self.durable[section] = if (self.live[section]) self.effective[section].count else null;
        }
    }
};

/// Decodes a LEB128 varint u32, returning `(header length, value)`.
fn read_varint(bytes: []const u8) ?struct { usize, usize } {
    var value: u32 = 0;
    for (bytes[0..@min(bytes.len, 5)], 0..) |byte, read| {
        if (read == 4 and byte & 0x70 != 0) return null;
        value |= @as(u32, byte & 0x7f) << @intCast(7 * read);
        if (byte & 0x80 == 0) return .{ read + 1, value };
    }
    return null;
}

/// The logical bytes of the blob's valid-page prefix, and whether any page validates. Init
/// sizes a section by its last valid page, so past the prefix only that matters.
fn valid_prefix(blob: runtime.storage.Blob, len: u64, logical: *std.ArrayList(u8)) !bool {
    const pages = len / physical_page_size;
    var prefix_open = true;
    var any_valid = false;
    var page: [physical_page_size]u8 = undefined;
    for (0..pages) |index| {
        if (!prefix_open and any_valid) break;
        try blob.read_at(index * physical_page_size, &page);
        if (paged.page_len(&page, page_size)) |page_len| {
            any_valid = true;
            if (prefix_open) {
                try logical.appendSlice(gpa, page[0..page_len]);
                if (page_len < page_size) prefix_open = false;
            }
        } else {
            prefix_open = false;
        }
    }
    return any_valid;
}

/// The whole frames of a section's logical prefix, which recovery must retain.
fn whole_frames(logical: []const u8) !Expected {
    var expected: Expected = .{ .size = 0, .frames = .{} };
    var offset: usize = 0;
    while (offset < logical.len) {
        const header, const data = read_varint(logical[offset..]) orelse break;
        const end = offset + header + data;
        if (end > logical.len or data > max_item_len + 1) break;
        const payload = logical[offset + header .. end];
        // A page-valid frame must be authentic: the item's own length prefix spans it.
        const inner, const item_len = read_varint(payload) orelse return error.Unauthentic;
        try testing.expectEqual(data, inner + item_len);
        expected.frames.push(payload[inner..]);
        offset = end;
    }
    expected.size = offset;
    return expected;
}

/// Rebuilds each section's expected recovery from the raw crash image, without repairing it.
fn recover_expected(faults: *Faults) !Image {
    var image: Image = .{};
    const storage = faults.interface();
    var names = try storage.scan(gpa, partition);
    defer names.deinit(gpa);
    var logical: std.ArrayList(u8) = .empty;
    defer logical.deinit(gpa);
    for (names.items) |name| {
        try testing.expectEqual(8, name.len);
        const section = std.mem.readInt(u64, name[0..8], .big);
        try testing.expect(section < sections);
        const opened = try storage.open(partition, name);
        defer opened.blob.close();
        logical.clearRetainingCapacity();
        const any_valid = try valid_prefix(opened.blob, opened.len, &logical);
        if (!any_valid) image.empty = @min(image.empty orelse section, section);
        image.sections[section] = try whole_frames(logical.items);
    }
    return image;
}

fn config(cache_ref: *paged.CacheRef) Journal.Cfg {
    return .{
        .partition = partition,
        .codec_config = .{ .range = .inclusive(0, max_item_len), .item = {} },
        .cache_ref = cache_ref,
        .write_buffer = 4096,
        .replay_buffer = 1024,
    };
}

/// Drains a full replay, requiring exactly the expected frames and logical sizes.
fn assert_replay(recovery: *Journal.Recovery, image: *const Image) !Journal {
    var seen: [sections]Frames = @splat(.{});
    while (recovery.next() catch |err| {
        recovery.deinit();
        return err;
    }) |entry| {
        defer codec.free(Item, gpa, entry.item);
        seen[@intCast(entry.section)].push(entry.item);
    }
    var journal = try recovery.finish();
    errdefer journal.deinit();
    for (0..sections) |section| {
        const expected = image.sections[section] orelse {
            try testing.expectEqual(0, seen[section].count);
            continue;
        };
        try testing.expectEqual(expected.frames.count, seen[section].count);
        try testing.expect(expected.frames.prefix_of(&seen[section]));
        try testing.expectEqual(expected.size, try journal.size(section));
    }
    return journal;
}

/// A faulted recovery attempt: a complete replay, then the journal is dropped.
fn recover_once(harness: *Harness) !void {
    var recovery = try Journal.init(gpa, harness.faults.interface(), config(&harness.cache_ref));
    try recovery.drain();
    var journal = try recovery.finish();
    journal.deinit();
}

const Harness = struct {
    faults: Faults,
    cache_ref: paged.CacheRef,

    fn init(self: *Harness, seed: u64) !void {
        self.faults.init(gpa, seed);
        self.cache_ref = try paged.CacheRef.init(gpa, page_size, 8);
    }

    fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.faults.deinit();
    }

    fn open(self: *Harness, image: *const Image) !Journal {
        var recovery = try Journal.init(gpa, self.faults.interface(), config(&self.cache_ref));
        return assert_replay(&recovery, image);
    }
};

/// Prunes below the floor `op` selects with remove faults armed; returns false once a prune
/// fails (the journal is gone then).
fn prune(harness: *Harness, journal: *Journal, model: *Model, floor: *u64, op: u8) !bool {
    const min: u64 = (op >> 3) % sections;
    const pruned = journal.prune(min) catch {
        harness.faults.disarm();
        // An oldest-first prefix of the live sections below the floor is gone.
        for (0..min) |section| model.doomed[section] = model.live[section];
        model.doomed_any = true;
        return false;
    };
    harness.faults.disarm();
    if (pruned) {
        floor.* = @max(floor.*, min);
        for (0..min) |section| {
            model.live[section] = false;
            model.durable[section] = null;
        }
    }
    return true;
}

/// The final sync: completed, or interrupted with the first live section left unsynced.
fn final_sync(harness: *Harness, journal: *Journal, model: *Model, input: *const Input) !void {
    harness.faults.layer.config = .{ .write_rate = .{
        .failure_rate = .zero,
        .retention_rate = Probability.init(input.retention % 101, 100).?,
        .mode = if (input.subset) .subset else .prefix,
    } };
    defer harness.faults.disarm();
    if (input.final_polls % 2 == 1) {
        try journal.sync_all();
        model.sync_all_succeeded();
        return;
    }
    var first: ?u64 = null;
    var others: [sections]u64 = undefined;
    var others_len: usize = 0;
    for (0..sections) |section| {
        if (!model.live[section]) continue;
        if (first == null) first = section else {
            others[others_len] = section;
            others_len += 1;
        }
    }
    try journal.sync(others[0..others_len]);
    const parked = first orelse return;
    // A section with nothing unsynced has no blob sync to fail.
    harness.faults.layer.config.sync_rate = .one;
    journal.sync(&.{parked}) catch {};
}

/// Runs the script; leaves the journal dropped and storage crashed.
fn operation_phase(harness: *Harness, input: *const Input, model: *Model) !void {
    const remove_rate = Probability.init(input.remove_failure % 101, 100).?;
    const script_len = input.script_len();
    const baseline = input.baseline % (script_len + 1);
    const empty: Image = .{};
    var journal = try harness.open(&empty);
    var floor: u64 = 0;
    var buffer: [max_item_len]u8 = undefined;
    for (0..script_len + 1) |offset| {
        if (offset == baseline and baseline > 0) {
            try journal.sync_all();
            model.sync_all_succeeded();
        }
        if (offset == script_len) break;
        // Appends below the prune floor fail, so route them above it.
        var section = input.route(offset);
        if (section < floor) section = floor + section % (sections - floor);
        const bytes = item_bytes(offset, &buffer);
        _ = try journal.append(section, bytes);
        model.effective[@intCast(section)].push(bytes);
        model.appended[@intCast(section)] = true;
        model.live[@intCast(section)] = true;
        const op = input.ops[offset % input.ops.len];
        if (op & 0x07 != 7) continue;
        harness.faults.layer.config = .{ .remove_rate = remove_rate };
        if (!try prune(harness, &journal, model, &floor, op)) {
            journal.deinit();
            return;
        }
    }
    final_sync(harness, &journal, model, input) catch |err| {
        journal.deinit();
        return err;
    };
    journal.deinit();
}

/// Every legal image holds, per section, a prefix of the routed append stream, keeps what a
/// completed sync covered, and matches the prunes.
fn check_image(image: *const Image, model: *const Model) !void {
    for (0..sections) |section| {
        const found = image.sections[section];
        // Sections come only from appends and go only through prunes.
        if (found != null) try testing.expect(model.appended[section]);
        if (model.appended[section] and !model.live[section]) try testing.expect(found == null);
        if (model.live[section] and !model.doomed[section]) try testing.expect(found != null);
        if (found) |expected| {
            try testing.expect(expected.frames.prefix_of(&model.effective[section]));
        }
        const durable = model.durable[section] orelse continue;
        if (model.doomed[section] and found == null) continue;
        try testing.expect(found.?.frames.count >= durable);
    }
    if (!model.doomed_any) return;
    // A failed prune removes oldest first and stops at its faulted removal, which keeps its
    // blob: the covered sections split into an absent prefix and a nonempty present suffix.
    var survivors: usize = 0;
    var seen_present = false;
    for (0..sections) |section| {
        if (!model.doomed[section]) continue;
        const present = image.sections[section] != null;
        if (seen_present) try testing.expect(present);
        seen_present = seen_present or present;
        if (present) survivors += 1;
    }
    try testing.expect(survivors > 0);
}

/// Repairs through a full replay, then appends a probe and sentinels and reopens.
fn verify_repair(harness: *Harness, image: *Image) !void {
    var journal = try harness.open(image);
    errdefer journal.deinit();
    // A section recovered at size zero resumes at offset zero; the probe frame is one outer
    // varint, one inner varint, and five payload bytes.
    const probe: [5]u8 = @splat(0xAB);
    if (image.empty) |section| {
        try testing.expectEqual(0, (try journal.append(section, &probe)).offset);
        image.sections[@intCast(section)].?.size = 7;
        image.sections[@intCast(section)].?.frames.push(&probe);
    }
    const sentinel: [9]u8 = @splat(0xCD);
    for (0..sections) |section| {
        const expected = if (image.sections[section]) |*found| found else continue;
        try testing.expectEqual(expected.size, (try journal.append(section, &sentinel)).offset);
        expected.size += 11;
        expected.frames.push(&sentinel);
    }
    try journal.sync_all();
    journal.deinit();
    // A clean reopen replays the repaired image plus the sentinels.
    journal = try harness.open(image);
    try journal.destroy();
}

fn recovery_run(bytes: []const u8) anyerror!void {
    const input = Input.decode(bytes);
    var harness: Harness = undefined;
    try harness.init(input.seed);
    defer harness.deinit();
    var model: Model = .{};
    try operation_phase(&harness, &input, &model);
    try harness.faults.crash();
    try harness.faults.faulted_recovery(&harness, recover_once);
    var image = try recover_expected(&harness.faults);
    try check_image(&image, &model);
    try verify_repair(&harness, &image);
}

test "fuzz journal_segmented_variable_recovery (seeded)" {
    try fuzz_bytes.seeded(96, 0x73766172, 64, recovery_run);
}

test "fuzz journal_segmented_variable_recovery" {
    try testing.fuzz({}, fuzz_bytes.smith(96, recovery_run), .{});
}
