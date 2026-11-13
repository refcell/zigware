//! Common blob management for segmented journals (commonware's `segmented/manager.rs`).
//!
//! `Manager` keeps one paged writer per section, each in its own blob named by the section
//! number (big-endian u64), and handles initialization, pruning, syncing, and truncation.
//! Section writers stay in recovery mode so journals can repair torn tails.
//!
//! Mutating methods leave the manager unusable after an error (commonware consumes it); only
//! `deinit` may follow. Sections above the initialization `ceiling` stay unopened until
//! `truncate_pending` or `clear` removes them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const paged = runtime.buffer.paged;
const journal = @import("../mod.zig");

/// List stored blob names, treating a missing partition as empty. Caller frees.
pub fn stored_names(gpa: Allocator, storage: anytype, partition: []const u8) ![][]u8 {
    return storage.scan(gpa, partition) catch |err| switch (err) {
        error.PartitionMissing => try gpa.alloc([]u8, 0),
        else => return err,
    };
}

pub fn free_names(gpa: Allocator, names: [][]u8) void {
    for (names) |name| gpa.free(name);
    gpa.free(names);
}

/// The section number stored in a blob name (canonical big-endian u64).
pub fn section_from_name(name: []const u8) journal.Error!u64 {
    if (name.len != 8) return error.InvalidBlobName;
    return std.mem.readInt(u64, name[0..8], .big);
}

pub fn section_name(section: u64) [8]u8 {
    var name: [8]u8 = undefined;
    std.mem.writeInt(u64, &name, section, .big);
    return name;
}

/// Sorted section numbers of every stored blob. Caller frees.
pub fn stored_sections(gpa: Allocator, storage: anytype, partition: []const u8) ![]u64 {
    const names = try stored_names(gpa, storage, partition);
    defer free_names(gpa, names);
    const sections = try gpa.alloc(u64, names.len);
    errdefer gpa.free(sections);
    for (names, sections) |name, *section| section.* = try section_from_name(name);
    std.mem.sortUnstable(u64, sections, {}, std.sort.asc(u64));
    return sections;
}

/// Remove sections above `section`, newest first, and whole pages of `section` above logical
/// `end`, before opening recovery owners. The page containing `end` stays intact for checksum
/// validation and exact logical truncation.
pub fn truncate_paged_tail(
    gpa: Allocator,
    storage: anytype,
    partition: []const u8,
    page_size: u64,
    section: u64,
    end: u64,
) !void {
    const sections = try stored_sections(gpa, storage, partition);
    defer gpa.free(sections);
    var index = sections.len;
    while (index > 0) {
        index -= 1;
        const stored = sections[index];
        if (stored > section) {
            try storage.remove(partition, &section_name(stored));
            continue;
        }
        if (stored == section) {
            const opened = try storage.open(partition, &section_name(stored));
            defer opened.blob.deinit();
            // An unrepresentable physical ceiling excludes no representable blob bytes.
            const pages = std.math.divCeil(u64, end, page_size) catch unreachable;
            const ceiling = std.math.mul(u64, pages, page_size + paged.checksum_size) catch
                std.math.maxInt(u64);
            if (ceiling < opened.len) {
                try opened.blob.resize(ceiling);
                try opened.blob.sync();
            }
        }
        break;
    }
}

/// Configuration for section writers.
pub const Config = struct {
    /// The storage partition holding one blob per section.
    partition: []const u8,
    /// Write buffer size of each section writer.
    write_buffer: usize,
    /// The page cache shared by section writers.
    cache_ref: *paged.CacheRef,
};

pub fn Manager(comptime Storage: type) type {
    return struct {
        const Self = @This();
        pub const Buffer = paged.Writer(Storage.Blob);
        pub const Error = journal.Error || Storage.Error || error{InvalidChecksum};
        pub const Section = struct { section: u64, buffer: Buffer };

        gpa: Allocator,
        storage: *Storage,
        partition: []u8,
        write_buffer: usize,
        cache_ref: *paged.CacheRef,
        /// Open sections, sorted by section number.
        sections: std.ArrayList(Section) = .empty,
        /// Sections above this stay unopened until truncation or clear removes them.
        ceiling: u64,
        /// Unopened sections above `ceiling`, ascending.
        discarded: std.ArrayList(u64) = .empty,
        /// Sections below this were pruned during this execution (not persisted).
        oldest_retained_section: u64 = 0,
        failed: bool = false,

        /// Metrics: sections tracked is `num_sections()`.
        synced: u64 = 0,
        pruned_count: u64 = 0,

        /// Open stored sections through `ceiling`, recording later ones for removal.
        pub fn init(gpa: Allocator, storage: *Storage, cfg: Config, ceiling: u64) Error!Self {
            var self: Self = .{
                .gpa = gpa,
                .storage = storage,
                .partition = try gpa.dupe(u8, cfg.partition),
                .write_buffer = cfg.write_buffer,
                .cache_ref = cfg.cache_ref,
                .ceiling = ceiling,
            };
            errdefer self.deinit();
            const sections = try stored_sections(gpa, storage, self.partition);
            defer gpa.free(sections);
            for (sections) |section| {
                if (section > ceiling) {
                    try self.discarded.append(gpa, section);
                    continue;
                }
                const buffer = try self.open_section(section);
                try self.sections.append(gpa, .{ .section = section, .buffer = buffer });
            }
            assert(std.sort.isSorted(u64, self.discarded.items, {}, std.sort.asc(u64)));
            return self;
        }

        /// Close every section writer (dropping unsynced bytes) and free memory.
        pub fn deinit(self: *Self) void {
            for (self.sections.items) |*entry| entry.buffer.deinit();
            self.sections.deinit(self.gpa);
            self.discarded.deinit(self.gpa);
            self.gpa.free(self.partition);
            self.* = undefined;
        }

        fn open_section(self: *Self, section: u64) Error!Buffer {
            const opened = try self.storage.open(self.partition, &section_name(section));
            errdefer opened.blob.deinit();
            return Buffer.open_recovery(
                self.gpa,
                opened.blob,
                opened.len,
                self.write_buffer,
                self.cache_ref,
            );
        }

        /// Index of `section` in `sections`, or where it would be inserted.
        fn search(self: *const Self, section: u64) struct { index: usize, found: bool } {
            var low: usize = 0;
            var high: usize = self.sections.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const value = self.sections.items[middle].section;
                if (value == section) return .{ .index = middle, .found = true };
                if (value < section) low = middle + 1 else high = middle;
            }
            return .{ .index = low, .found = false };
        }

        /// Fails if `section` was pruned during this execution.
        pub fn prune_guard(self: *const Self, section: u64) Error!void {
            if (section < self.oldest_retained_section) return error.AlreadyPrunedToSection;
        }

        /// The writer of `section`, if it exists. Invalidated by inserts and removals.
        pub fn get(self: *Self, section: u64) Error!?*Buffer {
            try self.prune_guard(section);
            const position = self.search(section);
            if (!position.found) return null;
            return &self.sections.items[position.index].buffer;
        }

        /// The writer of `section`, opening (and creating) its blob if needed.
        pub fn get_or_create(self: *Self, section: u64) Error!*Buffer {
            try self.prune_guard(section);
            assert(section <= self.ceiling); // Truncate sections above the ceiling first.
            const position = self.search(section);
            if (position.found) return &self.sections.items[position.index].buffer;
            try self.sections.ensureUnusedCapacity(self.gpa, 1);
            var buffer = try self.open_section(section);
            errdefer buffer.deinit();
            self.sections.insertAssumeCapacity(position.index, .{
                .section = section,
                .buffer = buffer,
            });
            return &self.sections.items[position.index].buffer;
        }

        /// Sync the given sections (those that need it). Every selected section counts.
        pub fn sync(self: *Self, sections: []const u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            for (sections) |section| try self.prune_guard(section);
            for (sections) |section| {
                const position = self.search(section);
                if (!position.found) continue;
                const buffer = &self.sections.items[position.index].buffer;
                if (buffer.needs_sync()) try buffer.sync();
                self.synced += 1;
            }
        }

        /// commonware's `start_sync`: syncs complete synchronously, so this is `sync`.
        pub fn start_sync(self: *Self, sections: []const u64) Error!void {
            return self.sync(sections);
        }

        /// Sync every section.
        pub fn sync_all(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            for (self.sections.items) |*entry| {
                if (entry.buffer.needs_sync()) try entry.buffer.sync();
                self.synced += 1;
            }
        }

        /// Remove the open section at `index`: its blob's name first, then its owner.
        fn remove_at(self: *Self, index: usize) Error!void {
            assert(index < self.sections.items.len);
            const section = self.sections.items[index].section;
            try self.storage.remove(self.partition, &section_name(section));
            var entry = self.sections.orderedRemove(index);
            entry.buffer.deinit();
            assert(self.search(section).found == false);
        }

        /// Prune every section below `min`, oldest first. Returns whether any were pruned.
        pub fn prune(self: *Self, min: u64) Error!bool {
            assert(!self.failed);
            errdefer self.failed = true;
            var any_pruned = false;
            while (self.sections.items.len > 0 and self.sections.items[0].section < min) {
                try self.remove_at(0);
                any_pruned = true;
                self.pruned_count += 1;
            }
            // Reject pruned sections for the rest of this execution.
            if (any_pruned) self.oldest_retained_section = min;
            return any_pruned;
        }

        /// Whether `section` is below the prune floor.
        pub fn pruned(self: *const Self, section: u64) bool {
            return section < self.oldest_retained_section;
        }

        pub fn oldest_section(self: *const Self) ?u64 {
            if (self.sections.items.len == 0) return null;
            return self.sections.items[0].section;
        }

        pub fn newest_section(self: *const Self) ?u64 {
            if (self.sections.items.len == 0) return null;
            return self.sections.items[self.sections.items.len - 1].section;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.sections.items.len == 0;
        }

        pub fn num_sections(self: *const Self) usize {
            return self.sections.items.len;
        }

        /// Remove one section. Returns whether it existed.
        pub fn remove_section(self: *Self, section: u64) Error!bool {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.prune_guard(section);
            const position = self.search(section);
            if (!position.found) return false;
            try self.remove_at(position.index);
            return true;
        }

        /// Remove every blob and the partition, then free the manager.
        pub fn destroy(self: *Self) Error!void {
            defer self.deinit();
            while (self.sections.items.len > 0) try self.remove_at(0);
            for (self.discarded.items) |section| {
                try self.storage.remove(self.partition, &section_name(section));
            }
            self.storage.remove(self.partition, null) catch |err| switch (err) {
                // Partition already removed or never existed.
                error.PartitionMissing => {},
                else => return err,
            };
        }

        /// Remove every blob, keeping the manager usable and empty.
        pub fn clear(self: *Self) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.remove_discarded();
            while (self.sections.items.len > 0) try self.remove_at(0);
            self.oldest_retained_section = 0;
        }

        /// Remove unopened suffix sections newest first and lift the ceiling.
        fn remove_discarded(self: *Self) Error!void {
            while (self.discarded.pop()) |section| {
                try self.storage.remove(self.partition, &section_name(section));
            }
            self.ceiling = std.math.maxInt(u64);
        }

        /// Remove every section after `section` (newest first, so a crash leaves a contiguous
        /// record) and durably shorten `section` to `bytes` bytes.
        pub fn truncate_pending(self: *Self, section: u64, bytes: u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.prune_guard(section);
            assert(section <= self.ceiling);
            try self.remove_discarded();
            while (self.newest_section()) |newest| {
                if (newest <= section) break;
                try self.remove_at(self.sections.items.len - 1);
            }
            try self.truncate_section(section, bytes);
        }

        /// Durably shorten only `section` to `size` bytes.
        pub fn truncate_pending_section(self: *Self, section: u64, bytes: u64) Error!void {
            assert(!self.failed);
            errdefer self.failed = true;
            try self.prune_guard(section);
            try self.truncate_section(section, bytes);
        }

        fn truncate_section(self: *Self, section: u64, bytes: u64) Error!void {
            const position = self.search(section);
            if (!position.found) return;
            const buffer = &self.sections.items[position.index].buffer;
            if (bytes < buffer.size()) try buffer.truncate(bytes);
        }

        /// The logical byte size of `section` (0 if missing).
        pub fn size(self: *Self, section: u64) Error!u64 {
            const buffer = try self.get(section) orelse return 0;
            return buffer.size();
        }
    };
}

test {
    _ = @import("manager_test.zig");
}
