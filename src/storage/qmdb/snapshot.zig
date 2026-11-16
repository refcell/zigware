//! Rebuild snapshot indexes and activity bitmaps from the operations log (qmdb/snapshot.rs).
//!
//! A snapshot maps each active key (through its translator) to the location of its latest
//! update. Translated keys collide, so resolving a key walks the cursor over the colliding
//! locations and reads each candidate's key from the log (or from a `Cache`).
//!
//! A log `reader` provides `get_bounds()` (a `journal.contiguous.Bounds`) and
//! `read(position) !Op`; decoded operations that own memory are freed with `codec.free`. An
//! index is any `storage.index` index over `u64` locations.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const value = @import("value.zig");
const Cache = @import("cache.zig").Cache;

/// The activity bitmap a serial build returns: bit `i` is location `floor + i`.
pub const ActivityBitMap = utils.bitmap.DefaultBitMap;

fn key_bytes(comptime Op: type, key: *const Op.Key) []const u8 {
    return value.bytes(Op.Key, key);
}

/// Finds the location of `key`'s update among the cursor's values, leaving the cursor at it.
/// Candidates read from the log that do not match are admitted to `cache`.
fn find_update_op(
    comptime Op: type,
    gpa: Allocator,
    reader: anytype,
    cursor: anytype,
    key: *const Op.Key,
    cache: ?*Cache(Op.Key),
) !?u64 {
    while (cursor.next()) |location_ptr| {
        const location = location_ptr.*;
        if (cache) |c| if (c.get(location)) |cached| {
            if (value.eql(Op.Key, cached.*, key.*)) return location;
            continue;
        };
        var op: Op = try reader.read(location);
        defer codec.free(Op, gpa, op);
        const candidate = op.key() orelse return error.DataCorrupted; // Not a keyed operation.
        if (value.eql(Op.Key, candidate.*, key.*)) return location;
        // Every caller immediately mutates a match, so only non-matches are admitted: admitting
        // the match could evict another location before the caller invalidates this one.
        if (cache) |c| c.put(gpa, location, try value.clone(Op.Key, gpa, candidate.*));
    }
    return null;
}

/// Deletes `key` from the snapshot if present and returns its previous location.
pub fn delete_key(
    comptime Op: type,
    gpa: Allocator,
    snapshot: anytype,
    reader: anytype,
    key: *const Op.Key,
    cache: ?*Cache(Op.Key),
) !?u64 {
    var cursor = snapshot.get_mut(key_bytes(Op, key)) orelse return null;
    defer cursor.finish();
    const location = try find_update_op(Op, gpa, reader, &cursor, key, cache) orelse return null;
    // Cache entries mirror current snapshot locations, so invalidate the match with the
    // authoritative deletion.
    cursor.delete();
    if (cache) |c| c.remove(gpa, location);
    return location;
}

/// Points `key` at `new_location` and returns its previous location, if any.
pub fn update_key(
    comptime Op: type,
    gpa: Allocator,
    snapshot: anytype,
    reader: anytype,
    key: *const Op.Key,
    new_location: u64,
    cache: ?*Cache(Op.Key),
) !?u64 {
    var cursor = try snapshot.get_mut_or_insert(key_bytes(Op, key), new_location) orelse
        return null;
    defer cursor.finish();
    if (try find_update_op(Op, gpa, reader, &cursor, key, cache)) |location| {
        assert(new_location > location);
        cursor.update(new_location);
        if (cache) |c| c.remove(gpa, location);
        return location;
    }
    // The key was not in the snapshot: add it among the colliding keys.
    try cursor.insert(new_location);
    return null;
}

/// Builds the snapshot by replaying the log from `floor` (which must be retained). For every
/// keyed update or delete and every commit, `context.status(is_active, superseded)` reports the
/// operation's activity and the location it made inactive, if any. Returns the number of
/// active keys. `cache_size` bounds a `location -> key` cache used to resolve collisions
/// (null disables it).
pub fn build_from_log(
    comptime Op: type,
    gpa: Allocator,
    floor: u64,
    reader: anytype,
    snapshot: anytype,
    cache_size: ?usize,
    context: anytype,
) !usize {
    const bounds = reader.get_bounds();
    if (floor < bounds.start) return error.ItemPruned;
    if (floor > bounds.end) return error.DataCorrupted;
    const last_commit = bounds.end -| 1;
    var cache_storage: ?Cache(Op.Key) = if (cache_size) |size|
        try Cache(Op.Key).init(gpa, size)
    else
        null;
    defer if (cache_storage) |*c| c.deinit(gpa);
    const cache: ?*Cache(Op.Key) = if (cache_storage) |*c| c else null;

    var active_keys: usize = 0;
    var location = floor;
    while (location < bounds.end) : (location += 1) {
        var op: Op = try reader.read(location);
        defer codec.free(Op, gpa, op);
        if (op.key()) |key| {
            if (op.is_delete()) {
                const old = try delete_key(Op, gpa, snapshot, reader, key, cache);
                try context.status(false, old);
                if (old != null) active_keys -= 1;
            } else if (op.is_update()) {
                const old = try update_key(Op, gpa, snapshot, reader, key, location, cache);
                try context.status(true, old);
                if (old == null) active_keys += 1;
                // This update is now a candidate for later operations on its key.
                if (cache) |c| c.put(gpa, location, try value.clone(Op.Key, gpa, key.*));
            }
        } else if (op.inactivity_floor() != null) {
            try context.status(location == last_commit, null);
        }
    }
    assert(location == bounds.end);
    return active_keys;
}

/// Collects each replayed location's final activity into a bitmap.
const Activity = struct {
    gpa: Allocator,
    floor: u64,
    bitmap: ActivityBitMap = .{},

    pub fn status(self: *Activity, is_active: bool, superseded: ?u64) !void {
        try self.bitmap.push(self.gpa, is_active);
        if (superseded) |location| {
            assert(location >= self.floor);
            self.bitmap.set(location - self.floor, false);
        }
    }
};

/// The result of a serial build: active key count and the activity of every location from
/// the floor to the log's end.
pub const Build = struct {
    active_keys: usize,
    activity: ActivityBitMap,

    pub fn deinit(self: *Build, gpa: Allocator) void {
        self.activity.deinit(gpa);
        self.* = undefined;
    }
};

/// Builds the snapshot serially and collects the activity bitmap (commonware's
/// `build_snapshot_serial`, what `SnapshotBuild::build_snapshot` does for every index here).
pub fn build(
    comptime Op: type,
    gpa: Allocator,
    floor: u64,
    reader: anytype,
    snapshot: anytype,
    cache_size: ?usize,
) !Build {
    var activity: Activity = .{ .gpa = gpa, .floor = floor };
    errdefer activity.bitmap.deinit(gpa);
    const active_keys = try build_from_log(Op, gpa, floor, reader, snapshot, cache_size, &activity);
    assert(activity.bitmap.len() <= reader.get_bounds().end - floor);
    return .{ .active_keys = active_keys, .activity = activity.bitmap };
}

test {
    _ = @import("snapshot_test.zig");
}
