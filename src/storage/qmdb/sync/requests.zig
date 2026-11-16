//! The sync engine's outstanding requests (commonware's `qmdb/sync/requests.rs`): each tracked
//! request has an id and is indexed by its start location, at most one per location. A newer
//! request at a location supersedes the older one, whose late completion then resolves to no
//! tracked request. The engine runs the fetches; this tracks which results still count.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const source = @import("source.zig");

pub const Id = u64;

pub fn Requests(comptime F: type) type {
    return struct {
        const Self = @This();
        pub const Request = source.Request(F);
        const Tracked = struct { id: Id, request: Request };

        next_id: Id = 0,
        /// Sorted by start location, one per location.
        tracked: std.ArrayList(Tracked) = .empty,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.tracked.deinit(gpa);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            return self.tracked.items.len;
        }

        fn search(self: *const Self, start: u64) struct { index: usize, found: bool } {
            const index = std.sort.lowerBound(Tracked, self.tracked.items, start, order);
            const found = index < self.tracked.items.len and
                self.tracked.items[index].request.start() == start;
            return .{ .index = index, .found = found };
        }

        fn order(start: u64, item: Tracked) std.math.Order {
            return std.math.order(start, item.request.start());
        }

        /// Tracks `request` under a new id, superseding any request at its start.
        pub fn insert(self: *Self, gpa: Allocator, request: Request) Allocator.Error!Id {
            const id = self.next_id;
            const slot = self.search(request.start());
            const entry: Tracked = .{ .id = id, .request = request };
            if (slot.found) {
                self.tracked.items[slot.index] = entry;
            } else {
                try self.tracked.insert(gpa, slot.index, entry);
            }
            self.next_id += 1;
            assert(self.contains(request.start()));
            return id;
        }

        /// Stops tracking `id`, returning its request if it was tracked.
        pub fn remove(self: *Self, id: Id) ?Request {
            for (self.tracked.items, 0..) |entry, index| {
                if (entry.id != id) continue;
                _ = self.tracked.orderedRemove(index);
                assert(!self.contains(entry.request.start()));
                return entry.request;
            }
            return null;
        }

        /// Keeps only the requests `keep(context, request)` accepts.
        pub fn retain(
            self: *Self,
            context: anytype,
            comptime keep: fn (@TypeOf(context), Request) bool,
        ) void {
            var write: usize = 0;
            for (self.tracked.items) |entry| {
                if (!keep(context, entry.request)) continue;
                self.tracked.items[write] = entry;
                write += 1;
            }
            self.tracked.shrinkRetainingCapacity(write);
            assert(self.len() == write);
        }

        pub fn contains(self: *const Self, start: u64) bool {
            return self.search(start).found;
        }

        /// The ranges `[start, start + max_ops)` of the tracked requests, by start, into `out`.
        pub fn ranges(self: *const Self, gpa: Allocator, out: *std.ArrayList(Range)) !void {
            try out.ensureUnusedCapacity(gpa, self.len());
            for (self.tracked.items) |entry| {
                const start = entry.request.start();
                const end = start + entry.request.max_ops();
                out.appendAssumeCapacity(.{ .start = start, .end = end });
            }
        }

        pub const Range = struct { start: u64, end: u64 };
    };
}

const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const R = Requests(merkle.mmr.Family);

fn add(requests: *R, location: u64) !Id {
    const request: R.Request = .{ .operations = .{
        .size = location,
        .start = location,
        .max_ops = 1,
    } };
    return requests.insert(testing.allocator, request);
}

fn at_least(min: u64, request: R.Request) bool {
    return request.start() >= min;
}

fn none(_: void, _: R.Request) bool {
    return false;
}

fn all(_: void, _: R.Request) bool {
    return true;
}

// Commonware's `test_add_and_remove`.
test "sync requests add and remove" {
    var requests: R = .{};
    defer requests.deinit(testing.allocator);
    const id = try add(&requests, 10);
    try testing.expectEqual(@as(usize, 1), requests.len());
    try testing.expect(requests.contains(10));
    try testing.expect(requests.remove(id) != null);
    try testing.expect(!requests.contains(10));
    try testing.expect(requests.remove(id) == null);
}

// Commonware's `test_retain_matching`, `_none`, `_empty`, and `_all`.
test "sync requests retain" {
    var requests: R = .{};
    defer requests.deinit(testing.allocator);
    requests.retain({}, all);
    try testing.expectEqual(@as(usize, 0), requests.len());
    for ([_]u64{ 20, 5, 15, 10 }) |location| _ = try add(&requests, location);
    requests.retain({}, all);
    try testing.expectEqual(@as(usize, 4), requests.len());
    requests.retain(@as(u64, 10), at_least);
    try testing.expectEqual(@as(usize, 3), requests.len());
    try testing.expect(!requests.contains(5));
    for ([_]u64{ 10, 15, 20 }) |location| try testing.expect(requests.contains(location));
    var ranges: std.ArrayList(R.Range) = .empty;
    defer ranges.deinit(testing.allocator);
    try requests.ranges(testing.allocator, &ranges);
    try testing.expectEqual(@as(u64, 10), ranges.items[0].start);
    try testing.expectEqual(@as(u64, 21), ranges.items[2].end);
    requests.retain({}, none);
    try testing.expectEqual(@as(usize, 0), requests.len());
}

// Commonware's `test_superseded_request` and `test_stale_completion_after_retain`.
test "sync requests supersede and ignore stale completions" {
    var requests: R = .{};
    defer requests.deinit(testing.allocator);
    const old_id = try add(&requests, 10);
    const new_id = try add(&requests, 10);
    try testing.expectEqual(@as(usize, 1), requests.len());
    try testing.expect(requests.remove(old_id) == null);
    try testing.expect(requests.contains(10));
    try testing.expect(requests.remove(new_id) != null);
    const stale = try add(&requests, 5);
    _ = try add(&requests, 15);
    requests.retain(@as(u64, 10), at_least);
    try testing.expect(requests.remove(stale) == null);
    const fresh = try add(&requests, 5);
    try testing.expect(fresh != stale);
    try testing.expect(requests.remove(fresh) != null);
}
