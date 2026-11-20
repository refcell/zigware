//! An index whose translated keys live in a hash map (port of commonware's
//! `storage/src/index/unordered.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const storage = @import("storage.zig");

/// The heads of an unordered index: a hash map keyed by the translated key.
fn Heads(comptime T: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Map = std.HashMapUnmanaged(T.Key, V, storage.Context(T), 80);

        map: Map = .empty,
        context: storage.Context(T),

        /// A lookup leaves the key's entry warm for a following update (commonware's
        /// `LOOKUP_WARMS_UPDATE`).
        pub const lookup_warms_update = true;

        pub fn init(translator: T) Self {
            return .{ .context = .{ .translator = translator } };
        }

        pub fn get(self: *const Self, key: T.Key) ?*V {
            return self.map.getPtrContext(key, self.context);
        }

        /// Starts loading the slot `get(key)` probes first (its metadata, key, and value),
        /// so a batch of lookups issued a few keys ahead overlaps their cache misses.
        pub fn prefetch(self: *const Self, key: T.Key) void {
            const metadata = self.map.metadata orelse return;
            const capacity = self.map.capacity();
            assert(std.math.isPowerOfTwo(capacity));
            const index: usize = @intCast(self.context.hash(key) & (capacity - 1));
            @prefetch(metadata + index, .{});
            @prefetch(self.map.keyIterator().items + index, .{});
            @prefetch(self.map.valueIterator().items + index, .{});
        }

        pub fn get_or_put(self: *Self, gpa: Allocator, key: T.Key) !storage.GetOrPut(V) {
            const entry = try self.map.getOrPutContext(gpa, key, self.context);
            return .{ .value_ptr = entry.value_ptr, .found_existing = entry.found_existing };
        }

        pub fn remove(self: *Self, _: Allocator, key: T.Key) void {
            const removed = self.map.removeContext(key, self.context);
            assert(removed);
        }

        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const V) void,
        ) void {
            var values = self.map.valueIterator();
            while (values.next()) |value| visit(visit_context, value);
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.map.deinit(gpa);
        }
    };
}

/// An unordered index from keys (through translator `T`) to values `V`.
pub fn Index(comptime T: type, comptime V: type) type {
    return storage.Index(T, V, Heads(T, V));
}
