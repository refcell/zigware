//! A shared key-value map standing in for a resolver's store (commonware
//! `marshal/mocks/resolver.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Values of type `V` by key `K` (compared with `eql`, or by value), shared by every copy
/// (commonware's `Clone` over an `Arc<Mutex<HashMap>>`). Unlocked: the mocks run on the
/// single-threaded deterministic runtime.
pub fn Resolver(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: K, value: V };
        const Data = struct { gpa: Allocator, entries: std.ArrayList(Entry) = .empty };

        data: *Data,

        pub fn init(gpa: Allocator) Allocator.Error!Self {
            const data = try gpa.create(Data);
            data.* = .{ .gpa = gpa };
            return .{ .data = data };
        }

        /// Frees the map; every copy is invalid afterwards.
        pub fn deinit(self: *Self) void {
            const gpa = self.data.gpa;
            self.data.entries.deinit(gpa);
            gpa.destroy(self.data);
            self.* = undefined;
        }

        /// The value under `key`; panics when it is missing, as commonware's `unwrap` does.
        pub fn get(self: Self, key: K) V {
            const index = self.find(key) orelse @panic("resolver key missing");
            return self.data.entries.items[index].value;
        }

        /// Stores `value` under `key`, replacing any previous value.
        pub fn put(self: Self, key: K, value: V) Allocator.Error!void {
            if (self.find(key)) |index| {
                self.data.entries.items[index].value = value;
                return;
            }
            try self.data.entries.append(self.data.gpa, .{ .key = key, .value = value });
            assert(self.find(key) != null);
        }

        fn find(self: Self, key: K) ?usize {
            for (self.data.entries.items, 0..) |entry, index| {
                if (key_eql(entry.key, key)) return index;
            }
            return null;
        }

        fn key_eql(a: K, b: K) bool {
            if (comptime @typeInfo(K) == .@"struct" and @hasDecl(K, "eql")) return a.eql(b);
            return std.meta.eql(a, b);
        }
    };
}

test "copies share one map and puts replace values" {
    var resolver = try Resolver(u64, u32).init(std.testing.allocator);
    defer resolver.deinit();
    const copy = resolver;
    try resolver.put(7, 1);
    try std.testing.expectEqual(@as(u32, 1), copy.get(7));
    try copy.put(7, 2);
    try copy.put(8, 3);
    try std.testing.expectEqual(@as(u32, 2), resolver.get(7));
    try std.testing.expectEqual(@as(u32, 3), resolver.get(8));
}
