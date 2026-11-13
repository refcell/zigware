//! A mock scheme provider for aggregation (commonware `aggregation/mocks/provider.rs`):
//! schemes registered by epoch.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Epoch = @import("../../types.zig").Epoch;

/// Signing schemes by epoch. Owns the registered schemes; pointers returned by `scheme`
/// stay valid until `deinit`.
pub fn Provider(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Scheme = S;
        const Entry = struct { epoch: Epoch, scheme: *S };

        gpa: Allocator,
        entries: std.ArrayList(Entry) = .empty,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa };
        }

        pub fn deinit(self: *Self) void {
            for (self.entries.items) |entry| {
                entry.scheme.deinit(self.gpa);
                self.gpa.destroy(entry.scheme);
            }
            self.entries.deinit(self.gpa);
            self.* = undefined;
        }

        /// Registers `scheme` for `epoch`, taking ownership. Returns false (releasing
        /// `scheme`) when the epoch already has one.
        pub fn register(self: *Self, epoch: Epoch, value: S) Allocator.Error!bool {
            var owned = value;
            if (self.scheme(epoch) != null) {
                owned.deinit(self.gpa);
                return false;
            }
            errdefer owned.deinit(self.gpa);
            const slot = try self.gpa.create(S);
            errdefer self.gpa.destroy(slot);
            slot.* = owned;
            try self.entries.append(self.gpa, .{ .epoch = epoch, .scheme = slot });
            assert(self.scheme(epoch) == slot);
            return true;
        }

        /// The scheme for `epoch`, or null when none is registered.
        pub fn scheme(self: *const Self, epoch: Epoch) ?*const S {
            for (self.entries.items) |entry| {
                if (entry.epoch == epoch) return entry.scheme;
            }
            return null;
        }
    };
}

test "provider registers one scheme per epoch" {
    const gpa = std.testing.allocator;
    const Counted = struct {
        value: u32,
        pub fn deinit(self: *@This(), _: Allocator) void {
            self.* = undefined;
        }
    };
    var provider = Provider(Counted).init(gpa);
    defer provider.deinit();
    try std.testing.expect(try provider.register(.new(1), .{ .value = 7 }));
    try std.testing.expect(!try provider.register(.new(1), .{ .value = 8 }));
    try std.testing.expectEqual(7, provider.scheme(.new(1)).?.value);
    try std.testing.expectEqual(null, provider.scheme(.new(2)));
}
