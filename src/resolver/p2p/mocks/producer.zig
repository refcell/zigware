//! A producer for tests (commonware `resolver/src/p2p/mocks/producer.rs`).
//!
//! Serves the values inserted with `insert`; a missing key closes the receiver without a
//! value. Copies of a `Producer` share one state (Rust `Clone`); call `deinit` once.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const Produced = @import("../produced.zig").Produced;

const oneshot = utils.channel.oneshot;

pub fn Producer(comptime K: type) type {
    return struct {
        const Self = @This();
        pub const Key = K;

        const Entry = struct { key: K, value: []u8 };
        const Shared = struct {
            gpa: Allocator,
            io: Io,
            mutex: Io.Mutex = .init,
            data: std.ArrayList(Entry) = .empty,
        };

        shared: *Shared,

        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Self {
            const shared = try gpa.create(Shared);
            shared.* = .{ .gpa = gpa, .io = io };
            return .{ .shared = shared };
        }

        pub fn deinit(self: Self) void {
            const shared = self.shared;
            for (shared.data.items) |entry| shared.gpa.free(entry.value);
            shared.data.deinit(shared.gpa);
            shared.gpa.destroy(shared);
        }

        /// Adds (or replaces) the value served for `key` (copied).
        pub fn insert(self: Self, key: K, value: []const u8) Allocator.Error!void {
            const shared = self.shared;
            const copy = try shared.gpa.dupe(u8, value);
            errdefer shared.gpa.free(copy);
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            for (shared.data.items) |*entry| {
                if (codec.order(K, entry.key, key) != .eq) continue;
                shared.gpa.free(entry.value);
                entry.value = copy;
                return;
            }
            try shared.data.append(shared.gpa, .{ .key = key, .value = copy });
        }

        /// A receiver holding a copy of the value for `key`, or closed when there is none.
        pub fn produce(self: Self, key: K) Allocator.Error!oneshot.Receiver(Produced) {
            const shared = self.shared;
            var pair = try oneshot.channel(Produced, shared.gpa, shared.io);
            const copy = self.lookup(key) catch |err| {
                pair.sender.deinit();
                pair.receiver.deinit();
                return err;
            };
            const value = copy orelse {
                pair.sender.deinit();
                return pair.receiver;
            };
            // Proof: the receiver is still open, so the send cannot be refused.
            pair.sender.send(.{ .bytes = value, .gpa = shared.gpa }) catch unreachable;
            assert(pair.receiver.is_ready());
            return pair.receiver;
        }

        fn lookup(self: Self, key: K) Allocator.Error!?[]u8 {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            for (shared.data.items) |entry| {
                if (codec.order(K, entry.key, key) != .eq) continue;
                return try shared.gpa.dupe(u8, entry.value);
            }
            return null;
        }
    };
}
