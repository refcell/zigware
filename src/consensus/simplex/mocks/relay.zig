//! An in-memory broadcast relay for mock applications, not a network (commonware
//! `simplex/mocks/relay.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const p2p = @import("p2p");

/// Distributes `(digest, contents)` pairs between registered applications.
pub fn Relay(comptime D: type, comptime P: type) type {
    return struct {
        const Self = @This();

        /// A recipient; `deliver` copies what it keeps.
        pub const Listener = struct {
            key: P,
            context: *anyopaque,
            deliver: *const fn (context: *anyopaque, payload: D, contents: []const u8) void,
        };

        /// The most listeners a relay holds (bounded, like every test network).
        const listeners_max = 256;

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        listeners: std.ArrayList(Listener) = .empty,
        /// Broadcasts delivering outside the lock; deregistration waits for them to end.
        delivering: u32 = 0,
        idle: Io.Condition = .init,

        pub fn init(gpa: Allocator, io: Io) Self {
            return .{ .gpa = gpa, .io = io };
        }

        pub fn deinit(self: *Self) void {
            self.listeners.deinit(self.gpa);
            self.* = undefined;
        }

        /// Registers a listener for every broadcast; a duplicate key adds another listener.
        pub fn register(self: *Self, listener: Listener) Allocator.Error!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            assert(self.listeners.items.len < listeners_max);
            try self.listeners.append(self.gpa, listener);
        }

        /// Removes every listener (payloads already delivered stay where they are).
        pub fn deregister_all(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.listeners.clearRetainingCapacity();
            self.wait_idle();
            assert(self.listeners.items.len == 0);
        }

        /// Removes `key`'s listeners. On return no broadcast can still reach them, so their
        /// contexts may be freed.
        pub fn deregister(self: *Self, key: P) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            var kept: usize = 0;
            for (self.listeners.items) |listener| {
                if (same(listener.key, key)) continue;
                self.listeners.items[kept] = listener;
                kept += 1;
            }
            self.listeners.shrinkRetainingCapacity(kept);
            self.wait_idle();
            for (self.listeners.items) |listener| assert(!same(listener.key, key));
        }

        /// Waits until no broadcast is delivering (the caller holds `mutex`).
        fn wait_idle(self: *Self) void {
            // Each wake re-checks the count; every delivery ends in bounded time.
            while (self.delivering > 0) self.idle.waitUncancelable(self.io, &self.mutex);
            assert(self.delivering == 0);
        }

        fn same(a: P, b: P) bool {
            return codec.order(P, a, b) == .eq;
        }

        fn wanted(recipients: p2p.Recipients(P), key: P) bool {
            return switch (recipients) {
                .all => true,
                .one => |one| same(one, key),
                .some => |some| for (some) |peer| {
                    if (same(peer, key)) break true;
                } else false,
            };
        }

        /// Delivers `(payload, contents)` to the selected listeners other than `sender`.
        pub fn broadcast(
            self: *Self,
            sender: P,
            recipients: p2p.Recipients(P),
            payload: D,
            contents: []const u8,
        ) void {
            var selected: [listeners_max]Listener = undefined;
            var count: usize = 0;
            {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.listeners.items) |listener| {
                    if (same(listener.key, sender) or !wanted(recipients, listener.key)) continue;
                    selected[count] = listener;
                    count += 1;
                }
                self.delivering += 1;
            }
            assert(count <= listeners_max);
            // Deliver outside the lock: a listener may take its own.
            for (selected[0..count]) |listener| {
                listener.deliver(listener.context, payload, contents);
            }
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            assert(self.delivering > 0);
            self.delivering -= 1;
            if (self.delivering == 0) self.idle.broadcast(self.io);
        }
    };
}
