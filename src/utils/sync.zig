//! Synchronization primitives (commonware `utils/src/sync`).
//!
//! commonware re-exports `parking_lot` and `tokio` locks; here `std.Io.Mutex`, `std.Io.RwLock`,
//! and `std.Io.Condition` fill those roles. This module adds `UpgradableRwLock`: a read/write
//! lock with an upgradable read that can become a write without letting another writer in
//! between. `Exclusive` (a Rust `Sync` marker) and the traced locks (tracing spans) have no Zig
//! counterpart.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

/// A read/write lock with upgradable reads (commonware `UpgradableAsyncRwLock`).
///
/// Writers and upgradable readers first take `gate`, so at most one of them is active; plain
/// readers do not take it and may run alongside an upgradable reader.
pub fn UpgradableRwLock(comptime T: type) type {
    return struct {
        const Self = @This();

        io: Io,
        rw: Io.RwLock = .init,
        gate: Io.Mutex = .init,
        value: T,

        pub fn init(io: Io, value: T) Self {
            return .{ .io = io, .value = value };
        }

        /// The value; no guard may be held.
        pub fn into_inner(self: *Self) T {
            assert(self.rw.tryLock(self.io));
            self.rw.unlock(self.io);
            return self.value;
        }

        pub fn read(self: *Self) Io.Cancelable!ReadGuard {
            try self.rw.lockShared(self.io);
            return .{ .lock = self };
        }

        pub fn write(self: *Self) Io.Cancelable!WriteGuard {
            try self.gate.lock(self.io);
            errdefer self.gate.unlock(self.io);
            try self.rw.lock(self.io);
            return .{ .lock = self };
        }

        /// A write guard if no reader, writer, or upgradable reader holds the lock.
        pub fn try_write(self: *Self) ?WriteGuard {
            if (!self.gate.tryLock()) return null;
            if (!self.rw.tryLock(self.io)) {
                self.gate.unlock(self.io);
                return null;
            }
            return .{ .lock = self };
        }

        /// A read that excludes writers and other upgradable readers until released or upgraded.
        pub fn upgradable_read(self: *Self) Io.Cancelable!UpgradableGuard {
            try self.gate.lock(self.io);
            errdefer self.gate.unlock(self.io);
            try self.rw.lockShared(self.io);
            return .{ .lock = self };
        }

        pub const ReadGuard = struct {
            lock: *Self,

            pub fn get(guard: ReadGuard) *const T {
                return &guard.lock.value;
            }

            pub fn deinit(guard: *ReadGuard) void {
                guard.lock.rw.unlockShared(guard.lock.io);
                guard.* = undefined;
            }
        };

        pub const WriteGuard = struct {
            lock: *Self,

            pub fn get(guard: WriteGuard) *T {
                return &guard.lock.value;
            }

            /// Becomes an upgradable read; no writer can enter in between, since the gate stays
            /// held throughout.
            pub fn downgrade_to_upgradable(guard: *WriteGuard) UpgradableGuard {
                const lock = guard.lock;
                lock.rw.unlock(lock.io);
                lock.rw.lockSharedUncancelable(lock.io);
                guard.* = undefined;
                return .{ .lock = lock };
            }

            pub fn deinit(guard: *WriteGuard) void {
                const lock = guard.lock;
                lock.rw.unlock(lock.io);
                lock.gate.unlock(lock.io);
                guard.* = undefined;
            }
        };

        pub const UpgradableGuard = struct {
            lock: *Self,

            pub fn get(guard: UpgradableGuard) *const T {
                return &guard.lock.value;
            }

            /// Becomes a write once plain readers leave; no writer can enter in between, since
            /// the gate stays held throughout.
            pub fn upgrade(guard: *UpgradableGuard) WriteGuard {
                const lock = guard.lock;
                lock.rw.unlockShared(lock.io);
                lock.rw.lockUncancelable(lock.io);
                guard.* = undefined;
                return .{ .lock = lock };
            }

            pub fn deinit(guard: *UpgradableGuard) void {
                const lock = guard.lock;
                lock.rw.unlockShared(lock.io);
                lock.gate.unlock(lock.io);
                guard.* = undefined;
            }
        };
    };
}

const testing = std.testing;
const Lock = UpgradableRwLock(u64);

test "sync: an upgradable read blocks writes" {
    var lock = Lock.init(testing.io, 1);
    var upgradable = try lock.upgradable_read();
    try testing.expectEqual(null, lock.try_write());
    upgradable.deinit();
    var writer = lock.try_write().?;
    writer.get().* = 2;
    writer.deinit();
    var reader = try lock.read();
    defer reader.deinit();
    try testing.expectEqual(2, reader.get().*);
}

test "sync: plain reads are allowed during an upgradable read" {
    var lock = Lock.init(testing.io, 5);
    var upgradable = try lock.upgradable_read();
    defer upgradable.deinit();
    var reader = try lock.read();
    defer reader.deinit();
    try testing.expectEqual(5, upgradable.get().*);
    try testing.expectEqual(5, reader.get().*);
}

fn contend_write(lock: *Lock, observed: *u64) Io.Cancelable!void {
    var writer = try lock.write();
    defer writer.deinit();
    observed.* = writer.get().*;
    writer.get().* = 7;
}

test "sync: an upgrade prevents writer interleaving" {
    const io = testing.io;
    var lock = Lock.init(io, 1);
    var upgradable = try lock.upgradable_read();
    var observed: u64 = 0;
    var writer = try io.concurrent(contend_write, .{ &lock, &observed });
    var upgraded = upgradable.upgrade();
    upgraded.get().* = 5;
    upgraded.deinit();
    try writer.await(io);
    // The writer ran only after the upgraded write.
    try testing.expectEqual(5, observed);
    try testing.expectEqual(7, lock.into_inner());
}

test "sync: downgrade to upgradable keeps writers out" {
    var lock = Lock.init(testing.io, 10);
    var writer = try lock.write();
    writer.get().* = 11;
    var upgradable = writer.downgrade_to_upgradable();
    try testing.expectEqual(null, lock.try_write());
    try testing.expectEqual(11, upgradable.get().*);
    upgradable.deinit();
    var again = lock.try_write().?;
    defer again.deinit();
    try testing.expectEqual(11, again.get().*);
}
