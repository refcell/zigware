//! Storage wrappers for tests (commonware `runtime/src/mocks.rs` `RecordingContext`,
//! `WriteFaultContext`, `SyncFaultContext`, `MutationFaultContext`, and `mocks/read_gate.rs`
//! `ReadGateContext`). `Wrapper(Policy)` wraps a `storage.Storage` and is one, so the wrappers
//! nest (commonware's `forward_context!` has no counterpart: Context's storage is a field).
//!
//! No counterpart: `DelayedSyncContext`/`PendingSyncs` (zigware's `sync` is synchronous, with
//! no `start_sync` to defer), `MigratingReadBlob` (moves a half-polled read between tasks),
//! and recorded read batches (there is no `read_many`).
//!
//! A parked operation waits until its caller is canceled and then returns `error.Canceled`
//! without reaching the wrapped storage, as dropping commonware's pending future does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const iface = @import("../storage.zig");

const Error = iface.Error;

/// Spin lock for the policies' short critical sections; nothing blocks while holding it.
const Lock = struct {
    mutex: std.atomic.Mutex = .unlocked,

    fn lock(self: *Lock) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Lock) void {
        self.mutex.unlock();
    }
};

/// Waits until the caller is canceled.
fn park(io: Io) Error {
    var never: Io.Event = .unset;
    never.wait(io) catch |err| return err;
    unreachable; // Nothing sets `never`.
}

/// A storage whose operations first go through `policy`. `Policy` declares `open(policy, gpa,
/// inner, partition, name) Error!bool` (whether the blob is selected), `remove`, `read(policy,
/// selected, options)`, `write(policy, options)`, `wrote(policy)`, `resize(policy)`, and
/// `sync(policy, selected)`.
pub fn Wrapper(comptime Policy: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        inner: iface.Storage,
        policy: *Policy,

        pub fn init(gpa: Allocator, inner: iface.Storage, policy: *Policy) Self {
            return .{ .gpa = gpa, .inner = inner, .policy = policy };
        }

        /// The `Storage` interface of this wrapper, which must not move while in use.
        pub fn storage(self: *Self) iface.Storage {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable: iface.Storage.VTable = .{
            .open_versioned = open_versioned,
            .remove = remove,
            .scan = scan,
        };

        fn from(ptr: *anyopaque) *Self {
            return @ptrCast(@alignCast(ptr));
        }

        fn open_versioned(
            ptr: *anyopaque,
            partition: []const u8,
            name: []const u8,
            versions: iface.VersionRange,
        ) Error!iface.Opened {
            const self = from(ptr);
            assert(versions.min <= versions.max);
            const selected = try self.policy.open(self.gpa, self.inner, partition, name);
            const blob = try self.gpa.create(Blob);
            errdefer self.gpa.destroy(blob);
            const opened = try self.inner.open_versioned(partition, name, versions);
            blob.* = .{ .owner = self, .inner = opened.blob, .selected = selected };
            return .{ .blob = blob.blob(), .len = opened.len, .version = opened.version };
        }

        fn remove(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
            const self = from(ptr);
            try self.policy.remove();
            return self.inner.remove(partition, name);
        }

        fn scan(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
            return from(ptr).inner.scan(gpa, partition);
        }

        const Blob = struct {
            owner: *Self,
            inner: iface.Blob,
            /// The policy picked this blob at open (its partition, for partition faults).
            selected: bool,

            fn blob(self: *Blob) iface.Blob {
                return .{ .ptr = self, .vtable = &blob_vtable };
            }

            const blob_vtable: iface.Blob.VTable = .{
                .read_at = read_at,
                .write_at = write_at,
                .resize = resize,
                .sync = sync,
                .close = close,
            };

            fn of(ptr: *anyopaque) *Blob {
                return @ptrCast(@alignCast(ptr));
            }

            fn read_at(
                ptr: *anyopaque,
                offset: u64,
                buffer: []u8,
                options: iface.ReadOptions,
            ) Error!void {
                const self = of(ptr);
                try self.owner.policy.read(self.selected, options);
                return self.inner.read_at_options(offset, buffer, options);
            }

            fn write_at(
                ptr: *anyopaque,
                offset: u64,
                chunks: []const []const u8,
                options: iface.WriteOptions,
            ) Error!void {
                const self = of(ptr);
                try self.owner.policy.write(options);
                try self.inner.write_at_vectored(offset, chunks, options);
                self.owner.policy.wrote();
            }

            fn resize(ptr: *anyopaque, length: u64) Error!void {
                const self = of(ptr);
                try self.owner.policy.resize();
                return self.inner.resize(length);
            }

            fn sync(ptr: *anyopaque) Error!void {
                const self = of(ptr);
                try self.owner.policy.sync(self.selected);
                return self.inner.sync();
            }

            fn close(ptr: *anyopaque) void {
                const self = of(ptr);
                const gpa = self.owner.gpa;
                self.inner.close();
                gpa.destroy(self);
            }
        };
    };
}

/// The options each operation was given, in call order (commonware `RecordingSnapshot`).
pub const Recordings = struct {
    gpa: Allocator,
    lock: Lock = .{},
    reads: std.ArrayList(iface.ReadOptions) = .empty,
    writes: std.ArrayList(iface.WriteOptions) = .empty,

    pub fn init(gpa: Allocator) Recordings {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Recordings) void {
        self.reads.deinit(self.gpa);
        self.writes.deinit(self.gpa);
        self.* = undefined;
    }

    /// Forgets every recorded operation.
    pub fn clear(self: *Recordings) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.reads.clearRetainingCapacity();
        self.writes.clearRetainingCapacity();
        assert(self.reads.items.len == 0 and self.writes.items.len == 0);
    }

    fn open(
        self: *Recordings,
        gpa: Allocator,
        inner: iface.Storage,
        partition: []const u8,
        name: []const u8,
    ) Error!bool {
        _ = .{ self, gpa, inner, partition, name };
        return true;
    }

    fn remove(self: *Recordings) Error!void {
        _ = self;
    }

    fn read(self: *Recordings, selected: bool, options: iface.ReadOptions) Error!void {
        assert(selected);
        self.lock.lock();
        defer self.lock.unlock();
        try self.reads.append(self.gpa, options);
    }

    fn write(self: *Recordings, options: iface.WriteOptions) Error!void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.writes.append(self.gpa, options);
    }

    fn wrote(self: *Recordings) void {
        _ = self;
    }

    fn resize(self: *Recordings) Error!void {
        _ = self;
    }

    fn sync(self: *Recordings, selected: bool) Error!void {
        _ = .{ self, selected };
    }
};

/// Records the options of every read and write (commonware `RecordingContext`).
pub const Recording = Wrapper(Recordings);

/// While armed, every `write_at` fails with `error.Io`; successful writes are counted
/// (commonware `WriteFaults`).
pub const WriteFaults = struct {
    lock: Lock = .{},
    fail: bool = false,
    writes: u64 = 0,

    pub fn arm(self: *WriteFaults) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.fail = true;
    }

    pub fn disarm(self: *WriteFaults) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.fail = false;
    }

    /// The number of successful writes so far.
    pub fn successful_writes(self: *WriteFaults) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.writes;
    }

    fn open(
        self: *WriteFaults,
        gpa: Allocator,
        inner: iface.Storage,
        partition: []const u8,
        name: []const u8,
    ) Error!bool {
        _ = .{ self, gpa, inner, partition, name };
        return true;
    }

    fn remove(self: *WriteFaults) Error!void {
        _ = self;
    }

    fn read(self: *WriteFaults, selected: bool, options: iface.ReadOptions) Error!void {
        _ = .{ self, selected, options };
    }

    fn write(self: *WriteFaults, options: iface.WriteOptions) Error!void {
        _ = options;
        self.lock.lock();
        defer self.lock.unlock();
        if (self.fail) return error.Io;
    }

    fn wrote(self: *WriteFaults) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.writes += 1;
        assert(self.writes > 0);
    }

    fn resize(self: *WriteFaults) Error!void {
        _ = self;
    }

    fn sync(self: *WriteFaults, selected: bool) Error!void {
        _ = .{ self, selected };
    }
};

/// Fails `write_at` while its `WriteFaults` is armed (commonware `WriteFaultContext`).
pub const WriteFault = Wrapper(WriteFaults);

/// Fails every sync of the blobs in one partition (commonware `SyncFaultContext`). A `write_at`
/// with `sync` set still reaches storage, as in commonware.
pub const SyncFaults = struct {
    partition: []const u8,

    fn open(
        self: *SyncFaults,
        gpa: Allocator,
        inner: iface.Storage,
        partition: []const u8,
        name: []const u8,
    ) Error!bool {
        _ = .{ gpa, inner, name };
        return std.mem.eql(u8, partition, self.partition);
    }

    fn remove(self: *SyncFaults) Error!void {
        _ = self;
    }

    fn read(self: *SyncFaults, selected: bool, options: iface.ReadOptions) Error!void {
        _ = .{ self, selected, options };
    }

    fn write(self: *SyncFaults, options: iface.WriteOptions) Error!void {
        _ = .{ self, options };
    }

    fn wrote(self: *SyncFaults) void {
        _ = self;
    }

    fn resize(self: *SyncFaults) Error!void {
        _ = self;
    }

    fn sync(self: *SyncFaults, selected: bool) Error!void {
        assert(self.partition.len > 0);
        if (selected) return error.Io;
    }
};

pub const SyncFault = Wrapper(SyncFaults);

/// After a set number of mutating operations succeed, every later one fails with `error.Io`
/// or parks (commonware `MutationFaults`). A mutation is a blob creation, write, resize,
/// sync, or removal; a refused one never reaches the wrapped storage.
pub const MutationFaults = struct {
    io: Io,
    lock: Lock = .{},
    allowed: ?u64 = null,
    parks: bool = false,
    refused: bool = false,

    pub fn init(io: Io) MutationFaults {
        return .{ .io = io };
    }

    /// Lets `operations` more mutations succeed, then fails every later one.
    pub fn allow(self: *MutationFaults, operations: u64) void {
        self.arm(operations, false);
    }

    /// Lets `operations` more mutations succeed, then parks every later one.
    pub fn park_after(self: *MutationFaults, operations: u64) void {
        self.arm(operations, true);
    }

    fn arm(self: *MutationFaults, operations: u64, parks: bool) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.allowed = operations;
        self.parks = parks;
        self.refused = false;
    }

    /// Stops failing and parking mutations.
    pub fn disarm(self: *MutationFaults) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.allowed = null;
    }

    /// Whether a mutation failed since the last `allow`.
    pub fn failed(self: *MutationFaults) bool {
        self.lock.lock();
        defer self.lock.unlock();
        return self.refused and !self.parks;
    }

    /// Whether a mutation parked since the last `park_after`.
    pub fn parked(self: *MutationFaults) bool {
        self.lock.lock();
        defer self.lock.unlock();
        return self.refused and self.parks;
    }

    fn check(self: *MutationFaults) Error!void {
        self.lock.lock();
        const allowed = self.allowed orelse {
            self.lock.unlock();
            return;
        };
        if (allowed > 0) {
            self.allowed = allowed - 1;
            self.lock.unlock();
            return;
        }
        self.refused = true;
        const parks = self.parks;
        self.lock.unlock();
        if (parks) return park(self.io);
        return error.Io;
    }

    fn open(
        self: *MutationFaults,
        gpa: Allocator,
        inner: iface.Storage,
        partition: []const u8,
        name: []const u8,
    ) Error!bool {
        // Opening a blob that is not stored creates it, which is a mutation.
        const names = inner.scan(gpa, partition) catch |err| switch (err) {
            error.PartitionMissing => {
                try self.check();
                return true;
            },
            else => return err,
        };
        defer names.deinit(gpa);
        if (!names.contains(name)) try self.check();
        return true;
    }

    fn remove(self: *MutationFaults) Error!void {
        return self.check();
    }

    fn read(self: *MutationFaults, selected: bool, options: iface.ReadOptions) Error!void {
        _ = .{ self, selected, options };
    }

    fn write(self: *MutationFaults, options: iface.WriteOptions) Error!void {
        _ = options;
        return self.check();
    }

    fn wrote(self: *MutationFaults) void {
        _ = self;
    }

    fn resize(self: *MutationFaults) Error!void {
        return self.check();
    }

    fn sync(self: *MutationFaults, selected: bool) Error!void {
        _ = selected;
        return self.check();
    }
};

pub const MutationFault = Wrapper(MutationFaults);

/// While armed, reads of one partition park, so a test can cancel their callers (commonware
/// `ReadGate`). Disarming lets new reads through; parked ones stay parked.
pub const ReadGate = struct {
    io: Io,
    partition: []const u8,
    lock: Lock = .{},
    armed: bool = false,
    blocked_reads: u64 = 0,

    pub fn init(io: Io, partition: []const u8) ReadGate {
        return .{ .io = io, .partition = partition };
    }

    /// Parks later reads and resets the count of blocked ones.
    pub fn arm(self: *ReadGate) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.armed = true;
        self.blocked_reads = 0;
    }

    pub fn disarm(self: *ReadGate) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.armed = false;
    }

    /// The reads that reached the gate since it was armed.
    pub fn blocked(self: *ReadGate) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.blocked_reads;
    }

    fn open(
        self: *ReadGate,
        gpa: Allocator,
        inner: iface.Storage,
        partition: []const u8,
        name: []const u8,
    ) Error!bool {
        _ = .{ gpa, inner, name };
        return std.mem.eql(u8, partition, self.partition);
    }

    fn remove(self: *ReadGate) Error!void {
        _ = self;
    }

    fn read(self: *ReadGate, selected: bool, options: iface.ReadOptions) Error!void {
        _ = options;
        if (!selected) return;
        self.lock.lock();
        const block = self.armed;
        if (block) self.blocked_reads += 1;
        self.lock.unlock();
        if (block) return park(self.io);
    }

    fn write(self: *ReadGate, options: iface.WriteOptions) Error!void {
        _ = .{ self, options };
    }

    fn wrote(self: *ReadGate) void {
        _ = self;
    }

    fn resize(self: *ReadGate) Error!void {
        _ = self;
    }

    fn sync(self: *ReadGate, selected: bool) Error!void {
        _ = .{ self, selected };
    }
};

pub const ReadGated = Wrapper(ReadGate);

test {
    _ = @import("mocks_test.zig");
}
