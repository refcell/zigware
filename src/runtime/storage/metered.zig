//! Storage that counts its operations in metrics (commonware `runtime/src/storage/metered.rs`).
//!
//! It registers `open_blobs` (gauge) and the counters `storage_reads`, `storage_read_bytes`,
//! `storage_writes`, `storage_write_bytes`, `storage_syncs`, and `storage_resizes` in the
//! scope it is given; the runtimes give it their `runtime` sub-registry. Reads and writes are
//! counted before they run, whether or not they then fail, as in commonware; an open counts
//! only once it succeeds. A write with `sync` also counts a sync.
//!
//! One spin lock guards the list of open handles, so a `Storage` may be shared by threads;
//! nothing blocks or yields while holding it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const iface = @import("../storage.zig");
const metrics = @import("../telemetry/metrics/mod.zig");

const Error = iface.Error;
const Counter = metrics.Registered(metrics.raw.Counter);
const Gauge = metrics.Registered(metrics.raw.Gauge);

/// The storage metrics (commonware `storage::metered::Metrics`).
pub const Metrics = struct {
    open_blobs: Gauge,
    storage_reads: Counter,
    storage_read_bytes: Counter,
    storage_writes: Counter,
    storage_write_bytes: Counter,
    storage_syncs: Counter,
    storage_resizes: Counter,

    /// Registers every metric in `scope`.
    pub fn init(scope: *const metrics.Scope) Allocator.Error!Metrics {
        var open_blobs = try scope.gauge("open_blobs", "Number of open blobs");
        errdefer open_blobs.deinit();
        var reads = try scope.counter("storage_reads", "Total number of storage reads");
        errdefer reads.deinit();
        var read_bytes = try scope.counter(
            "storage_read_bytes",
            "Total amount of data read from storage",
        );
        errdefer read_bytes.deinit();
        var writes = try scope.counter("storage_writes", "Total number of storage writes");
        errdefer writes.deinit();
        var write_bytes = try scope.counter(
            "storage_write_bytes",
            "Total amount of data written to storage",
        );
        errdefer write_bytes.deinit();
        var syncs = try scope.counter("storage_syncs", "Total number of storage sync requests");
        errdefer syncs.deinit();
        const resizes = try scope.counter("storage_resizes", "Total number of storage resizes");
        return .{
            .open_blobs = open_blobs,
            .storage_reads = reads,
            .storage_read_bytes = read_bytes,
            .storage_writes = writes,
            .storage_write_bytes = write_bytes,
            .storage_syncs = syncs,
            .storage_resizes = resizes,
        };
    }

    pub fn deinit(self: *Metrics) void {
        inline for (@typeInfo(Metrics).@"struct".field_names) |name| @field(self, name).deinit();
        self.* = undefined;
    }
};

pub const Storage = struct {
    gpa: Allocator,
    inner: iface.Storage,
    metrics: Metrics,
    mutex: std.atomic.Mutex = .unlocked,
    /// Every handle not yet closed.
    handles: std.DoublyLinkedList = .{},

    /// Wraps `inner`, registering the metrics in `scope`.
    pub fn init(
        gpa: Allocator,
        inner: iface.Storage,
        scope: *const metrics.Scope,
    ) Allocator.Error!Storage {
        return .{ .gpa = gpa, .inner = inner, .metrics = try .init(scope) };
    }

    /// Closes handles left open and unregisters the metrics. Call before the inner storage's
    /// deinit.
    pub fn deinit(self: *Storage) void {
        while (self.handles.first) |node| {
            const blob: *Blob = @fieldParentPtr("node", node);
            blob.close();
        }
        assert(self.metrics.open_blobs.metric().get() == 0);
        self.metrics.deinit();
        self.* = undefined;
    }

    /// The `Storage` interface of this wrapper.
    pub fn storage(self: *Storage) iface.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Storage.VTable = .{
        .open_versioned = open_erased,
        .remove = remove_erased,
        .scan = scan_erased,
    };

    fn from(ptr: *anyopaque) *Storage {
        return @ptrCast(@alignCast(ptr));
    }

    fn lock(self: *Storage) void {
        // Critical sections only link or unlink a node.
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Storage) void {
        self.mutex.unlock();
    }

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        return from(ptr).open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        return from(ptr).inner.remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        return from(ptr).inner.scan(gpa, partition);
    }

    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        assert(versions.min <= versions.max);
        const blob = try self.gpa.create(Blob);
        errdefer self.gpa.destroy(blob);
        const opened = try self.inner.open_versioned(partition, name, versions);
        blob.* = .{ .storage = self, .inner = opened.blob };
        self.lock();
        self.handles.append(&blob.node);
        self.unlock();
        self.metrics.open_blobs.metric().inc();
        assert(self.metrics.open_blobs.metric().get() > 0);
        return .{ .blob = blob.blob(), .len = opened.len, .version = opened.version };
    }

    /// An open blob that counts its operations.
    pub const Blob = struct {
        storage: *Storage,
        node: std.DoublyLinkedList.Node = .{},
        inner: iface.Blob,

        /// The `Blob` interface of this handle.
        pub fn blob(self: *Blob) iface.Blob {
            return .{ .ptr = self, .vtable = &blob_vtable };
        }

        const blob_vtable: iface.Blob.VTable = .{
            .read_at = read_at_erased,
            .write_at = write_at_erased,
            .resize = resize_erased,
            .sync = sync_erased,
            .close = close_erased,
        };

        fn from_blob(ptr: *anyopaque) *Blob {
            return @ptrCast(@alignCast(ptr));
        }

        fn read_at_erased(
            ptr: *anyopaque,
            offset: u64,
            buffer: []u8,
            options: iface.ReadOptions,
        ) Error!void {
            return from_blob(ptr).read_at(offset, buffer, options);
        }

        fn write_at_erased(
            ptr: *anyopaque,
            offset: u64,
            chunks: []const []const u8,
            options: iface.WriteOptions,
        ) Error!void {
            return from_blob(ptr).write_at(offset, chunks, options);
        }

        fn resize_erased(ptr: *anyopaque, length: u64) Error!void {
            return from_blob(ptr).resize(length);
        }

        fn sync_erased(ptr: *anyopaque) Error!void {
            return from_blob(ptr).sync();
        }

        fn close_erased(ptr: *anyopaque) void {
            from_blob(ptr).close();
        }

        pub fn read_at(
            self: *Blob,
            offset: u64,
            buffer: []u8,
            options: iface.ReadOptions,
        ) Error!void {
            const m = &self.storage.metrics;
            m.storage_reads.metric().inc();
            m.storage_read_bytes.metric().inc_by(buffer.len);
            return self.inner.read_at_options(offset, buffer, options);
        }

        pub fn write_at(
            self: *Blob,
            offset: u64,
            chunks: []const []const u8,
            options: iface.WriteOptions,
        ) Error!void {
            var total: u64 = 0;
            for (chunks) |chunk| total += chunk.len;
            const m = &self.storage.metrics;
            m.storage_writes.metric().inc();
            m.storage_write_bytes.metric().inc_by(total);
            if (options.sync) m.storage_syncs.metric().inc();
            return self.inner.write_at_vectored(offset, chunks, options);
        }

        pub fn resize(self: *Blob, length: u64) Error!void {
            self.storage.metrics.storage_resizes.metric().inc();
            return self.inner.resize(length);
        }

        pub fn sync(self: *Blob) Error!void {
            self.storage.metrics.storage_syncs.metric().inc();
            return self.inner.sync();
        }

        pub fn close(self: *Blob) void {
            const owner = self.storage;
            self.inner.close();
            owner.lock();
            owner.handles.remove(&self.node);
            owner.unlock();
            assert(owner.metrics.open_blobs.metric().get() > 0);
            owner.metrics.open_blobs.metric().dec();
            owner.gpa.destroy(self);
        }
    };
};

test {
    _ = @import("metered_test.zig");
}
