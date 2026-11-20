//! Storage that records every operation in the deterministic runtime's auditor (commonware
//! `runtime/src/storage/audited.rs`), so two runs that touch storage differently get different
//! auditor states.
//!
//! Each operation is one event: its label (`open`, `remove`, `scan`, `read_at`, `write_at`,
//! `resize`, `sync`) and its arguments as length-prefixed fields, in commonware's order. Writes
//! hash their bytes as one field however they are chunked. The event is recorded before the
//! operation runs, whether or not it then fails.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const iface = @import("../storage.zig");
const Auditor = @import("../deterministic.zig").Auditor;

const Error = iface.Error;

fn be_bytes(comptime T: type, value: T) [@sizeOf(T)]u8 {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    return bytes;
}

pub const Storage = struct {
    gpa: Allocator,
    inner: iface.Storage,
    auditor: *Auditor,
    /// Every handle not yet closed.
    handles: std.DoublyLinkedList = .{},

    pub fn init(gpa: Allocator, inner: iface.Storage, auditor: *Auditor) Storage {
        return .{ .gpa = gpa, .inner = inner, .auditor = auditor };
    }

    /// Closes handles left open. Call before the inner storage's deinit.
    pub fn deinit(self: *Storage) void {
        while (self.handles.first) |node| {
            const blob: *Blob = @fieldParentPtr("node", node);
            blob.close();
        }
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

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        return from(ptr).open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        return from(ptr).remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        return from(ptr).scan(gpa, partition);
    }

    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        assert(versions.min <= versions.max);
        const min = be_bytes(u16, versions.min);
        const max = be_bytes(u16, versions.max);
        self.auditor.event("open", &.{ partition, name, &min, &max });
        const blob = try self.gpa.create(Blob);
        errdefer self.gpa.destroy(blob);
        const identity = try std.mem.concat(self.gpa, u8, &.{ partition, name });
        errdefer self.gpa.free(identity);
        const opened = try self.inner.open_versioned(partition, name, versions);
        blob.* = .{
            .storage = self,
            .inner = opened.blob,
            .identity = identity,
            .partition_len = partition.len,
        };
        self.handles.append(&blob.node);
        assert(std.mem.eql(u8, blob.name(), name));
        return .{ .blob = blob.blob(), .len = opened.len, .version = opened.version };
    }

    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) Error!void {
        if (name) |blob_name| {
            self.auditor.event("remove", &.{ partition, &.{1}, blob_name });
        } else {
            self.auditor.event("remove", &.{ partition, &.{0} });
        }
        return self.inner.remove(partition, name);
    }

    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) Error!iface.Names {
        self.auditor.event("scan", &.{partition});
        return self.inner.scan(gpa, partition);
    }

    /// An open blob that audits its operations.
    pub const Blob = struct {
        storage: *Storage,
        node: std.DoublyLinkedList.Node = .{},
        inner: iface.Blob,
        /// The partition name followed by the blob name.
        identity: []u8,
        partition_len: usize,

        fn partition(self: *const Blob) []const u8 {
            return self.identity[0..self.partition_len];
        }

        fn name(self: *const Blob) []const u8 {
            return self.identity[self.partition_len..];
        }

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
            .io = io_erased,
        };

        fn from_blob(ptr: *anyopaque) *Blob {
            return @ptrCast(@alignCast(ptr));
        }

        fn io_erased(ptr: *anyopaque) ?std.Io {
            return from_blob(ptr).inner.io();
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
            const offset_bytes = be_bytes(u64, offset);
            const len_bytes = be_bytes(u64, buffer.len);
            const options_byte: [1]u8 = .{@bitCast(options)};
            self.storage.auditor.event("read_at", &.{
                self.partition(), self.name(), &offset_bytes, &len_bytes, &options_byte,
            });
            return self.inner.read_at_options(offset, buffer, options);
        }

        /// Audits the chunks as one field: commonware hashes the logical payload, not its
        /// physical chunking.
        pub fn write_at(
            self: *Blob,
            offset: u64,
            chunks: []const []const u8,
            options: iface.WriteOptions,
        ) Error!void {
            const offset_bytes = be_bytes(u64, offset);
            const options_byte: [1]u8 = .{@bitCast(options)};
            self.storage.auditor.event_chunked(
                "write_at",
                &.{ self.partition(), self.name(), &offset_bytes },
                chunks,
                &.{&options_byte},
            );
            return self.inner.write_at_vectored(offset, chunks, options);
        }

        pub fn resize(self: *Blob, length: u64) Error!void {
            const length_bytes = be_bytes(u64, length);
            const fields: []const []const u8 = &.{ self.partition(), self.name(), &length_bytes };
            self.storage.auditor.event("resize", fields);
            return self.inner.resize(length);
        }

        pub fn sync(self: *Blob) Error!void {
            self.storage.auditor.event("sync", &.{ self.partition(), self.name() });
            return self.inner.sync();
        }

        pub fn close(self: *Blob) void {
            const owner = self.storage;
            self.inner.close();
            owner.handles.remove(&self.node);
            owner.gpa.free(self.identity);
            owner.gpa.destroy(self);
        }
    };
};

test {
    _ = @import("audited_test.zig");
}
