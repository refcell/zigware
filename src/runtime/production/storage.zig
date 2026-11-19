//! File-backed storage for the production runtime (commonware `storage::tokio` and
//! `storage::iouring`), over `std.Io` files, so it runs on any `Io`: `std.Io.Uring` on Linux,
//! kqueue or `std.Io.Threaded` elsewhere.
//!
//! Layout: `<root>/<partition>/<hex(name)>`, each blob starting with the runtime header
//! (`storage/header.zig`). `<root>/.hold` carries an exclusive advisory lock for the life of the
//! storage, so two processes never share a directory (commonware `hold.rs`).
//!
//! Durability follows commonware: creating a blob makes its directory entry durable (fsyncs
//! the partition directory, and the root when the partition is new), then writes the header
//! with set_len(0), write, fsync, so a torn creation is recognized and healed on the next open.
//! Removal fsyncs the parent directory. The first open of an existing blob through a storage
//! instance fsyncs the file before trusting its length (commonware's first-open flush debt).
//! Writes reach the file at once; `sync` (or `WriteOptions.sync`) makes them durable.
//!
//! With `Config.ring`, blob reads, writes, and syncs go through io_uring (commonware
//! `storage::iouring`); namespace operations and blob creation stay on `std.Io`.
//!
//! One `Io.Mutex` serializes namespace operations (open, remove, scan), as commonware's
//! dispatch lock does. Blob I/O runs without it. A blob has one live handle: a second open
//! returns `error.BlobAlreadyOpen` until the first closes or the blob is removed. A removed
//! blob's handles keep reading and writing its unlinked file.

const std = @import("std");
const builtin = @import("builtin");
const iface = @import("../storage.zig");
const header = @import("../storage/header.zig");
const ring_mod = @import("ring.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Error = iface.Error;

/// Name of the hold file at the storage root. Partition names cannot contain `.`.
pub const hold_name = ".hold";

/// Longest blob name: its hex form must fit a 255-byte file name.
pub const name_size_max = 127;

pub const Config = struct {
    /// Layouts this storage accepts when opening existing blobs.
    layouts: iface.LayoutRange = .all,
    /// Layout of new blobs.
    layout: iface.BlobLayout = iface.default_blob_layout,
    /// Runs blob I/O through io_uring; it must outlive the storage.
    ring: ?*ring_mod.Ring = null,
    /// Fsync an inherited partition's directory the first time this instance scans, opens, or
    /// removes a blob in it. Like commonware, only off Linux by default.
    sync_inherited_partitions: bool = builtin.os.tag != .linux,
};

/// Most partitions remembered as synced; past it, inherited partitions sync on every access.
pub const synced_partitions_max = 1024;

/// Test hook: pauses the next directory sync, announcing it, until released.
pub const SyncGate = struct {
    entered: Io.Event = .unset,
    release: Io.Event = .unset,
};

/// Storage roots this process holds, by their hold file's inode: a second storage on a held
/// root would wait on its own process's lock forever. Inodes of different filesystems can
/// coincide; such a root is then refused, never shared.
const held_roots = struct {
    const count_max = 64;
    var mutex: Io.Mutex = .init;
    var inodes: [count_max]File.INode = undefined;
    var count: u32 = 0;

    fn claim(io: Io, inode: File.INode) Error!void {
        mutex.lockUncancelable(io);
        defer mutex.unlock(io);
        assert(count <= count_max);
        if (std.mem.indexOfScalar(File.INode, inodes[0..count], inode) != null) {
            return error.Io;
        }
        if (count == count_max) return error.Io;
        inodes[count] = inode;
        count += 1;
    }

    fn release(io: Io, inode: File.INode) void {
        mutex.lockUncancelable(io);
        defer mutex.unlock(io);
        const index = std.mem.indexOfScalar(File.INode, inodes[0..count], inode).?;
        count -= 1;
        inodes[index] = inodes[count];
        assert(std.mem.indexOfScalar(File.INode, inodes[0..count], inode) == null);
    }
};

pub const Storage = struct {
    io: Io,
    gpa: Allocator,
    config: Config,
    root: Dir,
    hold: File,
    mutex: Io.Mutex = .init,
    /// The live handle of each open blob, keyed by `partition/hex(name)` (owned by the blob).
    live: std.StringArrayHashMapUnmanaged(*Blob) = .empty,
    /// Keys whose first-open flush has run (or that were created) through this instance.
    flushed: std.StringArrayHashMapUnmanaged(void) = .empty,
    /// Partitions whose inherited directory entries this instance made durable (commonware's
    /// `Partitions.synced`), at most `synced_partitions_max`, under `mutex`.
    synced: std.StringArrayHashMapUnmanaged(void) = .empty,
    /// Test hook: the next directory sync fails with this error before reaching the disk.
    fail_next_dir_sync: ?Error = null,
    /// Test hook: the next directory sync waits on this gate first.
    dir_sync_gate: ?*SyncGate = null,

    /// Takes ownership of `root` and acquires its hold, waiting while another process holds
    /// it (commonware's `Hold::acquire`). A root this process already holds fails with
    /// `error.Io` before any lock: the wait would never end, and commonware likewise rejects a
    /// nested runtime before it takes the hold.
    pub fn init(io: Io, gpa: Allocator, root: Dir, config: Config) Error!Storage {
        assert(config.layouts.contains(config.layout));
        const hold = root.createFile(io, hold_name, .{ .truncate = false }) catch
            return error.Io;
        errdefer hold.close(io);
        const inode = (hold.stat(io) catch return error.Io).inode;
        try held_roots.claim(io, inode);
        errdefer held_roots.release(io, inode);
        hold.lock(io, .exclusive) catch return error.Io;
        return .{ .io = io, .gpa = gpa, .config = config, .root = root, .hold = hold };
    }

    /// Every handle must be closed first. Releases the hold and closes the root.
    pub fn deinit(self: *Storage) void {
        assert(self.live.count() == 0);
        for (self.flushed.keys()) |key| self.gpa.free(key);
        self.flushed.deinit(self.gpa);
        for (self.synced.keys()) |key| self.gpa.free(key);
        self.synced.deinit(self.gpa);
        self.live.deinit(self.gpa);
        held_roots.release(self.io, (self.hold.stat(self.io) catch unreachable).inode); // The
        // hold is open, and fstat of an open descriptor fails only on a bad descriptor.
        self.hold.close(self.io);
        self.root.close(self.io);
        self.* = undefined;
    }

    pub fn storage(self: *Storage) iface.Storage {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: iface.Storage.VTable = .{
        .open_versioned = open_erased,
        .remove = remove_erased,
        .scan = scan_erased,
    };

    fn open_erased(
        ptr: *anyopaque,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.open_versioned(partition, name, versions);
    }

    fn remove_erased(ptr: *anyopaque, partition: []const u8, name: ?[]const u8) Error!void {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.remove(partition, name);
    }

    fn scan_erased(ptr: *anyopaque, gpa: Allocator, partition: []const u8) Error!iface.Names {
        const self: *Storage = @ptrCast(@alignCast(ptr));
        return self.scan(gpa, partition);
    }

    /// Open or create a blob accepting only `default_blob_version`.
    pub fn open(self: *Storage, partition: []const u8, name: []const u8) Error!iface.Opened {
        return self.open_versioned(partition, name, .only(iface.default_blob_version));
    }

    /// Open or create a blob (see `iface.Storage.open_versioned`).
    pub fn open_versioned(
        self: *Storage,
        partition: []const u8,
        name: []const u8,
        versions: iface.VersionRange,
    ) Error!iface.Opened {
        assert(versions.min <= versions.max);
        try iface.validate_partition_name(partition);
        if (name.len > name_size_max) return error.BlobOpenFailed;
        var key_buffer: [key_size_max]u8 = undefined;
        const key = blob_key(&key_buffer, partition, name);
        self.mutex.lock(self.io) catch return error.Canceled;
        defer self.mutex.unlock(self.io);
        if (self.live.contains(key)) return error.BlobAlreadyOpen;
        try self.live.ensureUnusedCapacity(self.gpa, 1);
        try self.flushed.ensureUnusedCapacity(self.gpa, 1);
        const partition_dir = try self.partition_create(partition);
        defer partition_dir.close(self.io);
        const file = partition_dir.createFile(self.io, key[partition.len + 1 ..], .{
            .read = true,
            .truncate = false,
        }) catch |err| return or_canceled(err, error.BlobOpenFailed);
        errdefer file.close(self.io);
        const resolved = try self.header_resolve_or_create(partition_dir, file, .{
            .key = key,
            .partition = partition,
            .name = name,
        }, versions);
        const handle = try Blob.create(self, file, key, resolved.data_offset);
        self.live.putAssumeCapacityNoClobber(handle.key, handle);
        assert(self.live.get(key).? == handle);
        return .{ .blob = handle.blob(), .len = resolved.len, .version = resolved.blob_version };
    }

    /// Creates the partition directory if needed, making a new one durable in the root.
    fn partition_create(self: *Storage, partition: []const u8) Error!Dir {
        const status = self.root.createDirPathStatus(self.io, partition, .default_dir) catch |err|
            return or_canceled(err, error.PartitionCreationFailed);
        if (status == .created) try self.dir_sync(self.root);
        return self.root.openDir(self.io, partition, .{}) catch |err|
            or_canceled(err, error.PartitionCreationFailed);
    }

    fn header_resolve_or_create(
        self: *Storage,
        partition_dir: Dir,
        file: File,
        path: Path,
        versions: iface.VersionRange,
    ) Error!header.Resolved {
        const key = path.key;
        const raw_len = file.length(self.io) catch |err| return or_canceled(err, error.ReadFailed);
        var raw_buffer: [header.region_max]u8 = undefined;
        const raw = raw_buffer[0..header.resolve_len(raw_len)];
        const read = file.readPositionalAll(self.io, raw, 0) catch |err|
            return or_canceled(err, error.ReadFailed);
        if (read != raw.len) return error.ReadFailed;
        const layouts = self.config.layouts;
        const resolved = try header.resolve(
            raw,
            raw_len,
            layouts,
            versions,
            path.partition,
            path.name,
        );
        if (resolved) |existing| {
            try self.partition_sync_once(path.partition, partition_dir);
            if (!self.flushed.contains(key)) {
                // The previous run may have left writes in the page cache: settle them first.
                file.sync(self.io) catch |err| return or_canceled(err, error.BlobSyncFailed);
                self.flushed.putAssumeCapacityNoClobber(try self.gpa.dupe(u8, key), {});
            }
            return existing;
        }
        // A new blob (or one torn during creation): make its directory entry durable, then
        // write the header region over an emptied file.
        try self.dir_sync(partition_dir);
        try self.partition_synced(path.partition);
        var region: [header.region_max]u8 = undefined;
        const created = header.create(.only(self.config.layout), versions, &region);
        file.setLength(self.io, 0) catch |err| return or_canceled(err, error.BlobResizeFailed);
        file.writePositionalAll(self.io, created.region, 0) catch |err|
            return or_canceled(err, error.WriteFailed);
        file.sync(self.io) catch |err| return or_canceled(err, error.BlobSyncFailed);
        if (!self.flushed.contains(key)) {
            self.flushed.putAssumeCapacityNoClobber(try self.gpa.dupe(u8, key), {});
        }
        return .{
            .len = 0,
            .blob_version = created.blob_version,
            .data_offset = created.region.len,
        };
    }

    /// Remove a blob, or the whole partition when `name` is null. Open handles stay usable.
    pub fn remove(self: *Storage, partition: []const u8, name: ?[]const u8) Error!void {
        try iface.validate_partition_name(partition);
        self.mutex.lock(self.io) catch return error.Canceled;
        defer self.mutex.unlock(self.io);
        if (name) |blob_name| {
            if (blob_name.len > name_size_max) return error.BlobMissing;
            var key_buffer: [key_size_max]u8 = undefined;
            const key = blob_key(&key_buffer, partition, blob_name);
            const partition_dir = self.root.openDir(self.io, partition, .{}) catch
                return error.BlobMissing;
            defer partition_dir.close(self.io);
            // Retired before the unlink, so a failed removal never leaves it marked durable.
            self.partition_invalidate(partition);
            partition_dir.deleteFile(self.io, key[partition.len + 1 ..]) catch
                return error.BlobMissing;
            self.forget(key, false);
            try self.dir_sync(partition_dir);
            try self.partition_synced(partition);
        } else {
            const partition_dir = self.root.openDir(self.io, partition, .{}) catch |err|
                return if (err == error.FileNotFound) error.PartitionMissing else error.Io;
            partition_dir.close(self.io);
            self.partition_invalidate(partition);
            self.root.deleteTree(self.io, partition) catch return error.Io;
            var prefix_buffer: [iface_partition_size_max + 1]u8 = undefined;
            if (partition.len > iface_partition_size_max) return error.PartitionNameInvalid;
            @memcpy(prefix_buffer[0..partition.len], partition);
            prefix_buffer[partition.len] = '/';
            self.forget(prefix_buffer[0 .. partition.len + 1], true);
            try self.dir_sync(self.root);
        }
    }

    /// Makes `dir`'s entries durable, through the test hooks.
    fn dir_sync(self: *Storage, dir: Dir) Error!void {
        if (self.dir_sync_gate) |gate| {
            self.dir_sync_gate = null;
            gate.entered.set(self.io);
            gate.release.wait(self.io) catch return error.Canceled;
        }
        if (self.fail_next_dir_sync) |err| {
            self.fail_next_dir_sync = null;
            return err;
        }
        try sync_dir(self.io, dir);
    }

    /// Syncs an inherited partition's directory on its first access (commonware `sync_once`).
    fn partition_sync_once(self: *Storage, partition: []const u8, dir: Dir) Error!void {
        if (!self.config.sync_inherited_partitions) return;
        if (self.synced.contains(partition)) return;
        try self.dir_sync(dir);
        try self.partition_synced(partition);
        assert(self.synced.contains(partition) or self.synced.count() == synced_partitions_max);
    }

    /// Records `partition` as synced; call only after its directory sync succeeded.
    fn partition_synced(self: *Storage, partition: []const u8) Error!void {
        if (!self.config.sync_inherited_partitions) return;
        if (self.synced.contains(partition)) return;
        if (self.synced.count() == synced_partitions_max) return;
        const key = try self.gpa.dupe(u8, partition);
        errdefer self.gpa.free(key);
        try self.synced.putNoClobber(self.gpa, key, {});
        assert(self.synced.count() <= synced_partitions_max);
    }

    fn partition_invalidate(self: *Storage, partition: []const u8) void {
        if (self.synced.fetchSwapRemove(partition)) |entry| self.gpa.free(entry.key);
        assert(!self.synced.contains(partition));
    }

    /// Drops the live claim and first-open record of `key`, or of every key it prefixes.
    fn forget(self: *Storage, key: []const u8, prefix: bool) void {
        var index: usize = 0;
        while (index < self.live.count()) {
            const live_key = self.live.keys()[index];
            if (key_matches(live_key, key, prefix)) {
                self.live.swapRemoveAt(index);
            } else index += 1;
        }
        index = 0;
        while (index < self.flushed.count()) {
            const flushed_key = self.flushed.keys()[index];
            if (key_matches(flushed_key, key, prefix)) {
                self.flushed.swapRemoveAt(index);
                self.gpa.free(flushed_key);
            } else index += 1;
        }
    }

    /// Every blob name in `partition`, sorted.
    pub fn scan(self: *Storage, gpa: Allocator, partition: []const u8) Error!iface.Names {
        try iface.validate_partition_name(partition);
        self.mutex.lock(self.io) catch return error.Canceled;
        defer self.mutex.unlock(self.io);
        const options: Dir.OpenOptions = .{ .iterate = true };
        const partition_dir = self.root.openDir(self.io, partition, options) catch |err|
            return if (err == error.FileNotFound) error.PartitionMissing else error.ReadFailed;
        defer partition_dir.close(self.io);
        // Make inherited directory entries durable before exposing their blob names.
        try self.partition_sync_once(partition, partition_dir);
        var names: std.ArrayList([]u8) = .empty;
        errdefer {
            for (names.items) |item| gpa.free(item);
            names.deinit(gpa);
        }
        var iterator = partition_dir.iterate();
        while (iterator.next(self.io) catch return error.ReadFailed) |entry| {
            if (entry.kind != .file) return error.PartitionCorrupt;
            // Like commonware, names that are not UTF-8 are skipped, not corrupt.
            if (!std.unicode.utf8ValidateSlice(entry.name)) continue;
            const decoded = try gpa.alloc(u8, entry.name.len / 2);
            errdefer gpa.free(decoded);
            if (!hex_decode(decoded, entry.name)) return error.PartitionCorrupt;
            try names.append(gpa, decoded);
        }
        std.mem.sortUnstable([]u8, names.items, {}, order_names);
        return .{ .items = try names.toOwnedSlice(gpa) };
    }
};

/// A blob's partition, name, and key (`partition/hex(name)`).
const Path = struct { key: []const u8, partition: []const u8, name: []const u8 };

const iface_partition_size_max = 255;
const key_size_max = iface_partition_size_max + 1 + 2 * name_size_max;

fn order_names(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn key_matches(candidate: []const u8, key: []const u8, prefix: bool) bool {
    if (prefix) return std.mem.startsWith(u8, candidate, key);
    return std.mem.eql(u8, candidate, key);
}

/// `partition/hex(name)`, the blob's path below the root.
fn blob_key(buffer: *[key_size_max]u8, partition: []const u8, name: []const u8) []const u8 {
    assert(partition.len <= iface_partition_size_max);
    assert(name.len <= name_size_max);
    @memcpy(buffer[0..partition.len], partition);
    buffer[partition.len] = '/';
    const digits = "0123456789abcdef";
    for (name, 0..) |byte, index| {
        buffer[partition.len + 1 + 2 * index] = digits[byte >> 4];
        buffer[partition.len + 2 + 2 * index] = digits[byte & 0xf];
    }
    return buffer[0 .. partition.len + 1 + 2 * name.len];
}

/// Decodes lowercase hex (commonware rejects names that do not round-trip).
fn hex_decode(out: []u8, text: []const u8) bool {
    if (text.len != out.len * 2) return false;
    for (out, 0..) |*byte, index| {
        const high = hex_digit(text[2 * index]) orelse return false;
        const low = hex_digit(text[2 * index + 1]) orelse return false;
        byte.* = high << 4 | low;
    }
    return true;
}

fn hex_digit(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        else => null,
    };
}

/// `failure`, unless the task was canceled during the call: then `error.Canceled`, so a
/// task stopped mid-write ends quietly instead of reporting a failed device.
fn or_canceled(err: anyerror, failure: Error) Error {
    assert(failure != error.Canceled);
    return if (err == error.Canceled) error.Canceled else failure;
}

/// Reads up to `buffer.len` bytes at `offset`, fewer only at the end of the file.
fn file_read(storage: *const Storage, file: File, buffer: []u8, offset: u64) Error!usize {
    const worker = ring_worker(storage) orelse
        return file.readPositionalAll(storage.io, buffer, offset) catch |err|
            or_canceled(err, error.ReadFailed);
    var done: usize = 0;
    while (done < buffer.len) {
        const result = try ring_perform(worker, .{ .read = .{
            .fd = file.handle,
            .buffer = buffer[done..],
            .offset = offset + done,
        } }) orelse continue;
        if (result.failed) return error.ReadFailed;
        if (result.count == 0) break;
        done += result.count;
    }
    assert(done <= buffer.len);
    return done;
}

fn file_write(storage: *const Storage, file: File, bytes: []const u8, offset: u64) Error!void {
    const worker = ring_worker(storage) orelse
        return file.writePositionalAll(storage.io, bytes, offset) catch |err|
            or_canceled(err, error.WriteFailed);
    var done: usize = 0;
    while (done < bytes.len) {
        const result = try ring_perform(worker, .{ .write = .{
            .fd = file.handle,
            .bytes = bytes[done..],
            .offset = offset + done,
        } }) orelse continue;
        if (result.failed or result.count == 0) return error.WriteFailed;
        done += result.count;
    }
    assert(done == bytes.len);
}

fn file_sync(storage: *const Storage, file: File) Error!void {
    const worker = ring_worker(storage) orelse
        return file.sync(storage.io) catch |err| or_canceled(err, error.BlobSyncFailed);
    while (true) {
        const result = try ring_perform(worker, .{ .fsync = .{ .fd = file.handle } }) orelse
            continue;
        if (result.failed) return error.BlobSyncFailed;
        assert(result.count == 0);
        return;
    }
}

/// The calling thread's io_uring worker, or null to use `std.Io`.
fn ring_worker(storage: *const Storage) ?*ring_mod.Worker {
    const ring = storage.config.ring orelse return null;
    return ring.worker();
}

const RingResult = struct { count: usize, failed: bool };

/// One ring operation: its count, a failure, or null for an interrupted call to retry.
fn ring_perform(worker: *ring_mod.Worker, operation: ring_mod.Operation) Error!?RingResult {
    const result = worker.perform(operation, .none) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => unreachable, // No timeout was given.
    };
    if (result >= 0) return .{ .count = @intCast(result), .failed = false };
    return switch (ring_mod.errno(result)) {
        .INTR, .AGAIN => null,
        else => .{ .count = 0, .failed = true },
    };
}

/// Makes a directory's entries durable (commonware `sync_dir`).
fn sync_dir(io: Io, dir: Dir) Error!void {
    // A directory opened without `iterate` is an `O_PATH` handle on Linux, which cannot be
    // synced: reopen it readable.
    const readable = dir.openDir(io, ".", .{ .iterate = true }) catch |err|
        return or_canceled(err, error.BlobSyncFailed);
    defer readable.close(io);
    const file: File = .{ .handle = readable.handle, .flags = .{ .nonblocking = false } };
    file.sync(io) catch |err| return or_canceled(err, error.BlobSyncFailed);
}

pub const Blob = struct {
    storage: *Storage,
    file: File,
    data_offset: u64,
    key: []u8,
    /// Bumped after every write and resize, once its I/O has finished (or failed partway).
    generation: std.atomic.Value(u64) = .init(0),
    /// The highest generation a successful fsync covered. Equal to `generation`: clean.
    synced_generation: std.atomic.Value(u64) = .init(0),
    /// Syncs skipped because nothing changed since the last one (commonware `skipped`).
    syncs_skipped: std.atomic.Value(u64) = .init(0),

    fn create(storage: *Storage, file: File, key: []const u8, data_offset: u64) Error!*Blob {
        assert(data_offset <= header.region_max);
        const handle = try storage.gpa.create(Blob);
        errdefer storage.gpa.destroy(handle);
        handle.* = .{
            .storage = storage,
            .file = file,
            .data_offset = data_offset,
            .key = try storage.gpa.dupe(u8, key),
        };
        return handle;
    }

    pub fn blob(self: *Blob) iface.Blob {
        return .{ .ptr = self, .vtable = &blob_vtable };
    }

    const blob_vtable: iface.Blob.VTable = .{
        .read_at = read_erased,
        .write_at = write_erased,
        .resize = resize_erased,
        .sync = sync_erased,
        .close = close_erased,
    };

    fn read_erased(
        ptr: *anyopaque,
        offset: u64,
        buffer: []u8,
        options: iface.ReadOptions,
    ) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.read_at(offset, buffer, options);
    }

    fn write_erased(
        ptr: *anyopaque,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.write_at(offset, chunks, options);
    }

    fn resize_erased(ptr: *anyopaque, length: u64) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.resize(length);
    }

    fn sync_erased(ptr: *anyopaque) Error!void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        return self.sync();
    }

    fn close_erased(ptr: *anyopaque) void {
        const self: *Blob = @ptrCast(@alignCast(ptr));
        self.close();
    }

    fn raw_offset(self: *const Blob, offset: u64, length: usize) Error!u64 {
        const start = std.math.add(u64, self.data_offset, offset) catch return error.OffsetOverflow;
        _ = std.math.add(u64, start, length) catch return error.OffsetOverflow;
        return start;
    }

    pub fn read_at(self: *Blob, offset: u64, buffer: []u8, options: iface.ReadOptions) Error!void {
        _ = options; // `dont_cache` is a hint; std.Io has no per-read cache control.
        const start = try self.raw_offset(offset, buffer.len);
        if (buffer.len == 0) return;
        // The kernel rejects offsets past the signed file extent (commonware's "read failed");
        // std.Io would report that EINVAL as a bug.
        if (start > std.math.maxInt(i64)) return error.ReadFailed;
        const read = try file_read(self.storage, self.file, buffer, start);
        if (read < buffer.len) return error.BlobInsufficientLength;
        assert(read == buffer.len);
    }

    pub fn write_at(
        self: *Blob,
        offset: u64,
        chunks: []const []const u8,
        options: iface.WriteOptions,
    ) Error!void {
        var total: usize = 0;
        for (chunks) |chunk| total += chunk.len;
        var position = try self.raw_offset(offset, total);
        if (total == 0) return;
        // Like commonware, the write must end within the signed file extent, checked before
        // any I/O.
        if (position + total > std.math.maxInt(i64)) return error.OffsetOverflow;
        {
            defer self.mutated();
            for (chunks) |chunk| {
                try file_write(self.storage, self.file, chunk, position);
                position += chunk.len;
            }
        }
        assert(position == self.data_offset + offset + total);
        if (options.sync) try self.sync();
    }

    pub fn resize(self: *Blob, length: u64) Error!void {
        const raw_length = try self.raw_offset(length, 0);
        defer self.mutated();
        self.file.setLength(self.storage.io, raw_length) catch |err|
            return or_canceled(err, error.BlobResizeFailed);
    }

    /// Fsyncs the blob unless nothing changed since the last successful sync. A mutation
    /// that finishes during the fsync bumps `generation` past the one recorded, so it stays
    /// dirty; one that finished before the load is in the page cache the fsync flushes.
    pub fn sync(self: *Blob) Error!void {
        const current = self.generation.load(.acquire);
        if (self.synced_generation.load(.acquire) == current) {
            _ = self.syncs_skipped.fetchAdd(1, .monotonic);
            return;
        }
        try file_sync(self.storage, self.file);
        var seen = self.synced_generation.load(.monotonic);
        while (seen < current) {
            seen = self.synced_generation.cmpxchgWeak(seen, current, .release, .monotonic) orelse
                break;
        }
        assert(self.synced_generation.load(.monotonic) >= current);
    }

    fn mutated(self: *Blob) void {
        _ = self.generation.fetchAdd(1, .release);
    }

    fn dirty(self: *const Blob) bool {
        return self.synced_generation.load(.acquire) != self.generation.load(.acquire);
    }

    /// Releases the handle without syncing.
    pub fn close(self: *Blob) void {
        const storage = self.storage;
        storage.mutex.lockUncancelable(storage.io);
        if (storage.live.get(self.key)) |live| {
            if (live == self) {
                const removed = storage.live.swapRemove(self.key);
                assert(removed);
                // Unsynced changes stay owed: the next open flushes the file again.
                if (self.dirty()) {
                    if (storage.flushed.fetchSwapRemove(self.key)) |entry| {
                        storage.gpa.free(entry.key);
                    }
                }
            }
        }
        storage.mutex.unlock(storage.io);
        self.file.close(storage.io);
        storage.gpa.free(self.key);
        storage.gpa.destroy(self);
    }
};
