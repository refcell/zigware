//! Shared setup of the page-cache benchmarks (commonware `runtime/src/utils/buffer/benches`,
//! bench `buffer_paged`): a `Writer` over a blob of either backend. `deterministic` is the
//! deterministic runner's in-memory storage, isolating buffer and page-cache work; `tokio`
//! (commonware's name for its production runtime) is the production storage over a fresh
//! directory under `.zig-cache/tmp`, exercising real storage I/O.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");

const paged = runtime.buffer.paged;
pub const CacheRef = paged.CacheRef;
pub const Writer = paged.Writer;

pub const page_size: u16 = paged.page_size(runtime.storage.blob_page_size);
pub const write_buffer_size: usize = @as(usize, page_size) * 4;
pub const cache_size: u32 = 10_000;
pub const partition = "bench_partition";

pub const Backend = enum { deterministic, tokio };

/// One backend's storage, holding a writer over blob `name` and its page cache.
pub const Store = struct {
    gpa: Allocator,
    io: Io,
    backend: union(Backend) {
        deterministic: *runtime.deterministic.Runner,
        tokio: runtime.production.storage.Storage,
    },
    directory: [96]u8 = undefined,
    directory_len: usize = 0,

    pub fn init(store: *Store, gpa: Allocator, io: Io, backend: Backend) !void {
        store.* = .{ .gpa = gpa, .io = io, .backend = undefined };
        switch (backend) {
            .deterministic => {
                const runner = try gpa.create(runtime.deterministic.Runner);
                errdefer gpa.destroy(runner);
                runner.* = try .init(gpa, .{});
                store.backend = .{ .deterministic = runner };
            },
            .tokio => {
                var nonce: [8]u8 = undefined;
                io.random(&nonce);
                const name = try std.fmt.bufPrint(&store.directory, ".zig-cache/tmp/{s}-{x}", .{
                    "bench-buffer-paged",
                    std.mem.readInt(u64, &nonce, .little),
                });
                store.directory_len = name.len;
                const root = try Io.Dir.cwd().createDirPathOpen(io, name, .{});
                store.backend = .{ .tokio = try .init(io, gpa, root, .{}) };
            },
        }
        assert(std.meta.activeTag(store.backend) == backend);
    }

    pub fn deinit(store: *Store) void {
        switch (store.backend) {
            .deterministic => |runner| {
                runner.deinit();
                store.gpa.destroy(runner);
            },
            .tokio => |*production| {
                assert(store.directory_len > 0);
                production.deinit();
                const name = store.directory[0..store.directory_len];
                Io.Dir.cwd().deleteTree(store.io, name) catch |err|
                    std.log.warn("bench: removing {s}: {t}", .{ name, err });
            },
        }
        store.* = undefined;
    }

    pub fn storage(store: *Store) runtime.storage.Storage {
        return switch (store.backend) {
            .deterministic => |runner| runner.storage(),
            .tokio => |*production| production.storage(),
        };
    }

    /// Open a writer over blob `name` (commonware `create_append`).
    pub fn create_append(store: *Store, name: []const u8, cache_ref: *CacheRef) !Writer {
        assert(name.len > 0);
        const opened = try store.storage().open(partition, name);
        errdefer opened.blob.close();
        return Writer.init(store.gpa, opened.blob, opened.len, write_buffer_size, cache_ref);
    }

    /// Close the writer and remove its blob (commonware `destroy_append`).
    pub fn destroy_append(store: *Store, writer: *Writer, name: []const u8) !void {
        assert(name.len > 0);
        writer.deinit();
        try store.storage().remove(partition, name);
    }
};
