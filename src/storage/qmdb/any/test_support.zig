//! Shared fixtures of the `any` tests: unordered fixed databases over `Digest` keys and values
//! with a `OneCap` index, and commonware's test key and value constructors.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const fixed = @import("../../journal/contiguous/fixed.zig");
const index = @import("../../index/mod.zig");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const any = @import("mod.zig");

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
const metrics = runtime.telemetry.metrics;
pub const Encoding = value.Fixed(Digest);
pub const Index = index.unordered.Index(translator.OneCap, u64);

pub fn UnorderedFixed(comptime F: type) type {
    const Journal = fixed.Journal(any.operation.Unordered(F, Digest, Encoding));
    return any.Db(F, any.operation.update.Unordered(Digest, Encoding), Journal, Index, Sha256);
}

/// Commonware's `to_digest(i)`: the hash of `i` as 8 big-endian bytes.
pub fn to_digest(i: u64) Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, i, .big);
    return Sha256.hash(&.{&bytes});
}

/// Commonware's `to_val(i, salt)`.
pub fn to_val(i: u64, salt: u64) Digest {
    var a: [8]u8 = undefined;
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &a, i, .big);
    std.mem.writeInt(u64, &b, salt +% 1, .big);
    return Sha256.hash(&.{ &a, &b });
}

/// A digest whose first byte is `prefix`, so keys collide under `OneCap`.
pub fn colliding_digest(prefix: u8, suffix: u64) Digest {
    var bytes = std.mem.zeroes([32]u8);
    bytes[0] = prefix;
    std.mem.writeInt(u64, bytes[24..32], suffix, .big);
    return .{ .bytes = bytes };
}

/// Storage, page cache, and metrics for opening test databases.
pub const Harness = struct {
    gpa: Allocator,
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    pub fn init(gpa: Allocator) !Harness {
        return .{
            .gpa = gpa,
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    pub fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    pub fn cfg(self: *Harness, comptime D: type) D.Cfg {
        return .{
            .merkle = .{
                .journal_partition = "cf-mj",
                .metadata_partition = "cf-mm",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = .{
                .partition = "cf-log",
                .items_per_blob = 7,
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 1024,
        };
    }

    /// Opens `D`, registering its metrics afresh (as commonware's new child contexts do).
    pub fn open(self: *Harness, comptime D: type, max_size: ?u64) !D {
        self.registry.deinit();
        self.registry = metrics.Registry.init(self.gpa);
        const scope = metrics.Scope.init(&self.registry).child("db");
        return D.init(self.gpa, self.storage.interface(), scope, self.cfg(D), max_size);
    }
};

/// A key and its new value, or null to delete it.
pub const Write = struct { key: Digest, value: ?Digest };

/// Applies `writes` in one batch merkleized with the default policy.
pub fn apply_writes(comptime D: type, db: *D, writes: []const Write) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (writes) |w| try batch.write(w.key, w.value);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}
