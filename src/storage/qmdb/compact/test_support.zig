//! Compact db types and a storage harness for the compact tests, with commonware's
//! conformance configuration (`compact_witness_config`: 64 witnesses per section).

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const value = @import("../value.zig");
const compact = @import("mod.zig");

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const U64 = utils.sequence.U64;
pub const Bytes = []const u8;

pub fn KeylessFixed(comptime F: type) type {
    return compact.Keyless(F, value.Fixed(U64), Sha256);
}

pub fn KeylessVariable(comptime F: type) type {
    return compact.Keyless(F, value.Variable(Bytes), Sha256);
}

pub fn ImmutableFixed(comptime F: type) type {
    return compact.Immutable(F, Digest, value.Fixed(Digest), Sha256);
}

pub fn ImmutableVariable(comptime F: type) type {
    return compact.Immutable(F, Digest, value.Variable(Digest), Sha256);
}

/// commonware's codec configuration of `Db`'s commits.
pub fn codec_config(comptime Db: type) @FieldType(Db.Cfg, "codec_config") {
    const C = @FieldType(Db.Cfg, "codec_config");
    if (C == void) return {};
    if (comptime @hasField(C, "range")) return .{ .range = .inclusive(0, 10000) };
    return .{ {}, {} };
}

/// A keyless value made from `x`: `U64(x)`, or `x`'s 8 big-endian bytes (owned).
pub fn make_value(comptime Db: type, gpa: Allocator, x: u64) !Db.Value {
    if (Db.Value == U64) return U64.init(x);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, x, .big);
    return gpa.dupe(u8, &bytes);
}

/// Storage and a page cache for opening compact dbs.
pub const Harness = struct {
    gpa: Allocator,
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    /// Witnesses per journal section (commonware's conformance uses 64).
    items_per_section: u64 = 64,

    pub fn init(gpa: Allocator) !Harness {
        return .{
            .gpa = gpa,
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
        };
    }

    pub fn deinit(self: *Harness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    pub fn cfg(self: *Harness, comptime Db: type) Db.Cfg {
        return .{
            .witness = .{
                .partition = "cf-compact-witness",
                .items_per_section = self.items_per_section,
                .codec_config = {},
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .codec_config = codec_config(Db),
        };
    }

    pub fn open(self: *Harness, comptime Db: type, max_size: ?u64) !Db {
        return Db.init(self.gpa, self.storage.interface(), self.cfg(Db), max_size);
    }
};
