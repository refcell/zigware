//! Shared fixtures of the immutable tests: fixed and variable databases over `Digest` keys and
//! values with a `TwoCap` translator (commonware's test and conformance types).

const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const fixed = @import("../../journal/contiguous/fixed.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const test_support = @import("../test_support.zig");
const translator = @import("../../translator.zig");
const value = @import("../value.zig");
const any_support = @import("../any/test_support.zig");
const immutable = @import("mod.zig");

pub const Sha256 = cryptography.Sha256;
pub const Digest = Sha256.Digest;
pub const Encoding = value.Fixed(Digest);
const metrics = runtime.telemetry.metrics;

pub const to_digest = any_support.to_digest;
pub const to_val = any_support.to_val;
pub const colliding_digest = any_support.colliding_digest;

pub fn Fixed(comptime F: type) type {
    const Journal = fixed.Journal(immutable.Operation(F, Digest, Encoding));
    return immutable.Db(F, Digest, Encoding, Journal, Sha256, translator.TwoCap);
}

/// The variable-encoded database of commonware's conformance types (`Digest` values).
pub fn Variable(comptime F: type) type {
    const E = value.Variable(Digest);
    const Journal = variable.Journal(immutable.Operation(F, Digest, E));
    return immutable.Db(F, Digest, E, Journal, Sha256, translator.TwoCap);
}

/// Commonware's `Sha256::fill(byte)`: a digest of 32 copies of `byte`.
pub fn fill(byte: u8) Digest {
    return .{ .bytes = @splat(byte) };
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
            .log = test_support.log_config(@FieldType(D.Cfg, "log"), &self.cache_ref),
            .translator = .{},
        };
    }

    /// Opens the fixed database, registering its metrics afresh.
    pub fn open(self: *Harness, comptime F: type, max_size: ?u64) !Fixed(F) {
        return self.open_db(Fixed(F), max_size);
    }

    /// Opens `D`, registering its metrics afresh.
    pub fn open_db(self: *Harness, comptime D: type, max_size: ?u64) !D {
        self.registry.deinit();
        self.registry = metrics.Registry.init(self.gpa);
        const scope = metrics.Scope.init(&self.registry).child("db");
        return D.init(self.gpa, self.storage.interface(), scope, self.cfg(D), max_size);
    }
};
