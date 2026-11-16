//! Shared fixtures of the `current` tests: unordered fixed databases over `Digest` keys and
//! values (commonware's conformance types), opened on `any`'s test harness.

const std = @import("std");
const assert = std.debug.assert;
const fixed = @import("../../journal/contiguous/fixed.zig");
const any = @import("../any/mod.zig");
const any_support = @import("../any/test_support.zig");
const current = @import("mod.zig");

pub const Sha256 = any_support.Sha256;
pub const Digest = any_support.Digest;
pub const Write = any_support.Write;
pub const to_digest = any_support.to_digest;
pub const to_val = any_support.to_val;
pub const colliding_digest = any_support.colliding_digest;
const metrics = @import("runtime").telemetry.metrics;

/// The unordered fixed `current` database of commonware's conformance types (32-byte chunks).
pub fn UnorderedFixed(comptime F: type) type {
    return UnorderedFixedChunks(F, 32);
}

pub fn UnorderedFixedChunks(comptime F: type, comptime N: usize) type {
    const E = any_support.Encoding;
    const Journal = fixed.Journal(any.operation.Unordered(F, Digest, E));
    const U = any.operation.update.Unordered(Digest, E);
    return current.Db(F, U, Journal, any_support.Index, Sha256, N);
}

/// The ordered fixed `current` database of commonware's conformance types.
pub fn OrderedFixed(comptime F: type) type {
    const E = any_support.Encoding;
    const Journal = fixed.Journal(any.operation.Ordered(F, Digest, E));
    const U = any.operation.update.Ordered(Digest, E);
    return current.Db(F, U, Journal, any_support.OrderedIndex, Sha256, 32);
}

/// `any`'s storage harness, opening `current` databases.
pub const Harness = struct {
    inner: any_support.Harness,

    pub fn init(gpa: std.mem.Allocator) !Harness {
        return .{ .inner = try any_support.Harness.init(gpa) };
    }

    pub fn deinit(self: *Harness) void {
        self.inner.deinit();
    }

    pub fn cfg(self: *Harness, comptime D: type) D.Cfg {
        const base = self.inner.cfg(D.Any);
        return .{
            .merkle = base.merkle,
            .log = base.log,
            .grafted_metadata_partition = "cf-graft",
            .translator = base.translator,
            .init_cache = base.init_cache,
        };
    }

    /// Opens `D`, registering its metrics afresh.
    pub fn open(self: *Harness, comptime D: type, max_size: ?u64) !D {
        const gpa = self.inner.gpa;
        self.inner.registry.deinit();
        self.inner.registry = metrics.Registry.init(gpa);
        const scope = metrics.Scope.init(&self.inner.registry).child("db");
        const storage = self.inner.storage.interface();
        return D.init(gpa, storage, scope, self.cfg(D), max_size);
    }
};

/// Applies `writes` in one batch merkleized with the default policy, checking that the
/// batch's canonical root becomes the database's.
pub fn apply_writes(comptime D: type, db: *D, writes: []const Write) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (writes) |w| try batch.write(w.key, w.value);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    assert(db.root().eql(merkleized.root()));
}
