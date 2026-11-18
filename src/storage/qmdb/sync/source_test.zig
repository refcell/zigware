//! Tests of `source.zig`'s journal source: served responses verify against the database root
//! the request names, as the sync engine checks them (commonware's source tests over a real
//! database).

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const value = @import("../value.zig");
const verify = @import("../verify.zig");
const keyless = @import("../keyless/mod.zig");
const source = @import("source.zig");

const Sha256 = cryptography.Sha256;
const U64 = utils.sequence.U64;
const metrics = runtime.telemetry.metrics;
const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Encoding = value.Fixed(U64);
const Db = keyless.Db(Mmr, Encoding, fixed.Journal(keyless.Operation(Mmr, Encoding)), Sha256);
const Source = source.JournalSource(Mmr, Db.Journal);

comptime {
    source.assert_source(Source);
}

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init() !Harness {
        return .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness) !Db {
        const cfg: Db.Cfg = .{
            .merkle = .{
                .journal_partition = "source-merkle",
                .metadata_partition = "source-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &self.cache_ref,
            },
            .log = .{
                .partition = "source-log",
                .items_per_blob = 7,
                .cache_ref = &self.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
        };
        const scope = metrics.Scope.init(&self.registry).child("db");
        return Db.init(gpa, self.storage.interface(), scope, cfg, null);
    }
};

/// Appends `count` values in one committed batch.
fn append(db: *Db, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| try batch.append(U64.init(i * 10 + 1));
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn verified(proof: *const Db.Proof, ops: []const Db.Operation, root: *const Db.Digest) !bool {
    return verify.verify(Mmr, Sha256, Db.Operation, gpa, proof, 3, ops, root);
}

test "sync journal source serves verifiable operations and boundaries" {
    var harness = try Harness.init();
    defer harness.deinit();
    var db = try harness.open();
    defer db.deinit();
    try append(&db, 9);
    const historical_size = db.bounds().end;
    const historical_root = db.root();
    try append(&db, 6);
    var served_source: Source = .{ .journal = &db.journal };
    // An operations request proves against the historical root it names.
    const request: source.Request(Mmr) =
        .{ .operations = .{ .size = historical_size, .start = 3, .max_ops = 4 } };
    var served = try served_source.serve(gpa, request);
    defer served.response.deinit(gpa);
    try testing.expect(served.feedback == null);
    const ops = served.response.operations;
    try testing.expectEqual(@as(usize, 4), ops.operations.len);
    const Op = Db.Operation;
    try testing.expect(try verified(&ops.proof, ops.operations, &historical_root));
    // The current root does not verify the historical response.
    const current_root = db.root();
    try testing.expect(!try verified(&ops.proof, ops.operations, &current_root));
    // A boundary response's pins verify with its one operation.
    const boundary: source.Request(Mmr) =
        .{ .boundary = .{ .size = db.bounds().end, .start = 5 } };
    var pinned = try served_source.serve(gpa, boundary);
    defer pinned.response.deinit(gpa);
    const at = pinned.response.boundary;
    try testing.expect(try verify.verify_with_pinned_nodes(
        Mmr,
        Sha256,
        Op,
        gpa,
        &at.proof,
        5,
        &.{at.op},
        at.pinned_nodes,
        &current_root,
    ));
    // A size beyond the journal is out of bounds.
    const beyond: source.Request(Mmr) =
        .{ .boundary = .{ .size = db.bounds().end + 1, .start = 0 } };
    try testing.expectError(error.RangeOutOfBounds, served_source.serve(gpa, beyond));
}
