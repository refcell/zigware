//! Marshal's finalized stores (commonware `marshal/store.rs`).
//!
//! `Certificates(A, S, B, C)` keeps finalizations by height and block digest, and
//! `Blocks(A, B)` keeps finalized blocks by height and digest, each over an archive `A` from
//! `storage.archive` (immutable or prunable). The archives key by the digest's bytes; an
//! immutable archive ignores `prune`, as in commonware.
//!
//! Each adapter borrows its archive (`archive: *A`); the caller opens and closes it.

const std = @import("std");
const assert = std.debug.assert;
const storage = @import("storage");
const types = @import("../types.zig");
const simplex_types = @import("../simplex/types.zig");

const Height = types.Height;

/// A finalized item by height or by digest (commonware `archive::Identifier`).
pub fn Identifier(comptime D: type) type {
    return union(enum) {
        index: Height,
        key: D,
    };
}

/// Archive identifiers point into the key they look up, so the caller keeps `id` alive.
fn archive_identifier(comptime A: type, comptime D: type, id: *const Identifier(D)) A.Identifier {
    return switch (id.*) {
        .index => |height| .{ .index = height.get() },
        .key => |*digest| .{ .key = &digest.bytes },
    };
}

/// A started sync's durability (commonware's sync `Handle`): one reference to a
/// `runtime.storage.Completion`, which the caller waits on or releases.
pub const Durable = @import("runtime").storage.Completion;

fn height_range(range: storage.rmap.Range) struct { Height, Height } {
    assert(range.start <= range.end);
    return .{ .new(range.start), .new(range.end) };
}

/// Finalizations of commitments `C` under scheme `S`, by height and block digest `B`.
pub fn Certificates(comptime A: type, comptime S: type, comptime B: type, comptime C: type) type {
    return struct {
        const Self = @This();
        pub const Scheme = S;
        pub const BlockDigest = B;
        pub const Commitment = C;
        pub const Finalization = simplex_types.Finalization(S, C);
        pub const Error = A.Error;

        archive: *A,

        /// Stores the finalization of the block `digest` at `height` (a no-op when the
        /// height is already stored).
        pub fn put(
            self: Self,
            height: Height,
            digest: B,
            finalization: *const Finalization,
        ) Error!void {
            try self.archive.put(height.get(), digest.bytes, finalization.*);
        }

        pub fn sync(self: Self) Error!void {
            try self.archive.sync();
        }

        /// Starts a sync of every write so far; the handle says when it is durable.
        pub fn start_sync(self: Self) Error!Durable {
            return self.archive.start_sync();
        }

        /// The finalization at a height or for a block digest; the caller owns it.
        pub fn get(self: Self, id: Identifier(B)) Error!?Finalization {
            return self.archive.get(archive_identifier(A, B, &id));
        }

        pub fn has(self: Self, height: Height) Error!bool {
            return self.archive.has(.{ .index = height.get() });
        }

        /// Prunes heights below `min` (an immutable archive keeps everything).
        pub fn prune(self: Self, min: Height) Error!void {
            if (comptime @hasDecl(A, "prune")) try self.archive.prune(min.get());
        }

        pub fn last_index(self: Self) ?Height {
            const last = self.archive.last_index() orelse return null;
            return .new(last);
        }

        /// The stored height ranges at or above `from`, inclusive, in order.
        pub fn ranges_from(self: Self, from: Height) []const storage.rmap.Range {
            return self.archive.ranges_from(from.get());
        }
    };
}

/// Finalized blocks of type `Block` (codec values with `height()`), by height and digest.
pub fn Blocks(comptime A: type, comptime Block: type) type {
    return struct {
        const Self = @This();
        pub const Digest = Block.Digest;
        pub const Error = A.Error;

        archive: *A,

        /// Stores `block` under its height and `digest` (a no-op when the height is already
        /// stored).
        pub fn put(self: Self, digest: Digest, block: *const Block) Error!void {
            try self.archive.put(block.height().get(), digest.bytes, block.*);
        }

        pub fn sync(self: Self) Error!void {
            try self.archive.sync();
        }

        /// Starts a sync of every write so far; the handle says when it is durable.
        pub fn start_sync(self: Self) Error!Durable {
            return self.archive.start_sync();
        }

        /// The block at a height or with a digest; the caller owns it.
        pub fn get(self: Self, id: Identifier(Digest)) Error!?Block {
            return self.archive.get(archive_identifier(A, Digest, &id));
        }

        /// Prunes heights below `min` (an immutable archive keeps everything).
        pub fn prune(self: Self, min: Height) Error!void {
            if (comptime @hasDecl(A, "prune")) try self.archive.prune(min.get());
        }

        /// Up to `out.len` missing heights from `start`, in order.
        pub fn missing_items(self: Self, start: Height, out: []u64) []u64 {
            return self.archive.missing_items(start.get(), out);
        }

        /// The end of the stored range containing `value` and the start of the next one.
        pub fn next_gap(self: Self, value: Height) struct { ?Height, ?Height } {
            const gap = self.archive.next_gap(value.get());
            const current_end: ?Height = if (gap.current_end) |end| .new(end) else null;
            const next_start: ?Height = if (gap.next_start) |start| .new(start) else null;
            return .{ current_end, next_start };
        }

        pub fn last_index(self: Self) ?Height {
            const last = self.archive.last_index() orelse return null;
            return .new(last);
        }
    };
}

const testing = std.testing;
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const mocks_block = @import("mocks/block.zig");

const Sha256 = cryptography.Sha256;
const TestBlock = mocks_block.EmptyBlock(Sha256);
const gpa = testing.allocator;

const ArchiveHarness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: runtime.telemetry.metrics.Registry,

    fn init() !ArchiveHarness {
        return .{
            .storage = runtime.buffer.mocks.Storage.init(gpa),
            .cache_ref = try runtime.buffer.paged.CacheRef.init(gpa, 1024, 10),
            .registry = runtime.telemetry.metrics.Registry.init(gpa),
        };
    }

    fn deinit(self: *ArchiveHarness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn scope(self: *ArchiveHarness) runtime.telemetry.metrics.Scope {
        return runtime.telemetry.metrics.Scope.init(&self.registry);
    }
};

fn expect_blocks(blocks: anytype) !void {
    var parent = Sha256.Digest.empty;
    var stored: [3]TestBlock = undefined;
    for ([_]u64{ 1, 2, 5 }, &stored) |height, *block| {
        block.* = TestBlock.init(parent, .new(height), height * 10);
        try blocks.put(block.digest(), block);
        parent = block.digest();
    }
    try blocks.sync();
    try testing.expectEqual(Height.new(5), blocks.last_index().?);
    const by_height = (try blocks.get(.{ .index = .new(2) })).?;
    try testing.expect(by_height.eql(stored[1]));
    const by_digest = (try blocks.get(.{ .key = stored[2].digest() })).?;
    try testing.expect(by_digest.eql(stored[2]));
    try testing.expectEqual(null, try blocks.get(.{ .index = .new(3) }));
    var missing_buffer: [4]u64 = undefined;
    const missing = blocks.missing_items(.zero(), &missing_buffer);
    try testing.expectEqualSlices(u64, &.{ 0, 3, 4 }, missing);
    const current_end, const next_start = blocks.next_gap(.new(1));
    try testing.expectEqual(Height.new(2), current_end.?);
    try testing.expectEqual(Height.new(5), next_start.?);
}

test "blocks over an immutable archive" {
    var harness = try ArchiveHarness.init();
    defer harness.deinit();
    const Archive = storage.archive.immutable.Archive([32]u8, TestBlock);
    var archive = try Archive.init(gpa, harness.storage.interface(), harness.scope(), .{
        .metadata_partition = "blocks-metadata",
        .freezer_table_partition = "blocks-freezer-table",
        .freezer_table_initial_size = 64,
        .freezer_table_resize_frequency = 2,
        .freezer_table_resize_chunk_size = 32,
        .freezer_key_partition = "blocks-freezer-key",
        .freezer_key_cache_ref = &harness.cache_ref,
        .freezer_value_partition = "blocks-freezer-value",
        .freezer_value_target_size = 1024 * 1024,
        .ordinal_partition = "blocks-ordinal",
        .items_per_section = 4,
        .freezer_key_write_buffer = 1024,
        .freezer_value_write_buffer = 1024,
        .ordinal_write_buffer = 1024,
        .replay_buffer = 1024,
        .codec_config = {},
    });
    defer archive.deinit();
    const blocks: Blocks(Archive, TestBlock) = .{ .archive = &archive };
    try expect_blocks(blocks);
    // An immutable archive ignores pruning.
    try blocks.prune(.new(5));
    try testing.expect((try blocks.get(.{ .index = .new(1) })) != null);
}

test "blocks over a prunable archive" {
    var harness = try ArchiveHarness.init();
    defer harness.deinit();
    const T = storage.translator.EightCap;
    const Archive = storage.archive.prunable.Archive(T, [32]u8, TestBlock);
    var archive = try Archive.init(gpa, harness.storage.interface(), harness.scope(), .{
        .translator = .{},
        .metadata_partition = "blocks-metadata",
        .key_partition = "blocks-key",
        .key_cache_ref = &harness.cache_ref,
        .value_partition = "blocks-value",
        .codec_config = {},
        .items_per_section = 2,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .replay_buffer = 1024,
    });
    defer archive.deinit();
    const blocks: Blocks(Archive, TestBlock) = .{ .archive = &archive };
    try expect_blocks(blocks);
    // Pruning drops whole sections below the minimum.
    try blocks.prune(.new(4));
    try testing.expectEqual(null, try blocks.get(.{ .index = .new(1) }));
    try testing.expect((try blocks.get(.{ .index = .new(5) })) != null);
}

test "certificates over a prunable archive" {
    var harness = try ArchiveHarness.init();
    defer harness.deinit();
    const D = Sha256.Digest;
    const simplex = @import("../simplex/root.zig");
    const S = simplex.scheme.ed25519.Scheme(D);
    var rng = @import("utils").rng.TestRng.init(0);
    var fixture = try simplex.scheme.ed25519.fixture(D, gpa, &rng, "store", 4);
    defer fixture.deinit(gpa);
    const Finalize = simplex_types.Finalize(S, D);
    const Finalization = simplex_types.Finalization(S, D);
    const proposal = simplex_types.Proposal(D).init(.new(.zero(), .new(7)), .new(6), D.fill(9));
    var votes: [3]Finalize = undefined;
    for (&votes, fixture.schemes[0..3]) |*vote, *scheme| {
        vote.* = (try Finalize.sign(gpa, scheme, proposal)).?;
    }
    const strategy = @import("parallel").sequential;
    var finalization = try Finalization.from_votes(gpa, &fixture.schemes[0], &votes, strategy);
    defer finalization.certificate.deinit(gpa);

    const T = storage.translator.EightCap;
    const Archive = storage.archive.prunable.Archive(T, [32]u8, Finalization);
    var archive = try Archive.init(gpa, harness.storage.interface(), harness.scope(), .{
        .translator = .{},
        .metadata_partition = "certificates-metadata",
        .key_partition = "certificates-key",
        .key_cache_ref = &harness.cache_ref,
        .value_partition = "certificates-value",
        .codec_config = fixture.verifier.certificate_codec_config(),
        .items_per_section = 2,
        .key_write_buffer = 1024,
        .value_write_buffer = 1024,
        .replay_buffer = 1024,
    });
    defer archive.deinit();
    const certificates: Certificates(Archive, S, D, D) = .{ .archive = &archive };
    const block_digest = D.fill(3);
    try certificates.put(.new(7), block_digest, &finalization);
    try certificates.sync();
    try testing.expect(try certificates.has(.new(7)));
    try testing.expect(!try certificates.has(.new(6)));
    var by_digest = (try certificates.get(.{ .key = block_digest })).?;
    defer by_digest.certificate.deinit(gpa);
    try testing.expect(by_digest.eql(finalization));
    try testing.expectEqual(Height.new(7), certificates.last_index().?);
    const ranges = certificates.ranges_from(.zero());
    try testing.expectEqual(1, ranges.len);
    try testing.expectEqual(7, ranges[0].start);
    try certificates.prune(.new(8));
    try testing.expect(!try certificates.has(.new(7)));
}
