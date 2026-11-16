//! Types for erasure coding (commonware `consensus/src/marshal/coding/types.rs`).
//!
//! `B` is the application block (Digestible; a `Block` for `CodedBlock`), `C` the coding
//! scheme (`coding.assert_scheme`), and `H` the hasher of consensus contexts. All three name
//! one consensus commitment, `Commitment(B, C, H)`.
//!
//! Ownership: a `Shard` owns its inner shard, bytes included (`deinit(gpa)`), where
//! commonware shares `Bytes`. A `CodedBlock` shares its block (a `broadcast.Digested`) and its
//! shards (reference counted) with its clones; a `StoredCodedBlock` shares the block. Release
//! each handle with `deinit(gpa)`. A `CodedBlock` only encodes: the coding variant decodes the
//! block and its config and checks them with `from_decoded`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const codec = @import("codec");
const coding = @import("coding");
const parallel = @import("parallel");
const utils = @import("utils");

const commitment_module = @import("../../commitment.zig");
const Height = @import("../../types.zig").Height;

const CodingConfig = coding.Config;

/// The consensus commitment of block `B` coded with scheme `C`, its context hashed with `H`.
pub fn CommitmentOf(comptime B: type, comptime C: type, comptime H: type) type {
    return commitment_module.Commitment(B.Digest, C.Commitment, H.Digest);
}

/// A broadcastable shard of erasure coded data, with the coding commitment and the index of
/// the shard within it. Decoded with the largest application block size as its config.
pub fn Shard(comptime B: type, comptime C: type, comptime H: type) type {
    comptime coding.assert_scheme(C);
    comptime assert(@hasField(C.Shard, "shard") and @hasField(C.Shard, "proof"));
    return struct {
        const Self = @This();
        pub const Commitment = CommitmentOf(B, C, H);
        /// An upper bound on the encoded size of an application block.
        pub const Cfg = usize;

        commitment_value: Self.Commitment,
        /// The index of this shard within the commitment.
        index: u16,
        /// The shard itself (owned, bytes included).
        inner: C.Shard,

        /// The largest encoded size of a shard whose inner shard encodes to at most `shard`
        /// bytes.
        pub fn max_encode_size(shard: usize) usize {
            return shard + Self.Commitment.fixed_size + 2;
        }

        /// A shard owning `inner`.
        pub fn init(commitment_value: Self.Commitment, index: u16, inner: C.Shard) Self {
            return .{ .commitment_value = commitment_value, .index = index, .inner = inner };
        }

        pub fn commitment(self: *const Self) Self.Commitment {
            return self.commitment_value;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.inner.shard);
            self.inner.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return init(self.commitment_value, self.index, try clone_inner(gpa, &self.inner));
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.commitment_value.eql(b.commitment_value) and a.index == b.index and
                a.inner.eql(&b.inner);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.commitment_value.write(writer);
            codec.write(u16, self.index, writer);
            self.inner.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return Self.Commitment.fixed_size + 2 + self.inner.encode_size();
        }

        /// A coded payload is the block followed by its coding config. The claimed config is
        /// untrusted until consensus confirms the commitment, so the data width it admits may
        /// be the scheme's widest for a payload at this bound.
        pub fn read(gpa: Allocator, reader: *codec.Reader, max_block_size: Cfg) codec.Error!Self {
            const commitment_value = try codec.read(Self.Commitment, gpa, reader);
            const index = try codec.read(u16, gpa, reader);
            const maximum = max_block_size +| CodingConfig.fixed_size;
            var inner = try C.Shard.read(gpa, reader, .{
                .config = commitment_value.config(),
                .maximum_data_bytes = maximum,
            });
            errdefer inner.deinit(gpa);
            inner.shard = try gpa.dupe(u8, inner.shard);
            assert(inner.shard.len <= C.max_shard_size(commitment_value.config(), maximum));
            return init(commitment_value, index, inner);
        }
    };
}

/// A copy of `inner` owning its bytes and proof.
fn clone_inner(gpa: Allocator, inner: anytype) Allocator.Error!@TypeOf(inner.*) {
    var copy = inner.*;
    copy.proof = try inner.proof.clone(gpa);
    errdefer copy.proof.deinit(gpa);
    copy.shard = try gpa.dupe(u8, inner.shard);
    assert(copy.shard.len == inner.shard.len);
    return copy;
}

/// Why a decoded block does not match the commitment it was expected to have (commonware's
/// `Error::Invalid("CodedBlock", ...)` messages).
pub const DecodeError = error{
    /// "config mismatch".
    ConfigMismatch,
    /// "block digest mismatch".
    BlockDigestMismatch,
    /// "Failed to re-commit to block".
    RecommitFailed,
    /// "commitment mismatch".
    CommitmentMismatch,
} || Allocator.Error;

/// An erasure coded block: the application block, the consensus commitment binding its
/// digest, the coding root, the digest of its context, and the coding config, and its shards
/// once computed. Reading the commitment or the block's digest never hashes or codes.
pub fn CodedBlock(comptime B: type, comptime C: type, comptime H: type) type {
    comptime coding.assert_scheme(C);
    return struct {
        const Self = @This();
        pub const Commitment = CommitmentOf(B, C, H);
        pub const Digest = B.Digest;
        pub const Context = B.Context;
        pub const Inner = broadcast.Digested(B);
        pub const ShardType = Shard(B, C, H);
        const Encoding = @typeInfo(@typeInfo(@TypeOf(C.encode)).@"fn".return_type.?)
            .error_union.payload;

        /// The shards of one encoding, shared by the clones of a coded block.
        const Shards = struct {
            gpa: Allocator,
            references: std.atomic.Value(u32),
            encoding: Encoding,
        };

        inner_value: Inner,
        commitment_value: Self.Commitment,
        /// Computed by `encode`, an untrusted decode, or on demand by `shards`.
        shared_shards: ?*Shards = null,

        /// The largest encoded size of a coded block whose application block encodes to at
        /// most `application` bytes.
        pub fn max_encode_size(application: usize) usize {
            return application + CodingConfig.fixed_size;
        }

        /// A coded block of `inner` (owned) under `commitment_value`, which must encode it;
        /// `shards` codes it on demand and panics if the coding root does not match. Panics if
        /// the commitment does not commit to the block's digest.
        pub fn precomputed(block: Inner, commitment_value: Self.Commitment) Self {
            if (!block.digest().eql(commitment_value.block())) {
                std.debug.panic("commitment does not commit to block", .{});
            }
            return .{ .inner_value = block, .commitment_value = commitment_value };
        }

        /// Erasure codes `block` (owned) with `coding_config` into a coded block holding its
        /// shards.
        /// On error the caller keeps `inner`.
        pub fn encode(
            gpa: Allocator,
            block: Inner,
            coding_config: CodingConfig,
            strategy: anytype,
        ) Allocator.Error!Self {
            const encoded = encode_shards(gpa, block.inner(), coding_config, strategy);
            const computed = encoded catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => std.debug.panic("must encode block successfully: {t}", .{err}),
            };
            errdefer release(computed);
            const root = computed.encoding.commitment;
            const commitment_value = try commit(gpa, block, root, coding_config);
            assert(commitment_value.block().eql(block.digest()));
            return .{
                .inner_value = block,
                .commitment_value = commitment_value,
                .shared_shards = computed,
            };
        }

        /// A coded block of a decoded block (owned) and coding config, failing unless its
        /// commitment equals `expected`'s (`.trusted` or `.untrusted`, from
        /// `core.variant.ExpectedCommitment`). A trusted commitment fixes the coding root, so
        /// only an untrusted one codes the block.
        pub fn from_decoded(
            gpa: Allocator,
            block: B,
            coding_config: CodingConfig,
            expected: anytype,
            strategy: anytype,
        ) DecodeError!Self {
            var owned = block;
            const trusted, const expected_commitment = switch (expected) {
                .trusted => |value| .{ true, value },
                .untrusted => |value| .{ false, value },
            };
            // Coding is bounded by the expected config and skipped for a block that cannot
            // match, so both are checked first.
            if (!coding_config.eql(expected_commitment.config())) {
                free_block(gpa, &owned);
                return error.ConfigMismatch;
            }
            var digested = Inner.compute(gpa, owned) catch |err| {
                free_block(gpa, &owned);
                return err;
            };
            errdefer digested.deinit();
            if (!digested.digest().eql(expected_commitment.block())) {
                return error.BlockDigestMismatch;
            }
            var computed: ?*Shards = null;
            errdefer if (computed) |value| release(value);
            if (!trusted) {
                const encoded = encode_shards(gpa, digested.inner(), coding_config, strategy);
                computed = encoded catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.RecommitFailed;
                };
            }
            const root = if (computed) |value|
                value.encoding.commitment
            else
                expected_commitment.root();
            const actual = try commit(gpa, digested, root, coding_config);
            if (!actual.eql(expected_commitment)) return error.CommitmentMismatch;
            return .{
                .inner_value = digested,
                .commitment_value = actual,
                .shared_shards = computed,
            };
        }

        fn encode_shards(
            gpa: Allocator,
            block: *const B,
            coding_config: CodingConfig,
            strategy: anytype,
        ) (C.Error || Allocator.Error)!*Shards {
            const size = codec.encode_size(B, block.*) + CodingConfig.fixed_size;
            const payload = try gpa.alloc(u8, size);
            defer gpa.free(payload);
            var writer = codec.Writer.init(payload);
            codec.write(B, block.*, &writer);
            coding_config.write(&writer);
            assert(writer.written().len == size);
            const shared = try gpa.create(Shards);
            errdefer gpa.destroy(shared);
            const encoding = try C.encode(gpa, coding_config, payload, strategy);
            shared.* = .{ .gpa = gpa, .references = .init(1), .encoding = encoding };
            return shared;
        }

        fn release(shared: *Shards) void {
            if (shared.references.fetchSub(1, .acq_rel) != 1) return;
            const gpa = shared.gpa;
            shared.encoding.deinit(gpa);
            gpa.destroy(shared);
        }

        fn free_block(gpa: Allocator, block: *B) void {
            if (comptime @hasDecl(B, "deinit")) block.deinit(gpa);
        }

        /// The consensus commitment of `block` coded to `root` with `coding_config`.
        fn commit(
            gpa: Allocator,
            block: Inner,
            root: C.Commitment,
            coding_config: CodingConfig,
        ) Allocator.Error!Self.Commitment {
            const context_digest = try hash_context(H, gpa, block.inner().context());
            return .init(block.digest(), root, context_digest, coding_config);
        }

        /// Shares the block and any computed shards.
        pub fn clone(self: *const Self) Self {
            if (self.shared_shards) |shared| _ = shared.references.fetchAdd(1, .monotonic);
            return .{
                .inner_value = self.inner_value.clone(),
                .commitment_value = self.commitment_value,
                .shared_shards = self.shared_shards,
            };
        }

        /// Drops this handle (`gpa` is the allocator the block was created with).
        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(gpa.ptr == self.inner_value.shared.gpa.ptr);
            if (self.shared_shards) |shared| release(shared);
            self.inner_value.deinit();
            self.* = undefined;
        }

        /// Drops a handle with the allocator it was created with (Rust `Drop`).
        pub fn discard(self: Self) void {
            var owned = self;
            owned.deinit(self.inner_value.shared.gpa);
        }

        /// The coding configuration of the data committed.
        pub fn config(self: *const Self) CodingConfig {
            return self.commitment_value.config();
        }

        /// The shards, coding the block now if they were not computed yet. Panics if the block
        /// does not code to the commitment's root: a commitment trusted at construction must
        /// never serve shards under a different root.
        pub fn shards(
            self: *Self,
            gpa: Allocator,
            strategy: anytype,
        ) Allocator.Error![]const C.Shard {
            if (self.shared_shards == null) {
                const encoded = encode_shards(gpa, self.inner(), self.config(), strategy);
                const computed = encoded catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => std.debug.panic("must encode block successfully: {t}", .{err}),
                };
                if (!computed.encoding.commitment.eql(self.commitment_value.root())) {
                    release(computed);
                    std.debug.panic("coded block constructed with trusted commitment does " ++
                        "not match commitment", .{});
                }
                self.shared_shards = computed;
            }
            return self.shared_shards.?.encoding.shards;
        }

        /// A copy of the shard at `index`; null if the shards were not computed yet or the
        /// index is out of range.
        pub fn shard(self: *const Self, gpa: Allocator, index: u16) Allocator.Error!?ShardType {
            const computed = self.shared_shards orelse return null;
            if (index >= computed.encoding.shards.len) return null;
            const inner_shard = try clone_inner(gpa, &computed.encoding.shards[index]);
            return ShardType.init(self.commitment_value, index, inner_shard);
        }

        /// The application block.
        pub fn inner(self: *const Self) *const B {
            return self.inner_value.inner();
        }

        /// A shared handle to the application block and its digest, which the commitment
        /// binds (commonware `inner_shared` and `inner_digested`).
        pub fn inner_digested(self: *const Self) Inner {
            const result = self.inner_value.clone();
            assert(result.digest().eql(self.commitment_value.block()));
            return result;
        }

        pub fn commitment(self: *const Self) Self.Commitment {
            return self.commitment_value;
        }

        pub fn digest(self: *const Self) Digest {
            return self.commitment_value.block();
        }

        pub fn parent(self: *const Self) Digest {
            return self.inner().parent();
        }

        pub fn height(self: *const Self) Height {
            return self.inner().height();
        }

        pub fn context(self: *const Self) Context {
            return self.inner().context();
        }

        /// Equal blocks, commitments, and shards (both computed and equal, or neither).
        pub fn eql(a: *const Self, b: *const Self) bool {
            if (!a.commitment_value.eql(b.commitment_value)) return false;
            if (!block_eql(a.inner(), b.inner())) return false;
            const a_shards = a.shared_shards orelse return b.shared_shards == null;
            const b_shards = b.shared_shards orelse return false;
            if (a_shards == b_shards) return true;
            return shards_eql(a_shards.encoding.shards, b_shards.encoding.shards);
        }

        /// The block, then its coding config.
        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(B, self.inner().*, writer);
            self.config().write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(B, self.inner().*) + CodingConfig.fixed_size;
        }
    };
}

fn block_eql(a: anytype, b: @TypeOf(a)) bool {
    const B = @typeInfo(@TypeOf(a)).pointer.child;
    if (comptime @hasDecl(B, "eql")) {
        // Blocks compare by value or by pointer.
        const Other = @typeInfo(@TypeOf(B.eql)).@"fn".param_types[1].?;
        return if (comptime Other == B) a.eql(b.*) else a.eql(b);
    }
    return codec.order(B, a.*, b.*) == .eq;
}

fn shards_eql(a: anytype, b: @TypeOf(a)) bool {
    if (a.len != b.len) return false;
    for (a, b) |*x, *y| if (!x.eql(y)) return false;
    return true;
}

/// A verified `CodedBlock` with its commitment, for storage only (never sent over the
/// network): reading it back neither codes nor hashes the block.
pub fn StoredCodedBlock(comptime B: type, comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Commitment = CommitmentOf(B, C, H);
        pub const Digest = B.Digest;
        pub const Context = B.Context;
        pub const Cfg = codec.Cfg(B);
        const Coded = CodedBlock(B, C, H);

        inner_value: Coded.Inner,
        commitment_value: Self.Commitment,

        /// Stores `block` (owned), whose commitment must have been computed or validated
        /// against a trusted source. Its shards are dropped.
        pub fn init(block: Coded) Self {
            const owned = block;
            if (owned.shared_shards) |shards| Coded.release(shards);
            const result: Self = .{
                .inner_value = owned.inner_value,
                .commitment_value = owned.commitment_value,
            };
            assert(result.inner_value.digest().eql(result.commitment_value.block()));
            return result;
        }

        /// Stores a shared handle to `block`'s application block.
        pub fn from_shared(block: *const Coded) Self {
            const inner_value = block.inner_digested();
            return .{ .inner_value = inner_value, .commitment_value = block.commitment_value };
        }

        /// The coded block under the trusted commitment (owned; shards coded on demand).
        pub fn into_coded_block(self: Self) Coded {
            return .{ .inner_value = self.inner_value, .commitment_value = self.commitment_value };
        }

        pub fn clone(self: *const Self) Self {
            const inner_value = self.inner_value.clone();
            return .{ .inner_value = inner_value, .commitment_value = self.commitment_value };
        }

        /// Drops this handle (`gpa` is the allocator the block was created with).
        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(gpa.ptr == self.inner_value.shared.gpa.ptr);
            self.inner_value.deinit();
            self.* = undefined;
        }

        pub fn inner(self: *const Self) *const B {
            return self.inner_value.inner();
        }

        pub fn commitment(self: *const Self) Self.Commitment {
            return self.commitment_value;
        }

        pub fn digest(self: *const Self) Digest {
            return self.commitment_value.block();
        }

        pub fn parent(self: *const Self) Digest {
            return self.inner().parent();
        }

        pub fn height(self: *const Self) Height {
            return self.inner().height();
        }

        pub fn context(self: *const Self) Context {
            return self.inner().context();
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.commitment_value.eql(b.commitment_value) and block_eql(a.inner(), b.inner());
        }

        /// The block, then its commitment.
        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(B, self.inner().*, writer);
            self.commitment_value.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(B, self.inner().*) + Self.Commitment.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const block = try codec.read_cfg(B, gpa, reader, cfg);
            const commitment_value = codec.read(Self.Commitment, gpa, reader) catch |err| {
                codec.free(B, gpa, block);
                return err;
            };
            const block_digest = commitment_value.block();
            const digested = Coded.Inner.precomputed(gpa, block, block_digest) catch {
                codec.free(B, gpa, block);
                return error.OutOfMemory;
            };
            return .{ .inner_value = digested, .commitment_value = commitment_value };
        }
    };
}

/// The digest of a consensus context, for a `Commitment`: `H` over its encoding.
pub fn hash_context(comptime H: type, gpa: Allocator, context: anytype) Allocator.Error!H.Digest {
    const T = @TypeOf(context);
    const encoded = try codec.encode(T, gpa, context);
    defer gpa.free(encoded);
    assert(encoded.len == codec.encode_size(T, context));
    return H.hash(&.{encoded});
}

/// The coding configuration for `participants` participants: `f + 1` minimum shards (the
/// `N3f1` fault bound) and the rest extra. Panics with fewer than 4 participants.
pub fn coding_config_for_participants(participants: u16) CodingConfig {
    const max_faults = utils.N3f1.max_faults(participants);
    if (max_faults < 1) {
        std.debug.panic("Need at least 4 participants to maintain fault tolerance", .{});
    }
    const minimum_shards: u16 = @intCast(max_faults + 1);
    assert(minimum_shards < participants);
    return .{ .minimum_shards = minimum_shards, .extra_shards = participants - minimum_shards };
}

/// An upper bound on the encoded size of any shard a committee of 4 to `participants` members
/// codes from a block of at most `application` bytes (commonware `Coding`'s
/// `max_buffer_payload_size`). A larger committee can split a block into more data shards or
/// prove each shard with a deeper tree, so this takes the widest over every size. Panics if
/// `participants` is below 4 or above `maxInt(u16)`.
pub fn max_buffer_payload_size(
    comptime B: type,
    comptime C: type,
    comptime H: type,
    participants: u32,
    application: usize,
) usize {
    if (participants < 4) std.debug.panic("committee must have at least 4 members", .{});
    if (participants > std.math.maxInt(u16)) {
        std.debug.panic("committee must have at most u16::MAX members", .{});
    }
    const block = CodedBlock(B, C, H).max_encode_size(application);
    var widest: usize = 0;
    var size: u16 = 4;
    while (size <= participants) : (size += 1) {
        const config = coding_config_for_participants(size);
        widest = @max(widest, C.max_shard_size(config, block));
        if (size == std.math.maxInt(u16)) break;
    }
    assert(widest > 0);
    return Shard(B, C, H).max_encode_size(widest);
}
