//! A Reed-Solomon coder that emits shards provable against a Binary Merkle Tree (commonware's
//! `coding::reed_solomon`).
//!
//! Encoding prefixes the data with its 4-byte big-endian length, splits it into `k` original
//! shards of the canonical even width (zero padded), and computes `m` recovery shards. All
//! `n = k + m` shards are hashed into a `storage.bmt` tree, whose root is the commitment, and
//! each shard is sent as a `Chunk` with its index and inclusion proof.
//!
//! Decoding feeds exactly `k` checked shards to the Reed-Solomon decoder, which reconstructs
//! the full codeword (with every original present, the recovery shards are re-encoded and
//! provided ones compared). A new tree over the whole codeword must reproduce the commitment,
//! and the original shards must be the canonical layout of the data. So a commitment that
//! decodes at all is the canonical encoding of its data, and every set of at least `k` shards
//! checked against it decodes to the same data.
//!
//! `k + m` must fit in a `u16` (`TooManyTotalShards`), and the backend must support the counts
//! (`UnsupportedShardCount`). Encoding rejects payloads longer than `u32::MAX`, canonical widths
//! beyond `u32::MAX`, and codewords beyond `MAX_ALLOCATION_BYTES` (`InvalidDataLength`). Callers
//! that accept configs or shards from untrusted sources must bound the shard counts and the
//! payload length: decoding even `k` shards rebuilds and hashes the whole codeword.
//!
//! Errors carry no payload (commonware's `DuplicateIndex(u16)` is `error.DuplicateIndex`), and
//! Reed-Solomon errors join the set directly (`error.InvalidShardSize`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const storage = @import("storage");
const utils = @import("utils");
const Config = @import("../root.zig").Config;
pub const striped = @import("striped.zig");

const bmt = storage.bmt;
const rs = cryptography.reed_solomon;
const u32_max: usize = std.math.maxInt(u32);
const prefix_bytes: usize = 4;

pub const Error = rs.InitError || error{
    Inconsistent,
    InvalidProof,
    NotEnoughChunks,
    DuplicateIndex,
    InvalidDataLength,
    InvalidIndex,
    TooManyTotalShards,
    CommitmentMismatch,
};

/// How a shard decodes: its coding config and the maximum number of data bytes. A chunk is
/// accepted only if its shard is no wider than encoding that many bytes would produce.
pub const ShardCfg = struct {
    config: Config,
    maximum_data_bytes: usize,
};

/// One shard of an encoded object, with its index and inclusion proof.
pub fn Chunk(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Proof = bmt.Proof(D);
        pub const Cfg = ShardCfg;

        /// The shard bytes; borrowed (from the encoding, or from decoded input).
        shard: []const u8,
        /// The shard's position in the codeword.
        index: u16,
        /// Inclusion proof of the shard digest at `index`; owned.
        proof: Proof,

        /// The largest encoding of a chunk with at most `shard` bytes and `siblings` siblings.
        pub fn max_encode_size(shard: usize, siblings: usize) usize {
            return codec.util.max_items_size(shard, 1) + 2 + Proof.max_encode_size(siblings);
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(codec.Bytes, .init(self.shard), writer);
            codec.write(u16, self.index, writer);
            self.proof.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(codec.Bytes, .init(self.shard)) + 2 +
                self.proof.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const maximum = @min(cfg.maximum_data_bytes, u32_max);
            const width = canonical_shard_len(maximum, cfg.config.minimum_shards);
            const shard = try codec.read_cfg(codec.Bytes, gpa, reader, .to_inclusive(width));
            const index = try codec.read(u16, gpa, reader);
            const proof = try codec.read_cfg(Proof, gpa, reader, 1);
            assert(shard.data.len <= width);
            return .{ .shard = shard.data, .index = index, .proof = proof };
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return std.mem.eql(u8, a.shard, b.shard) and a.index == b.index and
                a.proof.eql(&b.proof);
        }
    };
}

/// A shard checked against a commitment: the shard, its index, the commitment it was checked
/// against (decode rejects any other), and the digest computed while checking, which decode
/// trusts instead of hashing again. The type is bound to the hasher that computed the digest.
pub fn CheckedChunk(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Hasher = H;

        root: H.Digest,
        /// Borrowed from the checked chunk.
        shard: []const u8,
        index: u16,
        digest: H.Digest,

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.root.eql(b.root) and std.mem.eql(u8, a.shard, b.shard) and
                a.index == b.index and a.digest.eql(b.digest);
        }
    };
}

/// The commitment and the `n` chunks of one encoding. The chunks' shards point into
/// `codeword`, the `k` originals followed by the `m` recoveries.
pub fn Encoding(comptime D: type) type {
    return struct {
        const Self = @This();

        commitment: D,
        shards: []Chunk(D),
        codeword: []u8,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.shards) |*shard| shard.deinit(gpa);
            gpa.free(self.shards);
            gpa.free(self.codeword);
            self.* = undefined;
        }
    };
}

/// The total shard count, if it fits the `u16` indices.
pub fn total_shards(config: Config) Error!u16 {
    const total = config.total_shards();
    assert(total > config.minimum_shards);
    return std.math.cast(u16, total) orelse error.TooManyTotalShards;
}

/// The canonical shard width: the prefixed payload split across `k` shards, rounded up to an
/// even number of bytes. Decode recomputes it to reject non-canonical widths.
pub fn canonical_shard_len(data_len: usize, k: usize) usize {
    assert(k > 0);
    const prefixed = data_len +| prefix_bytes;
    const shard_len = prefixed / k + @intFromBool(prefixed % k != 0);
    return if (shard_len % 2 == 0) shard_len else shard_len +| 1;
}

/// Whether `n` shards of `shard_len` bytes fit in one allocation.
pub fn codeword_fits(n: usize, shard_len: usize) bool {
    const bytes, const overflow = @mulWithOverflow(n, shard_len);
    return overflow == 0 and bytes <= utils.MAX_ALLOCATION_BYTES;
}

/// Rejects shard counts the Reed-Solomon backend does not support.
pub fn validate_counts(k: usize, m: usize) Error!void {
    if (!rs.Encoder.supports(k, m)) return error.UnsupportedShardCount;
}

/// The shard width for `data_len` bytes over `k` originals and `m` recoveries, checked before
/// anything is allocated: the payload and the width must fit the `u32` length prefixes, and
/// the codeword must fit one allocation.
pub fn shard_layout(data_len: usize, k: usize, m: usize) Error!usize {
    if (data_len > u32_max) return error.InvalidDataLength;
    try validate_counts(k, m);
    const shard_len = canonical_shard_len(data_len, k);
    if (shard_len > u32_max or !codeword_fits(k + m, shard_len)) return error.InvalidDataLength;
    assert(shard_len >= 2 and shard_len % 2 == 0);
    return shard_len;
}

/// Reads the 4-byte big-endian length prefix, which may span shards, and checks that the
/// length fits in the payload region after the prefix.
pub fn read_data_len(shards: []const []const u8) Error!usize {
    var total_len: usize = 0;
    for (shards) |shard| total_len += shard.len;
    if (total_len < prefix_bytes) return error.Inconsistent;
    var prefix: [prefix_bytes]u8 = undefined;
    var prefix_len: usize = 0;
    for (shards) |shard| {
        if (prefix_len == prefix_bytes) break;
        const read = @min(prefix_bytes - prefix_len, shard.len);
        @memcpy(prefix[prefix_len..][0..read], shard[0..read]);
        prefix_len += read;
    }
    assert(prefix_len == prefix_bytes);
    const data_len: usize = std.mem.readInt(u32, &prefix, .big);
    if (data_len > total_len - prefix_bytes) return error.Inconsistent;
    return data_len;
}

/// Checks the length prefix, the zero padding, and the canonical width of the original
/// shards, and returns the payload length.
pub fn validate_data_layout(shards: []const []const u8, expected_shard_len: usize) Error!usize {
    const data_len = try read_data_len(shards);
    var data_end = prefix_bytes + data_len;
    for (shards) |shard| {
        if (data_end >= shard.len) {
            data_end -= shard.len;
            continue;
        }
        for (shard[data_end..]) |byte| if (byte != 0) return error.Inconsistent;
        data_end = 0;
    }
    if (canonical_shard_len(data_len, shards.len) != expected_shard_len) {
        return error.Inconsistent;
    }
    return data_len;
}

/// Validates the first `k` original shards and copies their payload into an owned buffer.
pub fn extract_data(
    gpa: Allocator,
    shards: []const []const u8,
    k: usize,
    expected_shard_len: usize,
) Error![]u8 {
    if (shards.len < k) return error.NotEnoughChunks;
    const originals = shards[0..k];
    const data_len = try validate_data_layout(originals, expected_shard_len);
    const data = try gpa.alloc(u8, data_len);
    var prefix_left: usize = prefix_bytes;
    var written: usize = 0;
    for (originals) |shard| {
        // The prefix may straddle shards; skip bytes until the first payload byte.
        if (prefix_left >= shard.len) {
            prefix_left -= shard.len;
            continue;
        }
        const payload = shard[prefix_left..];
        const copy_len = @min(data_len - written, payload.len);
        @memcpy(data[written..][0..copy_len], payload[0..copy_len]);
        written += copy_len;
        prefix_left = 0;
    }
    assert(written == data_len);
    return data;
}

/// Builds the tree over `digests`, leaf `i` being shard `i`'s digest.
pub fn build_tree(comptime H: type, gpa: Allocator, digests: []const H.Digest) !bmt.Tree(H.Digest) {
    var builder = try bmt.Builder(H).init(gpa, digests.len);
    defer builder.deinit(gpa);
    for (digests) |*digest| _ = try builder.add(gpa, digest);
    assert(builder.leaves.items.len == digests.len);
    return builder.build(gpa);
}

/// Validates the requested index, the embedded index, the proof's leaf count, and the shard
/// width (positive and even, which decode relies on) before anything is hashed.
pub fn check_metadata(comptime D: type, total: u16, index: u16, shard: *const Chunk(D)) Error!void {
    if (index >= total) return error.InvalidIndex;
    const width = shard.shard.len;
    if (width == 0 or width % 2 != 0) return error.InvalidShardSize;
    if (shard.proof.leaf_count != total) return error.InvalidProof;
    if (shard.index != index) return error.InvalidIndex;
}

/// Authenticates a shard at its requested position, given its digest, and binds the digest
/// to the commitment.
pub fn check_chunk(
    comptime H: type,
    total: u16,
    commitment: *const H.Digest,
    index: u16,
    shard: *const Chunk(H.Digest),
    digest: H.Digest,
) Error!CheckedChunk(H) {
    try check_metadata(H.Digest, total, index, shard);
    shard.proof.verify_element_inclusion(H, index, &digest, commitment, null) catch
        return error.InvalidProof;
    return .{ .root = commitment.*, .shard = shard.shard, .index = index, .digest = digest };
}

/// Encodes `data` into `total` chunks, `min` of which decode it, and commits to them.
pub fn encode(
    comptime H: type,
    gpa: Allocator,
    total: u16,
    min: u16,
    data: []const u8,
    strategy: anytype,
) Error!Encoding(H.Digest) {
    assert(total > min);
    assert(min > 0);
    const n: usize = total;
    const k: usize = min;
    const shard_len = try shard_layout(data.len, k, n - k);

    const codeword = try gpa.alloc(u8, n * shard_len);
    errdefer gpa.free(codeword);
    @memset(codeword, 0);
    std.mem.writeInt(u32, codeword[0..prefix_bytes], @intCast(data.len), .big);
    @memcpy(codeword[prefix_bytes..][0..data.len], data);

    const shards = try gpa.alloc([]const u8, n);
    defer gpa.free(shards);
    for (shards, 0..) |*shard, i| shard.* = codeword[i * shard_len ..][0..shard_len];
    try striped.encode_recovery(strategy, .{
        .gpa = gpa,
        .k = k,
        .m = n - k,
        .shard_len = shard_len,
        .originals = shards[0..k],
        .recovery = codeword[k * shard_len ..],
    });

    const digests = try gpa.alloc(H.Digest, n);
    defer gpa.free(digests);
    H.hash_many(shards, digests, strategy);
    var tree = try build_tree(H, gpa, digests);
    defer tree.deinit(gpa);
    const chunks = try prove_all(H.Digest, gpa, &tree, shards);
    return .{ .commitment = tree.root(), .shards = chunks, .codeword = codeword };
}

fn prove_all(
    comptime D: type,
    gpa: Allocator,
    tree: *const bmt.Tree(D),
    shards: []const []const u8,
) Allocator.Error![]Chunk(D) {
    const chunks = try gpa.alloc(Chunk(D), shards.len);
    var built: usize = 0;
    errdefer {
        for (chunks[0..built]) |*chunk| chunk.deinit(gpa);
        gpa.free(chunks);
    }
    for (chunks, shards, 0..) |*chunk, shard, i| {
        const position: u32 = @intCast(i);
        // Proof: every position is below the leaf count, so only allocation can fail.
        const proof = tree.proof(gpa, position, null) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable,
        };
        chunk.* = .{ .shard = shard, .index = @intCast(i), .proof = proof };
        built += 1;
    }
    assert(built == shards.len);
    return chunks;
}

/// Decodes the data from checked chunks, assumed checked against `root` with `check`.
pub fn decode(
    comptime H: type,
    gpa: Allocator,
    total: u16,
    min: u16,
    root: *const H.Digest,
    chunks: []const CheckedChunk(H),
    strategy: anytype,
) Error![]u8 {
    assert(total > min);
    assert(min > 0);
    const n: usize = total;
    const k: usize = min;
    try validate_counts(k, n - k);
    if (chunks.len == 0) return error.NotEnoughChunks;
    const shard_len = chunks[0].shard.len;
    if (!codeword_fits(n, shard_len)) return error.InvalidShardSize;

    var decoding: Decoding(H, @TypeOf(strategy)) = try .init(gpa, n, k, shard_len, root, strategy);
    defer decoding.deinit();
    try decoding.admit(chunks);
    if (decoding.original_count < k) {
        decoding.trim_surplus();
        return decoding.reveal();
    }
    return decoding.reencode();
}

/// The state of one decode: every shard's digest (null where missing) and the provided
/// originals and recoveries, in input order.
fn Decoding(comptime H: type, comptime S: type) type {
    return struct {
        const Self = @This();
        const D = H.Digest;

        gpa: Allocator,
        n: usize,
        k: usize,
        shard_len: usize,
        root: *const D,
        strategy: S,
        digests: []?D,
        indices: []usize,
        shards: [][]const u8,
        original_count: usize = 0,
        recovery_count: usize = 0,

        fn init(
            gpa: Allocator,
            n: usize,
            k: usize,
            shard_len: usize,
            root: *const D,
            strategy: S,
        ) Allocator.Error!Self {
            const digests = try gpa.alloc(?D, n);
            errdefer gpa.free(digests);
            @memset(digests, null);
            const indices = try gpa.alloc(usize, n);
            errdefer gpa.free(indices);
            const shards = try gpa.alloc([]const u8, n);
            assert(n > k and k > 0);
            return .{
                .gpa = gpa,
                .n = n,
                .k = k,
                .shard_len = shard_len,
                .root = root,
                .strategy = strategy,
                .digests = digests,
                .indices = indices,
                .shards = shards,
            };
        }

        fn deinit(self: *Self) void {
            self.gpa.free(self.digests);
            self.gpa.free(self.indices);
            self.gpa.free(self.shards);
            self.* = undefined;
        }

        // Provided originals sit in `indices[0..k]` and `shards[0..k]`, recoveries (by
        // recovery index) from `k` on.
        fn original_indices(self: *const Self) []const usize {
            return self.indices[0..self.original_count];
        }
        fn originals(self: *const Self) []const []const u8 {
            return self.shards[0..self.original_count];
        }
        fn recovery_indices(self: *const Self) []const usize {
            return self.indices[self.k..][0..self.recovery_count];
        }
        fn recoveries(self: *const Self) []const []const u8 {
            return self.shards[self.k..][0..self.recovery_count];
        }

        /// Records each chunk's digest and bytes, rejecting other commitments, other widths,
        /// out-of-range indices, and repeats.
        fn admit(self: *Self, chunks: []const CheckedChunk(H)) Error!void {
            for (chunks) |*chunk| {
                if (!chunk.root.eql(self.root.*)) return error.CommitmentMismatch;
                // The striped paths slice every shard by stripe, so widths must agree.
                if (chunk.shard.len != self.shard_len) return error.Inconsistent;
                const index: usize = chunk.index;
                if (index >= self.n) return error.InvalidIndex;
                if (self.digests[index] != null) return error.DuplicateIndex;
                self.digests[index] = chunk.digest;
                if (index < self.k) {
                    self.indices[self.original_count] = index;
                    self.shards[self.original_count] = chunk.shard;
                    self.original_count += 1;
                } else {
                    self.indices[self.k + self.recovery_count] = index - self.k;
                    self.shards[self.k + self.recovery_count] = chunk.shard;
                    self.recovery_count += 1;
                }
            }
            if (chunks.len < self.k) return error.NotEnoughChunks;
            assert(self.original_count + self.recovery_count == chunks.len);
        }

        /// Keeps exactly `k` shards for the decoder. Surplus recoveries lose their digests,
        /// so the reconstruction rebuilds them and the root check binds them.
        fn trim_surplus(self: *Self) void {
            assert(self.original_count < self.k);
            const keep = self.k - self.original_count;
            assert(self.recovery_count >= keep);
            for (self.recovery_indices()[keep..]) |index| self.digests[self.k + index] = null;
            self.recovery_count = keep;
        }

        /// With every original present: re-encodes the recoveries, compares any provided
        /// recovery with its re-encoding (this rejects a malicious encoder's non-canonical
        /// recovery), and verifies the commitment.
        fn reencode(self: *Self) Error![]u8 {
            const k = self.k;
            const m = self.n - k;
            const original_refs = try self.gpa.alloc([]const u8, k);
            defer self.gpa.free(original_refs);
            for (self.original_indices(), self.originals()) |index, shard| {
                original_refs[index] = shard;
            }
            const buffer = try self.gpa.alloc(u8, m * self.shard_len);
            defer self.gpa.free(buffer);
            try striped.encode_recovery(self.strategy, .{
                .gpa = self.gpa,
                .k = k,
                .m = m,
                .shard_len = self.shard_len,
                .originals = original_refs,
                .recovery = buffer,
            });
            const recovery_refs = try self.split(buffer, m);
            defer self.gpa.free(recovery_refs);
            for (self.recovery_indices(), self.recoveries()) |index, shard| {
                if (!std.mem.eql(u8, shard, recovery_refs[index])) return error.Inconsistent;
            }
            return self.verify_root(original_refs, recovery_refs);
        }

        fn split(self: *const Self, buffer: []const u8, count: usize) ![][]const u8 {
            assert(buffer.len == count * self.shard_len);
            const refs = try self.gpa.alloc([]const u8, count);
            for (refs, 0..) |*shard, i| shard.* = buffer[i * self.shard_len ..][0..self.shard_len];
            return refs;
        }

        /// With an original missing: reconstructs the missing originals and recoveries from
        /// the `k` kept shards and verifies the commitment over the whole codeword.
        fn reveal(self: *Self) Error![]u8 {
            const k = self.k;
            const m = self.n - k;
            const missing = try self.gpa.alloc(usize, self.n - k);
            defer self.gpa.free(missing);
            var missing_originals: usize = 0;
            for (self.digests[0..k], 0..) |digest, i| if (digest == null) {
                missing[missing_originals] = i;
                missing_originals += 1;
            };
            var missing_recoveries: usize = 0;
            for (self.digests[k..], 0..) |digest, i| if (digest == null) {
                missing[missing_originals + missing_recoveries] = i;
                missing_recoveries += 1;
            };
            assert(missing_originals + missing_recoveries == self.n - k);

            var plan = try rs.Plan.init(
                self.gpa,
                k,
                m,
                self.original_indices(),
                self.recovery_indices(),
            );
            defer plan.deinit(self.gpa);
            const restored_originals = try self.gpa.alloc(u8, missing_originals * self.shard_len);
            var keep = false;
            defer if (!keep) self.gpa.free(restored_originals);
            const restored_recoveries = try self.gpa.alloc(u8, missing_recoveries * self.shard_len);
            defer self.gpa.free(restored_recoveries);
            try striped.reveal(self.strategy, .{
                .gpa = self.gpa,
                .k = k,
                .m = m,
                .shard_len = self.shard_len,
                .original_indices = self.original_indices(),
                .originals = self.originals(),
                .recovery_indices = self.recovery_indices(),
                .recoveries = self.recoveries(),
                .plan = &plan,
                .missing_originals = missing[0..missing_originals],
                .missing_recoveries = missing[missing_originals..],
                .restored_originals = restored_originals,
                .restored_recoveries = restored_recoveries,
            });
            return self.finish_reveal(
                missing,
                missing_originals,
                restored_originals,
                restored_recoveries,
                &keep,
            );
        }

        /// Assembles the codeword from provided and restored shards and verifies it. When the
        /// result reuses `restored_originals`, sets `keep` so the caller does not free it.
        fn finish_reveal(
            self: *Self,
            missing: []const usize,
            missing_originals: usize,
            restored_originals: []u8,
            restored_recoveries: []const u8,
            keep: *bool,
        ) Error![]u8 {
            assert(!keep.*);
            const k = self.k;
            const original_refs = try self.gpa.alloc([]const u8, k);
            defer self.gpa.free(original_refs);
            for (self.original_indices(), self.originals()) |index, shard| {
                original_refs[index] = shard;
            }
            for (missing[0..missing_originals], 0..) |index, slot| {
                const start = slot * self.shard_len;
                original_refs[index] = restored_originals[start..][0..self.shard_len];
            }
            const recovery_refs = try self.gpa.alloc([]const u8, self.n - k);
            defer self.gpa.free(recovery_refs);
            for (missing[missing_originals..], 0..) |index, slot| {
                const start = slot * self.shard_len;
                recovery_refs[index] = restored_recoveries[start..][0..self.shard_len];
            }
            if (self.original_count > 0) return self.verify_root(original_refs, recovery_refs);
            // With no originals supplied, the restored buffer holds them in shard order:
            // verify the whole codeword, then move the payload to the front.
            const data_len = try validate_data_layout(original_refs, self.shard_len);
            try self.verify_commitment(original_refs, recovery_refs);
            const payload = restored_originals[prefix_bytes..][0..data_len];
            std.mem.copyForwards(u8, restored_originals[0..data_len], payload);
            const data = try self.gpa.realloc(restored_originals, data_len);
            keep.* = true;
            return data;
        }

        /// Extracts the payload, then verifies the commitment to the complete codeword.
        fn verify_root(
            self: *Self,
            original_refs: []const []const u8,
            recovery_refs: []const []const u8,
        ) Error![]u8 {
            const data = try extract_data(self.gpa, original_refs, self.k, self.shard_len);
            errdefer self.gpa.free(data);
            try self.verify_commitment(original_refs, recovery_refs);
            return data;
        }

        /// Hashes the shards without a checked digest and rebuilds the tree over every
        /// shard; its root must equal the commitment.
        fn verify_commitment(
            self: *Self,
            original_refs: []const []const u8,
            recovery_refs: []const []const u8,
        ) Error!void {
            var missing: usize = 0;
            for (self.digests) |digest| missing += @intFromBool(digest == null);
            const payloads = try self.gpa.alloc([]const u8, missing);
            defer self.gpa.free(payloads);
            const hashed = try self.gpa.alloc(D, missing);
            defer self.gpa.free(hashed);
            var slot: usize = 0;
            for (self.digests, 0..) |digest, i| if (digest == null) {
                payloads[slot] = if (i < self.k) original_refs[i] else recovery_refs[i - self.k];
                slot += 1;
            };
            H.hash_many(payloads, hashed, self.strategy);
            const leaves = try self.gpa.alloc(D, self.n);
            defer self.gpa.free(leaves);
            slot = 0;
            for (self.digests, leaves) |digest, *leaf| {
                leaf.* = digest orelse blk: {
                    slot += 1;
                    break :blk hashed[slot - 1];
                };
            }
            assert(slot == missing);
            var tree = try build_tree(H, self.gpa, leaves);
            defer tree.deinit(self.gpa);
            if (!tree.root().eql(self.root.*)) return error.Inconsistent;
        }
    };
}

/// The Reed-Solomon coding scheme over hasher `H` (commonware's `ReedSolomon<H>`).
pub fn ReedSolomon(comptime H: type) type {
    cryptography.assert_hasher(H);
    return struct {
        pub const Commitment = H.Digest;
        pub const Shard = Chunk(H.Digest);
        pub const CheckedShard = CheckedChunk(H);
        pub const Error = SchemeError;

        /// A shard to check, with the index it is expected at.
        pub const ShardRef = struct {
            index: u16,
            shard: *const Shard,
        };

        /// An upper bound on the encoded size of any chunk `encode` produces under `config`
        /// from at most `data` bytes. Panics when `config` cannot encode `data` bytes.
        pub fn max_shard_size(config: Config, data: usize) usize {
            const total = total_shards(config) catch @panic("total shards must fit in u16");
            const n: usize = total;
            const k: usize = config.minimum_shards;
            validate_counts(k, n - k) catch @panic("backend must support the shard counts");
            if (data > u32_max) @panic("data must fit the u32 length prefix");
            const len = canonical_shard_len(data, k);
            if (len > u32_max) @panic("len must fit the u32 length prefix");
            if (!codeword_fits(n, len)) @panic("codeword must fit the allocation bound");
            // Chunk 0 has a sibling at every level, so its proof is the longest.
            const siblings: usize = std.math.log2_int_ceil(u32, total);
            return Shard.max_encode_size(len, siblings);
        }

        /// Encodes `data`; `deinit` the result.
        pub fn encode(
            gpa: Allocator,
            config: Config,
            data: []const u8,
            strategy: anytype,
        ) SchemeError!EncodingOf(H.Digest) {
            const total = try total_shards(config);
            return encode_codeword(H, gpa, total, config.minimum_shards, data, strategy);
        }

        pub fn check(
            config: Config,
            commitment: *const Commitment,
            index: u16,
            shard: *const Shard,
            strategy: anytype,
        ) SchemeError!CheckedShard {
            const total = try total_shards(config);
            try check_metadata(H.Digest, total, index, shard);
            const digest = H.hash_across(&.{shard.shard}, strategy);
            return check_chunk(H, total, commitment, index, shard, digest);
        }

        /// Checks every shard into `out`, each result equal to `check` of that shard. Shards
        /// of one width with valid metadata are hashed together; otherwise each is checked
        /// alone, so invalid metadata is rejected before hashing.
        pub fn check_many(
            gpa: Allocator,
            config: Config,
            commitment: *const Commitment,
            shards: []const ShardRef,
            out: []SchemeError!CheckedShard,
            strategy: anytype,
        ) Allocator.Error!void {
            assert(out.len == shards.len);
            const total = total_shards(config) catch 0;
            const width = if (shards.len > 0) shards[0].shard.shard.len else 0;
            const uniform = for (shards) |ref| {
                if (ref.shard.shard.len != width) break false;
                check_metadata(H.Digest, total, ref.index, ref.shard) catch break false;
            } else total > 0;
            if (!uniform) {
                for (shards, out) |ref, *result| {
                    result.* = check(config, commitment, ref.index, ref.shard, strategy);
                }
                return;
            }
            const payloads = try gpa.alloc([]const u8, shards.len);
            defer gpa.free(payloads);
            for (shards, payloads) |ref, *payload| payload.* = ref.shard.shard;
            const digests = try gpa.alloc(H.Digest, shards.len);
            defer gpa.free(digests);
            H.hash_many(payloads, digests, strategy);
            for (shards, digests, out) |ref, digest, *result| {
                result.* = check_chunk(H, total, commitment, ref.index, ref.shard, digest);
            }
        }

        /// Decodes the data from shards checked against `commitment`; the caller owns it.
        pub fn decode(
            gpa: Allocator,
            config: Config,
            commitment: *const Commitment,
            checked: []const CheckedShard,
            strategy: anytype,
        ) SchemeError![]u8 {
            const total = try total_shards(config);
            const min = config.minimum_shards;
            return decode_codeword(H, gpa, total, min, commitment, checked, strategy);
        }
    };
}

const SchemeError = Error;
const EncodingOf = Encoding;
const encode_codeword = encode;
const decode_codeword = decode;
