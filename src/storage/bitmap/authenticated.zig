//! An authenticated bitmap: a prunable bitmap whose complete chunks are the leaves of an MMR.
//!
//! Port of commonware's `storage/src/bitmap/authenticated.rs`. The root is the MMR root when
//! the bitmap is chunk-aligned; otherwise it also commits the bit length and the trailing
//! partial chunk: `hash(mmr_root || len_be64 || hash(last_chunk))`. A proof of a bit is an MMR
//! proof of its chunk whose `leaves` field carries the bit length, plus the partial chunk's
//! digest when there is one.
//!
//! Commonware separates `MerkleizedBitMap` and `UnmerkleizedBitMap` with a typestate; here one
//! type tracks the state and asserts it: mutate after `into_dirty`, read the root and prove
//! after `merkleize`. Pruning state (the pruned chunk count and the MMR's pinned nodes)
//! persists in a `Metadata` store under `write_pruned` and is recovered by `init`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const merkle = @import("../merkle/mod.zig");
const metadata = @import("../metadata/mod.zig");
const Storage = @import("runtime").storage.Storage;

const Mmr = merkle.mmr.Family;
const Key = utils.sequence.PrefixedU64;

/// Metadata key prefix of the pinned MMR node digests, keyed by pin order.
const node_prefix: u8 = 0;
/// Metadata key prefix of the pruned chunk count (key 0), a big-endian `u64`.
const chunk_count_prefix: u8 = 1;

/// The root of a bitmap that is not chunk-aligned: the MMR root over its complete chunks,
/// bound to the bit length and the trailing partial chunk.
pub fn partial_chunk_root(
    hasher: anytype,
    mmr_root: anytype,
    bit_len: u64,
    last_chunk_digest: anytype,
) @TypeOf(mmr_root.*) {
    assert(bit_len > 0);
    var len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_bytes, bit_len, .big);
    return hasher.hash(&.{ &mmr_root.bytes, &len_bytes, &last_chunk_digest.bytes });
}

/// An authenticated bitmap of `N`-byte chunks whose pruning state persists in `runtime.storage`.
pub fn BitMap(comptime Digest: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        const Bits = utils.bitmap.Prunable(N);
        const Mem = merkle.mem.Mem(Mmr, Digest);
        const Store = metadata.Metadata(Key, []const u8);

        pub const Proof = Mem.Proof;
        pub const Chunk = Bits.Chunk;
        pub const CHUNK_SIZE_BITS: u64 = Bits.CHUNK_SIZE_BITS;
        pub const Error = merkle.Error || Store.Error || Allocator.Error;

        gpa: Allocator,
        bitmap: Bits,
        mmr: Mem,
        store: Store,
        /// Indices of complete chunks already in the MMR whose bits changed since merkleizing.
        dirty_chunks: std.AutoArrayHashMapUnmanaged(usize, void) = .empty,
        /// The root as of the last `merkleize`, valid while `merkleized`.
        cached_root: Digest,
        merkleized: bool = true,

        /// Opens the bitmap in `partition`, restoring any pruning state `write_pruned`
        /// persisted there.
        pub fn init(
            gpa: Allocator,
            storage: Storage,
            partition: []const u8,
            hasher: anytype,
        ) Error!Self {
            var store = try Store.init(gpa, storage, .{
                .partition = partition,
                .codec_config = .{ .range = .full(), .item = {} },
            });
            errdefer store.deinit();
            const chunk_count = try read_pruned_chunks(&store);
            var mmr = try restore_mmr(gpa, &store, chunk_count);
            errdefer mmr.deinit(gpa);
            const bitmap = Bits.init_pruned(@intCast(chunk_count)) catch
                unreachable; // A valid location times the chunk size fits in a u64.
            const cached_root = try mmr.root(hasher, 0);
            assert(mmr.leaves() == chunk_count);
            return .{
                .gpa = gpa,
                .bitmap = bitmap,
                .mmr = mmr,
                .store = store,
                .cached_root = cached_root,
            };
        }

        fn read_pruned_chunks(store: *const Store) Error!u64 {
            const bytes = store.get(Key.init(chunk_count_prefix, 0)) orelse return 0;
            if (bytes.len != 8) return error.DataCorrupted; // pruned chunks not a valid u64
            const chunk_count = std.mem.readInt(u64, bytes.*[0..8], .big);
            if (!merkle.location_is_valid(Mmr, chunk_count)) return error.DataCorrupted;
            // A pruned chunk count whose bits overflow a u64 cannot come from `write_pruned`.
            _ = std.math.mul(u64, chunk_count, CHUNK_SIZE_BITS) catch
                return error.DataCorrupted;
            return chunk_count;
        }

        fn restore_mmr(gpa: Allocator, store: *const Store, chunk_count: u64) Error!Mem {
            assert(merkle.location_is_valid(Mmr, chunk_count));
            var positions_buffer: [merkle.max_pinned_nodes]u64 = undefined;
            const positions = merkle.nodes_to_pin(Mmr, chunk_count, &positions_buffer);
            var pinned: [merkle.max_pinned_nodes]Digest = undefined;
            for (0..positions.len) |index| {
                const key = Key.init(node_prefix, index);
                const bytes = store.get(key) orelse return error.MissingNode;
                if (bytes.len != Digest.fixed_size) return error.MissingNode;
                pinned[index] = codec.decode(Digest, gpa, bytes.*) catch return error.MissingNode;
            }
            return Mem.init(gpa, &.{}, chunk_count, pinned[0..positions.len]);
        }

        /// Closes the metadata store and frees all memory, dropping unwritten pruning state.
        pub fn deinit(self: *Self) void {
            self.store.deinit();
            self.release();
        }

        /// Removes the persisted pruning state and frees all memory.
        pub fn destroy(self: *Self) Error!void {
            defer self.release();
            try self.store.destroy();
        }

        fn release(self: *Self) void {
            self.dirty_chunks.deinit(self.gpa);
            self.mmr.deinit(self.gpa);
            self.bitmap.deinit(self.gpa);
            self.* = undefined;
        }

        /// The MMR's node count.
        pub fn size(self: *const Self) u64 {
            return self.mmr.size();
        }

        /// The bit count, including pruned bits.
        pub fn len(self: *const Self) u64 {
            return self.bitmap.len();
        }

        pub fn is_empty(self: *const Self) bool {
            return self.len() == 0;
        }

        pub fn pruned_bits(self: *const Self) u64 {
            return self.bitmap.pruned_bits();
        }

        pub fn pruned_chunks(self: *const Self) usize {
            return self.bitmap.pruned_chunks();
        }

        /// The last chunk and how many of its bits are in use.
        pub fn last_chunk(self: *const Self) struct { Chunk, u64 } {
            return self.bitmap.last_chunk();
        }

        pub fn get_chunk_containing(self: *const Self, bit: u64) *const Chunk {
            return self.bitmap.get_chunk_containing(bit);
        }

        pub fn get_bit(self: *const Self, bit: u64) bool {
            return self.bitmap.get_bit(bit);
        }

        pub fn get_bit_from_chunk(chunk: *const Chunk, bit: u64) bool {
            return Bits.get_bit_from_chunk(chunk, bit);
        }

        /// The MMR node digest at `position`, or null if pruned or past the end.
        pub fn get_node(self: *const Self, position: u64) ?Digest {
            return self.mmr.get_node(position);
        }

        /// The root as of the last `merkleize`.
        pub fn root(self: *const Self) Digest {
            assert(self.merkleized); // Read the root only after merkleizing.
            return self.cached_root;
        }

        /// Starts a round of mutations (commonware's `into_dirty`).
        pub fn into_dirty(self: *Self) void {
            assert(self.merkleized);
            assert(self.dirty_chunks.count() == 0);
            self.merkleized = false;
        }

        pub fn push(self: *Self, bit: bool) Allocator.Error!void {
            assert(!self.merkleized); // Mutate only between `into_dirty` and `merkleize`.
            try self.bitmap.push(self.gpa, bit);
        }

        pub fn push_byte(self: *Self, byte: u8) Allocator.Error!void {
            assert(!self.merkleized);
            try self.bitmap.push_byte(self.gpa, byte);
        }

        pub fn push_chunk(self: *Self, chunk: *const Chunk) Allocator.Error!void {
            assert(!self.merkleized);
            try self.bitmap.push_chunk(self.gpa, chunk);
        }

        /// Sets a retained bit, marking its chunk for re-hashing if the MMR already has it.
        pub fn set_bit(self: *Self, bit: u64, value: bool) Allocator.Error!void {
            assert(!self.merkleized);
            self.bitmap.set_bit(bit, value);
            const chunk = Bits.to_chunk_index(bit);
            if (chunk < self.mmr.leaves()) try self.dirty_chunks.put(self.gpa, chunk, {});
        }

        /// Adds the newly completed chunks to the MMR, re-hashes the dirty ones, and caches
        /// the new root.
        pub fn merkleize(self: *Self, hasher: anytype) Error!void {
            assert(!self.merkleized);
            const start: usize = @intCast(self.mmr.leaves());
            for (start..self.bitmap.complete_chunks()) |index| {
                const chunk = self.bitmap.get_chunk(index);
                try self.mmr.add(self.gpa, hasher, &chunk);
            }
            for (self.dirty_chunks.keys()) |index| {
                const chunk = self.bitmap.get_chunk(index);
                try self.mmr.update_leaf(hasher, index, &chunk);
            }
            self.dirty_chunks.clearRetainingCapacity();
            assert(self.mmr.leaves() == self.bitmap.complete_chunks());
            const mmr_root = try self.mmr.root(hasher, 0);
            self.cached_root = if (self.bitmap.is_chunk_aligned()) mmr_root else root: {
                const chunk, _ = self.bitmap.last_chunk();
                const chunk_digest = hasher.digest(&chunk);
                break :root partial_chunk_root(hasher, &mmr_root, self.len(), &chunk_digest);
            };
            self.merkleized = true;
        }

        /// Prunes every chunk before the one containing `bit`. The root is unchanged.
        pub fn prune_to_bit(self: *Self, bit: u64) merkle.Error!void {
            assert(self.merkleized);
            const chunk = Bits.to_chunk_index(bit);
            if (chunk < self.bitmap.pruned_chunks()) return;
            self.bitmap.prune_to_bit(bit);
            try self.mmr.prune(chunk);
            assert(self.mmr.pruning_boundary() == self.bitmap.pruned_chunks());
        }

        /// Persists the pruned chunk count and the MMR nodes pinned at it, replacing anything
        /// else in the metadata store.
        pub fn write_pruned(self: *Self) Error!void {
            assert(self.merkleized);
            self.store.clear();
            const chunk_count: u64 = self.bitmap.pruned_chunks();
            var count_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &count_bytes, chunk_count, .big);
            try self.put(Key.init(chunk_count_prefix, 0), &count_bytes);
            var digests_buffer: [merkle.max_pinned_nodes]Digest = undefined;
            const digests = self.mmr.node_digests_to_pin(chunk_count, &digests_buffer);
            for (digests, 0..) |*digest, index| {
                try self.put(Key.init(node_prefix, index), &digest.bytes);
            }
            try self.store.sync();
        }

        fn put(self: *Self, key: Key, bytes: []const u8) Allocator.Error!void {
            const value = try self.gpa.dupe(u8, bytes);
            errdefer self.gpa.free(value);
            const previous = try self.store.put(key, value);
            assert(previous == null); // The store was cleared first.
        }

        /// A proof of `bit` and the chunk holding it. Caller owns the proof.
        pub fn proof(self: *const Self, hasher: anytype, bit: u64) Error!struct { Proof, Chunk } {
            assert(self.merkleized);
            if (bit >= self.len()) return error.BitOutOfBounds;
            const chunk = self.get_chunk_containing(bit).*;
            const chunk_location: u64 = Bits.to_chunk_index(bit);
            const tail, const next_bit = self.bitmap.last_chunk();
            if (chunk_location == self.mmr.leaves()) {
                // The bit is in the partial chunk: the proof is just the MMR root.
                assert(next_bit > 0 and next_bit < CHUNK_SIZE_BITS);
                const digests = try self.gpa.alloc(Digest, 1);
                digests[0] = try self.mmr.root(hasher, 0);
                return .{ .{ .leaves = self.len(), .digests = digests }, chunk };
            }
            const range: merkle.Range = .{ .start = chunk_location, .end = chunk_location + 1 };
            var result = try self.mmr.range_proof(self.gpa, hasher, range, 0);
            errdefer result.deinit(self.gpa);
            result.leaves = self.len();
            if (next_bit == CHUNK_SIZE_BITS) return .{ result, chunk };
            const count = result.digests.len;
            result.digests = try self.gpa.realloc(result.digests, count + 1);
            result.digests[count] = hasher.digest(&tail);
            return .{ result, chunk };
        }

        /// Whether `chunk` holds `bit` under `root`, per `proof` (from `BitMap.proof`).
        pub fn verify_bit_inclusion(
            hasher: anytype,
            bit_proof: *const Proof,
            bit: u64,
            chunk: *const Chunk,
            root_digest: *const Digest,
        ) bool {
            const bit_len = bit_proof.leaves;
            if (bit >= bit_len) return false;
            if (bit_proof.inactive_peaks != 0) return false; // Bitmap proofs fold no peaks.
            const location = bit / CHUNK_SIZE_BITS;
            var mmr_proof: Proof = .{
                .leaves = bit_len / CHUNK_SIZE_BITS,
                .digests = bit_proof.digests,
            };
            if (bit_len % CHUNK_SIZE_BITS == 0) {
                return mmr_proof.verify_element_inclusion(hasher, location, chunk, root_digest);
            }
            const digests = bit_proof.digests;
            if (digests.len == 0) return false;
            const last_digest = digests[digests.len - 1];
            mmr_proof.digests = digests[0 .. digests.len - 1];
            if (mmr_proof.leaves == location) {
                // A proof over the partial chunk holds only the MMR root.
                if (mmr_proof.digests.len != 0) return false;
                const chunk_digest = hasher.digest(chunk);
                const reconstructed =
                    partial_chunk_root(hasher, &last_digest, bit_len, &chunk_digest);
                return reconstructed.eql(root_digest.*);
            }
            const elements = [_][]const u8{chunk};
            const mmr_root = mmr_proof.reconstruct_root(hasher, location, &elements) catch
                return false;
            const reconstructed = partial_chunk_root(hasher, &mmr_root, bit_len, &last_digest);
            return reconstructed.eql(root_digest.*);
        }
    };
}
