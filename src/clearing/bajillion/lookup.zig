//! Openings of one key in a sorted list committed with a binary Merkle tree
//! (commonware `bajillion/lookup.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const arb = @import("arbitrary.zig");

const bmt = storage.bmt;

/// An opening does not verify.
pub const InvalidOpening = error{InvalidOpening};

/// Tag of `member` in the encoding.
const member_tag: u8 = 0;
/// Tag of `non_member` in the encoding.
const non_member_tag: u8 = 1;

/// Scratch for verifying an opening of at most two entries without the heap.
const scratch_bytes = 4096;

/// Converts a bmt failure on a tree that commits the entries into an allocation failure.
fn committed(err: (bmt.Error || Allocator.Error)) Allocator.Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // Proof: positions come from the entries the tree commits, so they are in range.
        else => unreachable,
    };
}

/// Opens the value bound to one key in a list that is strictly increasing by key and committed
/// with a binary Merkle tree (commonware `Lookup<K, V, D>`).
///
/// Each leaf is bound to its position and the root binds the number of entries, so an opening
/// also proves whether an entry is the first or last. An opening is sound only under the root of
/// a sorted list, because an unsorted list can prove a present key absent. A lookup owns its
/// proof; `deinit` frees it.
pub fn Lookup(comptime K: type, comptime V: type, comptime D: type) type {
    comptime assert(codec.fixed_size(K) != null and codec.fixed_size(V) != null);
    comptime assert(!codec.owns_memory(K) and !codec.owns_memory(V));
    return union(enum) {
        const Self = @This();

        pub const Entry = struct { K, V };
        pub const Proof = bmt.Proof(D);

        /// The key is present.
        member: Member,
        /// The key is absent.
        non_member: NonMember,

        pub const Member = struct {
            /// Position of the key's entry.
            position: u32,
            /// Value bound to the key.
            value: V,
            /// Opening of the entry.
            proof: Proof,
        };

        pub const NonMember = struct {
            /// Position at which the key would be inserted.
            position: u32,
            /// Entry preceding `position`, unless the key precedes every entry.
            lower: ?Entry,
            /// Entry at `position`, unless the key follows every entry.
            upper: ?Entry,
            /// Opening of the neighbors present, or of the empty list.
            proof: Proof,
        };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                inline else => |*variant| variant.proof.deinit(gpa),
            }
            self.* = undefined;
        }

        pub fn clone(self: *const Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self.*) {
                .member => |m| .{ .member = .{
                    .position = m.position,
                    .value = m.value,
                    .proof = try m.proof.clone(gpa),
                } },
                .non_member => |n| .{ .non_member = .{
                    .position = n.position,
                    .lower = n.lower,
                    .upper = n.upper,
                    .proof = try n.proof.clone(gpa),
                } },
            };
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            return switch (self.*) {
                .member => |a| switch (other.*) {
                    .member => |b| a.position == b.position and
                        codec.order(V, a.value, b.value) == .eq and a.proof.eql(&b.proof),
                    .non_member => false,
                },
                .non_member => |a| switch (other.*) {
                    .member => false,
                    .non_member => |b| a.position == b.position and
                        codec.order(?Entry, a.lower, b.lower) == .eq and
                        codec.order(?Entry, a.upper, b.upper) == .eq and a.proof.eql(&b.proof),
                },
            };
        }

        /// Opens `key` in `entries`, which must be strictly increasing by key and committed by
        /// `tree`.
        pub fn init(
            gpa: Allocator,
            entries: []const Entry,
            tree: *const bmt.Tree(D),
            key: *const K,
        ) Allocator.Error!Self {
            assert(entries.len <= std.math.maxInt(u32));
            const index = std.sort.lowerBound(Entry, entries, key.*, compare_key);
            const position: u32 = @intCast(index);
            if (index < entries.len and codec.order(K, entries[index][0], key.*) == .eq) {
                const proof = tree.range_proof(gpa, position, position, null) catch |err|
                    return committed(err);
                return .{ .member = .{
                    .position = position,
                    .value = entries[index][1],
                    .proof = proof,
                } };
            }
            const lower: ?Entry = if (index > 0) entries[index - 1] else null;
            const upper: ?Entry = if (index < entries.len) entries[index] else null;
            const start = if (lower == null) position else position - 1;
            const end = if (upper == null) position -| 1 else position;
            const proof: Proof = if (lower == null and upper == null)
                .{}
            else
                tree.range_proof(gpa, start, end, null) catch |err| return committed(err);
            return .{ .non_member = .{
                .position = position,
                .lower = lower,
                .upper = upper,
                .proof = proof,
            } };
        }

        fn compare_key(key: K, entry: Entry) std.math.Order {
            return codec.order(K, key, entry[0]);
        }

        /// Verifies the opening of `key` under `root` with hasher `H`, where `leaf` computes an
        /// entry's leaf. Returns the value bound to `key`, or null if the opening proves it absent.
        pub fn verify(
            self: *const Self,
            comptime H: type,
            root: *const D,
            key: *const K,
            comptime leaf: fn (*const K, *const V) D,
        ) InvalidOpening!?V {
            comptime assert(H.Digest == D);
            switch (self.*) {
                .member => |*m| {
                    const digest = leaf(key, &m.value);
                    m.proof.verify_element_inclusion(H, m.position, &digest, root, null) catch
                        return error.InvalidOpening;
                    return m.value;
                },
                .non_member => |*n| {
                    try check_neighbors(n, key);
                    var elements: [2]Proof.Element = undefined;
                    var count: usize = 0;
                    if (n.lower) |*lower| {
                        elements[count] = .{
                            .position = n.position - 1,
                            .digest = leaf(&lower[0], &lower[1]),
                        };
                        count += 1;
                    }
                    if (n.upper) |*upper| {
                        elements[count] = .{
                            .position = n.position,
                            .digest = leaf(&upper[0], &upper[1]),
                        };
                        count += 1;
                    }
                    var scratch: [scratch_bytes]u8 = undefined;
                    var fixed: std.heap.FixedBufferAllocator = .init(&scratch);
                    const used = elements[0..count];
                    n.proof.verify_multi_inclusion(H, fixed.allocator(), used, root, null) catch
                        return error.InvalidOpening;
                    return null;
                },
            }
        }

        /// Checks a non-member opening's neighbors against `key` and its position.
        fn check_neighbors(n: *const NonMember, key: *const K) InvalidOpening!void {
            // The key lies strictly between its neighbors, and an entry is missing only because
            // the key precedes the first entry or follows the last one. An empty list has
            // neither neighbor, and only the empty proof opens its root.
            const count = n.proof.leaf_count;
            if ((n.lower != null) != (n.position > 0)) return error.InvalidOpening;
            if ((n.upper != null) != (n.position < count)) return error.InvalidOpening;
            if (n.lower) |lower| {
                if (codec.order(K, lower[0], key.*) != .lt) return error.InvalidOpening;
            }
            if (n.upper) |upper| {
                if (codec.order(K, upper[0], key.*) != .gt) return error.InvalidOpening;
            }
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            switch (self) {
                .member => |m| {
                    writer.write_byte(member_tag);
                    codec.write(u32, m.position, writer);
                    codec.write(V, m.value, writer);
                    m.proof.write(writer);
                },
                .non_member => |n| {
                    writer.write_byte(non_member_tag);
                    codec.write(u32, n.position, writer);
                    codec.write(?Entry, n.lower, writer);
                    codec.write(?Entry, n.upper, writer);
                    n.proof.write(writer);
                },
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + 4 + switch (self) {
                .member => |m| codec.encode_size(V, m.value) + m.proof.encode_size(),
                .non_member => |n| codec.encode_size(?Entry, n.lower) +
                    codec.encode_size(?Entry, n.upper) + n.proof.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tag = try reader.read_byte();
            switch (tag) {
                member_tag => {
                    const position = try codec.read(u32, gpa, reader);
                    const value = try codec.read(V, gpa, reader);
                    const proof = try Proof.read(gpa, reader, 1);
                    return .{ .member = .{ .position = position, .value = value, .proof = proof } };
                },
                non_member_tag => {
                    const position = try codec.read(u32, gpa, reader);
                    const lower = try codec.read(?Entry, gpa, reader);
                    const upper = try codec.read(?Entry, gpa, reader);
                    const proof = try Proof.read(gpa, reader, 2);
                    return .{ .non_member = .{
                        .position = position,
                        .lower = lower,
                        .upper = upper,
                        .proof = proof,
                    } };
                },
                else => return reader.fail(error.InvalidEnum, tag),
            }
        }

        /// commonware's `Arbitrary for Lookup`: the position, a proof, then the variant.
        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const position = u.int(u32);
            const proof = try arbitrary_proof(D, gpa, u);
            if (u.boolean()) {
                const value = try arb.value(V, gpa, u);
                return .{ .member = .{ .position = position, .value = value, .proof = proof } };
            }
            const lower = try arb.value(?Entry, gpa, u);
            const upper = try arb.value(?Entry, gpa, u);
            return .{ .non_member = .{
                .position = position,
                .lower = lower,
                .upper = upper,
                .proof = proof,
            } };
        }
    };
}

/// An arbitrary proof with at most four siblings (commonware `arbitrary_proof`).
pub fn arbitrary_proof(
    comptime D: type,
    gpa: Allocator,
    u: *arb.Unstructured,
) arb.Error!bmt.Proof(D) {
    const count = u.int_in_range(u64, 0, 4);
    const leaf_count = u.int(u32);
    const siblings = try gpa.alloc(D, count);
    for (siblings) |*sibling| sibling.* = try arb.value(D, gpa, u);
    return .{ .leaf_count = leaf_count, .siblings = siblings };
}
