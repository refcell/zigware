//! Hashing for Merkle-family structures: leaf, node, and root digests.
//!
//! Port of commonware's `storage/src/merkle/hasher.rs`. A Merkle hasher is a comptime
//! interface (see `check`): a type with `Digest`, `hash(parts)`, `root_bagging()`,
//! `leaf_digest(position, element)`, `node_digest(position, left, right)`, and
//! `fold(accumulator, peak)`. `Standard(H)` implements it over any cryptography hasher;
//! `root` and `root_with_folded_peaks` work over any implementation.
//!
//! Pre-images (byte-identical to commonware):
//! - leaf: `position_be64 || element`
//! - node: `position_be64 || left || right`
//! - fold: `accumulator || peak`
//! - root: `[family_domain, bagging_domain] || leaves_be64 [|| inactive_be64] [|| bag]`

const std = @import("std");
const assert = std.debug.assert;
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");

/// Asserts at comptime that `T` implements the Merkle hasher interface.
pub fn check(comptime T: type) void {
    comptime {
        assert(@hasDecl(T, "Digest"));
        for ([_][]const u8{
            "hash", "root_bagging", "leaf_digest", "node_digest", "fold",
        }) |name| assert(@hasDecl(T, name));
    }
}

fn big_endian(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

/// The standard Merkle hasher over cryptography hasher `H`.
pub fn Standard(comptime H: type) type {
    cryptography.assert_hasher(H);
    return struct {
        const Self = @This();
        pub const Digest = H.Digest;

        bagging: merkle.Bagging,

        pub fn init(bagging: merkle.Bagging) Self {
            return .{ .bagging = bagging };
        }

        pub fn root_bagging(self: *const Self) merkle.Bagging {
            return self.bagging;
        }

        pub fn hash(_: *const Self, parts: []const []const u8) Digest {
            return H.hash(parts);
        }

        /// Digest of `data` alone.
        pub fn digest(self: *const Self, data: []const u8) Digest {
            return self.hash(&.{data});
        }

        pub fn leaf_digest(self: *const Self, position: u64, element: []const u8) Digest {
            const position_bytes = big_endian(position);
            return self.hash(&.{ &position_bytes, element });
        }

        pub fn node_digest(
            self: *const Self,
            position: u64,
            left: *const Digest,
            right: *const Digest,
        ) Digest {
            const position_bytes = big_endian(position);
            return self.hash(&.{ &position_bytes, &left.bytes, &right.bytes });
        }

        /// Two node digests at once (hashed in parallel once `parallel` lands).
        pub fn node_digest_pair(self: *const Self, nodes: [2]NodeInput) [2]Digest {
            _ = self;
            const left_position = big_endian(nodes[0].position);
            const right_position = big_endian(nodes[1].position);
            return H.hash_pair(
                &.{ &left_position, &nodes[0].left.bytes, &nodes[0].right.bytes },
                &.{ &right_position, &nodes[1].left.bytes, &nodes[1].right.bytes },
                {},
            );
        }

        pub fn fold(self: *const Self, accumulator: *const Digest, peak: *const Digest) Digest {
            return self.hash(&.{ &accumulator.bytes, &peak.bytes });
        }

        pub const NodeInput = struct {
            position: u64,
            left: *const Digest,
            right: *const Digest,
        };
    };
}

/// The root of a structure with `leaves` leaves and the given peaks (oldest first), with the
/// oldest `inactive_peaks` peaks folded forward and committed.
pub fn root(
    comptime F: type,
    hasher: anytype,
    leaves: u64,
    inactive_peaks: usize,
    peaks: []const @TypeOf(hasher.*).Digest,
) merkle.Error!@TypeOf(hasher.*).Digest {
    return root_with_folded_peaks(F, hasher, leaves, inactive_peaks, inactive_peaks, peaks) orelse
        error.InvalidInactivePeaks;
}

/// Folds the oldest `inactive_peaks_to_fold` peaks forward, bags the rest under the hasher's
/// bagging policy, and commits `committed_inactive_peaks` (when non-zero) into the root.
/// Returns null when there are fewer peaks than the inactive prefix needs.
pub fn root_with_folded_peaks(
    comptime F: type,
    hasher: anytype,
    leaves: u64,
    inactive_peaks_to_fold: usize,
    committed_inactive_peaks: usize,
    peaks: []const @TypeOf(hasher.*).Digest,
) ?@TypeOf(hasher.*).Digest {
    check(@TypeOf(hasher.*));
    const domain = [2]u8{ F.domain, hasher.root_bagging().domain() };
    const leaves_bytes = big_endian(leaves);
    if (peaks.len == 0) {
        if (inactive_peaks_to_fold != 0 or committed_inactive_peaks != 0) return null;
        return hasher.hash(&.{ &domain, &leaves_bytes });
    }
    // The first peak plus `inactive_peaks_to_fold - 1` more are folded forward.
    const forward = @max(inactive_peaks_to_fold, 1);
    if (forward > peaks.len) return null;
    var accumulator = peaks[0];
    for (peaks[1..forward]) |*peak| accumulator = hasher.fold(&accumulator, peak);
    const rest = peaks[forward..];
    const folded = switch (hasher.root_bagging()) {
        .forward_fold => forward: {
            for (rest) |*peak| accumulator = hasher.fold(&accumulator, peak);
            break :forward accumulator;
        },
        .backward_fold => backward: {
            if (rest.len == 0) break :backward accumulator;
            var bag = rest[rest.len - 1];
            var index = rest.len - 1;
            while (index > 0) {
                index -= 1;
                bag = hasher.fold(&rest[index], &bag);
            }
            break :backward hasher.fold(&accumulator, &bag);
        },
    };
    if (committed_inactive_peaks == 0) {
        return hasher.hash(&.{ &domain, &leaves_bytes, &folded.bytes });
    }
    const committed_bytes = big_endian(committed_inactive_peaks);
    return hasher.hash(&.{ &domain, &leaves_bytes, &committed_bytes, &folded.bytes });
}

const testing = std.testing;
const Sha256 = cryptography.Sha256;
const MmrFamily = merkle.mmr.Family;

fn test_digest(value: u8) Sha256.Digest {
    return Sha256.hash(&.{&.{value}});
}

test "leaf digest sha256" {
    const hasher = Standard(Sha256).init(.forward_fold);
    const digest1 = test_digest(1);
    const digest2 = test_digest(2);
    const out = hasher.leaf_digest(0, &digest1.bytes);
    try testing.expect(!out.eql(test_digest(0)));
    try testing.expect(out.eql(hasher.leaf_digest(0, &digest1.bytes)));
    try testing.expect(!out.eql(hasher.leaf_digest(1, &digest1.bytes)));
    try testing.expect(!out.eql(hasher.leaf_digest(0, &digest2.bytes)));
    const position_bytes = big_endian(0);
    try testing.expect(out.eql(Sha256.hash(&.{ &position_bytes, &digest1.bytes })));
}

test "node digest sha256" {
    const hasher = Standard(Sha256).init(.forward_fold);
    const d1 = test_digest(1);
    const d2 = test_digest(2);
    const d3 = test_digest(3);
    const out = hasher.node_digest(0, &d1, &d2);
    try testing.expect(!out.eql(test_digest(0)));
    try testing.expect(out.eql(hasher.node_digest(0, &d1, &d2)));
    try testing.expect(!out.eql(hasher.node_digest(1, &d1, &d2)));
    try testing.expect(!out.eql(hasher.node_digest(0, &d3, &d2)));
    try testing.expect(!out.eql(hasher.node_digest(0, &d1, &d3)));
    try testing.expect(!out.eql(hasher.node_digest(0, &d2, &d1)));
}

test "root sha256" {
    const hasher = Standard(Sha256).init(.forward_fold);
    const d1 = test_digest(1);
    const d2 = test_digest(2);
    const d3 = test_digest(3);
    const d4 = test_digest(4);
    const empty = try root(MmrFamily, &hasher, 0, 0, &.{});
    try testing.expect(!empty.eql(test_digest(0)));
    try testing.expect(empty.eql(try root(MmrFamily, &hasher, 0, 0, &.{})));
    // The empty root is the hash of the domain and the big-endian leaf count.
    try testing.expect(empty.eql(Sha256.hash(&.{ &.{ 0, 0 }, &big_endian(0) })));

    const out = try root(MmrFamily, &hasher, 10, 0, &.{ d1, d2, d3, d4 });
    try testing.expect(!out.eql(test_digest(0)));
    try testing.expect(!out.eql(empty));
    try testing.expect(out.eql(try root(MmrFamily, &hasher, 10, 0, &.{ d1, d2, d3, d4 })));
    try testing.expect(!out.eql(try root(MmrFamily, &hasher, 11, 0, &.{ d1, d2, d3, d4 })));
    try testing.expect(!out.eql(try root(MmrFamily, &hasher, 10, 0, &.{ d1, d2, d4, d3 })));
    try testing.expect(!out.eql(try root(MmrFamily, &hasher, 10, 0, &.{ d1, d2, d3 })));
}

test "backward fold bags newest first" {
    const hasher = Standard(Sha256).init(.backward_fold);
    const d1 = test_digest(1);
    const d2 = test_digest(2);
    const d3 = test_digest(3);
    // bag = fold(d2, d3); root folds d1 with the bag.
    const bag = hasher.fold(&d1, &hasher.fold(&d2, &d3));
    const expected = Sha256.hash(&.{ &.{ 0, 1 }, &big_endian(3), &bag.bytes });
    try testing.expect(expected.eql(try root(MmrFamily, &hasher, 3, 0, &.{ d1, d2, d3 })));
    // With two inactive peaks, d1 and d2 fold forward and the count is committed.
    const forward = hasher.fold(&hasher.fold(&d1, &d2), &d3);
    const committed = Sha256.hash(&.{ &.{ 0, 1 }, &big_endian(3), &big_endian(2), &forward.bytes });
    try testing.expect(committed.eql(try root(MmrFamily, &hasher, 3, 2, &.{ d1, d2, d3 })));
}

test "node digest pair matches node digest" {
    const hasher = Standard(Sha256).init(.forward_fold);
    const d1 = test_digest(1);
    const d2 = test_digest(2);
    const d3 = test_digest(3);
    const d4 = test_digest(4);
    const pair = hasher.node_digest_pair(.{
        .{ .position = 2, .left = &d1, .right = &d2 },
        .{ .position = 5, .left = &d3, .right = &d4 },
    });
    try testing.expect(pair[0].eql(hasher.node_digest(2, &d1, &d2)));
    try testing.expect(pair[1].eql(hasher.node_digest(5, &d3, &d4)));
}

test "invalid inactive prefix returns error" {
    const hasher = Standard(Sha256).init(.backward_fold);
    const digests = [_]Sha256.Digest{ test_digest(1), test_digest(2) };
    try testing.expectError(
        error.InvalidInactivePeaks,
        root(MmrFamily, &hasher, 2, 3, &digests),
    );
    try testing.expect(root_with_folded_peaks(MmrFamily, &hasher, 2, 3, 3, &digests) == null);
    try testing.expectError(
        error.InvalidInactivePeaks,
        root(MmrFamily, &hasher, 0, 1, &.{}),
    );
}
