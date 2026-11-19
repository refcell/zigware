//! The persisted witness of a compact-db state and its verification (commonware's
//! `qmdb/compact/witness.rs`).
//!
//! A `Witness` records one applied state: the commit operation, the committed size, and the
//! pinned nodes one operation below it. The journal stores it as a `Stored` witness, whose
//! commit stays encoded, so selecting a witness by size never decodes a commit. `restore`
//! rebuilds the compact Merkle by appending the commit to the pinned nodes and derives the root
//! and the commit's proof from it; `rebuild` decodes a journaled witness's commit first and
//! reports an entry that cannot be restored as `DataCorrupted`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const variable = @import("../../journal/contiguous/variable.zig");
const qmdb = @import("../mod.zig");
const operation = @import("../operation.zig");
const source = @import("../sync/source.zig");
const compact_op = @import("operation.zig");

const Storage = runtime.storage.Storage;

/// A witness as the witness journal stores it, with its commit still encoded. Owns its bytes
/// and pinned nodes (`deinit`).
pub fn Stored(comptime F: type, comptime D: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        /// The encoded last commit operation, at `size - 1`.
        commit: []const u8,
        /// The committed database size.
        size: u64,
        /// Pinned nodes one operation below the commit, in `merkle.nodes_to_pin` order.
        pinned_nodes: []const D,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.commit);
            gpa.free(self.pinned_nodes);
            self.* = undefined;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const u8, self.commit) +
                operation.location_size(self.size) +
                codec.encode_size([]const D, self.pinned_nodes);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const u8, self.commit, writer);
            operation.write_location(self.size, writer);
            codec.write([]const D, self.pinned_nodes, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const commit = try codec.read_range([]const u8, gpa, reader, .full());
            errdefer gpa.free(commit);
            const size = try operation.read_location(F, reader);
            const range: codec.RangeCfg(usize) = .to_inclusive(merkle.max_pinned_nodes);
            const pinned = try codec.read_range([]const D, gpa, reader, range);
            return .{ .commit = commit, .size = size, .pinned_nodes = pinned };
        }

        /// commonware's `Arbitrary`: arbitrary bytes, a size in `1..=max_leaves`, and digests.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const commit = try codec.arbitrary.value([]const u8, gpa, u);
            const size = u.int_in_range(u64, 1, F.max_leaves);
            const pinned = try source.arbitrary_digests(D, gpa, u);
            return .{ .commit = commit, .size = size, .pinned_nodes = pinned };
        }
    };
}

/// An applied state: the last commit, the committed size, and the pinned nodes one operation
/// below the commit. Owns the commit and the pinned nodes (`deinit`).
pub fn Witness(comptime F: type, comptime D: type, comptime O: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();

        commit: O,
        size: u64,
        pinned_nodes: []D,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            codec.free(O, gpa, self.commit);
            gpa.free(self.pinned_nodes);
            self.* = undefined;
        }

        /// The journal form of this witness. The caller owns its encoded commit (free it with
        /// `gpa.free`); its pinned nodes are borrowed from this witness.
        pub fn stored(self: *const Self, gpa: Allocator) Allocator.Error!Stored(F, D) {
            const commit = try codec.encode(O, gpa, self.commit);
            assert(commit.len > 0);
            assert(self.size > 0);
            return .{ .commit = commit, .size = self.size, .pinned_nodes = self.pinned_nodes };
        }
    };
}

/// A witness whose commit was checked, with its root and the commit's inclusion proof derived
/// from it. Owns the witness and the proof (`deinit`).
pub fn Verified(comptime F: type, comptime D: type, comptime O: type) type {
    return struct {
        const Self = @This();

        witness: Witness(F, D, O),
        /// The inactivity floor the commit declares.
        inactivity_floor: u64,
        /// The root the witness commits to.
        root: D,
        /// Inclusion proof of the commit at `size - 1` against `root`.
        proof: merkle.Proof(F, D),

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.witness.deinit(gpa);
            self.proof.deinit(gpa);
            self.* = undefined;
        }

        pub fn size(self: *const Self) u64 {
            return self.witness.size;
        }

        /// The sync target this witness can serve: its root and its last commit.
        pub fn target(self: *const Self) qmdb.sync.Target(F, D) {
            const end = self.size();
            assert(end > 0);
            return .init(self.root, end - 1, end);
        }
    };
}

/// The compact Merkle of `F` over digests `D`.
pub fn Merkle(comptime F: type, comptime D: type) type {
    return merkle.compact.Merkle(F, D);
}

/// A Merkle materialized from a witness, with the witness verified against it.
pub fn Rebuilt(comptime F: type, comptime D: type, comptime O: type) type {
    return struct {
        merkle: Merkle(F, D),
        tip: Verified(F, D, O),
    };
}

/// Builds the witness of `commit`, which must be the last operation in `structure`, before
/// the structure is pruned to its frontier (the commit's proof needs its unpruned nodes).
/// Takes `commit`, also on error.
pub fn build(
    comptime F: type,
    comptime O: type,
    comptime H: type,
    gpa: Allocator,
    structure: *const Merkle(F, H.Digest),
    commit: O,
    inactivity_floor: u64,
) !Verified(F, H.Digest, O) {
    errdefer codec.free(O, gpa, commit);
    const hasher = qmdb.hasher(H);
    const size = structure.leaves();
    assert(size > 0);
    assert(inactivity_floor < size);
    const last = size - 1;
    const inactive_peaks = merkle.inactive_peaks(F, size, inactivity_floor);
    const root = try structure.root(&hasher, inactive_peaks);
    var buffer: [merkle.max_pinned_nodes]H.Digest = undefined;
    const pinned = try gpa.dupe(H.Digest, structure.mem.node_digests_to_pin(last, &buffer));
    errdefer gpa.free(pinned);
    const proof = try structure.mem.proof(gpa, &hasher, last, inactive_peaks);
    return .{
        .witness = .{ .commit = commit, .size = size, .pinned_nodes = pinned },
        .inactivity_floor = inactivity_floor,
        .root = root,
        .proof = proof,
    };
}

/// Validates `witness`, materializes its Merkle, and derives its root and commit proof. A zero
/// size is `DataCorrupted`, a non-commit `UnexpectedData`, and a floor beyond the commit
/// `FloorBeyondCommit`. Takes `witness`, also on error.
pub fn restore(
    comptime F: type,
    comptime O: type,
    comptime H: type,
    gpa: Allocator,
    witness: Witness(F, H.Digest, O),
) !Rebuilt(F, H.Digest, O) {
    defer gpa.free(witness.pinned_nodes);
    var commit_owned = true;
    errdefer if (commit_owned) codec.free(O, gpa, witness.commit);
    if (witness.size == 0) return error.DataCorrupted;
    const last = witness.size - 1;
    const floor = witness.commit.inactivity_floor() orelse return error.UnexpectedData;
    if (floor > last) return error.FloorBeyondCommit;
    var structure = try Merkle(F, H.Digest).from_compact_state(gpa, last, witness.pinned_nodes);
    errdefer structure.deinit();
    const encoded = try codec.encode(O, gpa, witness.commit);
    defer gpa.free(encoded);
    const hasher = qmdb.hasher(H);
    try structure.append_leaf(&hasher, encoded);
    commit_owned = false;
    const tip = try build(F, O, H, gpa, &structure, witness.commit, floor);
    structure.prune_to_frontier();
    assert(structure.leaves() == tip.size());
    return .{ .merkle = structure, .tip = tip };
}

/// Decodes a journaled witness's commit with `cfg`, then restores it. A commit that fails to
/// decode keeps its codec error; any restore failure is `DataCorrupted`, since the entry came
/// from this database's own journal. Borrows `stored`.
pub fn rebuild(
    comptime F: type,
    comptime O: type,
    comptime H: type,
    gpa: Allocator,
    stored: *const Stored(F, H.Digest),
    cfg: codec.Cfg(O),
) !Rebuilt(F, H.Digest, O) {
    const commit = try codec.decode_cfg(O, gpa, stored.commit, cfg);
    var commit_owned = true;
    errdefer if (commit_owned) codec.free(O, gpa, commit);
    const pinned = try gpa.dupe(H.Digest, stored.pinned_nodes);
    commit_owned = false;
    const witness: Witness(F, H.Digest, O) = .{
        .commit = commit,
        .size = stored.size,
        .pinned_nodes = pinned,
    };
    return restore(F, O, H, gpa, witness) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.DataCorrupted,
    };
}

/// The genesis witness: `Commit(None, 0)` alone.
pub fn genesis(comptime F: type, comptime D: type, comptime O: type) Witness(F, D, O) {
    return .{ .commit = compact_op.commit(O, null, 0), .size = 1, .pinned_nodes = &.{} };
}

/// The witness journal.
pub fn Journal(comptime F: type, comptime D: type) type {
    return variable.Journal(Stored(F, D));
}

/// Opens the witness journal for recovery, bounded at `max_size` when that view can settle
/// selection and unbounded otherwise. Witness position `p` has size at least `p + 1` in an
/// append-only journal (at least `p` after a compact-sync import resets it to position 1), so
/// positions below the cap hold every witness no larger than it. A retained start at or above
/// the cap opens unbounded, and a bounded view that ends at the cap with a smaller tip widens.
pub fn recover(
    comptime F: type,
    comptime D: type,
    gpa: Allocator,
    storage: Storage,
    cfg: Journal(F, D).Cfg,
    max_size: ?u64,
) !Journal(F, D).RecoveryType {
    const J = Journal(F, D);
    const cap = max_size orelse return J.recover(gpa, storage, cfg, null);
    assert(cap > 0);
    if ((try J.span(gpa, storage, cfg)).start >= cap) return J.recover(gpa, storage, cfg, null);
    var bounded = try J.recover(gpa, storage, cfg, cap);
    const bounds = bounded.get_bounds();
    if (bounds.end < cap) return bounded;
    var tip = bounded.read(bounds.end - 1) catch |err| {
        bounded.deinit();
        return err;
    };
    defer tip.deinit(gpa);
    if (tip.size >= cap) return bounded;
    bounded.deinit();
    return J.recover(gpa, storage, cfg, null);
}
