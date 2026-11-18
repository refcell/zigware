//! The `qmdb_verify_proof` fuzz target (commonware `storage/fuzz`): multi-proofs of arbitrary
//! digests, leaf counts, and inactive peaks over arbitrary byte operations must verify without
//! misbehaving, and operations out of strictly ascending order must be rejected, under both
//! families.
//!
//! Beyond commonware's target, which can only check robustness, each input also builds a real
//! tree over its operations: a genuine multi-proof of a drawn subset must verify, and the same
//! proof must fail on a tampered operation or root.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("../merkle/mod.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");
const qmdb = @import("mod.zig");
const verify = @import("verify.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Bytes = []const u8;

const max_digests = 128;
const max_operations = 50;
/// Payloads are short so seeded runs stay fast; commonware allows 512 bytes.
const max_payload_len = 24;

/// One operation of the arbitrary proof: a raw location and a payload of `len` copies of
/// `byte`.
const Op = struct { location: u64, byte: u8, len: u8 };

const Input = struct {
    leaves: u64,
    inactive_peaks: usize,
    digests: [max_digests]Digest,
    digest_count: usize,
    ops: [max_operations]Op,
    op_count: usize,
    root: Digest,

    fn decode(self: *Input, reader: *fuzz_bytes.Reader, comptime F: type) void {
        self.leaves = reader.below(F.max_leaves + 1);
        self.inactive_peaks = reader.int(u8);
        self.digest_count = reader.int(u8) % (max_digests + 1);
        for (self.digests[0..self.digest_count]) |*d| d.* = .{ .bytes = @splat(reader.int(u8)) };
        self.op_count = reader.int(u8) % (max_operations + 1);
        for (self.ops[0..self.op_count]) |*op| {
            // Mostly small locations, so proofs can reach reconstruction.
            const raw = if (reader.boolean()) reader.int(u64) else reader.int(u8);
            op.* = .{ .location = raw, .byte = reader.int(u8), .len = reader.int(u8) };
        }
        self.root = .{ .bytes = @splat(reader.int(u8)) };
    }
};

/// The payloads of `ops` (backed by `storage`) and their locations, keeping valid locations.
fn payloads(
    comptime F: type,
    ops: []const Op,
    storage: *[max_operations][max_payload_len]u8,
    locations: *[max_operations]u64,
    out: *[max_operations]Bytes,
) usize {
    var count: usize = 0;
    for (ops) |op| {
        if (op.location > F.max_leaves) continue; // Commonware's `Location::is_valid`.
        const len = op.len % (max_payload_len + 1);
        @memset(storage[count][0..len], op.byte);
        locations[count] = op.location;
        out[count] = storage[count][0..len];
        count += 1;
    }
    assert(count <= ops.len);
    return count;
}

fn ascending(locations: []const u64) bool {
    for (locations[0..locations.len -| 1], locations[@min(1, locations.len)..]) |a, b| {
        if (a >= b) return false;
    }
    return true;
}

/// Commonware's target: verification of an arbitrary proof must not misbehave, and must
/// reject operations that are not strictly ascending.
fn arbitrary_proof(comptime F: type, input: *const Input) !void {
    var digests = input.digests;
    const proof: verify.Proof(F, Sha256) = .{
        .leaves = input.leaves,
        .inactive_peaks = input.inactive_peaks,
        .digests = digests[0..input.digest_count],
    };
    var storage: [max_operations][max_payload_len]u8 = undefined;
    var locations: [max_operations]u64 = undefined;
    var ops: [max_operations]Bytes = undefined;
    const count = payloads(F, input.ops[0..input.op_count], &storage, &locations, &ops);
    const locs = locations[0..count];
    const root = &input.root;
    const items = ops[0..count];
    const verified = try verify.verify_multi(F, Sha256, Bytes, gpa, &proof, locs, items, root);
    if (ascending(locs)) return;
    try testing.expect(!verified);
    // Sorting and deduplicating lets verification reach reconstruction.
    var order: [max_operations]usize = undefined;
    for (order[0..count], 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order[0..count], locs, struct {
        fn less(l: []const u64, a: usize, b: usize) bool {
            return l[a] < l[b];
        }
    }.less);
    var sorted_locs: [max_operations]u64 = undefined;
    var sorted_ops: [max_operations]Bytes = undefined;
    var kept: usize = 0;
    for (order[0..count]) |i| {
        if (kept > 0 and sorted_locs[kept - 1] == locs[i]) continue;
        sorted_locs[kept] = locs[i];
        sorted_ops[kept] = ops[i];
        kept += 1;
    }
    _ = try verify.verify_multi(
        F,
        Sha256,
        Bytes,
        gpa,
        &proof,
        sorted_locs[0..kept],
        sorted_ops[0..kept],
        &input.root,
    );
}

/// A tree over the drawn operations' payloads: a genuine multi-proof of every other leaf from
/// a drawn offset verifies, and fails on a tampered operation or root.
fn genuine_proof(comptime F: type, input: *const Input, offset: u8) !void {
    var storage: [max_operations][max_payload_len]u8 = undefined;
    var locations: [max_operations]u64 = undefined;
    var ops: [max_operations]Bytes = undefined;
    const count = payloads(F, input.ops[0..input.op_count], &storage, &locations, &ops);
    if (count == 0) return;
    const leaves = ops[0..count];
    var hasher = qmdb.hasher(Sha256);
    var mem: merkle.mem.Mem(F, Digest) = .empty;
    defer mem.deinit(gpa);
    const encoded = try verify.encode_all(Bytes, gpa, leaves);
    defer verify.free_encoded(gpa, encoded);
    for (encoded) |bytes| try mem.add(gpa, &hasher, bytes);
    const inactive: usize = 0;
    const root = try mem.root(&hasher, inactive);
    const plan = try merkle.proof.RangePlan(F).init(mem.leaves(), .{ .start = 0, .end = count });
    var range = try plan.build(gpa, &hasher, inactive, &mem);
    defer range.deinit(gpa);
    var store = try verify.to_proof_store(F, Sha256, Bytes, gpa, &range, 0, leaves, &root);
    defer store.deinit(gpa);
    var chosen: [max_operations]u64 = undefined;
    var chosen_ops: [max_operations]Bytes = undefined;
    var n: usize = 0;
    var loc: u64 = offset % count;
    while (loc < count) : (loc += 2) {
        chosen[n] = loc;
        chosen_ops[n] = leaves[@intCast(loc)];
        n += 1;
    }
    assert(n > 0);
    var multi = try store.multi_proof(gpa, chosen[0..n], &.{});
    defer multi.deinit(gpa);
    const V = verify.verify_multi;
    const at = chosen[0..n];
    try testing.expect(try V(F, Sha256, Bytes, gpa, &multi, at, chosen_ops[0..n], &root));
    var bad_root = root;
    bad_root.bytes[0] ^= 1;
    try testing.expect(!try V(F, Sha256, Bytes, gpa, &multi, at, chosen_ops[0..n], &bad_root));
    // A payload one byte longer encodes differently.
    var longer: [max_payload_len + 1]u8 = undefined;
    const first = chosen_ops[0];
    @memcpy(longer[0..first.len], first);
    longer[first.len] = 0;
    chosen_ops[0] = longer[0 .. first.len + 1];
    try testing.expect(!try V(F, Sha256, Bytes, gpa, &multi, at, chosen_ops[0..n], &root));
}

fn run_family(comptime F: type, bytes: []const u8) !void {
    var reader = fuzz_bytes.Reader.init(bytes);
    var input: Input = undefined;
    input.decode(&reader, F);
    try arbitrary_proof(F, &input);
    try genuine_proof(F, &input, reader.int(u8));
}

fn run(bytes: []const u8) anyerror!void {
    try run_family(merkle.mmr.Family, bytes);
    try run_family(merkle.mmb.Family, bytes);
}

test "fuzz qmdb_verify_proof (seeded)" {
    try fuzz_bytes.seeded(512, 0x76657269, 64, run);
}

test "fuzz qmdb_verify_proof" {
    try testing.fuzz({}, fuzz_bytes.smith(512, run), .{});
}
