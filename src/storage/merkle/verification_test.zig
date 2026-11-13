//! Tests for `verification.zig`, ported from commonware's `storage/src/merkle/verification.rs`,
//! plus the `merkle_proof_store` fuzz target (storage/fuzz).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const merkle = @import("mod.zig");
const verification = @import("verification.zig");
const fuzz_bytes = @import("../fuzz_bytes.zig");

const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const H = merkle.hasher.Standard(Sha256);
const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;

fn Mem(comptime F: type) type {
    return merkle.mem.Mem(F, D);
}

fn Store(comptime F: type) type {
    return verification.ProofStore(F, D);
}

fn test_digest(value: u64) D {
    return Sha256.hash(&.{&.{@as(u8, @truncate(value))}});
}

/// A structure whose element `i` is `test_digest(i)`; `elements` receives the elements.
fn build(comptime F: type, elements: []D) !Mem(F) {
    const hasher = H.init(.forward_fold);
    var mem: Mem(F) = .empty;
    errdefer mem.deinit(gpa);
    for (elements, 0..) |*element, i| {
        element.* = test_digest(i);
        try mem.add(gpa, &hasher, &element.bytes);
    }
    return mem;
}

fn range(start: u64, end: u64) merkle.Range {
    return .{ .start = start, .end = end };
}

/// Every sub-range of `start..end` re-proven from `store` verifies under `root`.
fn expect_all_subranges(
    comptime F: type,
    store: *const Store(F),
    hasher: *const H,
    elements: []const D,
    start: u64,
    end: u64,
    root: *const D,
) !void {
    for (start..end) |sub_start| {
        for (sub_start + 1..end + 1) |sub_end| {
            var proof = try store.range_proof(gpa, hasher, range(sub_start, sub_end));
            defer proof.deinit(gpa);
            const proven = elements[sub_start..sub_end];
            try testing.expect(proof.verify_range_inclusion(hasher, sub_start, proven, root));
        }
    }
}

test "multi_proof rejects invalid inactive peaks" {
    var elements: [11]D = undefined;
    var mem = try build(Mmr, &elements);
    defer mem.deinit(gpa);
    var peaks_buffer: [merkle.max_pinned_nodes]D = undefined;
    const peaks = mem.peaks(&peaks_buffer).len;
    var proof = try verification.multi_proof(Mmr, gpa, &mem, peaks, &.{ 1, 7 });
    proof.deinit(gpa);
    const result = verification.multi_proof(Mmr, gpa, &mem, peaks + 1, &.{ 1, 7 });
    try testing.expectError(error.InvalidProof, result);
}

fn proof_store_shrinking(comptime F: type) !void {
    const hasher = H.init(.forward_fold);
    var elements: [49]D = undefined;
    var mem = try build(F, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var start: u64 = 0;
    var end: u64 = 49;
    while (start < end) : ({
        start += 1;
        end -= 1;
    }) {
        var proof = try mem.range_proof(gpa, &hasher, range(start, end), 0);
        defer proof.deinit(gpa);
        var store = try Store(F).init(gpa, &hasher, &proof, start, elements[start..end], &root);
        defer store.deinit(gpa);
        var sub_start = start;
        var sub_end = end;
        while (sub_start < sub_end) : ({
            sub_start += 1;
            sub_end -= 1;
        }) {
            var sub = try store.range_proof(gpa, &hasher, range(sub_start, sub_end));
            defer sub.deinit(gpa);
            const proven = elements[sub_start..sub_end];
            try testing.expect(sub.verify_range_inclusion(&hasher, sub_start, proven, &root));
        }
    }
}

test "proof store proves shrinking sub-ranges" {
    try proof_store_shrinking(Mmr);
    try proof_store_shrinking(Mmb);
}

test "proof store with a fold prefix" {
    // 49 MMR leaves have peaks over 0..32, 32..48, and 48: proving 32..49 folds the first.
    const hasher = H.init(.forward_fold);
    var elements: [49]D = undefined;
    var mem = try build(Mmr, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = try mem.range_proof(gpa, &hasher, range(32, 49), 0);
    defer proof.deinit(gpa);
    var store = try Store(Mmr).init(gpa, &hasher, &proof, 32, elements[32..49], &root);
    defer store.deinit(gpa);
    try expect_all_subranges(Mmr, &store, &hasher, &elements, 32, 49, &root);
}

test "proof store with a fold prefix (mmb)" {
    // With 8 leaves the oldest MMB peak covers 0..4 but sits at position 7, after leaf 4 at
    // position 6: classifying the fold prefix by position would get it wrong.
    const hasher = H.init(.forward_fold);
    var elements: [8]D = undefined;
    var mem = try build(Mmb, &elements);
    defer mem.deinit(gpa);
    const root = try mem.root(&hasher, 0);
    var proof = try mem.range_proof(gpa, &hasher, range(4, 8), 0);
    defer proof.deinit(gpa);
    var store = try Store(Mmb).init(gpa, &hasher, &proof, 4, elements[4..8], &root);
    defer store.deinit(gpa);
    try expect_all_subranges(Mmb, &store, &hasher, &elements, 4, 8, &root);
}

test "proof store with a backward-fold suffix (mmb)" {
    var elements: [123]D = undefined;
    var mem = try build(Mmb, &elements);
    defer mem.deinit(gpa);
    const hasher = H.init(.backward_fold);
    const root = try mem.root(&hasher, 0);
    var proof = try verification.historical_range_proof(
        Mmb,
        gpa,
        &hasher,
        &mem,
        mem.leaves(),
        range(0, 1),
        0,
    );
    defer proof.deinit(gpa);
    var store = try Store(Mmb).init(gpa, &hasher, &proof, 0, elements[0..1], &root);
    defer store.deinit(gpa);
    var same = try store.range_proof(gpa, &hasher, range(0, 1));
    defer same.deinit(gpa);
    try testing.expect(same.verify_range_inclusion(&hasher, 0, elements[0..1], &root));
    try testing.expectError(error.ElementPruned, store.range_proof(gpa, &hasher, range(64, 65)));
}

test "proof store with a backward-fold inactive prefix (mmb)" {
    // Proving the whole active region folds the inactive prefix and leaves no suffix.
    var elements: [123]D = undefined;
    var mem = try build(Mmb, &elements);
    defer mem.deinit(gpa);
    const inactive_peaks = 2;
    var active_start: u64 = 0;
    var peaks = Mmb.peaks(mem.size());
    for (0..inactive_peaks) |_| active_start += @as(u64, 1) << @intCast(peaks.next().?.height);
    const total = mem.leaves();
    try testing.expect(active_start > 0 and active_start < total);

    const hasher = H.init(.backward_fold);
    const root = try mem.root(&hasher, inactive_peaks);
    const proven = range(active_start, total);
    var proof = try verification.historical_range_proof(
        Mmb,
        gpa,
        &hasher,
        &mem,
        total,
        proven,
        inactive_peaks,
    );
    defer proof.deinit(gpa);
    const proven_elements = elements[active_start..total];
    var store = try Store(Mmb).init(gpa, &hasher, &proof, active_start, proven_elements, &root);
    defer store.deinit(gpa);
    try expect_all_subranges(Mmb, &store, &hasher, &elements, active_start, total, &root);
    // The inactive prefix peaks were folded into one accumulator, so they are gone.
    try testing.expectError(error.ElementPruned, store.range_proof(gpa, &hasher, range(0, 1)));
}

test "proof store multi_proof reports compressed suffix peaks (mmb)" {
    var elements: [123]D = undefined;
    var mem = try build(Mmb, &elements);
    defer mem.deinit(gpa);
    const hasher = H.init(.backward_fold);
    const root = try mem.root(&hasher, 0);
    const target = [_]u64{0};
    const selected = [_]D{elements[0]};

    var direct = try verification.multi_proof(Mmb, gpa, &mem, 0, &target);
    defer direct.deinit(gpa);
    try testing.expect(try direct.verify_multi_inclusion(gpa, &hasher, &target, &selected, &root));

    // A backward-folded proof of one leaf folds the other active peaks into one accumulator.
    var proof = try verification.historical_range_proof(
        Mmb,
        gpa,
        &hasher,
        &mem,
        mem.leaves(),
        range(0, 1),
        0,
    );
    defer proof.deinit(gpa);
    var store = try Store(Mmb).init(gpa, &hasher, &proof, 0, elements[0..1], &root);
    defer store.deinit(gpa);
    const hidden = store.suffix_peak_positions();
    try testing.expect(hidden.len > 0);
    try testing.expectError(error.CompressedDigest, store.multi_proof(gpa, &target, &.{}));

    var supplied: [merkle.max_pinned_nodes]Store(Mmb).NodeDigest = undefined;
    for (hidden, supplied[0..hidden.len]) |position, *node| {
        node.* = .{ .position = position, .digest = mem.get_node(position).? };
    }
    var derived = try store.multi_proof(gpa, &target, supplied[0..hidden.len]);
    defer derived.deinit(gpa);
    try testing.expect(try derived.verify_multi_inclusion(gpa, &hasher, &target, &selected, &root));
}

test "historical range proof matches the structure's own range proof" {
    const hasher = H.init(.forward_fold);
    var elements: [37]D = undefined;
    var mem = try build(Mmr, &elements);
    defer mem.deinit(gpa);
    var expected = try mem.range_proof(gpa, &hasher, range(5, 30), 1);
    defer expected.deinit(gpa);
    var actual = try verification.range_proof(Mmr, gpa, &hasher, &mem, range(5, 30), 1);
    defer actual.deinit(gpa);
    try testing.expect(expected.eql(&actual));
    try mem.prune(8);
    const pruned = verification.range_proof(Mmr, gpa, &hasher, &mem, range(5, 30), 1);
    try testing.expectError(error.ElementPruned, pruned);
}

// Fuzz (`merkle_proof_store`): commonware feeds raw proofs, which almost never verify, so this
// also proves random ranges of a real structure under either bagging and inactive boundary.
// A verified store must re-prove every sub-range; tampering must fail `init`; any proof the
// store does return must verify; multi-proofs must reject unsorted or repeated locations.

const fuzz_leaves_max = 160;

fn fuzz_peak_count(comptime F: type, size: u64) usize {
    var count: usize = 0;
    var peaks = F.peaks(size);
    while (peaks.next()) |_| count += 1;
    return count;
}

fn fuzz_raw(comptime F: type, reader: *fuzz_bytes.Reader) !void {
    const hasher = H.init(if (reader.boolean()) .forward_fold else .backward_fold);
    var digests: [64]D = undefined;
    const count = reader.below(digests.len + 1);
    for (digests[0..count]) |*digest| digest.* = .{ .bytes = @bitCast(reader.int(u256)) };
    var elements: [8]D = undefined;
    const element_count = reader.below(elements.len + 1);
    for (elements[0..element_count]) |*element| element.* = test_digest(reader.int(u8));
    const proof: Store(F).Proof = .{
        .leaves = reader.below(F.max_leaves + 1),
        .inactive_peaks = reader.below(66),
        .digests = digests[0..count],
    };
    const root: D = .{ .bytes = @bitCast(reader.int(u256)) };
    const start = reader.int(u64);
    var store = Store(F).init(gpa, &hasher, &proof, start, elements[0..element_count], &root) catch
        return;
    defer store.deinit(gpa);
    var sub = store.range_proof(gpa, &hasher, range(start, start + 1)) catch return;
    sub.deinit(gpa);
}

const FuzzCase = struct {
    hasher: H,
    leaves: u64,
    inactive_peaks: usize,
    proven: merkle.Range,
};

fn fuzz_case(comptime F: type, reader: *fuzz_bytes.Reader, mem: *const Mem(F)) FuzzCase {
    const leaves = mem.leaves();
    const start = reader.below(leaves);
    const end = start + 1 + reader.below(leaves - start);
    assert(start < end and end <= leaves);
    return .{
        .hasher = H.init(if (reader.boolean()) .forward_fold else .backward_fold),
        .leaves = leaves,
        .inactive_peaks = reader.below(fuzz_peak_count(F, mem.size()) + 1),
        .proven = range(start, end),
    };
}

fn fuzz_structured(comptime F: type, reader: *fuzz_bytes.Reader) !void {
    var elements: [fuzz_leaves_max]D = undefined;
    const leaves = 1 + reader.below(fuzz_leaves_max);
    var mem = try build(F, elements[0..leaves]);
    defer mem.deinit(gpa);
    const case = fuzz_case(F, reader, &mem);
    const hasher = &case.hasher;
    const root = try mem.root(hasher, case.inactive_peaks);
    const proven = case.proven;
    var proof = try verification.historical_range_proof(
        F,
        gpa,
        hasher,
        &mem,
        leaves,
        proven,
        case.inactive_peaks,
    );
    defer proof.deinit(gpa);
    var own = try mem.range_proof(gpa, hasher, proven, case.inactive_peaks);
    defer own.deinit(gpa);
    try testing.expect(own.eql(&proof));

    const proven_elements = elements[proven.start..proven.end];
    if (proof.digests.len > 0 and reader.below(4) == 0) {
        const slot = reader.below(proof.digests.len);
        proof.digests[slot].bytes[reader.below(32)] ^= 1 + reader.int(u8) % 255;
        const tampered = Store(F).init(gpa, hasher, &proof, proven.start, proven_elements, &root);
        if (tampered) |unexpected| {
            var leaked = unexpected;
            leaked.deinit(gpa);
            return error.TestUnexpectedResult;
        } else |err| {
            try testing.expect(err == error.RootMismatch or err == error.InvalidProof);
        }
        return;
    }
    var store = try Store(F).init(gpa, hasher, &proof, proven.start, proven_elements, &root);
    defer store.deinit(gpa);
    try fuzz_subranges(F, reader, &store, hasher, elements[0..leaves], proven, &root);
    try fuzz_multi(F, reader, &store, &mem, hasher, elements[0..leaves], &root);
}

fn fuzz_subranges(
    comptime F: type,
    reader: *fuzz_bytes.Reader,
    store: *const Store(F),
    hasher: *const H,
    elements: []const D,
    proven: merkle.Range,
    root: *const D,
) !void {
    for (0..4) |_| {
        // Inside the proven range: must re-prove. Anywhere: a returned proof must verify.
        const inside = reader.boolean();
        const bound = if (inside) proven else range(0, elements.len);
        const start = bound.start + reader.below(bound.end - bound.start);
        const end = start + 1 + reader.below(bound.end - start);
        var proof = store.range_proof(gpa, hasher, range(start, end)) catch |err| {
            if (inside) return err;
            continue;
        };
        defer proof.deinit(gpa);
        try testing.expect(proof.verify_range_inclusion(hasher, start, elements[start..end], root));
    }
}

fn fuzz_multi(
    comptime F: type,
    reader: *fuzz_bytes.Reader,
    store: *const Store(F),
    mem: *const Mem(F),
    hasher: *const H,
    elements: []const D,
    root: *const D,
) !void {
    var raw: [8]u64 = undefined;
    const count = 1 + reader.below(raw.len);
    for (raw[0..count]) |*location| location.* = reader.below(elements.len + 2);
    var sorted_buffer = raw;
    const sorted = sorted_buffer[0..count];
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));
    var unique: usize = 1;
    for (sorted[1..]) |location| {
        if (location == sorted[unique - 1]) continue;
        sorted[unique] = location;
        unique += 1;
    }
    // Supply every peak (or none) from the structure itself.
    var peaks: [merkle.max_pinned_nodes]Store(F).NodeDigest = undefined;
    var peak_count: usize = 0;
    if (reader.boolean()) {
        var iterator = F.peaks(mem.size());
        while (iterator.next()) |peak| : (peak_count += 1) {
            const digest = mem.get_node(peak.position).?;
            peaks[peak_count] = .{ .position = peak.position, .digest = digest };
        }
    }
    const result = store.multi_proof(gpa, sorted[0..unique], peaks[0..peak_count]);
    if (!std.mem.eql(u64, sorted[0..unique], raw[0..count])) {
        const raw_result = store.multi_proof(gpa, raw[0..count], peaks[0..peak_count]);
        if (raw_result) |unexpected| {
            var leaked = unexpected;
            leaked.deinit(gpa);
            return error.TestUnexpectedResult;
        } else |err| if (result) |_| {
            try testing.expect(err == error.DuplicateLocation or err == error.UnsortedLocation);
        } else |_| {}
    }
    var proof = result catch return;
    defer proof.deinit(gpa);
    var selected_buffer: [8]D = undefined;
    const locations = sorted[0..unique];
    const selected = selected_buffer[0..unique];
    for (locations, selected) |location, *element| element.* = elements[location];
    const verified = proof.verify_multi_inclusion(gpa, hasher, locations, selected, root);
    try testing.expect(try verified);
}

fn fuzz_run(bytes: []const u8) anyerror!void {
    inline for (.{ Mmr, Mmb }) |F| {
        var reader = fuzz_bytes.Reader.init(bytes);
        if (reader.below(8) == 0) try fuzz_raw(F, &reader) else try fuzz_structured(F, &reader);
    }
}

test "fuzz merkle proof store (seeded)" {
    try fuzz_bytes.seeded(256, 0x70726f6f66, 64, fuzz_run);
}

test "fuzz merkle proof store" {
    try testing.fuzz({}, fuzz_bytes.smith(256, fuzz_run), .{});
}
