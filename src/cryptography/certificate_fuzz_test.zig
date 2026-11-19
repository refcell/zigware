//! Decode fuzz for the certificate wire types: the signer bitmap, an attestation, a
//! certificate of individual signatures (ed25519's), and a bls12381 multisig certificate.
//! Inputs are random bytes or a valid encoding mutated by flips, truncation, or extension.
//! Every decode fails cleanly or yields a value that encodes back to exactly the input and
//! keeps the type's invariants: at most `participants` bits, and for a certificate at least
//! one signer and (individual signatures) one signature per signer.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const certificate = @import("certificate.zig");
const ed25519 = @import("ed25519.zig");

const rng = utils.rng;
const FuzzRng = rng.FuzzRng;
const Participant = utils.Participant;
const Signers = certificate.Signers;
const Certificate = ed25519.certificate.Certificate;
const Attestation = certificate.Attestation(struct {
    pub const Signature = ed25519.Signature;
});
const SignatureBytes = certificate.Deferred(ed25519.Signature);
const Multisig = @import("bls12381/certificate/multisig.zig")
    .Certificate(@import("bls12381/primitives/root.zig").MinPk);
const gpa = testing.allocator;

const participants_max = 40;
const input_max = 1024;

/// A valid encoding of `kind` over at most `total` participants, written to `out`.
fn valid_encoding(r: *FuzzRng, kind: u8, total: u32, out: *std.ArrayList(u8)) !void {
    var chosen: [participants_max + 4]Participant = undefined;
    var signers_count: usize = 0;
    for (0..total) |index| {
        if (rng.boolean(r)) {
            chosen[signers_count] = .init(@intCast(index));
            signers_count += 1;
        }
    }
    var signers = try Signers.init(gpa, total, chosen[0..signers_count]);
    defer signers.deinit(gpa);
    // Sometimes the signature count disagrees with the signers, encoded consistently.
    const signatures_count = if (rng.range_at_most(r, u8, 0, 3) == 0)
        rng.range_at_most(r, usize, 0, signers_count + 2)
    else
        signers_count;
    var signatures: [participants_max + 6]SignatureBytes = undefined;
    for (signatures[0..signatures_count]) |*signature| r.fill_bytes(&signature.bytes);
    const encoded = switch (kind) {
        0 => try codec.encode(Signers, gpa, signers),
        1 => blk: {
            const signer: Participant = .init(r.next_u32());
            var attestation: Attestation = .{ .signer = signer, .signature = undefined };
            r.fill_bytes(&attestation.signature.bytes);
            break :blk try codec.encode(Attestation, gpa, attestation);
        },
        2 => try codec.encode(Certificate, gpa, .{
            .signers = signers,
            .signatures = signatures[0..signatures_count],
        }),
        3 => blk: {
            var multisig: Multisig = .{ .signers = signers, .signature = undefined };
            r.fill_bytes(&multisig.signature.bytes);
            break :blk try codec.encode(Multisig, gpa, multisig);
        },
        else => unreachable,
    };
    defer gpa.free(encoded);
    try out.appendSlice(gpa, encoded);
}

/// Flip, truncate, or extend `bytes` a few times.
fn mutate(r: *FuzzRng, bytes: *std.ArrayList(u8)) !void {
    const mutations = rng.range_at_most(r, u8, 0, 3);
    for (0..mutations) |_| {
        switch (rng.range_at_most(r, u8, 0, 2)) {
            0 => if (bytes.items.len > 0) {
                const index = rng.range_less_than(r, usize, 0, bytes.items.len);
                bytes.items[index] ^= rng.range_at_most(r, u8, 1, 255);
            },
            1 => bytes.shrinkRetainingCapacity(rng.range_at_most(r, usize, 0, bytes.items.len)),
            2 => if (bytes.items.len < input_max) {
                var extra: [8]u8 = undefined;
                r.fill_bytes(&extra);
                const count = rng.range_at_most(r, usize, 1, extra.len);
                try bytes.appendSlice(gpa, extra[0..count]);
            },
            else => unreachable,
        }
    }
}

fn expect_canonical(comptime T: type, value: T, bytes: []const u8) !void {
    const encoded = try codec.encode(T, gpa, value);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, bytes, encoded);
}

fn check_decode(kind: u8, bytes: []const u8, participants: usize) !void {
    switch (kind) {
        0 => {
            var signers = codec.decode_cfg(Signers, gpa, bytes, participants) catch return;
            defer signers.deinit(gpa);
            try testing.expect(signers.len() <= participants);
            try testing.expect(signers.count() <= signers.len());
            try expect_canonical(Signers, signers, bytes);
        },
        1 => {
            const attestation = codec.decode(Attestation, gpa, bytes) catch return;
            try expect_canonical(Attestation, attestation, bytes);
        },
        2 => {
            var value = codec.decode_cfg(Certificate, gpa, bytes, participants) catch return;
            defer value.deinit(gpa);
            try testing.expect(value.signers.len() <= participants);
            try testing.expect(value.signers.count() > 0);
            try testing.expectEqual(value.signers.count(), value.signatures.len);
            try expect_canonical(Certificate, value, bytes);
        },
        3 => {
            var value = codec.decode_cfg(Multisig, gpa, bytes, participants) catch return;
            defer value.deinit(gpa);
            try testing.expect(value.signers.len() <= participants);
            try testing.expect(value.signers.count() > 0);
            try expect_canonical(Multisig, value, bytes);
        },
        else => unreachable,
    }
}

fn fuzz_certificate(_: void, r: *FuzzRng) !void {
    const kind = rng.range_at_most(r, u8, 0, 3);
    const participants = rng.range_at_most(r, usize, 0, participants_max);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    if (rng.range_at_most(r, u8, 0, 3) == 0) {
        try bytes.resize(gpa, rng.range_at_most(r, usize, 0, 128));
        r.fill_bytes(bytes.items);
    } else {
        // Encodings over a few more participants than the bound exercise the length check.
        const total = rng.range_at_most(r, u32, 0, @intCast(participants + 4));
        try valid_encoding(r, kind, total, &bytes);
        try mutate(r, &bytes);
    }
    assert(bytes.items.len <= input_max + 8 * 3 + 2048);
    try check_decode(kind, bytes.items, participants);
}

test "fuzz certificate decoders" {
    try utils.fuzz.run({}, fuzz_certificate, 0x6365_7274, 2000);
}
