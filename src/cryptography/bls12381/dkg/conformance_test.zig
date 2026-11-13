//! `CodecConformance` hashes of the Feldman-Desmedt DKG messages, checked against
//! commonware's cryptography `conformance.toml`. Each generator ports the Rust `Arbitrary`
//! impl of the message (with ed25519 identities and `MinPk`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const math = @import("math");
const ed25519 = @import("../../ed25519.zig");
const Summary = @import("../../transcript.zig").Summary;
const primitives = @import("../primitives/root.zig");
const shared = @import("../conformance_test.zig");
const fd = @import("feldman_desmedt.zig");

const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const MinPk = primitives.MinPk;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;

const module = "dkg::feldman_desmedt::test::conformance::";

/// `PrivateKey::random(StdRng::from_seed(u.arbitrary::<[u8; 32]>()))`.
fn gen_private_key(gpa: Allocator, u: *Unstructured) Error!ed25519.PrivateKey {
    var rng = utils.rng.TestRng.init_key(try arbitrary.value([32]u8, gpa, u));
    return ed25519.PrivateKey.random(&rng);
}

fn gen_public_key(gpa: Allocator, u: *Unstructured) Error!P {
    const private_key = try gen_private_key(gpa, u);
    return private_key.public_key();
}

/// A random key signs up to 255 arbitrary bytes under the empty namespace.
fn gen_signature(gpa: Allocator, u: *Unstructured) Error!ed25519.Signature {
    const private_key = try gen_private_key(gpa, u);
    const len = try arbitrary.value(usize, gpa, u) % 256;
    // `arbitrary_iter().take(len)`: a continuation byte before each element, none after.
    var message: std.ArrayList(u8) = .empty;
    while (message.items.len < len and u.keep_going()) try message.append(gpa, u.int(u8));
    assert(message.items.len <= len);
    return private_key.sign("", message.items);
}

/// `arbitrary_iter::<P>().take(limit)` into a `Set`; duplicates are `IncorrectFormat`.
fn gen_key_set(gpa: Allocator, u: *Unstructured, limit: u64) Error!Set(P) {
    var keys: std.ArrayList(P) = .empty;
    while (keys.items.len < limit and u.keep_going()) {
        try keys.append(gpa, try gen_public_key(gpa, u));
    }
    return Set(P).init(gpa, keys.items) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.IncorrectFormat,
    };
}

/// `Poly<G>::arbitrary`: the constant, then an arbitrary `Vec<G>`.
fn gen_pub_msg(gpa: Allocator, u: *Unstructured) Error!fd.DealerPubMsg(MinPk) {
    const gen = shared.gen_point(MinPk.Public);
    var coefficients: std.ArrayList(MinPk.Public) = .empty;
    try coefficients.append(gpa, try gen(gpa, u));
    while (u.keep_going()) try coefficients.append(gpa, try gen(gpa, u));
    const poly = fd.DealerPubMsg(MinPk).Commitment.from_owned(coefficients.items);
    return .{ .commitment = poly };
}

fn gen_priv_msg(gpa: Allocator, u: *Unstructured) Error!fd.DealerPrivMsg {
    return .init(try shared.gen_scalar(gpa, u));
}

fn gen_ack(gpa: Allocator, u: *Unstructured) Error!fd.PlayerAck(P) {
    return .{ .sig = try gen_signature(gpa, u) };
}

fn gen_ack_or_reveal(gpa: Allocator, u: *Unstructured) Error!fd.AckOrReveal(P) {
    if (u.int_in_range(u8, 0, 1) == 0) return .{ .ack = try gen_ack(gpa, u) };
    return .{ .reveal = try gen_priv_msg(gpa, u) };
}

/// Tag 0: an arbitrary `HashMap<P, AckOrReveal<P>>` (pairs until the continuation fails)
/// sorted into a `Map`. Arbitrary keys never repeat in practice.
fn gen_result(gpa: Allocator, u: *Unstructured) Error!fd.DealerResult(P) {
    if (u.int_in_range(u8, 0, 1) == 1) return .too_many_reveals;
    const Results = fd.DealerResult(P).Results;
    var pairs: std.ArrayList(Results.Pair) = .empty;
    while (u.keep_going()) {
        const key = try gen_public_key(gpa, u);
        try pairs.append(gpa, .{ key, try gen_ack_or_reveal(gpa, u) });
    }
    return .{ .ok = try Results.from_dedup(gpa, pairs.items) };
}

fn gen_log(gpa: Allocator, u: *Unstructured) Error!fd.DealerLog(MinPk, P) {
    const pub_msg = try gen_pub_msg(gpa, u);
    return .{ .pub_msg = pub_msg, .results = try gen_result(gpa, u) };
}

fn gen_signed_log(gpa: Allocator, u: *Unstructured) Error!fd.SignedDealerLog(MinPk, P) {
    const dealer = try gen_public_key(gpa, u);
    const log = try gen_log(gpa, u);
    return .{ .dealer = dealer, .log = log, .sig = try gen_signature(gpa, u) };
}

/// commonware's `Sharing::arbitrary`: a total, a mode, then a `TestRng` seed for a
/// polynomial of degree `quorum(total) - 1`.
fn gen_sharing(gpa: Allocator, u: *Unstructured) Error!primitives.Sharing(MinPk) {
    const total = u.int_in_range(u32, 1, 100);
    const mode: primitives.Mode = if (u.int_in_range(u8, 0, 1) == 0)
        .non_zero_counter
    else
        .roots_of_unity;
    var rng = utils.rng.TestRng.init(try arbitrary.value(u64, gpa, u));
    const degree = utils.N3f1.quorum(total) - 1;
    const poly = try math.poly.Poly(primitives.group.Scalar).random(gpa, &rng, degree);
    const committed = try math.poly.commit(gpa, MinPk.Public, poly);
    return primitives.Sharing(MinPk).init(gpa, mode, total, committed);
}

fn gen_output(gpa: Allocator, u: *Unstructured) Error!fd.Output(MinPk, P) {
    const summary: Summary = .{ .bytes = try arbitrary.value([32]u8, gpa, u) };
    const public = try gen_sharing(gpa, u);
    const total: u64 = public.total;
    const dealers = try gen_key_set(gpa, u, u.int_in_range(u64, 1, total * 2));
    const players = try gen_key_set(gpa, u, total);
    // `players.iter().filter(arbitrary bool).take(max_faults(total))`.
    const max_revealed = utils.N3f1.max_faults(public.total);
    var revealed: std.ArrayList(P) = .empty;
    for (players.items) |player| {
        if (revealed.items.len == max_revealed) break;
        if (u.boolean()) try revealed.append(gpa, player);
    }
    return .{
        .summary = summary,
        .public = public,
        .dealers = dealers,
        .players = players,
        .revealed = try Set(P).from_dedup(gpa, revealed.items),
    };
}

test "conformance: feldman-desmedt small messages" {
    try shared.skip_slow();
    try shared.verify(module ++ "CodecConformance<DealerPrivMsg>", fd.DealerPrivMsg, gen_priv_msg);
    const Ack = fd.PlayerAck(P);
    try shared.verify(module ++ "CodecConformance<PlayerAck<ed25519::PublicKey>>", Ack, gen_ack);
    try shared.verify(
        module ++ "CodecConformance<AckOrReveal<ed25519::PublicKey>>",
        fd.AckOrReveal(P),
        gen_ack_or_reveal,
    );
}

test "conformance: feldman-desmedt dealer messages and logs" {
    try shared.skip_slow();
    try shared.verify(
        module ++ "CodecConformance<DealerPubMsg<MinPk>>",
        fd.DealerPubMsg(MinPk),
        gen_pub_msg,
    );
    try shared.verify(
        module ++ "CodecConformance<DealerResult<ed25519::PublicKey>>",
        fd.DealerResult(P),
        gen_result,
    );
    try shared.verify(
        module ++ "CodecConformance<DealerLog<MinPk,ed25519::PublicKey>>",
        fd.DealerLog(MinPk, P),
        gen_log,
    );
    try shared.verify(
        module ++ "CodecConformance<SignedDealerLog<MinPk,ed25519::PublicKey>>",
        fd.SignedDealerLog(MinPk, P),
        gen_signed_log,
    );
}

test "conformance: feldman-desmedt output" {
    try shared.skip_slow();
    try shared.verify(
        module ++ "CodecConformance<Output<MinPk,ed25519::PublicKey>>",
        fd.Output(MinPk, P),
        gen_output,
    );
}
