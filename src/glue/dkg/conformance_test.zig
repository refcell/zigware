//! `CodecConformance` hashes of the DKG types, checked against commonware's glue
//! `conformance.toml`. Each generator ports the type's Rust `Arbitrary` impl (with ed25519
//! identities and `MinSig`), so the encoded values match commonware's.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const math = @import("math");
const p2p = @import("p2p");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const types = @import("types.zig");
const network = @import("network.zig");

const arbitrary = codec.arbitrary;
const Unstructured = arbitrary.Unstructured;
const Error = arbitrary.Error;
const ed25519 = cryptography.ed25519;
const P = ed25519.PublicKey;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const primitives = cryptography.bls12381.primitives;
const Scalar = primitives.group.Scalar;
const MinSig = primitives.MinSig;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Summary = cryptography.transcript.Summary;
const Addresses = network.Addresses(P);

const file = @embedFile("../conformance.toml");
const prefix = "commonware_glue::dkg::";

/// Types holding BLS points multiply a point by a scalar per case; Debug builds take minutes,
/// so they run only in optimized builds or with `-Dslow-tests`.
fn skip_slow() error{SkipZigTest}!void {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
}

fn CodecConformance(comptime T: type, comptime gen: arbitrary.Generator(T)) type {
    return struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const value = try arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

fn verify(
    comptime name: []const u8,
    comptime T: type,
    comptime gen: arbitrary.Generator(T),
    n_cases: u64,
) !void {
    const C = CodecConformance(T, gen);
    try conformance.verify(C, std.heap.smp_allocator, prefix ++ name, n_cases, file);
}

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

/// `Set::arbitrary`: an arbitrary `Vec<P>`, sorted and deduplicated.
fn gen_set(gpa: Allocator, u: *Unstructured) Error!Set(P) {
    var keys: std.ArrayList(P) = .empty;
    while (u.keep_going()) try keys.append(gpa, try gen_public_key(gpa, u));
    return Set(P).from_owned_dedup(gpa, try keys.toOwnedSlice(gpa));
}

/// `arbitrary_iter::<P>().take(limit)` into a `Set`; duplicates are `IncorrectFormat`.
fn gen_set_exact(gpa: Allocator, u: *Unstructured, limit: u64) Error!Set(P) {
    var keys: std.ArrayList(P) = .empty;
    while (keys.items.len < limit and u.keep_going()) {
        try keys.append(gpa, try gen_public_key(gpa, u));
    }
    return Set(P).init(gpa, keys.items) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.IncorrectFormat,
    };
}

/// `Scalar::from_ikm(&u.arbitrary::<[u8; 64]>()?)`.
fn gen_scalar(gpa: Allocator, u: *Unstructured) Error!Scalar {
    const ikm = try arbitrary.value([64]u8, gpa, u);
    return Scalar.from_ikm(&ikm);
}

/// `G::generator() * &u.arbitrary::<Scalar>()?`.
fn gen_point(comptime G: type, gpa: Allocator, u: *Unstructured) Error!G {
    return G.generator.mul(try gen_scalar(gpa, u));
}

/// The generators of BLS-typed values for variant `V`.
fn Gen(comptime V: type) type {
    return struct {
        /// commonware's `Sharing::arbitrary`: a total, a mode, then a `TestRng` seed for a
        /// polynomial of degree `quorum(total) - 1`.
        pub fn gen_sharing(gpa: Allocator, u: *Unstructured) Error!primitives.Sharing(V) {
            const total = u.int_in_range(u32, 1, 100);
            const mode: primitives.Mode = if (u.int_in_range(u8, 0, 1) == 0)
                .non_zero_counter
            else
                .roots_of_unity;
            var rng = utils.rng.TestRng.init(try arbitrary.value(u64, gpa, u));
            const degree = utils.N3f1.quorum(total) - 1;
            const poly = try math.poly.Poly(Scalar).random(gpa, &rng, degree);
            const committed = try math.poly.commit(gpa, V.Public, poly);
            return primitives.Sharing(V).init(gpa, mode, total, committed);
        }

        pub fn gen_output(gpa: Allocator, u: *Unstructured) Error!fd.Output(V, P) {
            const summary: Summary = .{ .bytes = try arbitrary.value([32]u8, gpa, u) };
            const public = try gen_sharing(gpa, u);
            const total: u64 = public.total;
            const dealers = try gen_set_exact(gpa, u, u.int_in_range(u64, 1, total * 2));
            const players = try gen_set_exact(gpa, u, total);
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

        /// `Poly<G>::arbitrary`: the constant, then an arbitrary `Vec<G>`.
        pub fn gen_pub_msg(gpa: Allocator, u: *Unstructured) Error!fd.DealerPubMsg(V) {
            var coefficients: std.ArrayList(V.Public) = .empty;
            try coefficients.append(gpa, try gen_point(V.Public, gpa, u));
            while (u.keep_going()) try coefficients.append(gpa, try gen_point(V.Public, gpa, u));
            const poly = fd.DealerPubMsg(V).Commitment.from_owned(coefficients.items);
            return .{ .commitment = poly };
        }

        pub fn gen_ack_or_reveal(gpa: Allocator, u: *Unstructured) Error!fd.AckOrReveal(P) {
            if (u.int_in_range(u8, 0, 1) == 0) {
                return .{ .ack = .{ .sig = try gen_signature(gpa, u) } };
            }
            return .{ .reveal = .init(try gen_scalar(gpa, u)) };
        }

        /// Tag 0: an arbitrary `HashMap<P, AckOrReveal<P>>` (pairs until the continuation fails)
        /// sorted into a `Map`. Arbitrary keys never repeat in practice.
        pub fn gen_result(gpa: Allocator, u: *Unstructured) Error!fd.DealerResult(P) {
            if (u.int_in_range(u8, 0, 1) == 1) return .too_many_reveals;
            const Results = fd.DealerResult(P).Results;
            var pairs: std.ArrayList(Results.Pair) = .empty;
            while (u.keep_going()) {
                const peer = try gen_public_key(gpa, u);
                try pairs.append(gpa, .{ peer, try gen_ack_or_reveal(gpa, u) });
            }
            return .{ .ok = try Results.from_dedup(gpa, pairs.items) };
        }

        pub fn gen_signed_log(gpa: Allocator, u: *Unstructured) Error!fd.SignedDealerLog(V, P) {
            const dealer = try gen_public_key(gpa, u);
            const pub_msg = try gen_pub_msg(gpa, u);
            const results = try gen_result(gpa, u);
            const log: fd.DealerLog(V, P) = .{ .pub_msg = pub_msg, .results = results };
            return .{ .dealer = dealer, .log = log, .sig = try gen_signature(gpa, u) };
        }

        pub fn info(comptime D: type) arbitrary.Generator(types.EpochInfo(V, P, D)) {
            return struct {
                fn generate(gpa: Allocator, u: *Unstructured) Error!types.EpochInfo(V, P, D) {
                    const outcome = try types.EpochOutcome.arbitrary(gpa, u);
                    const epoch = consensus.Epoch.new(u.int(u64));
                    const output = try gen_output(gpa, u);
                    const players = try gen_set(gpa, u);
                    const next_players = try gen_set(gpa, u);
                    return .{
                        .outcome = outcome,
                        .epoch = epoch,
                        .output = output,
                        .players = players,
                        .next_players = next_players,
                        .directory = try gen_directory(D, gpa, u),
                    };
                }
            }.generate;
        }
    };
}

fn gen_outcome(gpa: Allocator, u: *Unstructured) Error!types.EpochOutcome {
    return types.EpochOutcome.arbitrary(gpa, u);
}

fn gen_participants(gpa: Allocator, u: *Unstructured) Error!types.Participants(P) {
    const dealers = try gen_set(gpa, u);
    const players = try gen_set(gpa, u);
    return .{ .dealers = dealers, .players = players, .next_players = try gen_set(gpa, u) };
}

/// `Map<P, Address>::arbitrary`: an arbitrary `Vec<(P, Address)>` through `from_iter_dedup`.
fn gen_addresses(gpa: Allocator, u: *Unstructured) Error!Addresses {
    var pairs: std.ArrayList(Addresses.Inner.Pair) = .empty;
    while (u.keep_going()) {
        const peer = try gen_public_key(gpa, u);
        try pairs.append(gpa, .{ peer, try p2p.Address.arbitrary(gpa, u) });
    }
    return Addresses.init(gpa, pairs.items);
}

fn gen_directory(comptime D: type, gpa: Allocator, u: *Unstructured) Error!D {
    if (D == Unit) return .{};
    return gen_addresses(gpa, u);
}

const Sig = Gen(MinSig);

fn gen_payload(comptime D: type) arbitrary.Generator(types.Payload(MinSig, P, D)) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!types.Payload(MinSig, P, D) {
            if (u.boolean()) return .{ .dealer_log = try Sig.gen_signed_log(gpa, u) };
            return .{ .epoch_info = try Sig.info(D)(gpa, u) };
        }
    }.generate;
}

fn gen_message(gpa: Allocator, u: *Unstructured) Error!types.Message(MinSig, P) {
    if (u.boolean()) {
        const pub_msg = try Sig.gen_pub_msg(gpa, u);
        return .{ .dealer = .{ .pub_msg = pub_msg, .priv_msg = .init(try gen_scalar(gpa, u)) } };
    }
    return .{ .ack = .{ .sig = try gen_signature(gpa, u) } };
}

const addressed = "Addresses<\ned25519::PublicKey>";

test "conformance: dkg epoch outcome, participants, and addresses" {
    // Minutes in Debug, so it runs in optimized builds (CI's ReleaseSafe job) or -Dslow-tests.
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    const cases = conformance.default_cases;
    try verify(
        "types::conformance::CodecConformance<EpochOutcome>",
        types.EpochOutcome,
        gen_outcome,
        cases,
    );
    try verify(
        "types::conformance::CodecConformance<Participants<ed25519::PublicKey>>",
        types.Participants(P),
        gen_participants,
        cases,
    );
    try verify(
        "network::conformance::CodecConformance<Addresses<ed25519::PublicKey>>",
        Addresses,
        gen_addresses,
        cases,
    );
}

test "conformance: dkg epoch info" {
    try skip_slow();
    try verify(
        "types::conformance::CodecConformance<EpochInfo<MinSig,ed25519::PublicKey>>",
        types.EpochInfo(MinSig, P, Unit),
        Sig.info(Unit),
        8192,
    );
    try verify(
        "types::conformance::CodecConformance<EpochInfo<MinSig,ed25519::PublicKey," ++
            addressed ++ ">>",
        types.EpochInfo(MinSig, P, Addresses),
        Sig.info(Addresses),
        8192,
    );
}

test "conformance: dkg payload and message" {
    try skip_slow();
    try verify(
        "types::conformance::CodecConformance<Payload<MinSig,ed25519::PublicKey>>",
        types.Payload(MinSig, P, Unit),
        gen_payload(Unit),
        8192,
    );
    try verify(
        "types::conformance::CodecConformance<Payload<MinSig,ed25519::PublicKey," ++
            "Addresses<ed25519\n::PublicKey>>>",
        types.Payload(MinSig, P, Addresses),
        gen_payload(Addresses),
        8192,
    );
    try verify(
        "types::conformance::CodecConformance<Message<MinSig,ed25519::PublicKey>>",
        types.Message(MinSig, P),
        gen_message,
        conformance.default_cases,
    );
}

const Scheme = @import("state_sync_test.zig").Scheme;
const Sha256 = cryptography.sha256.Sha256;
const Digest = cryptography.sha256.Digest;
const Floor = consensus.simplex.types.Finalization(Scheme, Digest);
const Pk = Gen(primitives.MinPk);

/// `Sha256Digest::arbitrary`: the hash of up to 256 arbitrary bytes.
fn gen_digest(gpa: Allocator, u: *Unstructured) Error!Digest {
    const data = try gpa.alloc(u8, u.int_in_range(u64, 0, 256));
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

/// `Finalization::arbitrary` for the mock scheme: a proposal, then a `U64` certificate.
fn gen_floor(gpa: Allocator, u: *Unstructured) Error!Floor {
    const round = try consensus.Round.arbitrary(gpa, u);
    const parent = try consensus.View.arbitrary(gpa, u);
    const proposal: consensus.simplex.types.Proposal(Digest) = .init(
        round,
        parent,
        try gen_digest(gpa, u),
    );
    const certificate = utils.sequence.U64.from_bytes(try arbitrary.value([8]u8, gpa, u));
    return .{ .proposal = proposal, .certificate = certificate };
}

fn gen_state_sync(comptime D: type) arbitrary.Generator(StateSync(D)) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!StateSync(D) {
            const info = try Pk.info(D)(gpa, u);
            return .{ .info = info, .floor = try gen_floor(gpa, u) };
        }
    }.generate;
}

fn StateSync(comptime D: type) type {
    return @import("state_sync.zig").StateSync(Scheme, Digest, primitives.MinPk, D);
}

test "conformance: dkg state sync" {
    try skip_slow();
    const name = "state_sync::conformance::CodecConformance<StateSync<mocks::TestScheme," ++
        "mocks::TestDigest,mocks\n::TestBlsVariant";
    try verify(name ++ ">>", StateSync(Unit), gen_state_sync(Unit), 8192);
    const addressed_name = name ++ ",Addresses<mocks::TestPublicKey>>>";
    try verify(addressed_name, StateSync(Addresses), gen_state_sync(Addresses), 8192);
}

const Event = @import("reshare/event.zig").Event(MinSig, P);

/// `Event::arbitrary`: `int_in_range(0..=2)`, then the key and its message.
fn gen_event(gpa: Allocator, u: *Unstructured) Error!Event {
    const choice = u.int_in_range(u32, 0, 2);
    const key = try gen_public_key(gpa, u);
    return switch (choice) {
        0 => .{ .dealing = .{ .dealer = key, .public = try Sig.gen_pub_msg(gpa, u) } },
        1 => .{ .ack = .{ .player = key, .ack = .{ .sig = try gen_signature(gpa, u) } } },
        else => .{ .log = .{ .dealer = key, .log = .{
            .pub_msg = try Sig.gen_pub_msg(gpa, u),
            .results = try Sig.gen_result(gpa, u),
        } } },
    };
}

test "conformance: dkg reshare journal event" {
    try skip_slow();
    const name = "reshare::store::conformance::CodecConformance<Event<MinSig,ed25519::PublicKey>>";
    try verify(name, Event, gen_event, conformance.default_cases);
}
