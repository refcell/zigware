//! Threshold key generation and continuous resharing for epoch-based consensus (commonware
//! `glue::dkg`).
//!
//! `dkg` creates a BLS12-381 threshold key with a one-shot bootstrap ceremony and rotates its
//! shares across application epochs with reshare. Both use Feldman-Desmedt DKG and resharing
//! (`cryptography.bls12381.dkg.feldman_desmedt`).
//!
//! Each epoch has _dealers_ who hold shares from the previous output, _players_ receiving new
//! shares, and _next players_ announced one epoch before their ceremony. A `types.EpochInfo`
//! describes the epoch's public output, participants, and transport directory. Genesis carries
//! epoch zero's info, and each epoch's final block carries the next epoch's info.
//!
//! The application supplies, as comptime interfaces checked by the `assert_*` functions below:
//!
//! - a block type (`assert_reshare_block`) that may carry a reshare `types.Payload`;
//! - a `Registrar` that installs each epoch's threshold scheme into the consensus provider;
//! - a `SecretStore` for private ceremony material (shares, dealer seeds, private dealings);
//! - a `ParticipantsProvider` for future committees and transport directories.
//!
//! Rust's async trait methods block on the runtime's `std.Io` here: the caller passes `io`
//! and runs them with `io.async` to wait on several at once (as in `consensus.traits`).
//! Wire formats (`types.Message`, `types.Payload`) are byte-identical to commonware's.
//!
//! The `dkg` section of docs/lanes/glue.md tracks what is ported.

const std = @import("std");
const consensus = @import("consensus");

pub const fence = @import("fence.zig");
pub const limits = @import("limits.zig");
pub const max_payload_size = limits.max_payload_size;
pub const network = @import("network.zig");
pub const orchestrator = @import("orchestrator/root.zig");
pub const probe = @import("probe/mod.zig");
pub const reshare = @import("reshare/root.zig");
pub const state_sync = @import("state_sync.zig");
pub const types = @import("types.zig");

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime trait: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ trait ++ "." ++ decl);
            }
        }
    }
}

/// Asserts `B` is a `consensus` block that may carry a reshare payload: `B.Variant` (the BLS
/// variant), `B.PublicKey` (the participant key), `B.Directory` (the epoch artifacts'
/// transport directory), and `b.payload(gpa) !?types.Payload(Variant, PublicKey, Directory)`,
/// an owned copy of the payload when the block carries one.
pub fn assert_reshare_block(comptime B: type) void {
    comptime {
        consensus.traits.assert_block(B);
        assert_decls(B, &.{ "Variant", "PublicKey", "Directory", "payload" }, "ReshareBlock");
    }
}

/// Asserts `R` installs epoch-scoped threshold schemes into the consensus provider:
/// `R.Variant`, `R.PublicKey`, and `r.register(io, epoch, info: types.SchemeInfo(...))`.
/// When `register` returns, the provider must return the scheme for `epoch`; repeated calls
/// with the same epoch and info must be safe. `register` takes ownership of `info`.
pub fn assert_registrar(comptime R: type) void {
    assert_decls(R, &.{ "Variant", "PublicKey", "register" }, "Registrar");
}

/// Asserts `S` is application-owned storage for the secret material of DKG and reshare
/// ceremonies: `put_share`/`get_share` (this node's share per epoch), `put_seed`/`get_seed`
/// (this node's dealer RNG seed per epoch, replayed after a restart so a dealer deals the same
/// shares), `put_dealing`/`get_dealing` (private dealings received from each dealer), and
/// `prune(io, min)` (drops secrets older than `min`). All stored material must stay private,
/// and writes must be durable when they return: losing one can make a dealer equivocate after
/// a restart or lose a share already in use.
pub fn assert_secret_store(comptime S: type) void {
    assert_decls(S, &.{
        "put_share",   "get_share",   "put_seed", "get_seed",
        "put_dealing", "get_dealing", "prune",
    }, "SecretStore");
}

/// Asserts `P` is the source of the participant sets and transport directories of future
/// epochs: `P.PublicKey`, `P.Directory`, `p.participants(io, gpa, epoch) !Set(PublicKey)`, and
/// `p.directory(io, gpa, epoch, peers) !Directory`. For the same inputs, repeated calls and all
/// honest nodes must return the same value; divergence prevents agreement on the epoch's final
/// block. Participant sets are non-empty and hold at most `max_participants` keys, and a
/// directory names exactly `peers`.
pub fn assert_participants_provider(comptime P: type) void {
    const decls = &.{ "PublicKey", "Directory", "participants", "directory" };
    assert_decls(P, decls, "ParticipantsProvider");
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("tests/mocks.zig");
}
