//! What separates marshal's standard and erasure-coded modes (commonware
//! `marshal/core/variant.rs`).
//!
//! A variant `V` is a namespace type checked by `assert_variant`:
//!
//! - Types: `Block` (what the actor handles), `ApplicationBlock` (what the application builds,
//!   a consensus `Block`), `StoredBlock` (what the archives keep), and `Commitment` (what
//!   consensus orders). All three share `ApplicationBlock.Digest`.
//! - `commitment(*const Block) Commitment`, `commitment_to_inner(Commitment) Block.Digest`,
//!   `parent_commitment(*const Block) Commitment`, and
//!   `stored_parent_commitment(*const StoredBlock) Commitment`.
//! - `check_payload(scheme: anytype, payload: Commitment) bool`: whether consensus may order a
//!   payload under `scheme` (coding checks the embedded coding configuration).
//! - `decode_block(gpa, bytes, block_config, ExpectedCommitment(Commitment), strategy)
//!   codec.Error!Block`: decodes and checks the block against the commitment.
//! - `into_stored(gpa, *const Block) !StoredBlock` (an owned copy for the archive),
//!   `stored_view(*const Block) StoredBlock` (a borrowed form to write, valid while the block
//!   lives and never freed, so archive writes do not copy the payload),
//!   `restore(gpa, StoredBlock, Block.Digest) !Block`, and
//!   `restore_across(gpa, StoredBlock, strategy) !Block` (takes ownership of the stored
//!   block; on error the caller keeps it).
//! - `clone_block(*const Block) Block` (another reference to a shared block) and
//!   `deinit_block(gpa, *Block) void` (drops one), so core owns blocks of either variant.
//! - `into_shared(Block) broadcast.Digested(ApplicationBlock)` and
//!   `from_application_block(broadcast.Digested(ApplicationBlock), Commitment) Block`.
//! - `max_backfill_block_size(application: usize) usize` and
//!   `max_buffer_payload_size(participants: u32, application: usize) usize`.
//!
//! Rust's async `decode_block` and `restore_across` run on a strategy; here they block on it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const traits = @import("../../traits.zig");
const types = @import("../../types.zig");

/// The commitment a fetched block must match (commonware `ExpectedCommitment`). A trusted
/// commitment came from a certificate this node verified; an untrusted one only names what
/// was requested.
pub fn ExpectedCommitment(comptime C: type) type {
    return union(enum) {
        const Self = @This();

        trusted: C,
        untrusted: C,

        pub fn commitment(self: Self) C {
            return switch (self) {
                .trusted, .untrusted => |value| value,
            };
        }
    };
}

const variant_decls = [_][]const u8{
    "Block",                   "ApplicationBlock",         "StoredBlock",
    "Commitment",              "commitment",               "commitment_to_inner",
    "parent_commitment",       "stored_parent_commitment", "check_payload",
    "decode_block",            "into_stored",              "restore",
    "restore_across",          "into_shared",              "from_application_block",
    "max_backfill_block_size", "max_buffer_payload_size",  "clone_block",
    "deinit_block",            "stored_view",
};

pub fn assert_variant(comptime V: type) void {
    comptime {
        for (variant_decls) |decl| {
            if (!@hasDecl(V, decl)) @compileError(@typeName(V) ++ " lacks Variant." ++ decl);
        }
        traits.assert_block(V.ApplicationBlock);
        if (!@hasDecl(V.Block, "Digest") or !@hasDecl(V.StoredBlock, "Digest")) {
            @compileError("Variant.Block and Variant.StoredBlock must declare Digest");
        }
        if (V.Block.Digest != V.ApplicationBlock.Digest) {
            @compileError("Variant.ApplicationBlock must share Block.Digest");
        }
        if (V.StoredBlock.Digest != V.Block.Digest) {
            @compileError("Variant.StoredBlock must share Block.Digest");
        }
    }
}

const buffer_decls = [_][]const u8{
    "PublicKey",
    "find_by_digest",
    "find_by_commitment",
    "subscribe_by_digest",
    "subscribe_by_commitment",
    "send",
};

/// A buffer of blocks not yet finalized (commonware `Buffer<V>`), called on a pointer:
///
/// - `find_by_digest(V.Block.Digest) !?V.Block` and `find_by_commitment(V.Commitment)
///   !?V.Block`: a block the buffer holds now; the caller owns it.
/// - `subscribe_by_digest(V.Block.Digest) !?oneshot.Receiver(V.Block)` and
///   `subscribe_by_commitment(V.Commitment) !?oneshot.Receiver(V.Block)`: a receiver that
///   resolves once the buffer sees the block, or null when the buffer cannot deliver.
/// - `send(Round, V.Block, recipients) !void`: disseminates a block (taking ownership).
pub fn assert_buffer(comptime B: type) void {
    comptime {
        for (buffer_decls) |decl| {
            if (!@hasDecl(B, decl)) @compileError(@typeName(B) ++ " lacks Buffer." ++ decl);
        }
    }
}

/// A buffer that holds nothing (commonware `NoBuffer`), for an actor started without a
/// broadcast buffer. `send` releases the block.
pub fn NoBuffer(comptime V: type, comptime P: type) type {
    return struct {
        const Self = @This();
        const Receiver = utils.channel.oneshot.Receiver(V.Block);
        pub const PublicKey = P;

        gpa: Allocator,

        pub fn find_by_digest(_: *Self, _: V.Block.Digest) error{}!?V.Block {
            return null;
        }

        pub fn find_by_commitment(_: *Self, _: V.Commitment) error{}!?V.Block {
            return null;
        }

        pub fn subscribe_by_digest(_: *Self, _: V.Block.Digest) error{}!?Receiver {
            return null;
        }

        pub fn subscribe_by_commitment(_: *Self, _: V.Commitment) error{}!?Receiver {
            return null;
        }

        pub fn send(self: *Self, _: types.Round, block: V.Block, _: anytype) error{}!void {
            var owned = block;
            V.deinit_block(self.gpa, &owned);
        }
    };
}

test "expected commitment" {
    const Expected = ExpectedCommitment(u32);
    const trusted: Expected = .{ .trusted = 7 };
    const untrusted: Expected = .{ .untrusted = 9 };
    try std.testing.expectEqual(7, trusted.commitment());
    try std.testing.expectEqual(9, untrusted.commitment());
    try std.testing.expect(trusted != .untrusted);
}
