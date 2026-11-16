//! Marshal's configuration (commonware `marshal/config.rs`).
//!
//! `Config(P)` takes a parameter type `P` declaring `Scheme` (the certificate scheme),
//! `Provider` (`scheme(epoch) ?*const Scheme`), `Epocher` (`types.assert_epocher`),
//! `Strategy` (a `parallel` strategy), `ApplicationBlock`, `Block` (the start block), and
//! `Commitment`.
//!
//! # Epocher and provider coverage
//!
//! Any height marshal is asked to sync must be covered by both the epocher and the provider.
//! If either returns null for a requested height, responses to resolver requests for it are
//! ignored: the request is retired without validating the response, attributing it to the
//! serving peer, or retrying. Failing to cover a height marshal still needs to process the
//! canonical chain stalls marshal. Applications may prune epocher and provider entries once
//! the last processed height (`H - max_pending_acks` after an `Update.block` at `H`) passes
//! them.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const runtime = @import("runtime");
const types = @import("../types.zig");
const simplex_types = @import("../simplex/types.zig");

/// Startup anchor for marshal. Durable progress from a previous run takes precedence when it
/// already supersedes the configured anchor (including the processed round floor, which
/// covers every finalization round seen for a processed block or an installed floor
/// anchor). A later start neither verifies nor fetches a floor whose round that floor
/// covers.
pub fn Start(comptime S: type, comptime C: type, comptime B: type) type {
    return union(enum) {
        /// Start from the height-zero genesis block.
        genesis: B,
        /// Start from a finalized commitment.
        floor: simplex_types.Finalization(S, C),
    };
}

pub fn assert_parameters(comptime P: type) void {
    comptime {
        const decls = [_][]const u8{
            "Scheme",           "Provider", "Epocher",    "Strategy",
            "ApplicationBlock", "Block",    "Commitment",
        };
        for (decls) |decl| {
            if (!@hasDecl(P, decl)) @compileError(@typeName(P) ++ " lacks marshal Config." ++ decl);
        }
        types.assert_epocher(P.Epocher);
    }
}

pub fn Config(comptime P: type) type {
    comptime assert_parameters(P);
    return struct {
        const Self = @This();

        /// Signing schemes by epoch; must cover every epoch with heights marshal syncs.
        provider: P.Provider,
        /// Epoch lengths by height; must cover every height marshal syncs.
        epocher: P.Epocher,
        /// Startup anchor for marshal's processed floor.
        start: Start(P.Scheme, P.Commitment, P.Block),
        /// The prefix of every storage partition.
        partition_prefix: []const u8,
        /// Size of the backfill request and response mailbox.
        mailbox_size: u32,
        /// Minimum number of views to keep temporary data behind the previously witnessed
        /// finalization round, for peers that may still want it. Views restart each epoch:
        /// the views the window lacks in that round's epoch count one per height below it,
        /// and the epoch holding the lowest such height is kept whole. Where the epocher
        /// cannot place those heights, each earlier epoch counts as one view.
        view_retention: types.ViewDelta,
        /// Items per section of the prunable archives.
        prunable_items_per_section: u64,
        /// The page cache of the freezer journals; borrowed.
        page_cache: *runtime.buffer.paged.CacheRef,
        /// Replay buffer size of the storage archives, in bytes.
        replay_buffer: usize,
        /// Write buffer size of the archives' key journals, in bytes.
        key_write_buffer: usize,
        /// Write buffer size of the archives' value journals, in bytes.
        value_write_buffer: usize,
        /// Codec configuration of the application block; `max_payload_size` sizes marshal's
        /// payloads from the bound it reports.
        block_codec_config: codec.Cfg(P.ApplicationBlock),
        /// Most missing finalized heights fetched from peers at a time. Repair fetches the
        /// lowest missing heights above the processed height and moves up as they fill.
        /// Blocks requested by commitment, hints, and subscriptions are not counted.
        max_repair: u32,
        /// Most dispatched blocks awaiting application acknowledgement; up to twice this
        /// many finalized blocks stay in memory for dispatch without archive reads.
        max_pending_acks: u32,
        /// Strategy for parallel operations.
        strategy: P.Strategy,

        /// Panics on a zero where commonware requires a non-zero value.
        pub fn assert_valid(self: *const Self) void {
            if (self.mailbox_size == 0) @panic("mailbox_size must be non-zero");
            if (self.prunable_items_per_section == 0) {
                @panic("prunable_items_per_section must be non-zero");
            }
            if (self.max_repair == 0) @panic("max_repair must be non-zero");
            if (self.max_pending_acks == 0) @panic("max_pending_acks must be non-zero");
            assert(self.replay_buffer > 0);
            assert(self.key_write_buffer > 0 and self.value_write_buffer > 0);
        }
    };
}

test "config takes distinct application and start blocks" {
    const cryptography = @import("cryptography");
    const parallel = @import("parallel");
    const mocks_block = @import("mocks/block.zig");
    const simplex_scheme = @import("../simplex/root.zig").scheme;
    const Sha256 = cryptography.Sha256;
    const S = simplex_scheme.ed25519.Scheme(Sha256.Digest);
    const Parameters = struct {
        pub const Scheme = S;
        pub const Provider = cryptography.certificate.ConstantProvider(S);
        pub const Epocher = types.FixedEpocher;
        pub const Strategy = parallel.Sequential;
        pub const ApplicationBlock = mocks_block.Block(Sha256, types.Round);
        pub const Block = mocks_block.EmptyBlock(Sha256);
        pub const Commitment = Sha256.Digest;
    };
    const C = Config(Parameters);
    try std.testing.expect(@FieldType(C, "start") == Start(S, Sha256.Digest, Parameters.Block));
    try std.testing.expect(@FieldType(C, "block_codec_config") == void);
}
