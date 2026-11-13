//! Configuration for the aggregation engine (commonware `aggregation/config.rs`).
//!
//! Commonware's `Config<P, D, A, Z, M, B, T>` type parameters are the declarations of one
//! comptime parameter type `P`:
//!
//! - `P.Scheme`: the certificate scheme over `Item(P.Digest)` (`scheme.assert_scheme`).
//! - `P.Provider`: per-epoch schemes; `provider.scheme(epoch) ?*const Scheme` returns a
//!   pointer that stays valid while the engine runs.
//! - `P.Digest`: the item digest.
//! - `P.Automaton`: `propose(io, height) Io.Cancelable!?Digest`; null drops the request.
//! - `P.Reporter`: `report(activity) Feedback`, with `Activity(Scheme, Digest)` borrowed for
//!   the call (a reporter that keeps a certificate clones it).
//! - `P.Monitor`: `subscribe() !Subscription`, where the subscription has `latest() Epoch`
//!   and `recv() Io.Cancelable!?Epoch` (null once closed).
//! - `P.Blocker`: `block(peer) Feedback`.
//! - `P.Strategy`: the `parallel` strategy for certificate work.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const scheme = @import("scheme.zig");

const EpochDelta = consensus_types.EpochDelta;
const HeightDelta = consensus_types.HeightDelta;

/// Asserts that `P` declares the engine's types.
pub fn assert_parameters(comptime P: type) void {
    comptime {
        const names = .{
            "Scheme",   "Provider", "Digest",  "Automaton",
            "Reporter", "Monitor",  "Blocker", "Strategy",
        };
        for (names) |name| {
            if (!@hasDecl(P, name)) @compileError(@typeName(P) ++ " lacks " ++ name);
        }
        scheme.assert_scheme(P.Scheme, P.Digest);
    }
}

pub fn Config(comptime P: type) type {
    comptime assert_parameters(P);
    return struct {
        const Self = @This();

        /// Tracks the current epoch, which selects the participants.
        monitor: P.Monitor,
        /// Signing schemes by epoch.
        provider: P.Provider,
        /// Supplies the digest for each height.
        automaton: P.Automaton,
        /// Notified of acks, certificates, and tips.
        reporter: P.Reporter,
        /// Blocks peers that send invalid acks.
        blocker: P.Blocker,
        /// Whether acks are sent as priority messages.
        priority_acks: bool,
        /// How often an ack is rebroadcast while its height has no certificate (non-zero).
        rebroadcast_timeout: utils.Duration,
        /// Epochs kept below and accepted above the current epoch: with bounds (1, 2) at
        /// epoch 10, epochs 9 through 12 are accepted and older ones pruned.
        epoch_bounds: struct { EpochDelta, EpochDelta },
        /// Heights processed concurrently above the tip (non-zero).
        window: u64,
        /// Heights tracked below the tip when collecting acks and pruning.
        activity_timeout: HeightDelta,
        /// Partition of the activity journal.
        journal_partition: []const u8,
        /// Write buffer of each journal section, in bytes.
        journal_write_buffer: usize,
        /// Bytes buffered when replaying the journal.
        journal_replay_buffer: usize,
        /// Heights per journal section (non-zero).
        journal_heights_per_section: u64,
        /// zstd level for journal entries, or null for none.
        journal_compression: ?u8,
        /// Page cache for the journal; outlives the engine.
        journal_page_cache: *runtime.buffer.paged.CacheRef,
        /// Strategy for parallel certificate work.
        strategy: P.Strategy,

        /// Panics when a non-zero setting is zero.
        pub fn assert_valid(self: *const Self) void {
            if (self.rebroadcast_timeout.is_zero()) @panic("rebroadcast_timeout must be non-zero");
            if (self.window == 0) @panic("window must be non-zero");
            if (self.journal_heights_per_section == 0) {
                @panic("journal_heights_per_section must be non-zero");
            }
            assert(self.journal_write_buffer > 0);
            assert(self.journal_replay_buffer > 0);
        }
    };
}
