//! The `validator` subcommand (commonware `examples/dkg/src/validator.rs`): one node running
//! p2p, broadcast, marshal, the DKG probe, the QMDB resolver, the reshare actor, the
//! orchestrator, and the stateful application until one of them stops.
//!
//! So far this holds the probe's configuration over the persisted state-sync plan. The actor
//! wiring follows once glue.stateful's `Stateful` actor and the QMDB resolver actor land
//! (docs/lanes/examples-dkg.md).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const types = @import("types.zig");

const consensus = zigware.consensus;
const glue = zigware.glue;

/// Partition of the validator's `Secrets` store.
pub const partition: types.Partition = .validator;

/// The marshal variant: whole blocks, committed by digest.
pub const Variant = consensus.marshal.standard.Standard(types.Block);

/// The durable choice between peer state sync and recovery from marshal.
pub const Plan = glue.stateful.SyncPlan(types.Scheme, Variant);

/// How long the probe waits before re-soliciting floors.
pub const probe_retry_timeout_ns: u64 = 500 * std.time.ns_per_ms;

/// The DKG probe's configuration, bootstrapped from `genesis`'s participants at epoch zero
/// and floored at `plan`'s persisted state-sync floor, if any (commonware `probe_config`).
/// `P` declares the probe's types; `verifier` must outlive the probe.
pub fn probe_config(
    comptime P: type,
    gpa: Allocator,
    manager: P.Manager,
    blocker: P.Blocker,
    genesis: *const types.EpochInfo,
    plan: *const Plan,
    verifier: *const types.Scheme,
) Allocator.Error!glue.dkg.probe.Probe(P).Config {
    comptime assert(P.Scheme == types.Scheme);
    comptime assert(P.Variant == Variant);
    var participants = try genesis.participants(gpa);
    errdefer participants.deinit(gpa);
    const info = try genesis.clone(gpa);
    const floor_epoch: ?types.Epoch = if (plan.floor()) |floor| floor.epoch() else null;
    assert(floor_epoch == null or plan.may_sync());
    return .{
        .discovery = .{
            .manager = manager,
            .bootstrap = .{ .epoch = .zero(), .participants = participants, .directory = .{} },
            .floor_epoch = floor_epoch,
            .verifier = verifier,
            .genesis = info,
            .blocker = blocker,
            .blocks_per_epoch = types.blocks_per_epoch,
            .block_cfg = {},
        },
        .retry_timeout_ns = probe_retry_timeout_ns,
        .mailbox_size = types.mailbox_size,
    };
}
