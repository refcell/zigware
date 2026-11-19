//! The `Stateful` actor's parts (commonware `glue/src/stateful/actor`). So far: the syncer's
//! `SyncPlan`, the durable startup decision between peer state sync and recovery from marshal,
//! and the processor's prune schedule, finalization boundary, and speculative state.

const std = @import("std");

pub const plan = @import("syncer/plan.zig");
pub const SyncPlan = plan.SyncPlan;
pub const SyncState = plan.SyncState;
pub const syncer_mailbox = @import("syncer/mailbox.zig");
pub const Artifact = syncer_mailbox.Artifact;
pub const SyncerMailbox = syncer_mailbox.Mailbox;
pub const syncer = @import("syncer/actor.zig");
pub const Syncer = syncer.Syncer;

pub const pruning = @import("processor/pruning.zig");
pub const PruneConfig = pruning.PruneConfig;
pub const Pruning = pruning.Pruning;
pub const Prune = pruning.Prune;
pub const FinalizationBoundary = pruning.FinalizationBoundary;

pub const pending = @import("processor/pending.zig");
pub const Pending = pending.Pending;

pub const execution = @import("processor/execution.zig");
pub const Execution = execution.Execution;
pub const Finality = execution.Finality;
pub const PrepareBatchesError = execution.PrepareBatchesError;
pub const Boxed = @import("processor/boxed.zig").Boxed;

pub const processor = @import("processor/processor.zig");
pub const Processor = processor.Processor;
pub const verifier = @import("processor/verifier.zig");
pub const Verifier = verifier.Verifier;

pub const durability = @import("core/durability.zig");
pub const Durability = durability.Durability;
pub const verifications = @import("core/verifications.zig");
pub const Verifications = verifications.Verifications;
pub const core_mailbox = @import("core/mailbox.zig");
pub const Mailbox = core_mailbox.Mailbox;
pub const processing = @import("core/processing.zig");
pub const Processing = processing.Processing;
pub const syncing = @import("core/syncing.zig");
pub const Syncing = syncing.Syncing;
pub const stateful = @import("core/stateful.zig");
pub const Stateful = stateful.Stateful;
pub const MarshalProvider = stateful.MarshalProvider;

test {
    std.testing.refAllDecls(@This());
    _ = @import("syncer/plan_test.zig");
    _ = @import("syncer/actor_test.zig");
    _ = @import("processor/pruning_test.zig");
    _ = @import("processor/pending_test.zig");
    _ = @import("processor/execution_test.zig");
    _ = @import("processor/processor_test.zig");
    _ = @import("processor/verifier_test.zig");
    _ = @import("core/durability_test.zig");
    _ = @import("core/verifications_test.zig");
    _ = @import("core/mailbox_test.zig");
    _ = @import("core/processing_test.zig");
    _ = @import("core/processing_early_test.zig");
    _ = @import("core/processing_late_test.zig");
    _ = @import("core/syncing_test.zig");
    _ = @import("core/stateful_test.zig");
}
