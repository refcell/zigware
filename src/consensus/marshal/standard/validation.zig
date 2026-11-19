//! Verification steps the standard inline and deferred wrappers share (commonware
//! `marshal/standard/validation.rs`): the epoch and re-proposal precheck, the parent wait with
//! the standard ancestry invariants, and application verification over a two-block ancestry.
//!
//! The application verifies with `verify(*A, ctx, consensus_context, ancestry) !bool`, the
//! counterpart of `application.build`'s `propose`: it owns `ancestry`, must free it, and must
//! be cancelable. `ctx` is a runtime context (`child`, `io`).
//!
//! Blocks are `broadcast.Digested(B)` handles. Functions that take a block by value take
//! ownership of that handle; those that take a pointer borrow it.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const utils = @import("utils");
const ancestry = @import("../ancestry.zig");
const app_validation = @import("../application/validation.zig");
const gates = @import("../application/gates.zig");

const oneshot = utils.channel.oneshot;

/// Why a block fails standard verification.
pub const Error = error{
    /// The block does not name the parent it was checked against.
    ParentDigest,
    /// The parent is not the one the verification context expects.
    ExpectedParentDigest,
    /// The block is not one height above its parent.
    Height,
};

/// Checks that `block` names `parent`, that `parent` is the expected `parent_digest`, and
/// that the block is one height above it (commonware `validate_block`).
pub fn validate_block(block: anytype, parent: @TypeOf(block), parent_digest: anytype) Error!void {
    const inner = block.inner();
    if (!inner.parent().eql(parent.digest())) return error.ParentDigest;
    if (!parent.digest().eql(parent_digest)) return error.ExpectedParentDigest;
    if (!ancestry.has_contiguous_height(parent.inner().height(), inner.height())) {
        return error.Height;
    }
}

/// The outcome of the shared precheck (commonware `Decision`): verification is `complete`
/// with a verdict, or it continues with the block.
pub fn Decision(comptime Block: type) type {
    return union(enum) {
        complete: bool,
        @"continue": Block,
    };
}

/// Checks that the block's height belongs to the context's epoch and handles re-proposals,
/// which `digest == context.parent[1]` signals (commonware `precheck_epoch_and_reproposal`).
/// A valid re-proposal is marked verified in marshal and completes as valid; null means
/// marshal is gone. Takes `block`; it is returned only to continue.
pub fn precheck_epoch_and_reproposal(
    epocher: anytype,
    marshal: anytype,
    context: anytype,
    digest: anytype,
    block: anytype,
) !?Decision(@TypeOf(block)) {
    var owned = block;
    const height = owned.inner().height();
    if (!app_validation.is_block_in_expected_epoch(epocher, height, context.epoch())) {
        owned.deinit();
        return .{ .complete = false };
    }
    // Re-proposals skip the parent and height checks: consensus settled the block when it
    // certified the view that first carried it, and parent == block by construction.
    if (!digest.eql(context.parent[1])) return .{ .@"continue" = owned };
    if (!app_validation.is_valid_reproposal_at_verify(epocher, height, context.epoch())) {
        owned.deinit();
        return .{ .complete = false };
    }
    // Marshal takes the block.
    if (!try marshal.verified(context.round, owned)) return null;
    return .{ .complete = true };
}

/// The outcome of awaiting the parent (commonware `ParentCheck`): structurally `valid`,
/// carrying the parent for application verification, or `invalid` (bad parent linkage or a
/// non-contiguous height), so the verdict is false and the block must not be stored.
pub fn ParentCheck(comptime Block: type) type {
    return union(enum) {
        valid: Block,
        invalid,
    };
}

/// Awaits `parent_request` (a subscription to `parent_commitment` the caller started, so the
/// fetch overlaps earlier work) and checks the standard ancestry invariants of `block`
/// against it (commonware `await_and_validate_parent`). Null when work should stop: `tx`'s
/// receiver closed (consensus dropped it) or the parent never arrives. Borrows `block`,
/// `parent_request`, and `tx`.
pub fn await_and_validate_parent(
    comptime T: type,
    io: Io,
    parent_commitment: anytype,
    block: anytype,
    parent_request: anytype,
    tx: *const oneshot.Sender(T),
) Io.Cancelable!?ParentCheck(Child(@TypeOf(block))) {
    const Block = Child(@TypeOf(block));
    comptime assert(Child(@TypeOf(parent_request)) == oneshot.Receiver(Block));
    const result = try gates.recv_unless_closed(T, Block, io, tx, parent_request) orelse
        return null;
    var parent = result catch return null;
    validate_block(block, &parent, parent_commitment) catch {
        parent.deinit();
        return .invalid;
    };
    return .{ .valid = parent };
}

/// Runs `application.verify` over the two-block ancestry `block, parent` (commonware
/// `run_app_verify`). The block must already have passed `await_and_validate_parent`. Null
/// when `tx`'s receiver closes first, which cancels the verification. Storing the block is
/// separate, so callers can run it concurrently (durability is independent of validity).
/// Takes `block` and `parent`; borrows `application` (a pointer) and `marshal`.
pub fn run_app_verify(
    comptime T: type,
    runtime_context: anytype,
    context: anytype,
    block: anytype,
    parent: @TypeOf(block),
    application: anytype,
    marshal: anytype,
    tx: *const oneshot.Sender(T),
    fetch_duration: anytype,
) !?bool {
    comptime assert(@typeInfo(@TypeOf(application)) == .pointer);
    var blocks = [2]@TypeOf(block){ block, parent };
    // On success the stream owns both handles.
    // Bounded by the verified round: it ends the need for every ancestor fetched.
    const bound = context.round;
    const stream = marshal.ancestor_stream(&blocks, bound, fetch_duration) catch |err| {
        for (&blocks) |*owned| owned.deinit();
        return err;
    };
    const app_context = runtime_context.child("app_verify");
    const io = runtime_context.io();
    return verify_unless_closed(T, io, tx, application, app_context, context, stream);
}

/// `application.verify(ctx, context, stream)` unless `tx`'s receiver closes first (null).
/// The application owns `stream` from the call on.
fn verify_unless_closed(
    comptime T: type,
    io: Io,
    tx: *const oneshot.Sender(T),
    application: anytype,
    ctx: anytype,
    context: anytype,
    stream: anytype,
) !?bool {
    const A = Child(@TypeOf(application));
    const Verdict = @typeInfo(@TypeOf(A.verify)).@"fn".return_type.?;
    // The arguments outgrow a task closure, so the task reads them through one pointer; this
    // frame outlives the task (the select is drained before returning).
    const Job = struct {
        application: @TypeOf(application),
        ctx: @TypeOf(ctx),
        context: @TypeOf(context),
        stream: @TypeOf(stream),

        fn run(job: *@This()) Verdict {
            return job.application.verify(job.ctx, job.context, job.stream);
        }
    };
    var job: Job = .{
        .application = application,
        .ctx = ctx,
        .context = context,
        .stream = stream,
    };
    const Outcome = union(enum) { closed: Io.Cancelable!void, verified: Verdict };
    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);
    select.concurrent(.closed, oneshot.Sender(T).closed, .{tx.*}) catch {
        var owned = stream;
        owned.deinit();
        return error.Canceled;
    };
    select.concurrent(.verified, Job.run, .{&job}) catch {
        select.cancelDiscard();
        var owned = stream;
        owned.deinit();
        return error.Canceled;
    };
    const first = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    select.cancelDiscard();
    return switch (first) {
        .closed => null,
        .verified => |verdict| try verdict,
    };
}

fn Child(comptime P: type) type {
    return switch (@typeInfo(P)) {
        .pointer => |info| info.child,
        else => P,
    };
}

test {
    _ = @import("validation_test.zig");
}
