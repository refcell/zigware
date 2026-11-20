//! commonware `glue/src/stateful/actor/core/processing.rs` tests from its first half (lines
//! 2055-2440): maintenance keeping owned requests and retained work, a retained verification
//! finishing during finalization, finalization completing a build that processes the finalized
//! parent, and a recovered handoff ancestry executing once. The fixture is in `testing.zig`;
//! commonware's `ReplayGatedApp` gates are the processor harness's `Probe` gates, and its
//! `process_calls` are the `process_log` records.

const std = @import("std");
const testing = std.testing;
const utils = @import("utils");
const fixture_mod = @import("testing.zig");

const gpa = testing.allocator;
const harness = fixture_mod.harness;
const Fixture = fixture_mod.Fixture;
const Mailbox = fixture_mod.Mailbox;
const TestBlock = harness.TestBlock;
const Probe = harness.Probe;
const Digest = @TypeOf(TestBlock.genesis().digest());
const oneshot = utils.channel.oneshot;
const ProcessLog = std.ArrayList(harness.TestApp.ProcessRecord);

fn check(fixture: *Fixture) void {
    fixture.deinit() catch |err| std.debug.panic("processing failed: {}", .{err});
}

/// The `process` calls `log` recorded on `digest` (commonware `process_calls.at`).
fn processed(log: *const ProcessLog, digest: Digest) u32 {
    var count: u32 = 0;
    for (log.items) |record| {
        std.debug.assert(record.len > 0); // Every call processes the head of its ancestry.
        if (record.digests[0].eql(digest)) count += 1;
    }
    return count;
}

/// A probe gate whose release is dropped on any exit, so a failed assertion still lets the
/// held application call end.
const Held = struct {
    started: oneshot.Receiver(void),
    release: ?oneshot.Sender(void),

    fn add(probe: *Probe) !Held {
        const gate = try probe.add_gate();
        return .{ .started = gate.started, .release = gate.release };
    }

    /// Waits (bounded) until the held call starts.
    fn await_started(held: *Held) !void {
        // Each pass sleeps 1 ms; the bound is a hang guard.
        for (0..10_000) |_| {
            if (held.started.is_ready()) return held.started.recv();
            try test_io.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }

    fn open(held: *Held) !void {
        var sender = held.release.?;
        held.release = null;
        try sender.send({});
    }

    fn deinit(held: *Held) void {
        held.started.deinit();
        if (held.release) |*sender| sender.deinit();
    }
};

/// Receives from `receiver` once it is ready (bounded, so a missing answer fails).
fn await_ready(comptime T: type, receiver: *oneshot.Receiver(T)) !T {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (receiver.is_ready()) return receiver.recv();
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Waits until `waiter`'s block is acknowledged (bounded, so a lost acknowledgement fails).
fn await_acknowledged(waiter: *const utils.acknowledgement.Exact.Waiter) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        if (waiter.poll()) |outcome| return outcome;
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Sends a prepare on `blocks` (the parent first) at view `0xff` without waiting, and returns
/// its answer's receiver.
fn prepare_async(fixture: *Fixture, blocks: []const TestBlock) !oneshot.Receiver(Mailbox.Built) {
    const pair = try oneshot.channel(Mailbox.Built, gpa, test_io.io);
    try fixture.send(.{ .propose = .{
        .context = .{ .round = harness.round(0xff) },
        .ancestry = try fixture.harness.ancestry(blocks),
        .upstream = {},
        .proposal = .{ .prepare = pair.sender },
    } });
    return pair.receiver;
}

/// The shared side of a `GatedAncestry`: whether its blocks are available, how many
/// acquisitions cloned it, and whether a cloned acquisition was dropped (maintenance drops
/// an acquisition when it pauses it).
const AncestryGate = struct {
    mutex: std.Io.Mutex = .init,
    open: bool = false,
    clones: u32 = 0,
    parked: bool = false,
    /// Ancestries over this gate not yet freed (commonware's `PendingAncestry` owner count).
    live: u32 = 0,

    fn read(gate: *AncestryGate, comptime field: []const u8) @FieldType(AncestryGate, field) {
        gate.mutex.lockUncancelable(test_io.io);
        defer gate.mutex.unlock(test_io.io);
        return @field(gate, field);
    }

    fn release(gate: *AncestryGate) void {
        gate.mutex.lockUncancelable(test_io.io);
        defer gate.mutex.unlock(test_io.io);
        gate.open = true;
    }

    /// Waits until an acquisition was dropped (bounded: a hang guard).
    fn await_parked(gate: *AncestryGate) !void {
        for (0..10_000) |_| {
            if (gate.read("parked")) return;
            try test_io.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }
};

/// commonware's `GatedAncestry` and `PendingAncestry`: an ancestry whose first `always`
/// blocks are available at once and whose rest wait for its gate to open; with no gated
/// blocks it never ends. Each clone is one acquisition.
const GatedAncestry = struct {
    pub const Block = TestBlock;

    gate: *AncestryGate,
    blocks: [3]?harness.Digested = .{ null, null, null },
    index: usize = 0,
    always: usize = 0,
    acquisition: bool = false,

    fn init(
        gate: *AncestryGate,
        blocks: []const TestBlock,
        always: usize,
    ) !harness.Execution.Ancestry {
        std.debug.assert(blocks.len <= 3 and always <= blocks.len);
        var ancestry: GatedAncestry = .{ .gate = gate, .always = always };
        gate.mutex.lockUncancelable(test_io.io);
        gate.live += 1;
        gate.mutex.unlock(test_io.io);
        for (blocks, 0..) |block, index| ancestry.blocks[index] = try harness.digested(block);
        return harness.Execution.Ancestry.init(gpa, ancestry);
    }

    fn available(self: *const GatedAncestry) bool {
        return self.index < self.always or self.gate.read("open");
    }

    pub fn peek(self: *const GatedAncestry) ?*const harness.Digested {
        if (self.index >= self.blocks.len or !self.available()) return null;
        return if (self.blocks[self.index]) |*block| block else null;
    }

    pub fn next(self: *GatedAncestry) !?harness.Digested {
        // Waits for the gate (cancelable): a gate that never opens never ends the stream.
        while (!self.available()) try test_io.io.sleep(.fromMilliseconds(1), .awake);
        if (self.index >= self.blocks.len) return null;
        const block = self.blocks[self.index] orelse return null;
        self.blocks[self.index] = null;
        self.index += 1;
        return block;
    }

    pub fn clone(self: *const GatedAncestry) !GatedAncestry {
        self.gate.mutex.lockUncancelable(test_io.io);
        self.gate.clones += 1;
        self.gate.live += 1;
        self.gate.mutex.unlock(test_io.io);
        var copy = self.*;
        copy.acquisition = true;
        for (&copy.blocks) |*slot| {
            if (slot.*) |block| slot.* = block.clone();
        }
        return copy;
    }

    pub fn deinit(self: *GatedAncestry) void {
        for (&self.blocks) |*slot| if (slot.*) |*block| block.deinit();
        self.gate.mutex.lockUncancelable(test_io.io);
        defer self.gate.mutex.unlock(test_io.io);
        std.debug.assert(self.gate.live > 0);
        self.gate.live -= 1;
        if (self.acquisition) self.gate.parked = true;
    }
};

/// Sends a verification over `ancestry` (taken) and returns its verdict's receiver.
fn verify_with(
    fixture: *Fixture,
    ancestry: harness.Execution.Ancestry,
) !oneshot.Receiver(bool) {
    const pair = try oneshot.channel(bool, gpa, test_io.io);
    try fixture.send(.{ .verify = .{ .ancestry = ancestry, .verification = pair.sender } });
    return pair.receiver;
}

/// A grandparent of genesis at view 1 and its child at view 2, built in a scratch harness so
/// the fixture holds neither's state, as after a restart.
fn recovered_pair() !struct { TestBlock, TestBlock } {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    const grandparent = try scratch.stage_pending_child(&genesis, 1);
    const parent, var batch = try scratch.build_child(&grandparent, 2);
    batch.deinit();
    return .{ grandparent, parent };
}

fn recovered_handoff(verify_first: bool) !void {
    const grandparent, const parent = try recovered_pair();
    // The probe and log outlive the loop, which may still reach them as it stops.
    var log: ProcessLog = .empty;
    defer log.deinit(gpa);
    var probe: Probe = .{ .target = parent.digest() };
    defer probe.deinit();
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    // Marshal holds the grandparent, and the actor has cached neither it nor the parent.
    try fixture.harness.provider_state.insert(grandparent);
    const app = &fixture.processing.verifications.verifier.app;
    app.process_log = &log;
    var gate = try Held.add(&probe);
    defer gate.deinit();
    app.probe = &probe;

    // The second request is sent once the first has reached the application, and joins its
    // execution of the parent.
    const blocks: []const TestBlock = &.{ parent, grandparent };
    var verdict: oneshot.Receiver(bool) = undefined;
    var prepare: oneshot.Receiver(Mailbox.Built) = undefined;
    if (verify_first) verdict = try fixture.verify(blocks) else {
        prepare = try prepare_async(&fixture, blocks);
    }
    try gate.await_started();
    if (verify_first) prepare = try prepare_async(&fixture, blocks) else {
        verdict = try fixture.verify(blocks);
    }
    defer verdict.deinit();
    defer prepare.deinit();
    try fixture.await_joiners(parent.digest(), 2);
    try testing.expect(!verdict.is_ready());
    try testing.expect(!prepare.is_ready());

    try gate.open();
    try testing.expect(try await_ready(bool, &verdict));
    const built = try await_ready(Mailbox.Built, &prepare);
    defer built.discard();
    try testing.expect(built.handoff == .vote);
    try testing.expect(built.handoff.vote.inner().parent().eql(parent.digest()));
    try testing.expectEqual(1, processed(&log, grandparent.digest()));
    try testing.expectEqual(1, processed(&log, parent.digest()));
}

// commonware `recovered_handoff_ancestry_executes_once` (verify_first case): with neither the
// handoff parent nor its parent cached, as after a restart, the parent's verification and a
// handoff build on it execute each block once. Adapted: commonware awaits marshal's replies to
// learn the second request joined; here the flight's joiner count shows it.
test "stateful processing: a recovered handoff ancestry executes once, verify first" {
    try recovered_handoff(true);
}

// commonware `recovered_handoff_ancestry_executes_once` (prepare_first case).
test "stateful processing: a recovered handoff ancestry executes once, prepare first" {
    try recovered_handoff(false);
}

/// Genesis, `first` at view 1, `losing` (on `first`) at 2, `winner` (on `first`) at 3, and
/// `tip` (on `losing`) at 4, built in a scratch harness so the fixture holds none of them.
fn retained_family() !struct { TestBlock, TestBlock, TestBlock, TestBlock } {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    const first = try scratch.stage_pending_child(&genesis, 1);
    const losing = try scratch.stage_pending_child(&first, 2);
    const winner, var winner_batch = try scratch.build_child(&first, 3);
    winner_batch.deinit();
    const tip, var tip_batch = try scratch.build_child(&losing, 4);
    tip_batch.deinit();
    return .{ first, losing, winner, tip };
}

fn retained_verification(recover_parent: bool) !void {
    const genesis = TestBlock.genesis();
    const first, const losing, const winner, const tip = try retained_family();
    // The probes and log outlive the loop, which may still reach them as it stops.
    var log: ProcessLog = .empty;
    defer log.deinit(gpa);
    var probe: Probe = .{ .target = losing.digest() };
    defer probe.deinit();
    var hook_probe: Probe = .{ .target = first.digest() };
    defer hook_probe.deinit();
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    // Marshal holds the blocks a verification may fetch as parents.
    try fixture.harness.provider_state.insert(first);
    try fixture.harness.provider_state.insert(losing);
    const verifier = &fixture.processing.verifications.verifier.app;
    verifier.process_log = &log;
    var gate = try Held.add(&probe);
    defer gate.deinit();
    verifier.probe = &probe;
    var hook = try Held.add(&hook_probe);
    defer hook.deinit();
    fixture.processing.processor.app.finalized_probe = &hook_probe;

    // Cache the parent so its finalization retains the child's processing.
    var cached = try fixture.verify(&.{ first, genesis });
    defer cached.deinit();
    try testing.expect(try cached.recv());
    const recovering: []const TestBlock = &.{ tip, losing };
    const one_step: []const TestBlock = &.{ losing, first };
    const blocks = if (recover_parent) recovering else one_step;
    var verdict = try fixture.verify(blocks);
    defer verdict.deinit();
    try gate.await_started();

    // Hold the first finalized hook while the child completes and another finalization
    // waits.
    var first_waiter = try fixture.finalize(first);
    defer first_waiter.deinit();
    var winner_waiter = try fixture.finalize(winner);
    defer winner_waiter.deinit();
    try hook.await_started();
    try gate.open();
    try testing.expect(try await_ready(bool, &verdict));
    try testing.expectEqual(1, processed(&log, losing.digest()));
    try testing.expectEqual(@intFromBool(recover_parent), processed(&log, tip.digest()));
    try testing.expect(first_waiter.poll() == null);
    try hook.open();
    try await_acknowledged(&first_waiter);
    try await_acknowledged(&winner_waiter);
}

// commonware `retained_verification_finishes_during_finalization` (one_step case): a
// compatible execution advances through its remaining step while the parent's finalized hook
// is held and another finalization waits.
test "stateful processing: a retained verification finishes during finalization" {
    try retained_verification(false);
}

// commonware `retained_verification_finishes_during_finalization` (recovered_parent case): the
// same when the verification first recovers its parent.
test "stateful processing: a retained recovering verification finishes during finalization" {
    try retained_verification(true);
}

const Managed = enum { verify, prepare, propose };

/// A request on the first of `blocks` in flight: a verification's verdict, or a build's
/// answer (commonware `send_managed`).
const ManagedRequest = union(Managed) {
    verify: oneshot.Receiver(bool),
    prepare: oneshot.Receiver(Mailbox.Built),
    propose: oneshot.Receiver(Mailbox.Digested),

    fn send(fixture: *Fixture, kind: Managed, blocks: []const TestBlock) !ManagedRequest {
        std.debug.assert(blocks.len == 2);
        return switch (kind) {
            .verify => .{ .verify = try fixture.verify(blocks) },
            .prepare => .{ .prepare = try prepare_async(fixture, blocks) },
            .propose => .{ .propose = try fixture.propose_async(blocks, 0xff) },
        };
    }

    fn is_ready(request: *const ManagedRequest) bool {
        return switch (request.*) {
            inline else => |*receiver| receiver.is_ready(),
        };
    }

    /// Whether the request accepted `block`: a valid verdict, or a build of a child of it,
    /// which goes to `built` (owned by the caller).
    fn accepted(request: *ManagedRequest, block: TestBlock, built: *?Mailbox.Digested) !bool {
        switch (request.*) {
            .verify => |*verdict| return await_ready(bool, verdict),
            .prepare => |*receiver| {
                const answer = try await_ready(Mailbox.Built, receiver);
                if (answer.handoff != .vote) {
                    answer.discard();
                    return false;
                }
                built.* = answer.handoff.vote;
            },
            .propose => |*receiver| {
                built.* = await_ready(Mailbox.Digested, receiver) catch |err| switch (err) {
                    error.Closed => return false, // Declined: no block.
                    else => return err,
                };
            },
        }
        return built.*.?.inner().parent().eql(block.digest());
    }

    fn deinit(request: *ManagedRequest) void {
        switch (request.*) {
            inline else => |*receiver| receiver.deinit(),
        }
    }
};

/// A parent of genesis at view 1, built in a scratch harness so the fixture does not hold
/// its state.
fn uncached_parent() !TestBlock {
    var scratch: harness.Harness = undefined;
    try scratch.init();
    defer scratch.deinit();
    const genesis = TestBlock.genesis();
    return scratch.stage_pending_child(&genesis, 1);
}

/// The probes `finalization_completes_build` reads, installed on the fixture's apps.
const BuildProbes = struct {
    log: ProcessLog = .empty,
    /// Parks the acquisition finalization pauses; the loop drops it as it stops.
    ancestry_gate: AncestryGate = .{},
    candidate: Probe,
    finalized_path: Probe,
    capture: Probe,

    fn install(probes: *BuildProbes, fixture: *Fixture) void {
        const verifier = &fixture.processing.verifications.verifier.app;
        verifier.process_log = &probes.log;
        verifier.probe = &probes.candidate;
        fixture.processing.processor.app.probe = &probes.finalized_path;
        fixture.processing.processor.app.capture_probe = &probes.capture;
    }

    fn deinit(probes: *BuildProbes) void {
        probes.log.deinit(gpa);
        probes.candidate.deinit();
        probes.finalized_path.deinit();
        probes.capture.deinit();
    }
};

fn finalization_completes_build(build: Managed, verify_first: ?bool) !void {
    std.debug.assert(build != .verify);
    const genesis = TestBlock.genesis();
    const parent = try uncached_parent();
    const target = parent.digest();
    // The probes outlive the loop, which may still reach them as it stops.
    var probes: BuildProbes = .{
        .candidate = .{ .target = target },
        .finalized_path = .{ .target = target },
        .capture = .{ .target = target },
    };
    defer probes.deinit();
    var fixture: Fixture = undefined;
    try fixture.init();
    defer check(&fixture);
    var gate = try Held.add(&probes.candidate);
    defer gate.deinit();
    probes.install(&fixture);

    // The gate holds the first request's candidate processing of the uncached parent, and a
    // second request on the parent, if any, joins that processing.
    const blocks: []const TestBlock = &.{ parent, genesis };
    const first_kind = if (verify_first orelse false) .verify else build;
    var first = try ManagedRequest.send(&fixture, first_kind, blocks);
    defer first.deinit();
    try gate.await_started();
    var second: ?ManagedRequest = null;
    defer if (second) |*request| request.deinit();
    if (verify_first) |verifies| {
        second = try ManagedRequest.send(&fixture, if (verifies) build else .verify, blocks);
        try fixture.await_joiners(target, 2);
        try testing.expect(!second.?.is_ready());
    }
    try testing.expect(!first.is_ready());
    try testing.expectEqual(1, processed(&probes.log, target));
    try finalize_parent(&fixture, &probes, &gate, parent);

    // The same requests complete on the finalized parent without processing it again.
    var built: ?Mailbox.Digested = null;
    defer if (built) |*block| block.deinit();
    var second_built: ?Mailbox.Digested = null;
    defer if (second_built) |*block| block.deinit();
    try testing.expect(try first.accepted(parent, &built));
    if (second) |*request| try testing.expect(try request.accepted(parent, &second_built));
    try testing.expectEqual(1, processed(&probes.log, target));

    // The build cached the state of its block.
    const child = (if (built) |block| block else second_built.?).inner().*;
    var verdict = try fixture.verify(&.{ child, parent });
    defer verdict.deinit();
    try testing.expect(try await_ready(bool, &verdict));
    try testing.expectEqual(0, processed(&probes.log, child.digest()));
}

/// Finalizes `parent` while `gate` holds its shared execution: the finalization joins that
/// execution before applying its state, reusing it rather than reprocessing.
fn finalize_parent(fixture: *Fixture, probes: *BuildProbes, gate: *Held, parent: TestBlock) !void {
    // A verification that never acquires its block reports when finalization pauses it,
    // which happens once the finalization has started waiting.
    const ancestry_gate = &probes.ancestry_gate;
    var acquiring = try verify_with(fixture, try GatedAncestry.init(ancestry_gate, &.{}, 0));
    defer acquiring.deinit();
    var waiter = try fixture.finalize(parent);
    defer waiter.deinit();
    try ancestry_gate.await_parked();
    try testing.expectEqual(0, probes.capture.calls);
    try testing.expect(!gate.release.?.is_closed());
    try gate.open();
    try await_acknowledged(&waiter);
    try testing.expectEqual(0, probes.finalized_path.calls);
    try testing.expectEqual(1, probes.capture.calls);
    try testing.expectEqual(1, try fixture.counter());
    try testing.expect(!acquiring.is_ready());
}

/// `finalization_completes_build(build, verify_first)` for `test_io.run_on_deterministic`. On
/// threads the finalization cancels the gated acquisition just after it spawns; on Darwin a
/// `testing.allocator` call there can swallow that cancel (AGENTS.md), so the pause never
/// returns and `await_parked` timed out on macOS CI (runs 44810819613, 44814189507).
fn completes_build(comptime build: Managed, comptime verify_first: ?bool) fn () anyerror!void {
    return struct {
        fn run() anyerror!void {
            try finalization_completes_build(build, verify_first);
        }
    }.run;
}

// commonware `finalization_completes_build_processing_finalized_parent` (prepare case):
// finalization waits for a prepare's execution of the parent and reuses its state; the
// prepare then votes a child of the parent, whose state it cached.
test "stateful processing: finalization completes a prepare processing its parent" {
    try test_io.run_on_deterministic(completes_build(.prepare, null));
}

// commonware `finalization_completes_build_processing_finalized_parent` (propose case).
test "stateful processing: finalization completes a proposal processing its parent" {
    try test_io.run_on_deterministic(completes_build(.propose, null));
}

// commonware `finalization_completes_build_processing_finalized_parent`
// (verify_then_prepare case): the parent's verification starts the execution and a prepare
// joins it.
test "stateful processing: finalization completes a prepare joined to a verification" {
    try test_io.run_on_deterministic(completes_build(.prepare, true));
}

// commonware `finalization_completes_build_processing_finalized_parent`
// (verify_then_propose case).
test "stateful processing: finalization completes a proposal joined to a verification" {
    try test_io.run_on_deterministic(completes_build(.propose, true));
}

// commonware `finalization_completes_build_processing_finalized_parent`
// (prepare_then_verify case): the prepare starts the execution and the verification joins it.
test "stateful processing: finalization completes a prepare a verification joined" {
    try test_io.run_on_deterministic(completes_build(.prepare, false));
}

// commonware `finalization_completes_build_processing_finalized_parent`
// (propose_then_verify case).
test "stateful processing: finalization completes a proposal a verification joined" {
    try test_io.run_on_deterministic(completes_build(.propose, false));
}

const Handler = @import("verifications.zig").Verifications(harness.TestP);
const test_io = @import("../../test_io.zig");

/// Schedules a verification over `ancestry` (taken) and returns its verdict's receiver.
fn schedule(state: *Handler, ancestry: harness.Execution.Ancestry) !oneshot.Receiver(bool) {
    const pair = try oneshot.channel(bool, gpa, test_io.io);
    state.schedule(.{ .verify = .{ .ancestry = ancestry, .verification = pair.sender } });
    return pair.receiver;
}

/// Drives `state` until `held`'s call starts (bounded).
fn drive_until_started(state: *Handler, held: *Held) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        state.complete_ready();
        if (held.started.is_ready()) return held.started.recv();
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Drives `state` until `verdict` answers (bounded).
fn drive_verdict(state: *Handler, verdict: *oneshot.Receiver(bool)) !bool {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        state.complete_ready();
        if (verdict.is_ready()) return verdict.recv();
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Drives `state` until `sender`'s receiver closes (bounded): the held call was dropped.
fn drive_closed(state: *Handler, sender: *const oneshot.Sender(void)) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        state.complete_ready();
        if (sender.is_closed()) return;
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

/// Drives `state` until `len` requests are live (bounded).
fn drive_until_len(state: *Handler, len: usize) !void {
    // Each pass sleeps 1 ms; the bound is a hang guard.
    for (0..10_000) |_| {
        state.complete_ready();
        if (state.len() == len) return;
        try test_io.io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestTimedOut;
}

fn pause_on(state: *Handler, boundary: Handler.Boundary) std.Io.Cancelable!void {
    return state.pause(boundary);
}

/// The blocks of `maintenance`: `parent` (staged, so cached) on genesis, its children `child`
/// and `sibling`, and `losing` on genesis, the last three uncached.
const MaintenanceBlocks = struct {
    parent: TestBlock,
    child: TestBlock,
    sibling: TestBlock,
    losing: TestBlock,
};

fn maintenance_blocks(h: *harness.Harness) !MaintenanceBlocks {
    const genesis = TestBlock.genesis();
    const parent = try h.stage_pending_child(&genesis, 1);
    const child, var child_batch = try h.build_child(&parent, 2);
    child_batch.deinit();
    const sibling, var sibling_batch = try h.build_child(&parent, 3);
    sibling_batch.deinit();
    const losing, var losing_batch = try h.build_child(&genesis, 4);
    losing_batch.deinit();
    return .{ .parent = parent, .child = child, .sibling = sibling, .losing = losing };
}

fn maintenance(ready_loser: bool) !void {
    var h: harness.Harness = undefined;
    try h.init();
    defer h.deinit();
    const blocks = try maintenance_blocks(&h);
    const genesis = TestBlock.genesis();
    // Null target: the gates hold the child, the losing block, and the sibling, in the order
    // the test starts them.
    var probe: Probe = .{ .target = null };
    defer probe.deinit();
    var child_gate = try Held.add(&probe);
    defer child_gate.deinit();
    var losing_gate = try Held.add(&probe);
    defer losing_gate.deinit();
    var sibling_gate = try Held.add(&probe);
    defer sibling_gate.deinit();
    var pending_gate: AncestryGate = .{};
    var state: Handler = .init(gpa, test_io.io, h.processor.verifier(), h.provider());
    defer state.deinit();
    state.verifier.app.probe = &probe;

    // Verifications of the child and the sibling, a losing request whose ancestry never
    // arrives, and a losing request that executes its block.
    var child = try schedule(&state, try h.ancestry(&.{ blocks.child, blocks.parent }));
    defer child.deinit();
    try drive_until_started(&state, &child_gate);
    var pending = try schedule(&state, try GatedAncestry.init(&pending_gate, &.{}, 0));
    var pending_open = true;
    defer if (pending_open) pending.deinit();
    var reject = try schedule(&state, try h.ancestry(&.{ blocks.losing, genesis }));
    defer reject.deinit();
    try drive_until_started(&state, &losing_gate);
    var sibling = try schedule(&state, try h.ancestry(&.{ blocks.sibling, blocks.parent }));
    var sibling_open = true;
    defer if (sibling_open) sibling.deinit();
    try drive_until_started(&state, &sibling_gate);
    try pause_rejecting_loser(&state, &h, blocks.parent, &child_gate, &losing_gate, ready_loser);

    // The child answers once its retained execution finishes; the loser is rejected; the
    // sibling and the parked acquisition stay pending.
    try testing.expect(try drive_verdict(&state, &child));
    try testing.expect(!try drive_verdict(&state, &reject));
    try testing.expect(!pending.is_ready());
    try testing.expect(!sibling.is_ready());

    // Caller cancellation releases both a retained execution and a parked acquisition.
    try testing.expectEqual(2, state.len());
    sibling.deinit();
    sibling_open = false;
    try drive_closed(&state, &sibling_gate.release.?);
    try drive_until_len(&state, 1);
    pending.deinit();
    pending_open = false;
    state.complete_ready();
    try testing.expectEqual(0, state.len());
    try testing.expectEqual(0, pending_gate.read("live"));
    try testing.expect(h.processor.flights_idle());
    state.@"resume"();
    try testing.expectEqual(0, state.len());
}

/// Releases the child, then pauses for `parent`'s finalization, releasing the losing
/// execution before the pause (`ready_loser`) or while the pause waits for it.
fn pause_rejecting_loser(
    state: *Handler,
    h: *harness.Harness,
    parent: TestBlock,
    child_gate: *Held,
    losing_gate: *Held,
    ready_loser: bool,
) !void {
    try child_gate.open();
    if (ready_loser) {
        try losing_gate.open();
        // Let the losing execution finish before the pause starts.
        try test_io.io.sleep(.fromMilliseconds(20), .awake);
    }
    var finalized = try harness.digested(parent);
    defer finalized.deinit();
    const boundary = try h.processor.boundary(&finalized);
    var pausing = try test_io.io.concurrent(pause_on, .{ state, boundary });
    if (!ready_loser) {
        // The pause waits for the running loser.
        try test_io.io.sleep(.fromMilliseconds(20), .awake);
        try testing.expect(!losing_gate.release.?.is_closed());
        try losing_gate.open();
    }
    try pausing.await(test_io.io);
}

// commonware `maintenance_preserves_owned_requests_and_retained_work` (ready_loser case):
// finalization rejects a losing execution that finished before the pause, lets a descendant
// execution finish, and keeps a retained execution and a parked acquisition until their
// callers cancel. Adapted: it drives the `Verifications` handler directly, as commonware
// drives its `Handler`; the pause runs on its own task.
test "stateful processing: maintenance rejects a ready loser and keeps retained work" {
    try test_io.run_on_deterministic(maintenance_ready_loser);
}

fn maintenance_ready_loser() anyerror!void {
    try maintenance(true);
}

// commonware `maintenance_preserves_owned_requests_and_retained_work` (running_loser case):
// the same with the loser still executing when the pause starts.
test "stateful processing: maintenance rejects a running loser and keeps retained work" {
    try test_io.run_on_deterministic(maintenance_running_loser);
}

fn maintenance_running_loser() anyerror!void {
    try maintenance(false);
}
