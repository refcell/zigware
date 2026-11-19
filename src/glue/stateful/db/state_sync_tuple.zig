//! State sync of tuple sets (commonware `glue/src/stateful/db/mod.rs`:
//! `impl_state_sync_set`, `DbSyncChannels`, `ReachedEvent`, `drain_generation_updates`).
//!
//! Each member database syncs in its own task beside a reporter task that tags the targets it
//! reaches with the generation they belong to. The coordinator, in the caller's task, applies
//! `sync.CoordinatorState`'s convergence rules: it dispatches each tip as a generation, and
//! once every database reached one generation it signals them all to finish.
//!
//! Reached events keep only each database's newest pending generation (commonware's mailbox
//! keeps a ready queue and then the newest overflow event per database). A database reports
//! non-decreasing generations, and the coordinator ignores any generation a database is no
//! longer assigned, so the older events it drops would have been ignored.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const db = @import("mod.zig");
const sync = @import("sync.zig");
const state_sync = @import("state_sync.zig");

const mpsc = utils.channel.mpsc;
const ring = utils.channel.ring;
const Anchor = sync.Anchor;
const TipUpdate = sync.TipUpdate;
const max_databases = sync.max_databases;

/// The first member database whose sync failed, for diagnostics (commonware's error string
/// `state sync failed (index <i>, db <type>)`).
pub const Failure = struct { index: usize, name: []const u8, err: anyerror };

/// A synced tuple set and the anchor whose targets every member reached.
pub fn Synced(comptime types: anytype, comptime D: type) type {
    return struct { databases: db.Tuple(types), anchor: Anchor(D) };
}

/// The coordinator's inbox: each member's newest reached generation not yet taken, the
/// members whose syncs ended, and the first failure. One waiter, the coordinator.
const Events = struct {
    io: Io,
    count: usize,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    reached: [max_databases]?u64 = @splat(null),
    /// Ended syncs not yet taken by the coordinator.
    completions: u32 = 0,
    first_failure: ?Failure = null,

    const Event = union(enum) {
        reached: struct { index: usize, generation: u64 },
        completed,
    };

    fn report(events: *Events, index: usize, generation: u64) void {
        assert(index < events.count);
        events.mutex.lockUncancelable(events.io);
        defer events.mutex.unlock(events.io);
        if (events.reached[index]) |pending| assert(pending <= generation);
        events.reached[index] = generation;
        events.condition.broadcast(events.io);
    }

    fn complete(events: *Events, failure: ?Failure) void {
        events.mutex.lockUncancelable(events.io);
        defer events.mutex.unlock(events.io);
        assert(events.completions < events.count);
        events.completions += 1;
        if (failure != null and events.first_failure == null) events.first_failure = failure;
        events.condition.broadcast(events.io);
    }

    /// A pending reached event, lowest index first; with `completions`, else a completion.
    fn take_locked(events: *Events, completions: bool) ?Event {
        for (events.reached[0..events.count], 0..) |*pending, index| {
            const generation = pending.* orelse continue;
            pending.* = null;
            return .{ .reached = .{ .index = index, .generation = generation } };
        }
        if (!completions or events.completions == 0) return null;
        events.completions -= 1;
        return .completed;
    }

    /// A pending reached event, without waiting.
    fn try_take_reached(events: *Events) ?Event {
        events.mutex.lockUncancelable(events.io);
        defer events.mutex.unlock(events.io);
        return events.take_locked(false);
    }

    /// Waits for a reached event or a completion.
    fn recv(events: *Events) Io.Cancelable!Event {
        try events.mutex.lock(events.io);
        defer events.mutex.unlock(events.io);
        while (true) {
            if (events.take_locked(true)) |event| return event;
            try events.condition.wait(events.io, &events.mutex);
        }
    }
};

/// One member's sync: its inputs, its channels with the coordinator, and its result.
fn Member(comptime DB: type, comptime Env: type, comptime Source: type) type {
    return struct {
        const Self = @This();
        const Target = DB.SyncTarget;
        const Assignment = struct { generation: u64, target: Target };
        const Channels = state_sync.Channels(Target);
        const Result = @TypeOf(DB.sync_db(
            @as(Env, undefined),
            @as(DB.Config, undefined),
            @as(Source, undefined),
            @as(Target, undefined),
            @as(Channels, undefined),
            @as(state_sync.SyncEngineConfig, undefined),
        ));

        index: usize,
        env: Env,
        config: DB.Config,
        source: Source,
        target: Target,
        sync_config: state_sync.SyncEngineConfig,
        events: *Events,
        target_tx: ring.Sender(Target),
        target_rx: ring.Receiver(Target),
        finish_tx: mpsc.Sender(void),
        finish_rx: mpsc.Receiver(void),
        generation_tx: ring.Sender(Assignment),
        generation_rx: ring.Receiver(Assignment),
        reached_tx: ring.Sender(Target),
        reached_rx: ring.Receiver(Target),
        /// The target the coordinator last sent this database.
        dispatched: Target,
        result: ?Result = null,

        /// Opens the member's channels (commonware's `DbSyncChannels::new`).
        fn init(self: *Self, inputs: anytype) !void {
            const gpa = inputs.env.gpa;
            const io = inputs.env.io;
            const targets = try ring.channel(Target, gpa, io, 1);
            errdefer release_pair(targets);
            const finish = try mpsc.channel(void, gpa, io, 1);
            errdefer release_pair(finish);
            const generations = try ring.channel(Assignment, gpa, io, 1);
            errdefer release_pair(generations);
            const reached = try ring.channel(Target, gpa, io, 1);
            self.* = .{
                .index = inputs.index,
                .env = inputs.env,
                .config = inputs.config,
                .source = inputs.source,
                .target = inputs.target,
                .sync_config = inputs.sync_config,
                .events = inputs.events,
                .target_tx = targets.sender,
                .target_rx = targets.receiver,
                .finish_tx = finish.sender,
                .finish_rx = finish.receiver,
                .generation_tx = generations.sender,
                .generation_rx = generations.receiver,
                .reached_tx = reached.sender,
                .reached_rx = reached.receiver,
                .dispatched = inputs.target,
            };
        }

        fn release_pair(pair: anytype) void {
            var ends = pair;
            ends.sender.deinit();
            ends.receiver.deinit();
        }

        /// Releases the coordinator's senders, which ends a sync waiting on them.
        fn release_coordinator(self: *Self) void {
            self.target_tx.deinit();
            self.finish_tx.deinit();
            self.generation_tx.deinit();
        }

        /// Releases the ends of a member whose tasks never started.
        fn release_unstarted(self: *Self) void {
            self.target_rx.deinit();
            self.finish_rx.deinit();
            self.generation_rx.deinit();
            self.reached_tx.deinit();
            self.reached_rx.deinit();
        }

        /// The database's task: syncs, records the result, and reports the completion.
        fn run_sync(self: *Self) void {
            self.result = DB.sync_db(self.env, self.config, self.source, self.target, .{
                .tip_updates = &self.target_rx,
                .finish = &self.finish_rx,
                .reached_target = self.reached_tx,
            }, self.sync_config);
            self.target_rx.deinit();
            self.finish_rx.deinit();
            var failure: ?Failure = null;
            if (self.result.?) |_| {} else |err| {
                failure = .{ .index = self.index, .name = @typeName(DB), .err = err };
            }
            self.events.complete(failure);
        }

        const ReporterWake = union(enum) {
            reached: Io.Cancelable!?Target,
            assigned: Io.Cancelable!?Assignment,
        };

        /// The reporter's task: reports each assigned generation whose target the database
        /// reached, once. Ends when the database stops reporting.
        fn run_reporter(self: *Self) void {
            defer self.reached_rx.deinit();
            var reporter: Reporter = .{ .member = self, .current_target = self.target };
            defer reporter.close_assignments();
            while (true) {
                reporter.drain_assignments();
                const wake = reporter.wait() catch return;
                if (!reporter.handle(wake)) return;
            }
        }

        /// The reporter's state (commonware's `forward_reached` locals).
        const Reporter = struct {
            member: *Self,
            assignments_open: bool = true,
            current_generation: u64 = 0,
            current_target: Target,
            last_reached: ?Target = null,
            last_reported: ?u64 = null,

            /// Adopts every queued assignment (commonware's `drain_generation_updates`).
            fn drain_assignments(reporter: *Reporter) void {
                while (reporter.assignments_open) {
                    const assignment = reporter.member.generation_rx.try_recv() catch |err| {
                        switch (err) {
                            error.Empty => return,
                            error.Disconnected => return reporter.close_assignments(),
                        }
                    };
                    reporter.assign(assignment);
                }
            }

            /// Releases the assignment receiver once, however many wakes see it closed.
            fn close_assignments(reporter: *Reporter) void {
                if (!reporter.assignments_open) return;
                reporter.member.generation_rx.deinit();
                reporter.assignments_open = false;
                assert(!reporter.assignments_open);
            }

            /// Adopts `assignment` unless a newer one was adopted: a wake handled after the
            /// other wait's drain can carry an older assignment than the drain adopted.
            fn assign(reporter: *Reporter, assignment: Assignment) void {
                if (assignment.generation < reporter.current_generation) return;
                reporter.current_generation = assignment.generation;
                reporter.current_target = assignment.target;
                const reached = reporter.last_reached orelse return;
                if (db.targets_eql(Target, &reached, &reporter.current_target)) {
                    reporter.report();
                }
            }

            /// Reports the current generation unless it was reported.
            fn report(reporter: *Reporter) void {
                if (reporter.last_reported == reporter.current_generation) return;
                const member = reporter.member;
                member.events.report(member.index, reporter.current_generation);
                reporter.last_reported = reporter.current_generation;
            }

            fn wait(reporter: *Reporter) (Io.ConcurrentError || Io.Cancelable)!ReporterWake {
                const member = reporter.member;
                var buffer: [2]ReporterWake = undefined;
                var select: Io.Select(ReporterWake) = .init(member.env.io, &buffer);
                errdefer while (select.cancel()) |_| {};
                try select.concurrent(.reached, ring.Receiver(Target).recv, .{&member.reached_rx});
                if (reporter.assignments_open) {
                    const recv = ring.Receiver(Assignment).recv;
                    try select.concurrent(.assigned, recv, .{&member.generation_rx});
                }
                const first = try select.await();
                // A wait that completed while the other is canceled is handled first.
                while (select.cancel()) |rest| {
                    if (!reporter.handle(rest)) return .{ .reached = null };
                }
                return first;
            }

            /// Handles one wake; false once the database stopped reporting.
            fn handle(reporter: *Reporter, wake: ReporterWake) bool {
                switch (wake) {
                    .reached => |result| {
                        // A wait canceled because the other one won is not an end.
                        const reached = (result catch return true) orelse return false;
                        reporter.last_reached = reached;
                        reporter.drain_assignments();
                        if (db.targets_eql(Target, &reached, &reporter.current_target)) {
                            reporter.report();
                        }
                    },
                    .assigned => |result| {
                        // The other wait's drain may have closed the receiver already.
                        const assignment = (result catch return true) orelse {
                            reporter.close_assignments();
                            return true;
                        };
                        reporter.assign(assignment);
                    },
                }
                return true;
            }
        };
    };
}

fn Members(comptime types: anytype, comptime Env: type, comptime Sources: type) type {
    var fields: [types.len]type = undefined;
    for (types, 0..) |DB, i| {
        const Source = @FieldType(Sources, std.fmt.comptimePrint("{d}", .{i}));
        fields[i] = Member(DB, Env, Source);
    }
    return @Tuple(&fields);
}

/// Syncs every database of `db.Tuple(types)` from `sources` (a tuple of source pointers) to
/// `targets`, carried by `anchor`, adopting the finalized tips on `tip_updates` (commonware's
/// `StateSyncSet::sync` for tuples). Takes `tip_updates`. On a database's failure, returns the
/// first failing database's error and fills `failure` when given; fails with
/// `error.SyncTargetMismatch` when the databases finished at other targets than the
/// coordinator converged on, and `error.NotConverged` when the coordinator stopped first.
pub fn sync_tuple(
    comptime types: anytype,
    comptime D: type,
    env: anytype,
    config: db.Tuple(types).Config,
    sources: anytype,
    anchor: Anchor(D),
    targets: db.Tuple(types).SyncTargets,
    tip_updates: ring.Receiver(TipUpdate(D, db.Tuple(types).SyncTargets)),
    sync_config: state_sync.SyncEngineConfig,
    failure: ?*?Failure,
) !Synced(types, D) {
    const count = types.len;
    comptime assert(count >= 2 and count <= max_databases);
    inline for (types) |DB| comptime state_sync.assert_state_sync_db(DB);
    var tips: ?ring.Receiver(TipUpdate(D, db.Tuple(types).SyncTargets)) = tip_updates;
    defer if (tips) |*receiver| receiver.deinit();
    var events: Events = .{ .io = env.io, .count = count };
    var members: Members(types, @TypeOf(env), @TypeOf(sources)) = undefined;
    var opened: usize = 0;
    errdefer inline for (0..count) |i| {
        if (i < opened) {
            members[i].release_coordinator();
            members[i].release_unstarted();
        }
    };
    inline for (0..count) |i| {
        try members[i].init(.{
            .index = i,
            .env = env,
            .config = config[i],
            .source = sources[i],
            .target = targets[i],
            .sync_config = sync_config,
            .events = &events,
        });
        opened += 1;
    }
    var tasks = try Tasks(@TypeOf(members)).start(env.io, &members);
    opened = 0; // The tasks own the members' ends now.
    const converged = coordinate(types, D, &members, &events, &tips, anchor, targets);
    inline for (0..count) |i| members[i].release_coordinator();
    tasks.join(env.io);
    return collect(types, D, env, &members, &events, converged, failure);
}

/// Every member's sync and reporter tasks.
fn Tasks(comptime M: type) type {
    const count = @typeInfo(M).@"struct".field_names.len;
    return struct {
        const Self = @This();
        syncs: [count]Io.Future(void) = undefined,
        reporters: [count]Io.Future(void) = undefined,
        started: usize = 0,

        /// Starts each member's tasks; on failure, stops the started ones and releases the
        /// rest. The coordinator's senders stay with the caller.
        fn start(io: Io, members: *M) Io.ConcurrentError!Self {
            var self: Self = .{};
            inline for (0..count) |i| {
                const member = &members[i];
                const Mi = @TypeOf(member.*);
                self.syncs[i] = io.concurrent(Mi.run_sync, .{member}) catch |err| {
                    self.abort(io, members, i);
                    return err;
                };
                self.reporters[i] = io.concurrent(Mi.run_reporter, .{member}) catch |err| {
                    // Closing every coordinator sender ends the started syncs, this one too.
                    inline for (0..count) |j| members[j].release_coordinator();
                    self.syncs[i].await(io);
                    member.reached_rx.deinit();
                    member.generation_rx.deinit();
                    self.release_after(members, i);
                    self.join(io);
                    return err;
                };
                self.started += 1;
            }
            assert(self.started == count);
            return self;
        }

        /// Stops the started members when member `failed`'s sync did not start.
        fn abort(self: *Self, io: Io, members: *M, comptime failed: usize) void {
            inline for (0..count) |i| members[i].release_coordinator();
            members[failed].release_unstarted();
            self.release_after(members, failed);
            self.join(io);
        }

        /// Releases the ends of the members after `failed`, none of which started.
        fn release_after(_: *Self, members: *M, comptime failed: usize) void {
            inline for (failed + 1..count) |i| members[i].release_unstarted();
        }

        fn join(self: *Self, io: Io) void {
            for (self.syncs[0..self.started], self.reporters[0..self.started]) |*s, *r| {
                s.await(io);
                r.await(io);
            }
        }
    };
}

fn Converged(comptime D: type, comptime T: type) type {
    return struct { anchor: Anchor(D), targets: T };
}

/// The coordinator (commonware's `coordinator_handle` body): null when a database stopped
/// before convergence, a channel closed, or the wait failed.
fn coordinate(
    comptime types: anytype,
    comptime D: type,
    members: anytype,
    events: *Events,
    tips: anytype,
    anchor: Anchor(D),
    targets: db.Tuple(types).SyncTargets,
) ?Converged(D, db.Tuple(types).SyncTargets) {
    const T = db.Tuple(types).SyncTargets;
    var state = sync.CoordinatorState(D, T).init(types.len, anchor, targets);
    while (true) {
        while (events.try_take_reached()) |event| {
            state.record_reached(event.reached.index, event.reached.generation);
        }
        drain_tips(D, T, tips, &state);
        switch (state.next_action()) {
            .converged => |done| {
                inline for (0..types.len) |i| members[i].finish_tx.try_send({}) catch {};
                return .{ .anchor = done.anchor, .targets = done.targets };
            },
            .dispatch => |dispatch| {
                if (!dispatch_generation(types, D, members, &state, dispatch)) return null;
                continue;
            },
            .wait => {},
        }
        if (!(wait(D, T, events, tips, &state) catch return null)) return null;
    }
}

fn drain_tips(comptime D: type, comptime T: type, tips: anytype, state: anytype) void {
    var recorder: Recorder(D, T) = .{ .state = state };
    while (tips.*) |*receiver| {
        var update = receiver.try_recv() catch |err| switch (err) {
            error.Empty => return,
            error.Disconnected => {
                receiver.deinit();
                tips.* = null;
                return;
            },
        };
        update.record(&recorder);
    }
}

fn Recorder(comptime D: type, comptime T: type) type {
    return struct {
        state: *sync.CoordinatorState(D, T),

        pub fn record(recorder: *@This(), anchor: Anchor(D), targets: T) void {
            recorder.state.record_tip_update(anchor, targets);
        }
    };
}

/// Sends a dispatched generation to every member, and its target to those still seeking
/// it; a reached member whose target is unchanged counts as reached for the generation.
/// False when a member is gone.
fn dispatch_generation(
    comptime types: anytype,
    comptime D: type,
    members: anytype,
    state: *sync.CoordinatorState(D, db.Tuple(types).SyncTargets),
    dispatch: anytype,
) bool {
    inline for (types, 0..) |DB, i| {
        const member = &members[i];
        const target: DB.SyncTarget = dispatch.targets[i];
        const Assignment = @TypeOf(member.*).Assignment;
        const assignment: Assignment = .{ .generation = dispatch.generation, .target = target };
        if (!member.generation_tx.send_lossy(assignment)) return false;
        const unchanged = db.targets_eql(DB.SyncTarget, &target, &member.dispatched);
        if (state.should_dispatch(i)) {
            if (!unchanged) {
                if (!member.target_tx.send_lossy(target)) return false;
                member.dispatched = target;
            }
        } else if (unchanged) {
            state.mark_reached_same_target(i, dispatch.generation);
        }
    }
    return true;
}

fn Wake(comptime U: type) type {
    return union(enum) {
        event: Io.Cancelable!Events.Event,
        tip: Io.Cancelable!?U,
    };
}

/// Waits for a reached event, a completion, or a tip; false when a database stopped.
fn wait(
    comptime D: type,
    comptime T: type,
    events: *Events,
    tips: anytype,
    state: *sync.CoordinatorState(D, T),
) (Io.ConcurrentError || Io.Cancelable)!bool {
    const U = TipUpdate(D, T);
    const W = Wake(U);
    var buffer: [2]W = undefined;
    var select: Io.Select(W) = .init(events.io, &buffer);
    var keep = true;
    errdefer while (select.cancel()) |rest| {
        _ = handle_wake(D, T, rest, tips, state);
    };
    try select.concurrent(.event, Events.recv, .{events});
    if (tips.*) |*receiver| try select.concurrent(.tip, ring.Receiver(U).recv, .{receiver});
    keep = handle_wake(D, T, try select.await(), tips, state);
    // A wait that completed while the other was canceled is kept.
    while (select.cancel()) |rest| keep = handle_wake(D, T, rest, tips, state) and keep;
    return keep;
}

fn handle_wake(
    comptime D: type,
    comptime T: type,
    wake: Wake(TipUpdate(D, T)),
    tips: anytype,
    state: *sync.CoordinatorState(D, T),
) bool {
    switch (wake) {
        .event => |result| switch (result catch return true) {
            .reached => |reached| state.record_reached(reached.index, reached.generation),
            .completed => return false,
        },
        .tip => |result| {
            var update = (result catch return true) orelse {
                tips.*.?.deinit();
                tips.* = null;
                return true;
            };
            var recorder: Recorder(D, T) = .{ .state = state };
            update.record(&recorder);
        },
    }
    return true;
}

/// Collects the members' results into the synced set, or the first failure.
fn collect(
    comptime types: anytype,
    comptime D: type,
    env: anytype,
    members: anytype,
    events: *Events,
    converged: ?Converged(D, db.Tuple(types).SyncTargets),
    failure: ?*?Failure,
) !Synced(types, D) {
    const count = types.len;
    var databases: db.Tuple(types) = undefined;
    var shared: usize = 0;
    errdefer inline for (0..count) |i| {
        if (i < shared) databases.members[i].deinit();
    };
    // Close every successful database on an error, after the first failure is taken.
    defer inline for (0..count) |i| {
        if (i >= shared) {
            if (members[i].result.?) |*database| database.deinit() else |_| {}
        }
    };
    if (events.first_failure) |first| {
        if (failure) |out| out.* = first;
        inline for (0..count) |i| {
            if (i == first.index) _ = try members[i].result.?;
        }
        unreachable; // The first failure names a failed member.
    }
    const done = converged orelse return error.NotConverged;
    inline for (types, 0..) |DB, i| {
        const database = members[i].result.? catch unreachable; // No member failed.
        const reached = database.sync_target();
        if (!db.targets_eql(DB.SyncTarget, &reached, &done.targets[i])) {
            return error.SyncTargetMismatch;
        }
    }
    inline for (types, 0..) |DB, i| {
        const database = members[i].result.? catch unreachable; // No member failed.
        const label = std.fmt.comptimePrint("stateful.db.{d}", .{i});
        databases.members[i] = try db.Shared(DB).init(env.gpa, env.io, label, database);
        shared += 1;
    }
    return .{ .databases = databases, .anchor = done.anchor };
}

test {
    std.testing.refAllDecls(@This());
}

/// A database type for driving a member's reporter directly; it is never synced.
const ReporterTestDb = struct {
    pub const SyncTarget = u64;
    pub const Config = void;

    fn sync_db(
        _: anytype,
        _: void,
        _: void,
        _: u64,
        _: state_sync.Channels(u64),
        _: state_sync.SyncEngineConfig,
    ) error{Unused}!ReporterTestDb {
        unreachable; // The test runs only the reporter.
    }
};

/// A member whose tasks never start, for driving its reporter by hand: the coordinator's
/// senders are closed after `queued` is sent, and only the reached receiver stays open.
const ReporterHarness = struct {
    const TestEnv = struct { gpa: Allocator, io: Io };
    const M = Member(ReporterTestDb, TestEnv, void);

    events: Events,
    member: M,

    fn init(harness: *ReporterHarness, target: u64, queued: []const M.Assignment) !void {
        const env: TestEnv = .{ .gpa = std.testing.allocator, .io = std.testing.io };
        harness.events = .{ .io = env.io, .count = 1 };
        try harness.member.init(.{
            .index = 0,
            .env = env,
            .config = {},
            .source = {},
            .target = target,
            .sync_config = undefined,
            .events = &harness.events,
        });
        for (queued) |assignment| _ = harness.member.generation_tx.send_lossy(assignment);
        harness.member.release_coordinator();
        harness.member.target_rx.deinit();
        harness.member.finish_rx.deinit();
        harness.member.reached_tx.deinit();
    }

    fn deinit(harness: *ReporterHarness) void {
        harness.member.reached_rx.deinit();
    }

    fn reporter(harness: *ReporterHarness) M.Reporter {
        return .{ .member = &harness.member, .current_target = harness.member.target };
    }
};

test "state sync tuple: a reporter woken by both waits releases its assignments once" {
    // One wake can complete both of the reporter's waits (CI seed 0x6c117747). Handling the
    // reached target drains the closed assignment channel; the assignment wait that completed
    // in the same wake then carries an older assignment, and another sees the channel closed.
    var harness: ReporterHarness = undefined;
    try harness.init(5, &.{.{ .generation = 2, .target = 7 }});
    defer harness.deinit();
    const events = &harness.events;

    var reporter = harness.reporter();
    defer reporter.close_assignments();
    try std.testing.expect(reporter.handle(.{ .reached = 7 }));
    try std.testing.expect(!reporter.assignments_open);
    try std.testing.expectEqual(@as(?u64, 2), events.reached[0]);
    // Generation 1 was taken by the assignment wait before generation 2 was queued.
    try std.testing.expect(reporter.handle(.{ .assigned = .{ .generation = 1, .target = 5 } }));
    try std.testing.expectEqual(@as(u64, 2), reporter.current_generation);
    try std.testing.expectEqual(@as(u64, 7), reporter.current_target);
    try std.testing.expect(reporter.handle(.{ .assigned = null }));
    try std.testing.expect(!reporter.assignments_open);
}

test "state sync tuple: a generation drain reports only the newest assignment" {
    // commonware `generation_drain_reports_only_the_newest_assignment`: two assignments
    // arrive before the reporter reads them, so the one-slot ring keeps only the newest,
    // whose target the database already reached.
    var harness: ReporterHarness = undefined;
    try harness.init(0, &.{
        .{ .generation = 1, .target = 1 },
        .{ .generation = 2, .target = 2 },
    });
    defer harness.deinit();
    var reporter = harness.reporter();
    defer reporter.close_assignments();
    reporter.last_reached = 2;
    reporter.drain_assignments();

    // The skipped assignment is never reported; the newest one is reported once.
    try std.testing.expectEqual(@as(u64, 2), reporter.current_generation);
    try std.testing.expectEqual(@as(u64, 2), reporter.current_target);
    try std.testing.expectEqual(@as(?u64, 2), reporter.last_reported);
    const event = harness.events.try_take_reached().?;
    try std.testing.expectEqual(@as(usize, 0), event.reached.index);
    try std.testing.expectEqual(@as(u64, 2), event.reached.generation);
    try std.testing.expectEqual(@as(?Events.Event, null), harness.events.try_take_reached());
}

test "state sync tuple: reached events keep the newest event per database" {
    // commonware `reached_events_keep_the_newest_event_per_database`. commonware's mailbox
    // first delivers its ready queue, (0, 0) and (1, 0), and then each database's newest
    // overflow event; zigware keeps only each database's newest, which the coordinator would
    // reach after ignoring the older ones it drops (see the module comment).
    var events: Events = .{ .io = std.testing.io, .count = 2 };
    for ([_][2]u64{ .{ 0, 0 }, .{ 1, 0 }, .{ 0, 1 }, .{ 1, 1 }, .{ 0, 2 } }) |pair| {
        events.report(pair[0], pair[1]);
    }
    const expected = [_][2]u64{ .{ 0, 2 }, .{ 1, 1 } };
    for (expected) |pair| {
        const event = events.try_take_reached().?;
        try std.testing.expectEqual(@as(usize, pair[0]), event.reached.index);
        try std.testing.expectEqual(pair[1], event.reached.generation);
    }
    try std.testing.expectEqual(@as(?Events.Event, null), events.try_take_reached());
}
