//! The sync engine (commonware's `qmdb/sync/engine.rs`): fetches a target's operations from an
//! untrusted source, verifies each response against the trusted target root, applies them in
//! order to a sync journal, and builds the database once the journal reaches the target.
//!
//! Each request runs as its own concurrent task: it serves through the source (one `serve` at
//! a time, commonware's `AsyncRwLock` around the source), verifies the response, and walks the
//! source's `Feedback` candidates on a rejection. A finished task posts its request id to the
//! engine's completion channel. A request that a newer one at its start supersedes, or that a
//! target update retains out, has its task canceled and its result released (commonware's
//! `Aborter`); its id may still arrive later and is then ignored.
//!
//! `wait_for_event` selects over the target update channel, the finish channel, and the
//! completion channel, and keeps every result that completed while the others were canceled,
//! so no update is lost to the select.
//!
//! The database type `DB` provides the interface in `database.zig`. Its journal is opened with
//! `DB.open_journal(gpa, storage, cfg, range)` when declared, else with `journal.init` over
//! `DB.journal_config(cfg)`. A journal with `append_many` (a contiguous journal) copies what it
//! appends; any other (`journal.Memory`) takes ownership of the appended operations.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const runtime = @import("runtime");
const channel = @import("utils").channel;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const database = @import("database.zig");
const gaps = @import("gaps.zig");
const journal_mod = @import("journal.zig");
const metrics_mod = @import("metrics.zig");
const requests_mod = @import("requests.zig");
const source_mod = @import("source.zig");
const target_mod = @import("target.zig");

const ring = channel.ring;
const mpsc = channel.mpsc;
const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;
const Id = requests_mod.Id;

/// Configuration for synchronizing database `DB` from source `S` (commonware's `Config`).
pub fn Config(comptime DB: type, comptime S: type) type {
    return struct {
        storage: Storage,
        /// The database registers its metrics here, the engine under `sync`.
        scope: Scope,
        /// Source of operations and proofs; borrowed for the sync's lifetime.
        source: *S,
        /// Trusted sync target: the engine verifies source data against it.
        target: target_mod.Target(DB.Family, DB.Digest),
        /// Most outstanding requests, the boundary request included.
        max_outstanding_requests: usize,
        /// Most operations per request.
        fetch_batch_size: u64,
        /// Operations applied per batch when building the database.
        apply_batch_size: u64,
        db_config: DB.Config,
        /// Advancing target updates (borrowed); non-advancing ones are discarded.
        update_rx: ?*ring.Receiver(target_mod.Target(DB.Family, DB.Digest)) = null,
        /// Requests completion once the current target is reached (borrowed). When null, sync
        /// completes as soon as the target is reached.
        finish_rx: ?*mpsc.Receiver(void) = null,
        /// Notified (without waiting) of each reached target at most once; owned by the engine.
        reached_target_tx: ?ring.Sender(target_mod.Target(DB.Family, DB.Digest)) = null,
    };
}

/// Creates or opens a database and syncs it to the target in `config` (commonware's `sync`).
pub fn sync(
    comptime DB: type,
    comptime S: type,
    gpa: Allocator,
    io: Io,
    config: Config(DB, S),
) !DB {
    var engine: Engine(DB, S) = undefined;
    try engine.init(gpa, io, config);
    defer engine.deinit();
    // Each step handles at least one event or completes; a stall fails with `SyncStalled`.
    while (true) {
        if (try engine.step()) |db| return db;
    }
}

/// Whether `response` answers `request` and verifies under `root` (commonware's
/// `verify_response`).
pub fn verify_response(
    comptime F: type,
    comptime Op: type,
    comptime H: type,
    gpa: Allocator,
    request: source_mod.Request(F),
    root: *const H.Digest,
    response: *const source_mod.Response(F, Op, H.Digest),
) Allocator.Error!bool {
    if (response.proof().leaves != request.size()) return false;
    switch (request) {
        .operations => |asked| {
            if (response.* != .operations) return false;
            const answer = response.operations;
            const count = answer.operations.len;
            if (count == 0 or count > asked.max_ops) return false;
            const ops = answer.operations;
            return verify.verify(F, H, Op, gpa, &answer.proof, asked.start, ops, root);
        },
        .boundary => |asked| {
            if (response.* != .boundary) return false;
            const answer = response.boundary;
            const ops: []const Op = &.{answer.op};
            const pins = answer.pinned_nodes;
            const proof = &answer.proof;
            const start = asked.start;
            return verify.verify_with_pinned_nodes(F, H, Op, gpa, proof, start, ops, pins, root);
        },
    }
}

pub fn Engine(comptime DB: type, comptime S: type) type {
    database.assert_database(DB);
    source_mod.assert_source(S);
    comptime {
        assert(S.Family == DB.Family);
        assert(S.Op == DB.Op);
        assert(S.Digest == DB.Digest);
    }
    return struct {
        const Self = @This();
        pub const Family = DB.Family;
        pub const Op = DB.Op;
        pub const Digest = DB.Digest;
        pub const Target = target_mod.Target(Family, Digest);
        pub const Request = source_mod.Request(Family);
        pub const Response = source_mod.Response(Family, Op, Digest);
        pub const FetchError = S.Error || Io.Cancelable || Allocator.Error;
        /// A fetch's verified response, or null when every candidate failed verification.
        pub const FetchResult = FetchError!?Response;
        const Served = source_mod.Served(Response);
        const Requests = requests_mod.Requests(Family);

        /// Operations fetched ahead of the journal tip, starting at `start` (non-empty).
        pub const Batch = struct { start: u64, ops: []Op };
        const Task = struct { id: Id, future: Io.Future(FetchResult) };

        /// What woke `wait_for_event`.
        pub const Event = union(enum) {
            target_update: Target,
            update_closed,
            finish_requested,
            finish_closed,
            /// The request with this id finished (or was canceled).
            fetched: Id,
        };

        gpa: Allocator,
        io: Io,
        storage: Storage,
        scope: Scope,
        requests: Requests = .{},
        /// The running fetch of each tracked request that has one.
        tasks: std.ArrayList(Task) = .empty,
        done_tx: mpsc.Sender(Id),
        done_rx: mpsc.Receiver(Id),
        /// Sorted by start, non-overlapping starts, each non-empty.
        fetched: std.ArrayList(Batch) = .empty,
        /// Pinned nodes at `target.start` (owned), for database construction.
        pinned_nodes: ?[]Digest,
        target: Target,
        max_outstanding_requests: usize,
        fetch_batch_size: u64,
        apply_batch_size: u64,
        journal: DB.Journal,
        journal_taken: bool = false,
        source: *S,
        source_lock: Io.Mutex = .init,
        db_config: DB.Config,
        update_rx: ?*ring.Receiver(Target),
        finish_requested: bool = false,
        finish_rx: ?*mpsc.Receiver(void),
        reached_target_tx: ?ring.Sender(Target),
        metrics: metrics_mod.Metrics,
        reached_current_target_reported: bool = false,

        /// Opens the sync journal and schedules the first requests. Must not move afterwards.
        pub fn init(self: *Self, gpa: Allocator, io: Io, config: Config(DB, S)) !void {
            self.* = try open(gpa, io, config);
            self.schedule_requests() catch |err| {
                self.deinit();
                return err;
            };
            self.record_progress();
        }

        fn open(gpa: Allocator, io: Io, config: Config(DB, S)) !Self {
            const target = config.target;
            if (!merkle.location_is_valid(Family, target.end)) return error.InvalidTarget;
            assert(target.start < target.end);
            assert(config.max_outstanding_requests > 0);
            assert(config.fetch_batch_size > 0 and config.apply_batch_size > 0);
            const range: merkle.Range = .{ .start = target.start, .end = target.end };
            var journal = try open_journal(gpa, config.storage, config.db_config, range);
            errdefer journal.deinit();
            const size = journal.size();
            // A journal that resumes nothing holds none of the operations that persisted local
            // state was derived from: that state is discarded before anything is appended.
            if (size == target.start) {
                try DB.discard_local_state(gpa, config.storage, config.db_config);
            }
            const pinned_nodes = if (size == target.end)
                try DB.local_pinned_nodes(gpa, config.storage, config.db_config, target, &journal)
            else
                null;
            errdefer if (pinned_nodes) |pins| gpa.free(pins);
            var metrics = try metrics_mod.Metrics.init(config.scope.child("sync"));
            errdefer metrics.deinit();
            const done = try mpsc.unbounded(Id, gpa, io);
            return .{
                .gpa = gpa,
                .io = io,
                .storage = config.storage,
                .scope = config.scope,
                .done_tx = done.sender,
                .done_rx = done.receiver,
                .pinned_nodes = pinned_nodes,
                .target = target,
                .max_outstanding_requests = config.max_outstanding_requests,
                .fetch_batch_size = config.fetch_batch_size,
                .apply_batch_size = config.apply_batch_size,
                .journal = journal,
                .source = config.source,
                .db_config = config.db_config,
                .update_rx = config.update_rx,
                .finish_rx = config.finish_rx,
                .reached_target_tx = config.reached_target_tx,
                .metrics = metrics,
            };
        }

        fn open_journal(
            gpa: Allocator,
            storage: Storage,
            cfg: DB.Config,
            range: merkle.Range,
        ) !DB.Journal {
            if (@hasDecl(DB, "open_journal")) return DB.open_journal(gpa, storage, cfg, range);
            const bounds: journal_mod.Bounds = .{ .start = range.start, .end = range.end };
            return journal_mod.init(DB.Journal, gpa, storage, DB.journal_config(cfg), bounds);
        }

        /// Cancels every fetch and releases everything the engine still owns.
        pub fn deinit(self: *Self) void {
            for (self.tasks.items) |*task| release_result(self.gpa, task.future.cancel(self.io));
            self.tasks.deinit(self.gpa);
            self.requests.deinit(self.gpa);
            self.done_tx.deinit();
            self.done_rx.deinit();
            for (self.fetched.items) |batch| free_ops(self.gpa, batch.ops);
            self.fetched.deinit(self.gpa);
            if (self.pinned_nodes) |pins| self.gpa.free(pins);
            if (!self.journal_taken) self.journal.deinit();
            if (self.reached_target_tx) |*sender| sender.deinit();
            self.metrics.deinit();
            self.* = undefined;
        }

        fn free_ops(gpa: Allocator, ops: []Op) void {
            for (ops) |op| codec.free(Op, gpa, op);
            gpa.free(ops);
        }

        fn release_result(gpa: Allocator, result: FetchResult) void {
            var response = (result catch return) orelse return;
            response.deinit(gpa);
        }

        /// The arguments of one fetch task (copied into it).
        const Fetch = struct {
            gpa: Allocator,
            io: Io,
            source: *S,
            lock: *Io.Mutex,
            root: Digest,
            request: Request,
            id: Id,
            done: mpsc.Sender(Id),
        };

        /// Serves `fetch.request`, walking feedback candidates until one verifies; posts the
        /// id to the completion channel on return.
        fn run_fetch(fetch: Fetch) FetchResult {
            var done = fetch.done;
            defer {
                done.try_send(fetch.id) catch {}; // Closed: the engine is gone.
                done.deinit();
            }
            var served = serve(fetch) catch |err| return err;
            while (true) {
                const valid = verify_served(fetch, &served.response) catch |err| {
                    release_served(fetch.gpa, &served);
                    return err;
                };
                if (valid) {
                    if (served.feedback) |*feedback| feedback.accept();
                    return served.response;
                }
                served.response.deinit(fetch.gpa);
                var feedback = served.feedback orelse return null;
                served = (try feedback.reject()) orelse return null;
            }
        }

        fn verify_served(fetch: Fetch, response: *const Response) Allocator.Error!bool {
            const gpa = fetch.gpa;
            const H = DB.Hasher;
            return verify_response(Family, Op, H, gpa, fetch.request, &fetch.root, response);
        }

        fn serve(fetch: Fetch) FetchError!Served {
            try fetch.lock.lock(fetch.io);
            defer fetch.lock.unlock(fetch.io);
            return fetch.source.serve(fetch.gpa, fetch.request);
        }

        fn release_served(gpa: Allocator, served: *Served) void {
            served.response.deinit(gpa);
            if (served.feedback) |*feedback| feedback.deinit();
        }

        /// Tracks `request` and starts its fetch against the shared source.
        fn spawn_fetch(self: *Self, request: Request) !void {
            const id = try self.requests.insert(self.gpa, request);
            self.reap(); // A request it superseded no longer counts.
            try self.tasks.ensureUnusedCapacity(self.gpa, 1);
            const fetch: Fetch = .{
                .gpa = self.gpa,
                .io = self.io,
                .source = self.source,
                .lock = &self.source_lock,
                .root = self.target.root,
                .request = request,
                .id = id,
                .done = self.done_tx.clone(),
            };
            const future = self.io.concurrent(run_fetch, .{fetch}) catch |err| {
                var done = fetch.done;
                done.deinit();
                _ = self.requests.remove(id);
                return err;
            };
            self.tasks.appendAssumeCapacity(.{ .id = id, .future = future });
        }

        /// Cancels the fetches of requests no longer tracked and releases their results.
        fn reap(self: *Self) void {
            var index = self.tasks.items.len;
            while (index > 0) {
                index -= 1;
                const task = &self.tasks.items[index];
                if (self.requests.tracks(task.id)) continue;
                release_result(self.gpa, task.future.cancel(self.io));
                _ = self.tasks.swapRemove(index);
            }
            assert(self.tasks.items.len <= self.requests.len());
        }

        pub fn needs_pinned_nodes(self: *const Self) bool {
            return self.target.start > 0;
        }

        pub fn pinned_nodes_ready(self: *const Self) bool {
            return !self.needs_pinned_nodes() or self.pinned_nodes != null;
        }

        /// Schedules requests for the next unfetched gaps of the sync range, and the boundary
        /// request while pinned nodes are still needed.
        pub fn schedule_requests(self: *Self) !void {
            const size = self.target.end;
            if (!self.pinned_nodes_ready() and !self.requests.contains(self.target.start)) {
                const start = self.target.start;
                const boundary: Request = .{ .boundary = .{ .size = size, .start = start } };
                try self.spawn_fetch(boundary);
            }
            const count = self.max_outstanding_requests -| self.requests.len();
            var fetched: std.ArrayList(gaps.Range) = .empty;
            defer fetched.deinit(self.gpa);
            var tracked: std.ArrayList(Requests.Range) = .empty;
            defer tracked.deinit(self.gpa);
            var outstanding: std.ArrayList(gaps.Range) = .empty;
            defer outstanding.deinit(self.gpa);
            for (0..count) |_| {
                fetched.clearRetainingCapacity();
                tracked.clearRetainingCapacity();
                outstanding.clearRetainingCapacity();
                try fetched.ensureTotalCapacity(self.gpa, self.fetched.items.len);
                for (self.fetched.items) |batch| fetched.appendAssumeCapacity(.{
                    .start = batch.start,
                    .end = batch.start + batch.ops.len,
                });
                try self.requests.ranges(self.gpa, &tracked);
                try outstanding.ensureTotalCapacity(self.gpa, tracked.items.len);
                for (tracked.items) |range| {
                    outstanding.appendAssumeCapacity(.{ .start = range.start, .end = range.end });
                }
                const scan: gaps.Range = .{ .start = self.journal.size(), .end = size };
                const gap = gaps.find_next(scan, fetched.items, outstanding.items) orelse break;
                assert(gap.start < gap.end);
                const max_ops = @min(self.fetch_batch_size, gap.end - gap.start);
                const request: Request =
                    .{ .operations = .{ .size = size, .start = gap.start, .max_ops = max_ops } };
                try self.spawn_fetch(request);
            }
        }

        /// Resets for `new_target`: keeps fetched operations, keeps pinned nodes only while the
        /// lower bound is unchanged, and keeps outstanding requests except those at or below a
        /// moved lower bound (each verifies against the root it was issued with).
        pub fn reset_for_target_update(self: *Self, new_target: Target) !void {
            const start_moved = self.target.start != new_target.start;
            try self.resize_journal(new_target.start);
            if (start_moved) {
                if (self.pinned_nodes) |pins| self.gpa.free(pins);
                self.pinned_nodes = null;
                // A source may prune up to the new lower bound, so a request below it may never
                // be answered, and one at it would block the boundary request there.
                self.requests.retain(new_target.start, beyond);
                self.reap();
            }
            self.target = new_target;
            self.reached_current_target_reported = false;
        }

        fn beyond(start: u64, request: Request) bool {
            return request.start() > start;
        }

        fn resize_journal(self: *Self, start: u64) !void {
            if (@hasDecl(DB.Journal, "clear_to_size")) {
                try journal_mod.resize(&self.journal, start);
            } else {
                try self.journal.resize(start);
            }
            assert(self.journal.size() >= start);
        }

        fn drain_finish_requests(self: *Self) !void {
            const finish_rx = self.finish_rx orelse return;
            if (finish_rx.try_recv()) |_| {
                self.finish_rx = null;
                self.finish_requested = true;
            } else |err| switch (err) {
                error.Empty => {},
                error.Disconnected => return error.FinishChannelClosed,
            }
        }

        /// Notifies the observer once per target, never waiting.
        fn report_reached_target(self: *Self) void {
            if (self.reached_current_target_reported) return;
            if (self.reached_target_tx) |*sender| {
                if (!sender.send_lossy(self.target)) {
                    sender.deinit();
                    self.reached_target_tx = null;
                }
            }
            self.reached_current_target_reported = true;
        }

        fn record_progress(self: *Self) void {
            self.metrics.record_target(self.target.end);
            self.metrics.record_synced(self.journal.size());
        }

        /// Stores fetched operations at `start` (owned; an empty batch is released).
        pub fn store_operations(self: *Self, start: u64, ops: []Op) !void {
            if (ops.len == 0) {
                self.gpa.free(ops);
                return;
            }
            errdefer free_ops(self.gpa, ops);
            const index = std.sort.lowerBound(Batch, self.fetched.items, start, batch_order);
            if (index < self.fetched.items.len and self.fetched.items[index].start == start) {
                free_ops(self.gpa, self.fetched.items[index].ops);
                self.fetched.items[index].ops = ops;
                return;
            }
            try self.fetched.insert(self.gpa, index, .{ .start = start, .ops = ops });
        }

        fn batch_order(start: u64, batch: Batch) std.math.Order {
            return std.math.order(start, batch.start);
        }

        fn batch_at(self: *const Self, start: u64) ?Batch {
            const index = std.sort.lowerBound(Batch, self.fetched.items, start, batch_order);
            if (index == self.fetched.items.len) return null;
            const batch = self.fetched.items[index];
            return if (batch.start == start) batch else null;
        }

        /// Applies the fetched operations contiguous with the journal tip, dropping stale
        /// batches and trimming one that straddles the tip.
        pub fn apply_operations(self: *Self) !void {
            const next = self.journal.size();
            var kept: usize = 0;
            for (self.fetched.items) |batch| {
                assert(batch.ops.len > 0);
                if (batch.start + batch.ops.len - 1 < next) {
                    free_ops(self.gpa, batch.ops);
                    continue;
                }
                self.fetched.items[kept] = batch;
                kept += 1;
            }
            self.fetched.shrinkRetainingCapacity(kept);
            // Each pass removes one batch, so the loop runs at most once per batch.
            while (self.take_batch_at_tip()) |batch| {
                const tip = self.journal.size();
                const skip: usize = @intCast(tip - batch.start);
                assert(skip < batch.ops.len);
                for (batch.ops[0..skip]) |op| codec.free(Op, self.gpa, op);
                try self.append_journal(batch.ops, skip);
                assert(self.journal.size() == batch.start + batch.ops.len);
            }
        }

        fn take_batch_at_tip(self: *Self) ?Batch {
            const tip = self.journal.size();
            for (self.fetched.items, 0..) |batch, index| {
                if (batch.start <= tip and tip < batch.start + batch.ops.len) {
                    return self.fetched.orderedRemove(index);
                }
            }
            return null;
        }

        /// Appends `ops[skip..]` and releases `ops` (`ops[0..skip]` already released).
        fn append_journal(self: *Self, ops: []Op, skip: usize) !void {
            const rest = ops[skip..];
            if (@hasDecl(DB.Journal, "append_many")) {
                // A contiguous journal copies what it appends.
                defer {
                    for (rest) |op| codec.free(Op, self.gpa, op);
                    self.gpa.free(ops);
                }
                try journal_mod.append(&self.journal, rest);
                return;
            }
            // Any other journal takes ownership of the operations, also on error.
            defer self.gpa.free(ops);
            try self.journal.append(rest);
        }

        fn is_at_target(self: *const Self) !bool {
            const size = self.journal.size();
            if (size > self.target.end) return error.InvalidState;
            return size == self.target.end;
        }

        fn is_ready_to_complete(self: *const Self) !bool {
            return (try self.is_at_target()) and self.pinned_nodes_ready();
        }

        /// Handles the result of request `id` (commonware's `handle_fetch_result`): a result
        /// of a request no longer tracked is released and ignored.
        pub fn handle_fetch_result(self: *Self, id: Id, result: FetchResult) !void {
            const request = self.requests.remove(id) orelse {
                release_result(self.gpa, result);
                return;
            };
            const response = (try result) orelse return error.InvalidResponse;
            const start = request.start();
            switch (response) {
                .operations => |answer| {
                    var proof = answer.proof;
                    proof.deinit(self.gpa);
                    try self.store_operations(start, answer.operations);
                },
                .boundary => |answer| {
                    var proof = answer.proof;
                    proof.deinit(self.gpa);
                    // A tracked boundary request is at the current lower bound; a batch
                    // fetched there already holds its operation.
                    if (self.pinned_nodes) |pins| self.gpa.free(pins);
                    self.pinned_nodes = answer.pinned_nodes;
                    if (self.batch_at(start) != null) {
                        codec.free(Op, self.gpa, answer.op);
                        return;
                    }
                    const ops = self.gpa.alloc(Op, 1) catch |err| {
                        codec.free(Op, self.gpa, answer.op);
                        return err;
                    };
                    ops[0] = answer.op;
                    try self.store_operations(start, ops);
                },
            }
        }

        fn handle_fetched(self: *Self, id: Id) !void {
            for (self.tasks.items, 0..) |*task, index| {
                if (task.id != id) continue;
                const result = task.future.await(self.io);
                _ = self.tasks.swapRemove(index);
                return self.handle_fetch_result(id, result);
            }
            // Its task was canceled and its result already released.
        }

        pub fn handle_event(self: *Self, event: Event) !void {
            switch (event) {
                .target_update => |new_target| {
                    if (!new_target.advances(self.target)) return;
                    // A same-root advancing update is impossible for an append-only log.
                    if (new_target.root.eql(self.target.root)) {
                        return error.SyncTargetRootUnchanged;
                    }
                    try self.reset_for_target_update(new_target);
                    self.record_progress();
                    try self.schedule_requests();
                },
                .update_closed => self.update_rx = null,
                .finish_requested => {
                    self.finish_rx = null;
                    self.finish_requested = true;
                },
                .finish_closed => return error.FinishChannelClosed,
                .fetched => |id| {
                    try self.handle_fetched(id);
                    try self.schedule_requests();
                    try self.apply_operations();
                    self.record_progress();
                },
            }
        }

        /// Events woken together, in the order they completed.
        pub const Events = struct { items: [3]Event = undefined, len: usize = 0 };

        const Wake = union(enum) {
            update: Io.Cancelable!?Target,
            finish: Io.Cancelable!?void,
            fetched: Io.Cancelable!?Id,
        };

        /// Waits for the next events; null when nothing is outstanding and no channel is open.
        pub fn wait_for_event(self: *Self) !?Events {
            const waiting = self.requests.len() > 0;
            if (!waiting and self.update_rx == null and self.finish_rx == null) return null;
            var buffer: [3]Wake = undefined;
            var select: Io.Select(Wake) = .init(self.io, &buffer);
            var events: Events = .{};
            self.spawn_waits(&select, waiting) catch |err| {
                while (select.cancel()) |rest| self.push_wake(&events, rest);
                return err;
            };
            const first = select.await() catch |err| {
                while (select.cancel()) |_| {}
                return err;
            };
            self.push_wake(&events, first);
            // A result that completes while the others are canceled is kept.
            while (select.cancel()) |rest| self.push_wake(&events, rest);
            assert(events.len <= 3);
            return events;
        }

        fn spawn_waits(self: *Self, select: *Io.Select(Wake), waiting: bool) !void {
            if (self.update_rx) |rx| {
                try select.concurrent(.update, ring.Receiver(Target).recv, .{rx});
            }
            if (self.finish_rx) |rx| {
                try select.concurrent(.finish, mpsc.Receiver(void).recv, .{rx});
            }
            if (waiting) try select.concurrent(.fetched, mpsc.Receiver(Id).recv, .{&self.done_rx});
        }

        fn push_wake(_: *Self, events: *Events, wake: Wake) void {
            const event: Event = switch (wake) {
                .update => |result| if (result catch return) |new_target|
                    .{ .target_update = new_target }
                else
                    .update_closed,
                .finish => |result| if (result catch return) |_|
                    .finish_requested
                else
                    .finish_closed,
                // The engine holds a sender, so the channel never closes.
                .fetched => |result| .{ .fetched = (result catch return).? },
            };
            assert(events.len < events.items.len);
            events.items[events.len] = event;
            events.len += 1;
        }

        fn wait_and_handle(self: *Self) !void {
            const events = (try self.wait_for_event()) orelse return error.SyncStalled;
            assert(events.len <= events.items.len);
            for (events.items[0..events.len]) |event| try self.handle_event(event);
        }

        /// One step: completes when the target is reached (unless a queued advancing update
        /// or a pending finish request keeps it going), else handles the next events. Returns
        /// the database once complete.
        pub fn step(self: *Self) !?DB {
            try self.drain_finish_requests();
            if (!try self.is_ready_to_complete()) {
                try self.wait_and_handle();
                return null;
            }
            // Report the reached target before a queued update can replace it.
            self.report_reached_target();
            if (!self.finish_requested) {
                if (self.take_queued_update()) |new_target| {
                    try self.handle_event(.{ .target_update = new_target });
                    return null;
                }
            }
            if (self.finish_rx != null) {
                try self.wait_and_handle();
                return null;
            }
            return try self.complete();
        }

        /// The first queued update that advances the target; others are discarded.
        fn take_queued_update(self: *Self) ?Target {
            // Each pass takes one queued update, and the ring is bounded.
            while (self.update_rx) |rx| {
                const new_target = rx.try_recv() catch |err| switch (err) {
                    error.Empty => return null,
                    error.Disconnected => {
                        self.update_rx = null;
                        return null;
                    },
                };
                if (new_target.advances(self.target)) return new_target;
            }
            return null;
        }

        /// Builds the database from the completed journal and checks its root.
        fn complete(self: *Self) !DB {
            try self.journal.sync();
            const pinned = self.pinned_nodes;
            self.pinned_nodes = null;
            self.journal_taken = true;
            const range: merkle.Range = .{ .start = self.target.start, .end = self.target.end };
            var db = try DB.from_sync_result(
                self.gpa,
                self.storage,
                self.scope,
                self.db_config,
                self.journal,
                pinned,
                range,
                self.apply_batch_size,
            );
            errdefer db.deinit();
            if (!db.ops_root().eql(self.target.root)) return error.RootMismatch;
            try db.persist_sync_result();
            return db;
        }
    };
}

test {
    _ = @import("engine_test.zig");
}
