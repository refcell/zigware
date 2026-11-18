//! A resolver over an opaque fetcher (commonware `resolver/src/opaque.rs`).
//!
//! The actor coalesces fetches by key, runs one `Fetcher.fetch` per key at a time, retries
//! missing values after `fetch_retry_delay_ns`, and delivers values to the consumer through
//! the delivery tracker. Targets are accepted (`fetch_targeted`) and ignored: an opaque source
//! has no peers.
//!
//! Event loop: every source wakes one `delivery.Signal`. Fetches run as `std.Io` tasks that
//! queue their results; the delivery tracker queues verdicts; a forwarder task moves mailbox
//! messages into a one-message inbox (so mailbox backpressure is preserved); retry deadlines
//! bound the wait. Each turn handles one event in commonware's `select_loop!` order: fetch
//! completions, delivery completions, due retries, then mailbox messages. The loop ends when
//! every resolver handle is gone (mailbox closed) or the task is canceled.
//!
//! Fetcher contract: `F.Key`, `F.Value` (equal to the consumer's), and
//! `fetch(self: F, io, key) Io.Cancelable!?F.Value`, where null is a transient failure or
//! missing data. A fetch is canceled (`error.Canceled` at its next cancelation point) when its
//! key's last subscriber is pruned.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const resolver = @import("root.zig");
const ingress = @import("ingress.zig");
const delivery = @import("delivery.zig");
const subscribers = @import("subscribers.zig");
const metrics = @import("runtime").telemetry.metrics;

const Feedback = actor.Feedback;
const Outcome = resolver.Outcome;

/// Checks that `F` is a `Fetcher`.
pub fn assert_fetcher(comptime F: type) void {
    comptime {
        assert(@hasDecl(F, "Key"));
        assert(@hasDecl(F, "Value"));
        assert(@hasDecl(F, "fetch"));
    }
}

pub const Config = struct {
    /// Ready capacity of the actor's mailbox.
    mailbox_size: u32,
    /// Delay before retrying a key whose fetch failed or whose response did not resolve it.
    fetch_retry_delay_ns: u64,
};

/// The statuses the `fetch` counter records (commonware `telemetry::metrics::status::Status`):
/// `success`, `ambiguous`, and `dropped`.
pub const Status = metrics.status.Status;

/// Handle to an opaque-fetcher resolver actor (`Resolver`, `TargetedResolver`).
pub fn Resolver(comptime K: type, comptime S: type, comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Key = K;
        pub const Subscriber = S;
        pub const PublicKey = P;
        pub const Message = ingress.Message(K, S, void);
        const FetchType = resolver.Fetch(K, S);

        gpa: Allocator,
        mailbox: actor.mailbox.Sender(Message),

        pub fn fetch(self: Self, item: FetchType) Allocator.Error!Feedback {
            return self.fetch_all(&.{item});
        }

        pub fn fetch_all(self: Self, items: []const FetchType) Allocator.Error!Feedback {
            var fetches: std.ArrayList(Message.Fetch) = try .initCapacity(self.gpa, items.len);
            errdefer {
                for (fetches.items) |*item| item.deinit(self.gpa);
                fetches.deinit(self.gpa);
            }
            for (items) |item| {
                const key = try Message.Fetch.init(self.gpa, item.key, item.subscriber, {});
                fetches.appendAssumeCapacity(key);
            }
            assert(fetches.items.len == items.len);
            return self.mailbox.enqueue(.{ .fetch = .{ .gpa = self.gpa, .fetches = fetches } });
        }

        pub fn retain(self: Self, predicate: resolver.Predicate(K, S)) Allocator.Error!Feedback {
            return self.mailbox.enqueue(.{ .retain = predicate });
        }

        /// Targets are ignored: an opaque fetcher has no peers.
        pub fn fetch_targeted(
            self: Self,
            item: FetchType,
            targets: []const P,
        ) Allocator.Error!Feedback {
            assert(targets.len > 0);
            return self.fetch(item);
        }

        pub fn fetch_all_targeted(
            self: Self,
            items: []const resolver.Targeted(K, S, P),
        ) Allocator.Error!Feedback {
            var fetches: std.ArrayList(FetchType) = try .initCapacity(self.gpa, items.len);
            defer fetches.deinit(self.gpa);
            for (items) |item| {
                assert(item.targets.len > 0);
                fetches.appendAssumeCapacity(item.fetch);
            }
            return self.fetch_all(fetches.items);
        }

        pub fn clone(self: Self) Self {
            return .{ .gpa = self.gpa, .mailbox = self.mailbox.clone() };
        }

        /// Release this handle; the actor stops once every handle is gone.
        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.* = undefined;
        }
    };
}

/// The resolver actor for fetcher `F` and consumer `C`.
pub fn Actor(comptime F: type, comptime C: type) type {
    comptime assert_fetcher(F);
    comptime resolver.assert_consumer(C);
    comptime assert(F.Key == C.Key and F.Value == C.Value);
    return struct {
        const Self = @This();
        const K = C.Key;
        const S = C.Subscriber;
        const V = C.Value;
        pub const Message = ingress.Message(K, S, void);
        pub const Error = Allocator.Error || Io.ConcurrentError;

        /// The current attempt for a tracked key, held as the delivery tracker's key state.
        pub const Attempt = union(enum) {
            /// A fetch task is active for this key.
            fetching: *FetchTask,
            /// Consumer validation is active for this key.
            delivering,
            /// The fetch sleeps until this deadline (awake clock, nanoseconds).
            scheduled: i96,
        };

        pub const FetchTask = struct {
            key: K,
            /// Written by the task under the signal's mutex.
            value: ?V = null,
            future: Io.Future(void) = undefined,
        };

        const Retry = struct { deadline_ns: i96, key: K };

        const Event = union(enum) {
            fetched: *FetchTask,
            delivered,
            retry,
            message: Message,
            stopped,
        };

        /// A spawned actor: its handle, its task, and (for inspection while it runs on a
        /// single-threaded runtime) the actor itself.
        pub fn Spawned(comptime P: type) type {
            return struct {
                resolver: Resolver(K, S, P),
                future: Io.Future(Error!void),
                actor: *Self,
            };
        }

        gpa: Allocator,
        io: Io,
        fetcher: F,
        config: Config,
        signal: delivery.Signal = .{},
        mailbox: actor.mailbox.Receiver(Message),
        forwarder: ?Io.Future(void) = null,
        /// Guarded by `signal`: the next mailbox message, and whether the mailbox closed.
        inbox: ?Message = null,
        /// Broadcast when the actor empties `inbox`; only the forwarder waits on it, so the
        /// actor's timed waits on `signal.condition` cannot consume its wake (AGENTS.md:
        /// `Io.Condition` counts signals, not waiters).
        inbox_freed: Io.Condition = .init,
        mailbox_closed: bool = false,
        /// Every fetch task not yet handled (owner only).
        fetches: std.ArrayList(*FetchTask) = .empty,
        /// Guarded by `signal`: finished fetches, oldest first. Capacity covers `fetches`.
        fetch_done: std.ArrayList(*FetchTask) = .empty,
        /// Broadcast with `signal` when a fetch finishes; only `next_fetched` waits on it.
        fetched: Io.Condition = .init,
        deliveries: delivery.Tracker(C, void, Attempt),
        subscribers: subscribers.Tracker(K, S) = .empty,
        /// Ascending by (deadline, key).
        retry_schedule: std.ArrayList(Retry) = .empty,
        /// `fetch_total{status}`: useful and dropped responses, each counted once even when
        /// redelivered. A status appears in the output once first counted.
        fetch: metrics.status.Counter,
        removed: std.ArrayList(K) = .empty,

        /// Spawn an actor and return a handle to it (commonware `init`). Its metrics register
        /// under `scope.child("actor")`.
        pub fn spawn(
            comptime P: type,
            gpa: Allocator,
            io: Io,
            scope: metrics.Scope,
            fetcher: F,
            consumer: C,
            config: Config,
        ) Error!Spawned(P) {
            var pair = try actor.mailbox.new(Message, gpa, io, config.mailbox_size);
            const actor_scope = scope.child("actor");
            const receiver = pair.receiver;
            const created = create(gpa, io, actor_scope, fetcher, consumer, receiver, config);
            const self = created catch |err| {
                pair.receiver.deinit();
                pair.sender.deinit();
                return err;
            };
            const future = io.concurrent(run, .{self}) catch |err| {
                self.destroy();
                pair.sender.deinit();
                return err;
            };
            return .{
                .resolver = .{ .gpa = gpa, .mailbox = pair.sender },
                .future = future,
                .actor = self,
            };
        }

        /// An actor that is not running yet; `run` drives it, `destroy` frees it. Metrics
        /// register directly under `scope`.
        pub fn create(
            gpa: Allocator,
            io: Io,
            scope: metrics.Scope,
            fetcher: F,
            consumer: C,
            mailbox: actor.mailbox.Receiver(Message),
            config: Config,
        ) Allocator.Error!*Self {
            assert(config.mailbox_size > 0);
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{
                .gpa = gpa,
                .io = io,
                .fetcher = fetcher,
                .config = config,
                .mailbox = mailbox,
                .deliveries = undefined,
                .fetch = undefined,
            };
            self.fetch = try .register(&scope, "fetch", "Number of fetches by status");
            errdefer self.fetch.deinit();
            self.deliveries = try .init_with_signal(gpa, io, consumer, &self.signal);
            return self;
        }

        /// Cancel every task and free the actor (taking ownership of its mailbox receiver).
        pub fn destroy(self: *Self) void {
            if (self.forwarder) |*forwarder| forwarder.cancel(self.io);
            for (self.fetches.items) |task| {
                task.future.cancel(self.io);
                if (task.value) |value| self.drop_value(value);
                self.gpa.destroy(task);
            }
            self.fetches.deinit(self.gpa);
            self.fetch_done.deinit(self.gpa);
            self.deliveries.deinit();
            self.subscribers.deinit(self.gpa);
            self.retry_schedule.deinit(self.gpa);
            self.removed.deinit(self.gpa);
            self.fetch.deinit();
            if (self.inbox) |message| Message.discard(message);
            self.mailbox.deinit();
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
        }

        /// The actor task: handle events until the mailbox closes, then free the actor.
        pub fn run(self: *Self) Error!void {
            defer self.destroy();
            self.forwarder = try self.io.concurrent(forward, .{self});
            // Runs for the actor's lifetime; each turn handles exactly one event.
            while (true) {
                const event = self.wait_event() catch return; // canceled
                switch (event) {
                    .fetched => |task| try self.handle_fetched(task),
                    .delivered => {
                        const result = self.deliveries.try_next_completion() catch continue;
                        const completed = result orelse continue;
                        try self.handle_delivered(completed);
                    },
                    .retry => try self.process_retries(),
                    .message => |message| try self.handle_message(message),
                    .stopped => return,
                }
            }
        }

        fn wait_event(self: *Self) Io.Cancelable!Event {
            self.deliveries.close_canceled();
            const signal = &self.signal;
            signal.mutex.lockUncancelable(self.io);
            defer signal.mutex.unlock(self.io);
            // Each wake re-checks every source; waits end on a signal, timeout, or cancel.
            while (true) {
                if (self.fetch_done.items.len > 0) {
                    return .{ .fetched = self.fetch_done.orderedRemove(0) };
                }
                if (self.deliveries.has_completion_locked()) return .delivered;
                const deadline = if (self.retry_schedule.items.len > 0)
                    self.retry_schedule.items[0].deadline_ns
                else
                    null;
                if (deadline) |due| if (self.now() >= due) return .retry;
                if (self.inbox) |message| {
                    self.inbox = null;
                    self.inbox_freed.broadcast(self.io);
                    return .{ .message = message };
                }
                if (self.mailbox_closed) return .stopped;
                const timeout: Io.Timeout = if (deadline) |due|
                    .{ .deadline = .{ .raw = .{ .nanoseconds = due }, .clock = .awake } }
                else
                    .none;
                signal.condition.waitTimeout(self.io, &signal.mutex, timeout) catch |err|
                    switch (err) {
                        error.Timeout => {},
                        error.Canceled => return error.Canceled,
                    };
            }
        }

        /// Moves mailbox messages into the one-message inbox.
        fn forward(self: *Self) void {
            const signal = &self.signal;
            while (true) {
                const received = self.mailbox.recv() catch return; // canceled
                signal.mutex.lockUncancelable(self.io);
                defer signal.mutex.unlock(self.io);
                const message = received orelse {
                    self.mailbox_closed = true;
                    signal.condition.broadcast(self.io);
                    return;
                };
                while (self.inbox != null) {
                    self.inbox_freed.wait(self.io, &signal.mutex) catch {
                        Message.discard(message);
                        return;
                    };
                }
                self.inbox = message;
                signal.condition.broadcast(self.io);
            }
        }

        /// Apply a mailbox message to active resolver state.
        pub fn handle_message(self: *Self, message: Message) Error!void {
            switch (message) {
                .fetch => |batch| {
                    var owned = batch;
                    defer owned.deinit();
                    for (owned.fetches.items) |item| {
                        try self.add_fetch(item.key, item.subscribers.items);
                    }
                },
                .retain => |predicate| try self.retain(predicate),
            }
        }

        /// Add subscribers for a key and start the first fetch if the key is new.
        pub fn add_fetch(self: *Self, key: K, added: []const S) Error!void {
            assert(added.len > 0);
            const is_new = try self.subscribers.insert(self.gpa, key, added);
            if (!is_new) return;
            const attempt = try self.start_fetch(key);
            const inserted = try self.deliveries.insert_with_state(key, attempt);
            assert(inserted); // a new key must not have a delivery entry
        }

        /// Prune subscribers, deliveries, active fetches, and scheduled retries.
        pub fn retain(self: *Self, predicate: resolver.Predicate(K, S)) Allocator.Error!void {
            self.removed.clearRetainingCapacity();
            try self.subscribers.retain(self.gpa, &predicate, &self.removed);
            for (self.removed.items) |key| {
                const state = self.deliveries.remove_with_state(key) orelse continue;
                if (state) |attempt| self.release_attempt(key, attempt);
            }
        }

        fn start_fetch(self: *Self, key: K) Error!Attempt {
            const task = try self.gpa.create(FetchTask);
            errdefer self.gpa.destroy(task);
            task.* = .{ .key = key };
            try self.fetches.ensureUnusedCapacity(self.gpa, 1);
            {
                self.signal.mutex.lockUncancelable(self.io);
                defer self.signal.mutex.unlock(self.io);
                const needed = self.fetches.items.len + 1;
                try self.fetch_done.ensureTotalCapacity(self.gpa, needed);
            }
            task.future = try self.io.concurrent(run_fetch, .{ self, task });
            self.fetches.appendAssumeCapacity(task);
            return .{ .fetching = task };
        }

        /// The task behind each fetch: run the fetcher, then queue the result.
        fn run_fetch(self: *Self, task: *FetchTask) void {
            const value = self.fetcher.fetch(self.io, task.key) catch return; // aborted
            self.signal.mutex.lockUncancelable(self.io);
            defer self.signal.mutex.unlock(self.io);
            task.value = value;
            assert(self.fetch_done.items.len < self.fetch_done.capacity);
            self.fetch_done.appendAssumeCapacity(task);
            self.signal.condition.broadcast(self.io);
            self.fetched.broadcast(self.io);
        }

        /// Wait for the next finished fetch.
        pub fn next_fetched(self: *Self) Io.Cancelable!*FetchTask {
            self.signal.mutex.lockUncancelable(self.io);
            defer self.signal.mutex.unlock(self.io);
            while (self.fetch_done.items.len == 0) {
                try self.fetched.wait(self.io, &self.signal.mutex);
            }
            return self.fetch_done.orderedRemove(0);
        }

        /// The next finished fetch, if any, without waiting.
        pub fn try_next_fetched(self: *Self) ?*FetchTask {
            self.signal.mutex.lockUncancelable(self.io);
            defer self.signal.mutex.unlock(self.io);
            if (self.fetch_done.items.len == 0) return null;
            return self.fetch_done.orderedRemove(0);
        }

        /// Deliver a fetched value, or schedule a retry when the source had no data.
        pub fn handle_fetched(self: *Self, task: *FetchTask) Error!void {
            const key = task.key;
            const state = self.deliveries.state_mut(key).?; // key must have an attempt
            assert(state.* == .fetching and state.fetching == task);
            state.* = .delivering;
            task.future.await(self.io);
            const index = std.mem.indexOfScalar(*FetchTask, self.fetches.items, task).?;
            _ = self.fetches.swapRemove(index);
            const value = task.value;
            self.gpa.destroy(task);
            const fetched = value orelse return self.schedule_retry(key);
            if (self.subscribers.pending(key)) |pending| {
                const shown: resolver.Delivery(K, S) = .{ .key = key, .subscribers = pending };
                return self.deliveries.deliver(shown, {}, fetched);
            }
            self.drop_value(fetched);
            self.drop_key(key);
        }

        /// Complete, redeliver, or retry a key after consumer validation.
        pub fn handle_delivered(self: *Self, completion: Done) Error!void {
            var completed = completion;
            defer completed.deinit(self.gpa);
            const key = completed.key;
            const accepted = completed.previously_accepted;
            // Count useful source responses once, even if their fetch was canceled.
            if (!accepted) if (completed.outcome) |outcome| switch (outcome) {
                .resolved => try self.count(.success),
                .unresolved => try self.count(.ambiguous),
                else => {},
            };
            if (completed.canceled) return;
            // A dropped verdict only says the consumer did not judge the response for these
            // subscribers: hand it to the remaining ones, or retire the key.
            const outcome = completed.outcome orelse {
                const remaining = self.subscribers.remove_delivered(
                    self.gpa,
                    key,
                    completed.subscribers,
                );
                if (remaining) |pending| {
                    return self.deliveries.redeliver(.{ .key = key, .subscribers = pending });
                }
                if (!accepted) try self.count(.dropped);
                self.drop_key(key);
                return;
            };
            switch (outcome) {
                .resolved => |resolution| switch (resolution) {
                    .complete => try self.handle_complete(key, accepted, completed.subscribers),
                    .partial => try self.retry_response(key),
                },
                .unresolved => try self.retry_response(key),
                .invalid => {
                    // A rejection during redelivery of an accepted response is stale
                    // feedback: retire the key rather than refetch accepted data.
                    if (accepted) return self.drop_key(key);
                    try self.retry_response(key);
                },
                .ignored => {
                    // The consumer no longer needs the key: retire it without a retry.
                    try self.count(.dropped);
                    self.drop_key(key);
                },
            }
        }

        pub const Done = delivery.Completion(K, S, void);

        fn handle_complete(self: *Self, key: K, accepted: bool, delivered: []const S) Error!void {
            const remaining = self.subscribers.remove_delivered(self.gpa, key, delivered);
            // The first accepted response is reused for subscribers that joined during
            // validation, avoiding a duplicate source fetch for the same key.
            const pending = remaining orelse return self.drop_key(key);
            if (!accepted) self.deliveries.accept_response(key);
            try self.deliveries.redeliver(.{ .key = key, .subscribers = pending });
        }

        /// Discard the response and retry, without recounting it.
        fn retry_response(self: *Self, key: K) Allocator.Error!void {
            self.deliveries.discard_response(key);
            try self.schedule_retry(key);
        }

        /// Schedule the next fetch attempt for `key`.
        fn schedule_retry(self: *Self, key: K) Allocator.Error!void {
            try self.retry_schedule.ensureUnusedCapacity(self.gpa, 1);
            const deadline_ns = self.now() + self.config.fetch_retry_delay_ns;
            self.deliveries.state_mut(key).?.* = .{ .scheduled = deadline_ns };
            const retry: Retry = .{ .deadline_ns = deadline_ns, .key = key };
            const index = std.sort.lowerBound(Retry, self.retry_schedule.items, retry, order_retry);
            self.retry_schedule.insertAssumeCapacity(index, retry);
        }

        /// Start all retry attempts whose deadlines have passed.
        pub fn process_retries(self: *Self) Error!void {
            const now_ns = self.now();
            while (self.retry_schedule.items.len > 0) {
                const retry = self.retry_schedule.items[0];
                if (retry.deadline_ns > now_ns) break;
                _ = self.retry_schedule.orderedRemove(0);
                const attempt = try self.start_fetch(retry.key);
                self.deliveries.state_mut(retry.key).?.* = attempt;
            }
        }

        fn drop_key(self: *Self, key: K) void {
            _ = self.subscribers.remove(self.gpa, key);
            const state = self.deliveries.remove_with_state(key) orelse return;
            if (state) |attempt| self.release_attempt(key, attempt);
        }

        /// Abort an active fetch or unschedule a retry of a removed key.
        fn release_attempt(self: *Self, key: K, attempt: Attempt) void {
            switch (attempt) {
                .fetching => |task| self.abort_fetch(task),
                .delivering => {},
                .scheduled => |deadline_ns| {
                    const retry: Retry = .{ .deadline_ns = deadline_ns, .key = key };
                    const items = self.retry_schedule.items;
                    const index = std.sort.lowerBound(Retry, items, retry, order_retry);
                    assert(order_retry(retry, items[index]) == .eq);
                    _ = self.retry_schedule.orderedRemove(index);
                },
            }
        }

        fn abort_fetch(self: *Self, task: *FetchTask) void {
            task.future.cancel(self.io);
            {
                self.signal.mutex.lockUncancelable(self.io);
                defer self.signal.mutex.unlock(self.io);
                const done = std.mem.indexOfScalar(*FetchTask, self.fetch_done.items, task);
                if (done) |index| _ = self.fetch_done.orderedRemove(index);
            }
            if (task.value) |value| self.drop_value(value);
            const index = std.mem.indexOfScalar(*FetchTask, self.fetches.items, task).?;
            _ = self.fetches.swapRemove(index);
            self.gpa.destroy(task);
        }

        fn count(self: *Self, status: Status) Allocator.Error!void {
            try self.fetch.inc(status);
        }

        /// The `fetch_total` count for `status` (zero until first counted).
        pub fn fetch_count(self: *Self, status: Status) u64 {
            return self.fetch.get(status);
        }

        fn drop_value(self: *Self, value: V) void {
            if (comptime @hasDecl(C, "deinit_value")) C.deinit_value(self.gpa, value);
        }

        fn now(self: *const Self) i96 {
            return Io.Timestamp.now(self.io, .awake).nanoseconds;
        }

        fn order_retry(a: Retry, b: Retry) std.math.Order {
            const by_deadline = std.math.order(a.deadline_ns, b.deadline_ns);
            if (by_deadline != .eq) return by_deadline;
            return resolver.order(K, a.key, b.key);
        }
    };
}

test {
    _ = @import("opaque_test.zig");
}
