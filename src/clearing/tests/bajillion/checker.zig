//! A small explicit-state model checker standing in for Stateright in `model.zig`.
//!
//! It explores every state a model reaches from its initial states, depth first with an
//! explicit stack (no recursion), and checks every `always` property in each state when it is
//! first reached. As Stateright does, it identifies a state by a 64-bit fingerprint the model
//! computes, so two states with the same fingerprint count as one. It stops at the first
//! property that fails and returns the actions that lead there from an initial state. The
//! number of unique states is bounded by `Options.max_states`.
//!
//! As Stateright's `threads(n)`, `Options.workers` explore at once, and the model must be safe
//! to call from several threads. Each worker explores depth first on a stack of its own and
//! hands half of it to a shared stack while another worker waits; the visited set is split
//! into shards by fingerprint, each behind its own lock, and records how each state was first
//! reached. Without the split, one lock taken several times per transition held a
//! 32-worker check to a few cores (as Stateright's job market and sharded map avoid). Unique
//! states, transitions, and the flows a model records do not depend on the worker count;
//! `max_depth` and which violation is reported first may.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// A property that must hold in every reachable state of a model `M`.
pub fn Property(comptime M: type) type {
    return struct {
        name: []const u8,
        holds: *const fn (model: *M, state: *const M.State) anyerror!bool,
    };
}

pub const Options = struct {
    /// The most unique states to explore before failing with `error.StateSpaceTooLarge`.
    max_states: u64 = 1 << 20,
    /// Threads exploring at once; the caller's thread is one of them.
    workers: u32 = 1,
    /// Runs the other workers (`io.concurrent`); required when `workers > 1`.
    io: ?std.Io = null,
};

/// The most workers a check runs.
pub const max_workers = 64;

/// Checks the model `M`. `M` declares:
/// - `State`, with `deinit(*State, Allocator)`, and `Action`, a value type;
/// - `init_states(*M, Allocator) ![]State`, the caller owning the slice and the states;
/// - `actions(*M, Allocator, *const State, *std.ArrayList(Action)) !void`, appending the
///   enabled actions;
/// - `next_state(*M, *const State, Action) !?State`, null when the action changes nothing
///   worth exploring;
/// - `fingerprint(*M, *const State) u64`, equal for states the model considers the same;
/// - `properties: []const Property(M)`.
/// Every declaration must be `pub`.
pub fn Checker(comptime M: type) type {
    return struct {
        const Self = @This();
        pub const State = M.State;
        pub const Action = M.Action;

        /// A property that failed, with the actions leading to a state where it fails.
        pub const Violation = struct {
            property: []const u8,
            path: []Action,
        };

        pub const Result = struct {
            /// Unique states reached, counting the initial ones.
            unique: u64,
            /// Next states generated, including those already seen; an action whose
            /// `next_state` is null generates none (Stateright's `state_count` less the initial
            /// states).
            transitions: u64,
            /// The deepest state reached, in actions from an initial state.
            max_depth: u64,
            violation: ?Violation,

            pub fn deinit(self: *Result, gpa: Allocator) void {
                if (self.violation) |v| gpa.free(v.path);
                self.* = undefined;
            }
        };

        /// How a unique state was first reached: its parent's fingerprint and the action taken
        /// there.
        const Node = struct { parent: ?u64, action: ?Action, depth: u64 };
        /// A state waiting to have its actions explored.
        const Entry = struct { state: State, fingerprint: u64, depth: u64 };
        const Stack = std.ArrayList(Entry);
        /// The visited set is split by fingerprint, so workers recording states rarely wait on
        /// one another (as Stateright's sharded map).
        const shard_count = 64;
        const Shard = struct {
            mutex: std.Io.Mutex = .init,
            nodes: std.AutoHashMapUnmanaged(u64, Node) = .empty,
        };

        gpa: Allocator,
        model: *M,
        options: Options,
        shards: [shard_count]Shard = @splat(.{}),
        unique: std.atomic.Value(u64) = .init(0),
        transitions: std.atomic.Value(u64) = .init(0),
        max_depth: std.atomic.Value(u64) = .init(0),
        /// Set once a violation or an error ends the check.
        stopped: std.atomic.Value(bool) = .init(false),
        /// Workers waiting for shared states; a worker with spare states shares while nonzero.
        waiting: std.atomic.Value(u32) = .init(0),
        /// Guards the four fields below it.
        mutex: std.Io.Mutex = .init,
        /// Signalled when states are shared or the check ends.
        changed: std.Io.Condition = .init,
        /// The initial states, and states workers shared.
        stack: Stack = .empty,
        /// Workers exploring states they took (each from its own stack).
        active: u32 = 0,
        /// The first violation found, which ends the check.
        violation: ?Violation = null,
        /// The first error a worker hit, which ends the check.
        failure: ?anyerror = null,

        /// Explores every state of `model` reachable within `options`.
        pub fn run(gpa: Allocator, model: *M, options: Options) !Result {
            assert(options.max_states > 0);
            assert(options.workers >= 1 and options.workers <= max_workers);
            assert(options.workers == 1 or options.io != null);
            var self: Self = .{ .gpa = gpa, .model = model, .options = options };
            defer self.deinit();
            try self.seed();
            if (!self.stopped.load(.monotonic)) self.explore();
            if (self.failure) |err| {
                if (self.violation) |v| gpa.free(v.path);
                return err;
            }
            const result: Result = .{
                .unique = self.unique.load(.monotonic),
                .transitions = self.transitions.load(.monotonic),
                .max_depth = self.max_depth.load(.monotonic),
                .violation = self.violation,
            };
            var recorded: u64 = 0;
            for (&self.shards) |*shard| recorded += shard.nodes.count();
            assert(result.unique == recorded);
            return result;
        }

        fn deinit(self: *Self) void {
            for (self.stack.items) |*entry| entry.state.deinit(self.gpa);
            self.stack.deinit(self.gpa);
            for (&self.shards) |*shard| shard.nodes.deinit(self.gpa);
        }

        /// Discovers the initial states onto the shared stack, on the caller's thread.
        fn seed(self: *Self) !void {
            const initial = try M.init_states(self.model, self.gpa);
            defer self.gpa.free(initial);
            var taken: usize = 0;
            defer for (initial[taken..]) |*state| state.deinit(self.gpa);
            for (initial) |*state| {
                const owned = state.*;
                taken += 1;
                self.discover(owned, null, null, &self.stack);
                if (self.stopped.load(.monotonic)) return;
            }
        }

        /// Runs `options.workers` workers until every state is explored or the check ends.
        fn explore(self: *Self) void {
            const extra = self.options.workers - 1;
            var futures: [max_workers - 1]std.Io.Future(void) = undefined;
            var started: usize = 0;
            defer for (futures[0..started]) |*future| future.await(self.options.io.?);
            while (started < extra) : (started += 1) {
                futures[started] = self.options.io.?.concurrent(work, .{self}) catch |err| {
                    self.fail(err);
                    break;
                };
            }
            self.work();
        }

        fn lock(self: *Self, mutex: *std.Io.Mutex) void {
            if (self.options.io) |io| mutex.lockUncancelable(io);
        }

        fn unlock(self: *Self, mutex: *std.Io.Mutex) void {
            if (self.options.io) |io| mutex.unlock(io);
        }

        /// Records `err` as the check's failure unless one is recorded, and wakes the workers.
        fn fail(self: *Self, err: anyerror) void {
            self.lock(&self.mutex);
            defer self.unlock(&self.mutex);
            if (self.failure == null) self.failure = err;
            self.stop();
        }

        /// Ends the check (the lock held).
        fn stop(self: *Self) void {
            self.stopped.store(true, .monotonic);
            if (self.options.io) |io| self.changed.broadcast(io);
        }

        /// Takes shared states and explores each one's descendants depth first on a stack of
        /// its own, until no worker holds states or the check ends.
        fn work(self: *Self) void {
            var actions: std.ArrayList(Action) = .empty;
            defer actions.deinit(self.gpa);
            var local: Stack = .empty;
            defer local.deinit(self.gpa);
            while (self.take()) |taken| {
                self.drain(taken, &local, &actions);
                assert(local.items.len == 0);
                self.lock(&self.mutex);
                defer self.unlock(&self.mutex);
                assert(self.active > 0);
                self.active -= 1;
                const idle = self.stack.items.len == 0 and self.active == 0;
                if (idle) if (self.options.io) |io| self.changed.broadcast(io);
            }
        }

        /// Explores `first` and every state it leads to through `local`; once the check ends,
        /// frees the states left instead.
        fn drain(self: *Self, first: Entry, local: *Stack, actions: *std.ArrayList(Action)) void {
            var next: ?Entry = first;
            while (next) |popped| {
                var entry = popped;
                defer entry.state.deinit(self.gpa);
                if (!self.stopped.load(.monotonic)) {
                    self.expand(&entry, actions, local) catch |err| self.fail(err);
                    self.share(local);
                }
                next = local.pop();
            }
        }

        /// The next shared state (counted active), or null once the check is over.
        fn take(self: *Self) ?Entry {
            self.lock(&self.mutex);
            defer self.unlock(&self.mutex);
            while (true) {
                if (self.stopped.load(.monotonic)) return null;
                if (self.stack.pop()) |entry| {
                    self.active += 1;
                    return entry;
                }
                if (self.active == 0) return null;
                // Only a multi-worker check waits: one worker never sees others active.
                _ = self.waiting.fetchAdd(1, .monotonic);
                defer _ = self.waiting.fetchSub(1, .monotonic);
                self.changed.waitUncancelable(self.options.io.?, &self.mutex);
            }
        }

        /// Moves the older half of `local` to the shared stack while a worker waits for states.
        fn share(self: *Self, local: *Stack) void {
            if (self.waiting.load(.monotonic) == 0 or local.items.len < 2) return;
            self.lock(&self.mutex);
            defer self.unlock(&self.mutex);
            const half = local.items.len / 2;
            // Out of memory, the states stay on `local`, which explores them.
            self.stack.appendSlice(self.gpa, local.items[0..half]) catch return;
            local.replaceRangeAssumeCapacity(0, half, &.{});
            assert(local.items.len > 0);
            if (self.options.io) |io| self.changed.broadcast(io);
        }

        /// Applies every enabled action of `entry`'s state, discovering the next states onto
        /// `local`.
        fn expand(
            self: *Self,
            entry: *const Entry,
            actions: *std.ArrayList(Action),
            local: *Stack,
        ) !void {
            actions.clearRetainingCapacity();
            try M.actions(self.model, self.gpa, &entry.state, actions);
            var generated: u64 = 0;
            defer _ = self.transitions.fetchAdd(generated, .monotonic);
            for (actions.items) |action| {
                const next = try M.next_state(self.model, &entry.state, action) orelse continue;
                generated += 1;
                self.discover(next, entry, action, local);
            }
        }

        /// Records `state` (taken) if it is new, checks the properties in it, and pushes it on
        /// `out`. A violation or an error ends the check.
        fn discover(
            self: *Self,
            state: State,
            parent: ?*const Entry,
            action: ?Action,
            out: *Stack,
        ) void {
            var owned = state;
            const fingerprint = M.fingerprint(self.model, &owned);
            const depth = if (parent) |p| p.depth + 1 else 0;
            const node: Node = .{
                .parent = if (parent) |p| p.fingerprint else null,
                .action = action,
                .depth = depth,
            };
            const fresh = self.record(fingerprint, node) catch |err| {
                owned.deinit(self.gpa);
                return self.fail(err);
            };
            if (!fresh) return owned.deinit(self.gpa);
            for (M.properties) |property| {
                const holds = property.holds(self.model, &owned) catch |err| {
                    owned.deinit(self.gpa);
                    return self.fail(err);
                };
                if (holds) continue;
                owned.deinit(self.gpa);
                return self.violate(property.name, fingerprint);
            }
            const entry: Entry = .{ .state = owned, .fingerprint = fingerprint, .depth = depth };
            out.append(self.gpa, entry) catch |err| {
                owned.deinit(self.gpa);
                return self.fail(err);
            };
        }

        /// Records `node` under `fingerprint` unless the fingerprint is known, returning whether
        /// it was new.
        fn record(self: *Self, fingerprint: u64, node: Node) !bool {
            if (self.stopped.load(.monotonic)) return false;
            const shard = &self.shards[fingerprint >> (64 - @ctz(@as(u64, shard_count)))];
            self.lock(&shard.mutex);
            defer self.unlock(&shard.mutex);
            const seen = try shard.nodes.getOrPut(self.gpa, fingerprint);
            if (seen.found_existing) return false;
            if (self.unique.fetchAdd(1, .monotonic) >= self.options.max_states) {
                _ = self.unique.fetchSub(1, .monotonic);
                shard.nodes.removeByPtr(seen.key_ptr);
                return error.StateSpaceTooLarge;
            }
            seen.value_ptr.* = node;
            _ = self.max_depth.fetchMax(node.depth, .monotonic);
            return true;
        }

        /// Records the first violation, with the path to `fingerprint`, and ends the check.
        fn violate(self: *Self, property: []const u8, fingerprint: u64) void {
            self.lock(&self.mutex);
            defer self.unlock(&self.mutex);
            if (self.violation != null or self.failure != null) return;
            if (self.path_to(fingerprint)) |path| {
                self.violation = .{ .property = property, .path = path };
            } else |err| {
                self.failure = err;
            }
            self.stop();
        }

        fn node_of(self: *Self, fingerprint: u64) Node {
            const shard = &self.shards[fingerprint >> (64 - @ctz(@as(u64, shard_count)))];
            self.lock(&shard.mutex);
            defer self.unlock(&shard.mutex);
            return shard.nodes.get(fingerprint).?; // Proof: only recorded states are walked.
        }

        /// The actions from an initial state to the state of `fingerprint`, in order.
        fn path_to(self: *Self, fingerprint: u64) ![]Action {
            const depth = self.node_of(fingerprint).depth;
            const path = try self.gpa.alloc(Action, depth);
            var at = fingerprint;
            var index = depth;
            while (index > 0) {
                const n = self.node_of(at);
                index -= 1;
                path[index] = n.action.?;
                at = n.parent.?;
            }
            assert(self.node_of(at).parent == null);
            return path;
        }
    };
}

/// Two counters below `limit` that can each grow by one or hand one unit to the other. With
/// `planted`, the first counter may grow one past the limit, a bug `bounded` must catch.
const Counters = struct {
    limit: u8,
    planted: bool,

    const State = struct {
        a: u8,
        b: u8,
        fn deinit(_: *State, _: Allocator) void {}
    };
    const Action = enum { grow_a, grow_b, hand_over };

    const properties = [_]Property(Counters){
        .{ .name = "both counters stay within the limit", .holds = bounded },
    };

    fn bounded(model: *Counters, state: *const State) anyerror!bool {
        return state.a <= model.limit and state.b <= model.limit;
    }

    fn init_states(_: *Counters, gpa: Allocator) ![]State {
        return gpa.dupe(State, &.{.{ .a = 0, .b = 0 }});
    }

    fn actions(
        model: *Counters,
        gpa: Allocator,
        state: *const State,
        out: *std.ArrayList(Action),
    ) !void {
        const a_limit = if (model.planted) model.limit + 1 else model.limit;
        if (state.a < a_limit) try out.append(gpa, .grow_a);
        if (state.b < model.limit) try out.append(gpa, .grow_b);
        if (state.a > 0 and state.b < model.limit) try out.append(gpa, .hand_over);
    }

    fn next_state(_: *Counters, state: *const State, action: Action) !?State {
        var next = state.*;
        switch (action) {
            .grow_a => next.a += 1,
            .grow_b => next.b += 1,
            .hand_over => {
                next.a -= 1;
                next.b += 1;
            },
        }
        return next;
    }

    fn fingerprint(_: *Counters, state: *const State) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, state.*);
        return hasher.final();
    }
};

/// One worker, and four sharing the exploration.
const worker_options = [_]Options{ .{}, .{ .workers = 4, .io = std.testing.io } };

test "checker: explores every state once and finds no violation" {
    for (worker_options) |options| {
        var model: Counters = .{ .limit = 3, .planted = false };
        var result = try Checker(Counters).run(std.testing.allocator, &model, options);
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(result.violation == null);
        // Every pair of counters within the limit, and nothing else.
        try std.testing.expectEqual(@as(u64, 16), result.unique);
        // Depth first reaches (3, 3) by growing alone; workers may reach it another way.
        if (options.workers == 1) try std.testing.expectEqual(@as(u64, 6), result.max_depth);
        // Each state below the limit grows each counter, and hands over while `a > 0`.
        try std.testing.expectEqual(@as(u64, 12 + 12 + 9), result.transitions);
    }
}

test "checker: catches a planted bug with a path that reproduces it" {
    for (worker_options) |options| try expect_planted_bug_caught(options);
}

fn expect_planted_bug_caught(options: Options) !void {
    const gpa = std.testing.allocator;
    var model: Counters = .{ .limit = 3, .planted = true };
    var result = try Checker(Counters).run(gpa, &model, options);
    defer result.deinit(gpa);
    const violation = result.violation orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("both counters stay within the limit", violation.property);

    // Replaying the path from the initial state takes only enabled actions and ends where the
    // property fails.
    var state: Counters.State = .{ .a = 0, .b = 0 };
    var enabled: std.ArrayList(Counters.Action) = .empty;
    defer enabled.deinit(gpa);
    for (violation.path) |action| {
        try std.testing.expect(try Counters.bounded(&model, &state));
        enabled.clearRetainingCapacity();
        try Counters.actions(&model, gpa, &state, &enabled);
        const position = std.mem.indexOfScalar(Counters.Action, enabled.items, action);
        try std.testing.expect(position != null);
        state = (try Counters.next_state(&model, &state, action)).?;
    }
    try std.testing.expect(!try Counters.bounded(&model, &state));
    try std.testing.expectEqual(@as(u8, 4), state.a);
}

test "checker: refuses a state space beyond its bound" {
    for (worker_options) |options| {
        var bounded = options;
        bounded.max_states = 10;
        var model: Counters = .{ .limit = 3, .planted = false };
        const result = Checker(Counters).run(std.testing.allocator, &model, bounded);
        try std.testing.expectError(error.StateSpaceTooLarge, result);
    }
}
