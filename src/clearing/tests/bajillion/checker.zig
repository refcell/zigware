//! A small explicit-state model checker standing in for Stateright in `model.zig`.
//!
//! It explores every state a model reaches from its initial states, depth first with an
//! explicit stack (no recursion), and checks every `always` property in each state when it is
//! first reached. As Stateright does, it identifies a state by a 64-bit fingerprint the model
//! computes, so two states with the same fingerprint count as one. It stops at the first
//! property that fails and returns the actions that lead there from an initial state. The
//! number of unique states is bounded by `Options.max_states`.
//!
//! As Stateright's `threads(n)`, `Options.workers` explore at once: they share one stack, the
//! visited set, and the node list behind a mutex, and expand states (actions, next states, and
//! properties) outside it, so the model must be safe to call from several threads. Unique
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
            /// Actions taken, including those leading to states already seen.
            transitions: u64,
            /// The deepest state reached, in actions from an initial state.
            max_depth: u64,
            violation: ?Violation,

            pub fn deinit(self: *Result, gpa: Allocator) void {
                if (self.violation) |v| gpa.free(v.path);
                self.* = undefined;
            }
        };

        /// How a unique state was first reached: its parent node and the action taken there.
        const Node = struct { parent: ?u32, action: ?Action, depth: u64 };
        /// A state waiting on the stack to have its actions explored.
        const Entry = struct { state: State, node: u32 };

        gpa: Allocator,
        model: *M,
        options: Options,
        visited: std.AutoHashMapUnmanaged(u64, void) = .empty,
        nodes: std.ArrayList(Node) = .empty,
        stack: std.ArrayList(Entry) = .empty,
        transitions: u64 = 0,
        max_depth: u64 = 0,
        /// Guards every field above it but `gpa`, `model`, and `options`, and the three below.
        mutex: std.Io.Mutex = .init,
        /// Signalled when the stack grows or the check ends.
        changed: std.Io.Condition = .init,
        /// Workers expanding a popped state.
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
            if (self.violation == null) try self.explore();
            if (self.failure) |err| {
                if (self.violation) |v| gpa.free(v.path);
                return err;
            }
            const result: Result = .{
                .unique = self.nodes.items.len,
                .transitions = self.transitions,
                .max_depth = self.max_depth,
                .violation = self.violation,
            };
            assert(result.unique == self.visited.count());
            return result;
        }

        fn deinit(self: *Self) void {
            for (self.stack.items) |*entry| entry.state.deinit(self.gpa);
            self.stack.deinit(self.gpa);
            self.nodes.deinit(self.gpa);
            self.visited.deinit(self.gpa);
        }

        /// Discovers the initial states, on the caller's thread.
        fn seed(self: *Self) !void {
            const initial = try M.init_states(self.model, self.gpa);
            defer self.gpa.free(initial);
            var taken: usize = 0;
            defer for (initial[taken..]) |*state| state.deinit(self.gpa);
            for (initial) |*state| {
                const owned = state.*;
                taken += 1;
                self.discover(owned, null, null);
                if (self.ended()) return;
            }
        }

        /// Runs `options.workers` workers until the stack drains or the check ends.
        fn explore(self: *Self) !void {
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

        fn lock(self: *Self) void {
            if (self.options.io) |io| self.mutex.lockUncancelable(io);
        }

        fn unlock(self: *Self) void {
            if (self.options.io) |io| self.mutex.unlock(io);
        }

        /// Whether a violation or an error ended the check (the lock held, or one worker).
        fn ended(self: *const Self) bool {
            return self.violation != null or self.failure != null;
        }

        /// Records `err` as the check's failure unless one is recorded, and wakes the workers.
        fn fail(self: *Self, err: anyerror) void {
            self.lock();
            defer self.unlock();
            if (self.failure == null) self.failure = err;
            self.wake();
        }

        fn wake(self: *Self) void {
            if (self.options.io) |io| self.changed.broadcast(io);
        }

        /// Pops states and expands them until the stack is empty with no worker expanding, or
        /// the check ends.
        fn work(self: *Self) void {
            var actions: std.ArrayList(Action) = .empty;
            defer actions.deinit(self.gpa);
            while (self.take()) |popped| {
                var entry = popped;
                defer entry.state.deinit(self.gpa);
                self.expand(&entry, &actions) catch |err| self.fail(err);
                self.lock();
                assert(self.active > 0);
                self.active -= 1;
                if (self.stack.items.len == 0 and self.active == 0) self.wake();
                self.unlock();
            }
        }

        /// The next state to expand (counted active), or null once the check is over.
        fn take(self: *Self) ?Entry {
            self.lock();
            defer self.unlock();
            while (true) {
                if (self.ended()) return null;
                if (self.stack.pop()) |entry| {
                    self.active += 1;
                    return entry;
                }
                if (self.active == 0) return null;
                // Only a multi-worker check waits: one worker never sees others active.
                self.changed.waitUncancelable(self.options.io.?, &self.mutex);
            }
        }

        /// Applies every enabled action of `entry`'s state, discovering the next states.
        fn expand(self: *Self, entry: *const Entry, actions: *std.ArrayList(Action)) !void {
            actions.clearRetainingCapacity();
            try M.actions(self.model, self.gpa, &entry.state, actions);
            self.lock();
            self.transitions += actions.items.len;
            self.unlock();
            for (actions.items) |action| {
                const next = try M.next_state(self.model, &entry.state, action) orelse continue;
                self.discover(next, entry.node, action);
            }
        }

        /// Records `state` (taken) if it is new, checks the properties in it, and pushes it.
        /// A violation or an error ends the check.
        fn discover(self: *Self, state: State, parent: ?u32, action: ?Action) void {
            var owned = state;
            const node = self.record(&owned, parent, action) catch |err| {
                owned.deinit(self.gpa);
                return self.fail(err);
            } orelse {
                owned.deinit(self.gpa);
                return;
            };
            for (M.properties) |property| {
                const holds = property.holds(self.model, &owned) catch |err| {
                    owned.deinit(self.gpa);
                    return self.fail(err);
                };
                if (holds) continue;
                owned.deinit(self.gpa);
                return self.violate(property.name, node);
            }
            self.lock();
            defer self.unlock();
            self.stack.append(self.gpa, .{ .state = owned, .node = node }) catch |err| {
                owned.deinit(self.gpa);
                if (self.failure == null) self.failure = err;
                return self.wake();
            };
            if (self.options.io) |io| self.changed.signal(io);
        }

        /// Adds a node for `state` if its fingerprint is new, returning its index.
        fn record(self: *Self, state: *const State, parent: ?u32, action: ?Action) !?u32 {
            const fingerprint = M.fingerprint(self.model, state);
            self.lock();
            defer self.unlock();
            if (self.ended()) return null;
            const seen = try self.visited.getOrPut(self.gpa, fingerprint);
            if (seen.found_existing) return null;
            if (self.nodes.items.len >= self.options.max_states) {
                _ = self.visited.remove(fingerprint);
                return error.StateSpaceTooLarge;
            }
            const depth = if (parent) |p| self.nodes.items[p].depth + 1 else 0;
            self.max_depth = @max(self.max_depth, depth);
            const node: u32 = @intCast(self.nodes.items.len);
            const reached: Node = .{ .parent = parent, .action = action, .depth = depth };
            self.nodes.append(self.gpa, reached) catch |err| {
                _ = self.visited.remove(fingerprint);
                return err;
            };
            return node;
        }

        /// Records the first violation, with the path to `node`, and ends the check.
        fn violate(self: *Self, property: []const u8, node: u32) void {
            self.lock();
            defer self.unlock();
            if (self.ended()) return;
            const path = self.path_to(node) catch |err| {
                self.failure = err;
                return self.wake();
            };
            self.violation = .{ .property = property, .path = path };
            self.wake();
        }

        /// The actions from an initial state to `node`, in order.
        fn path_to(self: *Self, node: u32) ![]Action {
            const depth = self.nodes.items[node].depth;
            const path = try self.gpa.alloc(Action, depth);
            var at: ?u32 = node;
            var index = depth;
            while (index > 0) {
                const n = self.nodes.items[at.?];
                index -= 1;
                path[index] = n.action.?;
                at = n.parent;
            }
            assert(self.nodes.items[at.?].parent == null);
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
