//! A small explicit-state model checker standing in for Stateright in `model.zig`.
//!
//! It explores every state a model reaches from its initial states, depth first with an
//! explicit stack (no recursion), and checks every `always` property in each state when it is
//! first reached. As Stateright does, it identifies a state by a 64-bit fingerprint the model
//! computes, so two states with the same fingerprint count as one. It stops at the first
//! property that fails and returns the actions that lead there from an initial state. The
//! number of unique states is bounded by `Options.max_states`.

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
};

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

        /// Explores every state of `model` reachable within `options`.
        pub fn run(gpa: Allocator, model: *M, options: Options) !Result {
            assert(options.max_states > 0);
            var self: Self = .{ .gpa = gpa, .model = model, .options = options };
            defer self.deinit();
            const violation = try self.explore();
            const result: Result = .{
                .unique = self.nodes.items.len,
                .transitions = self.transitions,
                .max_depth = self.max_depth,
                .violation = violation,
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

        fn explore(self: *Self) !?Violation {
            const initial = try M.init_states(self.model, self.gpa);
            defer self.gpa.free(initial);
            var taken: usize = 0;
            defer for (initial[taken..]) |*state| state.deinit(self.gpa);
            for (initial) |*state| {
                const owned = state.*;
                taken += 1;
                if (try self.discover(owned, null, null)) |violation| return violation;
            }
            var actions: std.ArrayList(Action) = .empty;
            defer actions.deinit(self.gpa);
            while (self.stack.pop()) |popped| {
                var entry = popped;
                defer entry.state.deinit(self.gpa);
                actions.clearRetainingCapacity();
                try M.actions(self.model, self.gpa, &entry.state, &actions);
                for (actions.items) |action| {
                    self.transitions += 1;
                    const next = try M.next_state(self.model, &entry.state, action) orelse continue;
                    if (try self.discover(next, entry.node, action)) |violation| return violation;
                }
            }
            return null;
        }

        /// Records `state` (taken) if it is new, checks the properties in it, and pushes it.
        fn discover(self: *Self, state: State, parent: ?u32, action: ?Action) !?Violation {
            var owned = state;
            const fingerprint = M.fingerprint(self.model, &owned);
            const seen = try self.visited.getOrPut(self.gpa, fingerprint);
            if (seen.found_existing) {
                owned.deinit(self.gpa);
                return null;
            }
            if (self.nodes.items.len >= self.options.max_states) {
                owned.deinit(self.gpa);
                return error.StateSpaceTooLarge;
            }
            const depth = if (parent) |p| self.nodes.items[p].depth + 1 else 0;
            self.max_depth = @max(self.max_depth, depth);
            const node: u32 = @intCast(self.nodes.items.len);
            const reached: Node = .{ .parent = parent, .action = action, .depth = depth };
            try self.nodes.append(self.gpa, reached);
            for (M.properties) |property| {
                if (!try property.holds(self.model, &owned)) {
                    owned.deinit(self.gpa);
                    return .{ .property = property.name, .path = try self.path_to(node) };
                }
            }
            self.stack.append(self.gpa, .{ .state = owned, .node = node }) catch |err| {
                owned.deinit(self.gpa);
                return err;
            };
            return null;
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

test "checker: explores every state once and finds no violation" {
    var model: Counters = .{ .limit = 3, .planted = false };
    var result = try Checker(Counters).run(std.testing.allocator, &model, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.violation == null);
    // Every pair of counters within the limit, and nothing else.
    try std.testing.expectEqual(@as(u64, 16), result.unique);
    try std.testing.expectEqual(@as(u64, 6), result.max_depth);
    // Each state below the limit grows each counter, and hands over while `a > 0`.
    try std.testing.expectEqual(@as(u64, 12 + 12 + 9), result.transitions);
}

test "checker: catches a planted bug with a path that reproduces it" {
    const gpa = std.testing.allocator;
    var model: Counters = .{ .limit = 3, .planted = true };
    var result = try Checker(Counters).run(gpa, &model, .{});
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
    var model: Counters = .{ .limit = 3, .planted = false };
    const result = Checker(Counters).run(std.testing.allocator, &model, .{ .max_states = 10 });
    try std.testing.expectError(error.StateSpaceTooLarge, result);
}
