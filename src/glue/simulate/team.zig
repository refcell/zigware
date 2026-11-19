//! The validators of a simulation: starting, crashing, and restarting them (commonware
//! `glue/src/simulate/team.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const p2p = @import("p2p");
const engine_module = @import("engine.zig");
const events = @import("events.zig");
const action = @import("action.zig");
const processed = @import("processed.zig");

const Context = engine_module.Context;
const Handle = engine_module.Handle;

/// The validators of engine definition `D` (commonware `Team<D>`). Validators are kept by
/// participant index; listings follow the participants' key order, as commonware's maps do.
pub fn Team(comptime D: type) type {
    engine_module.assert_engine(D);
    return struct {
        const Self = @This();
        const P = D.PublicKey;
        const S = D.State;
        const Network = p2p.simulated.Network(P);

        gpa: Allocator,
        definition: *const D,
        participants: []const P,
        /// Participant indices in increasing key order.
        order: []usize,
        /// Running validators' task handles.
        handles: []?Handle,
        /// Per crashed validator, the task aborting it (an abort waits for the validator's
        /// teardown, since Zig cannot drop a running task). A restart joins its validator's
        /// before reusing the channels and state, and `deinit` joins the rest.
        stopping: []?Handle,
        /// Inspectable state per validator, kept after a crash until its restart.
        states: []?S,
        /// The slice of registered channels handed to each validator's engine.
        channels: [][]Network.Registered,
        /// Restart count per validator (monotonically increasing).
        restart_counts: []u32,

        pub fn init(gpa: Allocator, definition: *const D) Allocator.Error!Self {
            const participants = definition.participants();
            const n = participants.len;
            const order = try gpa.alloc(usize, n);
            errdefer gpa.free(order);
            for (order, 0..) |*index, i| index.* = i;
            std.mem.sort(usize, order, participants, key_less);
            const handles = try gpa.alloc(?Handle, n);
            errdefer gpa.free(handles);
            @memset(handles, null);
            const stopping = try gpa.alloc(?Handle, n);
            errdefer gpa.free(stopping);
            @memset(stopping, null);
            const states = try gpa.alloc(?S, n);
            errdefer gpa.free(states);
            @memset(states, null);
            const channels = try gpa.alloc([]Network.Registered, n);
            errdefer gpa.free(channels);
            @memset(channels, &.{});
            const restart_counts = try gpa.alloc(u32, n);
            @memset(restart_counts, 0);
            return .{
                .gpa = gpa,
                .definition = definition,
                .participants = participants,
                .order = order,
                .handles = handles,
                .stopping = stopping,
                .states = states,
                .channels = channels,
                .restart_counts = restart_counts,
            };
        }

        fn key_less(participants: []const P, a: usize, b: usize) bool {
            return participants[a].order(participants[b]) == .lt;
        }

        /// Aborts every running validator, waits for every crashed one, and releases every
        /// state.
        pub fn deinit(self: *Self) void {
            for (self.handles, self.stopping) |handle, stopped| {
                if (handle) |running| _ = running.abort() catch {};
                if (stopped) |crashing| _ = crashing.join() catch {};
            }
            for (self.states, self.channels) |*state, channels| {
                if (state.*) |*held| deinit_state(held);
                self.gpa.free(channels);
            }
            self.gpa.free(self.restart_counts);
            self.gpa.free(self.channels);
            self.gpa.free(self.states);
            self.gpa.free(self.stopping);
            self.gpa.free(self.handles);
            self.gpa.free(self.order);
            self.* = undefined;
        }

        fn deinit_state(state: *S) void {
            if (comptime @hasDecl(D, "deinit_state")) D.deinit_state(state);
        }

        /// The index of `pk` among the participants.
        pub fn index_of(self: *const Self, pk: P) ?usize {
            for (self.participants, 0..) |participant, index| {
                if (participant.order(pk) == .eq) return index;
            }
            return null;
        }

        /// Starts validator `index`: registers its channels, then calls `init` and `start`.
        /// A running validator is aborted first.
        pub fn start_one(
            self: *Self,
            ctx: Context,
            oracle: Network.Oracle,
            index: usize,
            monitor: events.Monitor(P),
            delayed: bool,
            storage_faults: *const action.FaultConfig,
        ) !void {
            assert(index < self.participants.len);
            if (self.handles[index]) |running| _ = running.abort() catch {};
            self.handles[index] = null;
            // The crashed instance still holds its channels and state until it returns.
            if (self.stopping[index]) |crashing| _ = crashing.join() catch {};
            self.stopping[index] = null;
            const restart = self.restart_counts[index];
            self.restart_counts[index] += 1;
            const validator_ctx = ctx.child("validator")
                .with_attribute("index", index)
                .with_attribute("restart", restart);

            const pk = self.participants[index];
            const specs = self.definition.channels();
            self.gpa.free(self.channels[index]);
            self.channels[index] = &.{};
            const channels = try self.gpa.alloc(Network.Registered, specs.len);
            self.channels[index] = channels;
            const control = oracle.control(pk);
            for (specs, channels) |spec, *channel| {
                channel.* = try control.register(spec.channel, spec.quota);
            }

            const engine, const state = try self.definition.init(.{
                .context = validator_ctx,
                .index = index,
                .delayed = delayed,
                .public_key = pk,
                .oracle = oracle,
                .channels = channels,
                .participants = self.participants,
                .monitor = monitor,
                .storage_faults = storage_faults,
            });
            if (self.states[index]) |*previous| deinit_state(previous);
            self.states[index] = state;
            self.handles[index] = try D.start(engine);
        }

        /// Links every pair of participants with `link`, then starts every validator not
        /// marked in `delayed`.
        pub fn start(
            self: *Self,
            ctx: Context,
            oracle: Network.Oracle,
            link: p2p.simulated.Link,
            monitor: events.Monitor(P),
            delayed: []const bool,
            storage_faults: *const action.FaultConfig,
        ) !void {
            assert(delayed.len == self.participants.len);
            for (self.participants) |from| {
                for (self.participants) |to| {
                    if (from.order(to) == .eq) continue;
                    try oracle.add_link(from, to, link);
                }
            }
            for (self.order) |index| {
                if (delayed[index]) continue;
                try self.start_one(ctx, oracle, index, monitor, false, storage_faults);
            }
        }

        /// Crashes validator `index` by aborting its task from a task spawned under `ctx`, so
        /// the caller does not wait for the validator's teardown (commonware drops the aborted
        /// handle) and validators due to crash together do. Returns whether it was running.
        pub fn crash(self: *Self, ctx: Context, index: usize) !bool {
            const running = self.handles[index] orelse return false;
            // A restart joined any earlier crash before the instance now running started.
            assert(self.stopping[index] == null);
            self.stopping[index] = try ctx.child("crash").spawn(abort_validator, .{running});
            self.handles[index] = null;
            return true;
        }

        fn abort_validator(_: Context, running: Handle) void {
            _ = running.abort() catch {};
        }

        /// The states of the running validators, in key order, written into `buffer`.
        pub fn active_states(self: *const Self, buffer: []*const S) []*const S {
            assert(buffer.len >= self.participants.len);
            var count: usize = 0;
            for (self.order) |index| {
                if (self.handles[index] == null) continue;
                buffer[count] = &self.states[index].?;
                count += 1;
            }
            return buffer[0..count];
        }

        /// The indices of the running validators, in key order, written into `buffer`.
        pub fn active_indices(self: *const Self, buffer: []usize) []usize {
            assert(buffer.len >= self.participants.len);
            var count: usize = 0;
            for (self.order) |index| {
                if (self.handles[index] == null) continue;
                buffer[count] = index;
                count += 1;
            }
            return buffer[0..count];
        }

        /// Validator `index`'s state, if it is running.
        pub fn active_state(self: *const Self, index: usize) ?*const S {
            if (self.handles[index] == null) return null;
            return &self.states[index].?;
        }

        /// The processed height of validator `index`, if it is running.
        pub fn processed_height(self: *const Self, index: usize) ?u64 {
            const state = self.active_state(index) orelse return null;
            return processed.processed_height(S, state);
        }
    };
}
