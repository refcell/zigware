//! Max-min fair bandwidth planner (commonware `p2p/src/simulated/bandwidth.rs`).
//!
//! The planner progressively fills a set of active flows to compute per-flow transmission
//! rates that respect both sender egress limits and receiver ingress limits. The caller
//! advances flow progress with the returned rates and plans again whenever the active set
//! changes. Rates are exact rationals in bytes per second, as in commonware.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const Rational = @import("rational.zig").Rational;

const Duration = utils.Duration;
const nanos_per_sec = utils.time.NANOS_PER_SEC;

/// Minimal description of a simulated transmission path. `delivered == false` means the flow
/// only uses the sender's egress (the message is dropped before the recipient), so it is not
/// charged against ingress capacity.
pub fn Flow(comptime P: type) type {
    return struct { id: u64, origin: P, recipient: P, delivered: bool };
}

/// Per-flow throughput in bytes per second.
pub const Rate = union(enum) {
    unlimited,
    finite: Rational,

    pub fn deinit(rate: *Rate) void {
        if (rate.* == .finite) rate.finite.deinit();
        rate.* = undefined;
    }

    pub fn clone(rate: Rate, gpa: Allocator) Allocator.Error!Rate {
        return switch (rate) {
            .unlimited => .unlimited,
            .finite => |ratio| .{ .finite = try ratio.clone(gpa) },
        };
    }
};

/// `order(a, b)` for integer peers (tests) and for types with an `order` method.
fn peer_order(comptime P: type, a: P, b: P) std.math.Order {
    if (@typeInfo(P) == .int) return std.math.order(a, b);
    return P.order(a, b);
}

/// Shared capacity (egress or ingress): unassigned bytes per second, the flows that use it,
/// and how many of them are still being filled.
const Resource = struct {
    remaining: Rational,
    members: std.ArrayList(usize),
    active: usize,
};

/// The resources a flow uses (at most egress and ingress) and whether it is still filling.
const State = struct {
    resources: [2]usize = undefined,
    resources_len: u8 = 0,
    limited: bool = false,
    active: bool = false,

    fn used(state: *const State) []const usize {
        assert(state.resources_len <= 2);
        return state.resources[0..state.resources_len];
    }
};

fn Planner(comptime P: type) type {
    return struct {
        const Self = @This();
        const Direction = enum { egress, ingress };
        const Constraint = struct { direction: Direction, peer: P };

        arena: Allocator,
        flows: []const Flow(P),
        resources: std.ArrayList(Resource) = .empty,
        constraints: std.ArrayList(Constraint) = .empty,
        states: []State,
        rates: []?Rational,
        active: usize = 0,
        fill: Rational,

        /// Builds the planner and registers every flow with the resources it uses. `arena`
        /// owns every allocation the planner makes.
        fn init(arena: Allocator, flows: []const Flow(P), caps: anytype) Allocator.Error!Self {
            const states = try arena.alloc(State, flows.len);
            @memset(states, .{});
            const rates = try arena.alloc(?Rational, flows.len);
            @memset(rates, null);
            var planner: Self = .{
                .arena = arena,
                .flows = flows,
                .states = states,
                .rates = rates,
                .fill = try .init_int(arena, 0),
            };
            try planner.register(caps);
            return planner;
        }

        /// The index of the resource for `constraint`, creating it when `limit` is set. Null
        /// for an unlimited resource.
        fn constrain(self: *Self, constraint: Constraint, limit: ?u128) !?usize {
            for (self.constraints.items, 0..) |existing, index| {
                if (existing.direction != constraint.direction) continue;
                if (peer_order(P, existing.peer, constraint.peer) == .eq) return index;
            }
            const value = limit orelse return null;
            try self.resources.append(self.arena, .{
                .remaining = try .init_int(self.arena, value),
                .members = .empty,
                .active = 0,
            });
            try self.constraints.append(self.arena, constraint);
            assert(self.resources.items.len == self.constraints.items.len);
            return self.resources.items.len - 1;
        }

        fn attach(self: *Self, resource_index: usize, flow_index: usize) !void {
            const resource = &self.resources.items[resource_index];
            try resource.members.append(self.arena, flow_index);
            resource.active += 1;
            const state = &self.states[flow_index];
            assert(state.resources_len < 2);
            state.resources[state.resources_len] = resource_index;
            state.resources_len += 1;
            state.limited = true;
        }

        fn register(self: *Self, caps: anytype) !void {
            for (self.flows, 0..) |flow, flow_index| {
                const egress: Constraint = .{ .direction = .egress, .peer = flow.origin };
                if (try self.constrain(egress, caps.egress(flow.origin))) |index| {
                    try self.attach(index, flow_index);
                }
                if (flow.delivered) {
                    const ingress: Constraint = .{ .direction = .ingress, .peer = flow.recipient };
                    if (try self.constrain(ingress, caps.ingress(flow.recipient))) |index| {
                        try self.attach(index, flow_index);
                    }
                }
                const state = &self.states[flow_index];
                if (state.limited) {
                    state.active = true;
                    self.active += 1;
                }
            }
            assert(self.active <= self.flows.len);
        }

        /// Freezes every still-filling flow on a saturated resource at the current fill level.
        fn freeze(self: *Self, resource_index: usize) !void {
            for (self.resources.items[resource_index].members.items) |flow_index| {
                const state = &self.states[flow_index];
                if (!state.active) continue;
                self.rates[flow_index] = try self.fill.clone(self.arena);
                state.active = false;
                self.active -= 1;
                for (state.used()) |other| {
                    const resource = &self.resources.items[other];
                    if (resource.active > 0) resource.active -= 1;
                }
            }
        }

        /// Progressive filling until every constrained flow is frozen.
        fn fill_all(self: *Self) !void {
            var limiting: std.ArrayList(usize) = .empty;
            var saturated: std.ArrayList(usize) = .empty;
            // Each round freezes at least one flow, so the loop runs at most flows.len times.
            var rounds: usize = 0;
            while (self.active > 0) : (rounds += 1) {
                assert(rounds <= 2 * self.flows.len);
                limiting.clearRetainingCapacity();
                const delta = try self.min_share(&limiting) orelse {
                    @panic("active flows without constraints");
                };
                if (delta.is_zero()) {
                    for (limiting.items) |index| try self.freeze(index);
                    continue;
                }
                self.fill = try self.fill.add(delta);
                saturated.clearRetainingCapacity();
                for (self.resources.items, 0..) |*resource, index| {
                    if (resource.active == 0) continue;
                    const count = try Rational.init_int(self.arena, resource.active);
                    const usage = try delta.mul(count);
                    if (usage.is_zero()) continue;
                    resource.remaining = try resource.remaining.sub(usage);
                    if (resource.remaining.is_zero()) try saturated.append(self.arena, index);
                }
                try saturated.appendSlice(self.arena, limiting.items);
                std.sort.pdq(usize, saturated.items, {}, std.sort.asc(usize));
                var previous: ?usize = null;
                for (saturated.items) |index| {
                    if (previous == index) continue;
                    previous = index;
                    try self.freeze(index);
                }
            }
        }

        /// The smallest per-flow headroom among resources serving active flows, with the
        /// resources that attain it in `limiting`. A saturated resource wins with zero.
        fn min_share(self: *Self, limiting: *std.ArrayList(usize)) !?Rational {
            var min_delta: ?Rational = null;
            for (self.resources.items, 0..) |resource, index| {
                if (resource.active == 0) continue;
                if (resource.remaining.is_zero()) {
                    limiting.clearRetainingCapacity();
                    try limiting.append(self.arena, index);
                    return try Rational.init_int(self.arena, 0);
                }
                const count = try Rational.init_int(self.arena, resource.active);
                const share = try resource.remaining.div(count);
                const order = if (min_delta) |current| try share.order(current) else .lt;
                switch (order) {
                    .lt => {
                        min_delta = share;
                        limiting.clearRetainingCapacity();
                        try limiting.append(self.arena, index);
                    },
                    .eq => try limiting.append(self.arena, index),
                    .gt => {},
                }
            }
            return min_delta;
        }
    };
}

/// Computes a max-min fair allocation for `flows`. `caps` provides `egress(P) ?u128` and
/// `ingress(P) ?u128` in bytes per second (null is unlimited). Returns one rate per flow, in
/// the order of `flows`, owned by the caller (`free_rates`).
pub fn allocate(comptime P: type, gpa: Allocator, flows: []const Flow(P), caps: anytype) ![]Rate {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var planner = try Planner(P).init(arena_state.allocator(), flows, caps);
    try planner.fill_all();
    assert(planner.active == 0);
    const rates = try gpa.alloc(Rate, flows.len);
    var filled: usize = 0;
    errdefer free_rates(gpa, rates[0..filled]);
    for (planner.rates, rates) |planned, *rate| {
        rate.* = if (planned) |ratio| .{ .finite = try ratio.clone(gpa) } else .unlimited;
        filled += 1;
    }
    return rates;
}

pub fn free_rates(gpa: Allocator, rates: []Rate) void {
    for (rates) |*rate| rate.deinit();
    gpa.free(rates);
}

/// The time needed to send `remaining` bytes at `rate`, rounded up to whole nanoseconds;
/// null when the rate is zero.
pub fn duration(rate: Rate, remaining: Rational) !?Duration {
    const ratio = switch (rate) {
        .unlimited => return Duration.zero,
        .finite => |ratio| ratio,
    };
    if (ratio.is_zero()) return null;
    const gpa = remaining.numerator.allocator;
    var seconds = try remaining.div(ratio);
    defer seconds.deinit();
    var scale = try Rational.init_int(gpa, nanos_per_sec);
    defer scale.deinit();
    var nanos = try seconds.mul(scale);
    defer nanos.deinit();
    return Duration.from_nanos_saturating(try nanos.ceil_to_u128());
}

/// The bytes left after sending for `elapsed` at `rate`, as a new value (fractional progress
/// carries over between calls).
pub fn transfer(rate: Rate, elapsed: Duration, remaining: Rational) !Rational {
    const gpa = remaining.numerator.allocator;
    if (remaining.is_zero()) return remaining.clone(gpa);
    const ratio = switch (rate) {
        .unlimited => return Rational.init_int(gpa, 0),
        .finite => |ratio| ratio,
    };
    if (ratio.is_zero() or elapsed.is_zero()) return remaining.clone(gpa);
    var seconds = try Rational.init_frac(gpa, elapsed.as_nanos(), @as(u128, nanos_per_sec));
    defer seconds.deinit();
    var usage = try ratio.mul(seconds);
    defer usage.deinit();
    if (try usage.order(remaining) != .lt) return Rational.init_int(gpa, 0);
    return remaining.sub(usage);
}

const testing = std.testing;

const ConstantCaps = struct {
    egress_limit: ?u128,
    ingress_limit: ?u128,
    pub fn egress(caps: ConstantCaps, _: u8) ?u128 {
        return caps.egress_limit;
    }
    pub fn ingress(caps: ConstantCaps, _: u8) ?u128 {
        return caps.ingress_limit;
    }
};

const Limit = struct { u8, u128 };

const PeerCaps = struct {
    egress_limits: []const Limit,
    ingress_limits: []const Limit,
    fn lookup(limits: []const Limit, peer: u8) ?u128 {
        for (limits) |limit| if (limit[0] == peer) return limit[1];
        return null;
    }
    pub fn egress(caps: PeerCaps, peer: u8) ?u128 {
        return lookup(caps.egress_limits, peer);
    }
    pub fn ingress(caps: PeerCaps, peer: u8) ?u128 {
        return lookup(caps.ingress_limits, peer);
    }
};

fn expect_rate(rate: Rate, numerator: u64, denominator: u64) !void {
    var expected = try Rational.init_frac(testing.allocator, numerator, denominator);
    defer expected.deinit();
    try testing.expect(rate == .finite);
    try testing.expect(rate.finite.eql(expected));
}

fn make_flow(id: u64, origin: u8, recipient: u8) Flow(u8) {
    return .{ .id = id, .origin = origin, .recipient = recipient, .delivered = true };
}

test "equal share on a single egress (equal_share_on_single_egress)" {
    const flows = [_]Flow(u8){ make_flow(1, 1, 10), make_flow(2, 1, 11) };
    const caps: ConstantCaps = .{ .egress_limit = 1_000, .ingress_limit = null };
    const rates = try allocate(u8, testing.allocator, &flows, caps);
    defer free_rates(testing.allocator, rates);
    for (rates) |rate| try expect_rate(rate, 500, 1);
}

test "ingress cap enforced and unlimited flows" {
    const ingress_caps: ConstantCaps = .{ .egress_limit = null, .ingress_limit = 2_000 };
    const rates = try allocate(u8, testing.allocator, &.{make_flow(1, 1, 5)}, ingress_caps);
    defer free_rates(testing.allocator, rates);
    try expect_rate(rates[0], 2_000, 1);

    const dropped: Flow(u8) = .{ .id = 7, .origin = 1, .recipient = 2, .delivered = false };
    const none: ConstantCaps = .{ .egress_limit = null, .ingress_limit = null };
    const unlimited = try allocate(u8, testing.allocator, &.{dropped}, none);
    defer free_rates(testing.allocator, unlimited);
    try testing.expect(unlimited[0] == .unlimited);
}

test "transfer carries fractional progress (transfer_accumulates_carry)" {
    const gpa = testing.allocator;
    var rate: Rate = .{ .finite = try .init_frac(gpa, 1, 2) };
    defer rate.deinit();
    var initial = try Rational.init_int(gpa, 10);
    defer initial.deinit();
    var short = try transfer(rate, Duration.from_millis(500), initial);
    defer short.deinit();
    try expect_rate(.{ .finite = short }, 39, 4);
    var long = try transfer(rate, Duration.from_millis(1500), short);
    defer long.deinit();
    try expect_rate(.{ .finite = long }, 9, 1);
}

test "durations account for fractional progress" {
    const gpa = testing.allocator;
    var rate: Rate = .{ .finite = try .init_frac(gpa, 1, 2) };
    defer rate.deinit();
    var initial = try Rational.init_int(gpa, 1);
    defer initial.deinit();
    var partial = try transfer(rate, Duration.from_millis(500), initial);
    defer partial.deinit();
    try expect_rate(.{ .finite = partial }, 3, 4);
    const full = (try duration(rate, initial)).?;
    try testing.expectEqual(Duration.from_secs(2), full);
    const finish = (try duration(rate, partial)).?;
    try testing.expectEqual(Duration.from_millis(1500), finish);

    var fast: Rate = .{ .finite = try .init_int(gpa, 500) };
    defer fast.deinit();
    var bytes = try Rational.init_int(gpa, 1_000);
    defer bytes.deinit();
    try testing.expectEqual(Duration.from_secs(2), (try duration(fast, bytes)).?);
    var stopped: Rate = .{ .finite = try .init_int(gpa, 0) };
    defer stopped.deinit();
    try testing.expect(try duration(stopped, bytes) == null);
    try testing.expectEqual(Duration.zero, (try duration(.unlimited, bytes)).?);
}

test "three peer fair sharing (three_peer_fair_sharing)" {
    const a = 'A';
    const b = 'B';
    const c = 'C';
    const flows = [_]Flow(u8){
        make_flow(1, a, b), make_flow(2, a, b), make_flow(3, b, c),
        make_flow(4, a, c), make_flow(5, c, b),
    };
    const caps: PeerCaps = .{
        .egress_limits = &.{ .{ a, 1_000_000 }, .{ b, 750_000 }, .{ c, 100_000 } },
        .ingress_limits = &.{ .{ a, 500_000 }, .{ b, 250_000 }, .{ c, 1_000_000 } },
    };
    const rates = try allocate(u8, testing.allocator, &flows, caps);
    defer free_rates(testing.allocator, rates);
    try expect_rate(rates[0], 250_000, 3);
    try expect_rate(rates[1], 250_000, 3);
    try expect_rate(rates[2], 500_000, 1);
    try expect_rate(rates[3], 500_000, 1);
    try expect_rate(rates[4], 250_000, 3);
}

test "bottlenecks propagate and fair shares hold" {
    const flows = [_]Flow(u8){ make_flow(1, 'A', 'B'), make_flow(2, 'A', 'C') };
    const ingress = [_]Limit{ .{ 'A', 500_000 }, .{ 'B', 1_000 }, .{ 'C', 500_000 } };
    const upstream: PeerCaps = .{
        .egress_limits = &.{ .{ 'A', 1_000_000 }, .{ 'B', 1_000_000 }, .{ 'C', 1_000_000 } },
        .ingress_limits = &ingress,
    };
    const first = try allocate(u8, testing.allocator, &flows, upstream);
    defer free_rates(testing.allocator, first);
    try expect_rate(first[0], 1_000, 1);
    try expect_rate(first[1], 500_000, 1);

    const limited: PeerCaps = .{
        .egress_limits = &.{ .{ 'A', 50_000 }, .{ 'B', 1_000_000 }, .{ 'C', 1_000_000 } },
        .ingress_limits = &ingress,
    };
    const second = try allocate(u8, testing.allocator, &flows, limited);
    defer free_rates(testing.allocator, second);
    try expect_rate(second[0], 1_000, 1);
    try expect_rate(second[1], 49_000, 1);
}

test "planner registration and freezing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const none: ConstantCaps = .{ .egress_limit = null, .ingress_limit = null };
    const skipped = try Planner(u8).init(arena, &.{make_flow(99, 1, 2)}, none);
    try testing.expectEqual(@as(usize, 0), skipped.resources.items.len);
    try testing.expect(!skipped.states[0].limited);
    try testing.expectEqual(@as(usize, 0), skipped.active);

    const caps: ConstantCaps = .{ .egress_limit = 1_000, .ingress_limit = null };
    var shared = try Planner(u8).init(arena, &.{ make_flow(1, 1, 10), make_flow(2, 1, 11) }, caps);
    try testing.expectEqual(@as(usize, 1), shared.resources.items.len);
    try testing.expectEqualSlices(usize, &.{ 0, 1 }, shared.resources.items[0].members.items);
    try testing.expectEqual(@as(usize, 2), shared.resources.items[0].active);
    try testing.expect(shared.states[0].active and shared.states[1].active);

    try shared.freeze(0);
    try testing.expectEqual(@as(usize, 0), shared.resources.items[0].active);
    try testing.expectEqual(@as(usize, 0), shared.active);
    for (shared.rates) |rate| try testing.expect(rate.?.is_zero());
}
