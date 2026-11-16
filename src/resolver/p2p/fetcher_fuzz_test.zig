//! Model-based fuzz of the p2p fetcher's state machine: random fetch, retry, send, response,
//! timeout, retain, roster, block, and target operations, each checked against a naive model
//! of every key's state, retry count, targets, and eligible peers.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const p2p = @import("p2p");
const fetcher_mod = @import("fetcher.zig");
const base = @import("fetcher_test.zig");
const MockKey = @import("mocks/key.zig").Key;

const gpa = testing.allocator;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const PublicKey = @import("cryptography").ed25519.PublicKey;
const Fetcher = fetcher_mod.Fetcher(PublicKey, MockKey);

/// Keys 0..7 and peers with seeds 0..5; seed 0 is the fetcher itself.
const keys_count = 8;
const peers_count = 6;
const steps_max = 64;
const retry_delay_ms = 100;
const all_peers: u8 = (1 << peers_count) - 1;

const State = enum { none, pending, active };

const Model = struct {
    states: [keys_count]State = @splat(.none),
    retries: [keys_count]u32 = @splat(0),
    /// Target peers as a bitset over seeds; null when the key is unrestricted.
    targets: [keys_count]?u8 = @splat(null),
    /// The pending order of each pending key.
    orders: [keys_count]fetcher_mod.Order = undefined,
    sequence: u64 = 0,
    tracked: u8 = 0,
    blocked: u8 = 0,

    /// Peers that may serve `key`: tracked, not self, not blocked, and targeted if targeted.
    fn eligible(model: *const Model, key: usize) u8 {
        const open = model.tracked & ~model.blocked & ~@as(u8, 1);
        return if (model.targets[key]) |targets| open & targets else open;
    }

    fn add(model: *Model, key: usize, retry: bool, now: SystemTime) void {
        assert(model.states[key] == .none);
        const delay = Duration.from_millis(if (retry) retry_delay_ms else 0);
        model.states[key] = .pending;
        model.orders[key] = .{
            .retry = retry,
            .deadline = now.saturating_add(delay),
            .sequence = model.sequence,
        };
        model.sequence += 1;
        if (retry) model.retries[key] +|= 1;
    }

    /// The pending key a successful send would pick: the first due key, in pending order,
    /// that has an eligible peer.
    fn next_send(model: *const Model, now: SystemTime) ?usize {
        var best: ?usize = null;
        for (model.states, 0..) |state, key| {
            if (state != .pending or model.eligible(key) == 0) continue;
            if (model.orders[key].deadline.order(now) == .gt) continue;
            if (best == null or before(model.orders[key], model.orders[best.?])) best = key;
        }
        return best;
    }
};

/// Pending order, written independently of `fetcher.Order`: fresh keys before retries, then
/// earlier deadlines, then arrival.
fn before(a: fetcher_mod.Order, b: fetcher_mod.Order) bool {
    if (a.retry != b.retry) return !a.retry;
    const deadline_a = a.deadline.nanos_since_epoch;
    const deadline_b = b.deadline.nanos_since_epoch;
    if (deadline_a != deadline_b) return deadline_a < deadline_b;
    return a.sequence < b.sequence;
}

var peers: [peers_count]PublicKey = undefined;

fn seed_of(peer: PublicKey) usize {
    for (peers, 0..) |candidate, seed| {
        if (candidate.order(peer) == .eq) return seed;
    }
    unreachable; // Proof: the fetcher only knows peers from `peers`.
}

fn peer_list(buffer: *[peers_count]PublicKey, bits: u8) []const PublicKey {
    var count: usize = 0;
    for (peers, 0..) |peer, seed| {
        if (bits & (@as(u8, 1) << @intCast(seed)) == 0) continue;
        buffer[count] = peer;
        count += 1;
    }
    return buffer[0..count];
}

fn key_at(value: usize) MockKey {
    return .init(@intCast(value));
}

/// The request (index into `fetcher.requests`) for `key`, if it is active.
fn request_of(fetcher: *const Fetcher, value: usize) ?usize {
    for (fetcher.requests.values(), 0..) |request, position| {
        if (request.key.value == value) return position;
    }
    return null;
}

fn expect_matches(fetcher: *Fetcher, model: *const Model) !void {
    var pending: usize = 0;
    var active: usize = 0;
    for (0..keys_count) |value| {
        const state = model.states[value];
        try testing.expectEqual(state == .pending, fetcher.pending.contains(key_at(value)));
        try testing.expectEqual(state == .active, request_of(fetcher, value) != null);
        pending += @intFromBool(state == .pending);
        active += @intFromBool(state == .active);
        try testing.expectEqual(model.retries[value], fetcher.retry_count(key_at(value)));
        const actual_targets = fetcher.targets_of(key_at(value));
        try testing.expectEqual(model.targets[value] == null, actual_targets == null);
        if (actual_targets) |targets| {
            var bits: u8 = 0;
            for (targets) |peer| bits |= @as(u8, 1) << @intCast(seed_of(peer));
            try testing.expectEqual(model.targets[value].?, bits);
        }
        const eligible = try fetcher.eligible_peers(key_at(value));
        defer gpa.free(eligible);
        var eligible_bits: u8 = 0;
        for (eligible) |peer| eligible_bits |= @as(u8, 1) << @intCast(seed_of(peer));
        try testing.expectEqual(eligible.len, @popCount(eligible_bits)); // no repeats
        try testing.expectEqual(model.eligible(value), eligible_bits);
    }
    try testing.expectEqual(pending, fetcher.len_pending());
    try testing.expectEqual(active, fetcher.len_active());
}

/// A send attempt: with a succeeding sender, exactly the model's next key moves to active,
/// requested from one of its eligible peers; with a failing sender, nothing moves.
fn step_fetch(fetcher: *Fetcher, model: *Model, succeed: bool) !void {
    const now = fetcher_mod.current(fetcher.io);
    const expected = if (succeed) model.next_send(now) else null;
    if (succeed) {
        var sender: base.SuccessSender = .{};
        try fetcher.fetch(&sender);
    } else {
        var sender: base.FailSender = .{};
        try fetcher.fetch(&sender);
    }
    const sent = expected orelse return;
    const position = request_of(fetcher, sent) orelse return error.KeyNotSent;
    const peer = fetcher.requests.values()[position].peer;
    const seed: u3 = @intCast(seed_of(peer));
    try testing.expect(model.eligible(sent) & (@as(u8, 1) << seed) != 0);
    model.states[sent] = .active;
}

/// Resolves the active request picked by `selector`: a response from its peer (`missing`
/// charges the peer), or from another peer, which matches nothing.
fn step_response(fetcher: *Fetcher, model: *Model, selector: u8, missing: bool) !void {
    const count = fetcher.requests.count();
    if (count == 0) return;
    const position = selector % count;
    const id = fetcher.requests.keys()[position];
    const request = fetcher.requests.values()[position];
    if (selector & 0x80 != 0) {
        const other = peers[(seed_of(request.peer) + 1) % peers_count];
        try testing.expect(fetcher.pop_response(id, other) == null);
        return;
    }
    const value = request.key.value;
    if (missing) {
        const popped = try fetcher.pop_missing(id, request.peer);
        try testing.expectEqual(value, popped.?.value);
    } else {
        const popped = fetcher.pop_response(id, request.peer).?;
        try testing.expectEqual(value, popped.key.value);
    }
    assert(model.states[value] == .active);
    model.states[value] = .none;
}

fn step_timeout(fetcher: *Fetcher, model: *Model) !void {
    const popped = try fetcher.pop_active() orelse {
        for (model.states) |state| try testing.expect(state != .active);
        return;
    };
    try testing.expectEqual(State.active, model.states[popped.value]);
    model.states[popped.value] = .none;
}

fn step_retain(fetcher: *Fetcher, model: *Model, max: usize) void {
    fetcher.retain(base.Keep{ .at_most = @intCast(max) });
    for (max + 1..keys_count) |value| {
        model.states[value] = .none;
        model.targets[value] = null;
        model.retries[value] = 0;
    }
}

fn step(fetcher: *Fetcher, model: *Model, op: [3]u8) !void {
    const value = op[1] % keys_count;
    const bits: u8 = op[2] & 0x3f;
    const now = fetcher_mod.current(fetcher.io);
    var buffer: [peers_count]PublicKey = undefined;
    switch (op[0] % 14) {
        0, 1 => if (model.states[value] == .none) {
            try fetcher.add_ready(key_at(value));
            model.add(value, false, now);
        },
        2 => if (model.states[value] == .none) {
            try fetcher.add_retry(key_at(value));
            model.add(value, true, now);
        },
        3, 4 => try step_fetch(fetcher, model, true),
        5 => try step_fetch(fetcher, model, false),
        6 => try step_response(fetcher, model, op[2], op[1] & 1 == 0),
        7 => try step_timeout(fetcher, model),
        8 => step_retain(fetcher, model, value),
        9 => {
            try fetcher.reconcile(peer_list(&buffer, bits));
            model.tracked = bits;
        },
        10 => {
            // Sparse blocks keep most keys servable.
            const blocked = bits & op[1];
            try fetcher.set_blocked(peer_list(&buffer, blocked));
            model.blocked = blocked;
        },
        11 => {
            try fetcher.add_targets(key_at(value), peer_list(&buffer, bits));
            model.targets[value] = (model.targets[value] orelse 0) | bits;
        },
        12 => if (op[2] & 1 == 0) {
            fetcher.clear_targets(key_at(value));
            model.targets[value] = null;
        } else {
            fetcher.clear(key_at(value));
            model.targets[value] = null;
            model.retries[value] = 0;
        },
        else => {
            const nanos: i96 = @as(i96, op[2]) * std.time.ns_per_ms;
            try fetcher.io.sleep(.fromNanoseconds(nanos), .real);
        },
    }
}

fn run_ops(io: Io, ops: *const [steps_max][3]u8) !void {
    var registry = runtime.telemetry.metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = runtime.telemetry.metrics.Scope.init(&registry).child("fetcher");
    var config = base.test_config(peers[0]);
    config.retry_delay = Duration.from_millis(retry_delay_ms);
    var fetcher = try Fetcher.init(gpa, io, &scope, config);
    defer fetcher.deinit();
    // Start from a full roster, as an engine does after its first peer set.
    var buffer: [peers_count]PublicKey = undefined;
    try fetcher.reconcile(peer_list(&buffer, all_peers));
    var model: Model = .{ .tracked = all_peers };
    for (ops) |op| {
        try step(&fetcher, &model, op);
        try expect_matches(&fetcher, &model);
    }
}

fn fetcher_model(_: void, smith: *testing.Smith) anyerror!void {
    // Operations come from raw bytes: `Smith.value` maps random words outside small ranges
    // to their minimum, so the seeded driver would otherwise replay one operation.
    var ops: [steps_max][3]u8 = undefined;
    smith.bytes(std.mem.asBytes(&ops));
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .seed = ops[0][0] });
    defer runner.deinit();
    try try runner.start(run_ops, .{ runner.io(), &ops });
}

test "fuzz: fetcher matches a model" {
    for (&peers, 0..) |*peer, seed| peer.* = base.peer_key(seed);
    try p2p.fuzz.run({}, fetcher_model, 0x6665746368657221, 100);
}
