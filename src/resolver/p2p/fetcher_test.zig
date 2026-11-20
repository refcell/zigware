//! Tests for `fetcher.zig`, ported from commonware `resolver/src/p2p/fetcher.rs`, on the
//! deterministic runtime.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const p2p = @import("p2p");
const cryptography = @import("cryptography");
const fetcher_mod = @import("fetcher.zig");
const Score = @import("score.zig").Score;
const MockKey = @import("mocks/key.zig").Key;
const metrics = runtime.telemetry.metrics;

const gpa = testing.allocator;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const Fetcher = fetcher_mod.Fetcher(PublicKey, MockKey);
const ID = fetcher_mod.ID;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;
const Recipients = p2p.Recipients(PublicKey);

/// Number of peer selections drawn by statistical selection tests.
pub const draws: usize = 1_200;

/// The environment a test body runs in.
pub const Env = struct {
    io: Io,
    scope: *const metrics.Scope,
    fetcher: *Fetcher,

    pub fn now(env: Env) SystemTime {
        return fetcher_mod.current(env.io);
    }

    pub fn sleep(env: Env, duration: Duration) !void {
        const nanos: i96 = @intCast(duration.as_nanos());
        try env.io.sleep(.fromNanoseconds(nanos), .real);
    }

    pub fn encode(env: Env) ![]u8 {
        return env.scope.encode(gpa);
    }
};

pub fn key(value: u8) MockKey {
    return .init(value);
}

pub fn peer_key(seed: u64) PublicKey {
    return PrivateKey.from_seed(seed).public_key();
}

pub fn test_config(me: ?PublicKey) fetcher_mod.Config(PublicKey) {
    return .{
        .me = me,
        .fetch_timeout = Duration.from_secs(5),
        .retry_delay = Duration.from_millis(100),
        .priority_requests = false,
    };
}

/// Runs `body` with a fetcher whose identity is seed 0, its metrics under `fetcher`.
pub fn run(comptime body: fn (Env) anyerror!void) !void {
    try run_with(.{}, body);
}

pub fn run_with(config: runtime.deterministic.Config, comptime body: fn (Env) anyerror!void) !void {
    try runtime.deterministic.soak(gpa, config, {}, struct {
        fn round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try try runner.start(go, .{runner.io()});
        }

        fn go(io: Io) !void {
            var registry = metrics.Registry.init(gpa);
            defer registry.deinit();
            const scope = metrics.Scope.init(&registry).child("fetcher");
            var fetcher = try Fetcher.init(gpa, io, &scope, test_config(peer_key(0)));
            defer fetcher.deinit();
            try body(.{ .io = io, .scope = &scope, .fetcher = &fetcher });
        }
    }.round);
}

/// Registers a request and its timeout for tests that bypass sending.
pub fn add_test_active(fetcher: *Fetcher, id: ID, item: MockKey) !void {
    const start = fetcher_mod.current(fetcher.io);
    const deadline = start.checked_add(Duration.from_secs(5)).?;
    try fetcher.active.put(gpa, id, deadline);
    try fetcher.requests.put(gpa, id, .{ .key = item, .peer = peer_key(1), .start = start });
}

pub fn peer_weight(fetcher: *const Fetcher, peer: PublicKey) u64 {
    return fetcher.peer_weight(peer).?;
}

/// A retain predicate over keys.
pub const Keep = union(enum) {
    all,
    none,
    at_most: u8,
    except: u8,
    except_both: [2]u8,
    only: u8,

    pub fn call(keep: Keep, item: MockKey) bool {
        return switch (keep) {
            .all => true,
            .none => false,
            .at_most => |max| item.value <= max,
            .except => |value| item.value != value,
            .except_both => |values| item.value != values[0] and item.value != values[1],
            .only => |value| item.value == value,
        };
    }
};

const keep_all: Keep = .all;
const keep_none: Keep = .none;

/// A checked sender that reports a fixed outcome, counting sends.
pub const MockChecked = struct {
    feedback: Unreliable(Feedback),
    sends: ?*u32 = null,

    pub fn send(self: MockChecked, parts: []const []const u8, priority: bool) Unreliable(Feedback) {
        assert(parts.len > 0);
        _ = priority;
        if (self.sends) |sends| sends.* += 1;
        return self.feedback;
    }

    pub fn deinit(_: MockChecked) void {}
};

/// A sender that accepts every check and rejects every send (commonware `FailMockSender`).
pub const FailSender = struct {
    pub fn check(_: *FailSender, recipients: Recipients) !p2p.Check(MockChecked) {
        assert(recipients == .one);
        return .{ .checked = .{ .feedback = .rejected } };
    }
};

/// A sender that accepts every request (commonware `SuccessMockSender`).
pub const SuccessSender = struct {
    sends: u32 = 0,

    pub fn check(self: *SuccessSender, recipients: Recipients) !p2p.Check(MockChecked) {
        assert(recipients == .one);
        return .{ .checked = .{ .feedback = .{ .outcome = .ok }, .sends = &self.sends } };
    }
};

/// A sender that rate-limits per peer before reporting `feedback` (commonware
/// `LimitedMockSender`).
pub const LimitedSender = struct {
    limiter: p2p.KeyedRateLimiter(PublicKey),
    feedback: Unreliable(Feedback),

    pub fn init(io: Io, quota: p2p.Quota, feedback: Unreliable(Feedback)) LimitedSender {
        return .{ .limiter = .init(gpa, io, quota), .feedback = feedback };
    }

    pub fn deinit(self: *LimitedSender) void {
        self.limiter.deinit();
    }

    pub fn check(self: *LimitedSender, recipients: Recipients) !p2p.Check(MockChecked) {
        const peer = recipients.one;
        if (try self.limiter.check_key(peer)) |not_until| return .{ .limited = not_until };
        return .{ .checked = .{ .feedback = self.feedback } };
    }
};

/// Sends the only pending fetch and returns its request ID and peer.
pub fn send_next(fetcher: *Fetcher, sender: anytype) !struct { ID, PublicKey } {
    try fetcher.fetch(sender);
    try testing.expectEqual(@as(usize, 0), fetcher.len_pending());
    try testing.expectEqual(@as(usize, 1), fetcher.len_active());
    const id = fetcher.requests.keys()[0];
    return .{ id, fetcher.requests.values()[0].peer };
}

/// Counts how often each peer is drawn first for `item` over `draws` selections. These draws
/// send no requests, so scores and retry counts stay fixed.
pub fn first_picks(fetcher: *Fetcher, item: MockKey, peers: []const PublicKey) ![]usize {
    const counts = try gpa.alloc(usize, peers.len);
    @memset(counts, 0);
    for (0..draws) |_| {
        const eligible = try fetcher.eligible_peers(item);
        defer gpa.free(eligible);
        for (peers, counts) |peer, *count| {
            if (peer.order(eligible[0]) == .eq) count.* += 1;
        }
    }
    return counts;
}

fn expect_contains_request(fetcher: *const Fetcher, value: u8) !void {
    for (fetcher.requests.values()) |request| {
        if (request.key.value == value) return;
    }
    return error.TestExpectedEqual;
}

fn expect_no_request(fetcher: *const Fetcher, value: u8) !void {
    for (fetcher.requests.values()) |request| {
        try testing.expect(request.key.value != value);
    }
}

fn expect_lens(fetcher: *const Fetcher, total: usize, pending: usize, active: usize) !void {
    try testing.expectEqual(total, fetcher.len());
    try testing.expectEqual(pending, fetcher.len_pending());
    try testing.expectEqual(active, fetcher.len_active());
}

test "add retry of a pending key panics" {
    // commonware `test_add_retry_duplicate_panics` (`should_panic`).
    try utils.death.expect_panic(@src(), "reached unreachable code", struct {
        fn body() !void {
            try run(struct {
                fn run_body(env: Env) !void {
                    try env.fetcher.add_retry(key(1));
                    try env.fetcher.add_retry(key(1));
                }
            }.run_body);
        }
    }.body);
}

test "retain function" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try fetcher.add_retry(key(3));
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));
            try add_test_active(fetcher, 102, key(30));
            try expect_lens(fetcher, 6, 3, 3);

            fetcher.retain(Keep{ .at_most = 10 });
            try expect_lens(fetcher, 4, 3, 1);
            try testing.expect(fetcher.pending.contains(key(1)));
            try testing.expect(fetcher.pending.contains(key(2)));
            try testing.expect(fetcher.pending.contains(key(3)));
            try expect_contains_request(fetcher, 10);
            try expect_no_request(fetcher, 20);
            try expect_no_request(fetcher, 30);
            try testing.expectEqual(@as(usize, 1), fetcher.active.len());
            try testing.expect(fetcher.active.contains(100));
        }
    }.body);
}

test "len functions" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try expect_lens(fetcher, 0, 0, 0);
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try expect_lens(fetcher, 2, 2, 0);
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));
            try expect_lens(fetcher, 4, 2, 2);
            try testing.expect(fetcher.pending.remove(key(1)));
            try expect_lens(fetcher, 3, 1, 2);
            fetcher.retain(Keep{ .except = 10 });
            try expect_lens(fetcher, 2, 1, 1);
        }
    }.body);
}

test "retain with empty collections" {
    try run(struct {
        fn body(env: Env) !void {
            env.fetcher.retain(keep_all);
            try testing.expectEqual(@as(usize, 0), env.fetcher.len());
            env.fetcher.retain(keep_none);
            try testing.expectEqual(@as(usize, 0), env.fetcher.len());
        }
    }.body);
}

test "retain all elements match predicate" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));
            fetcher.retain(keep_all);
            try expect_lens(fetcher, 4, 2, 2);
        }
    }.body);
}

test "retain no elements match predicate" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));
            fetcher.retain(keep_none);
            try expect_lens(fetcher, 0, 0, 0);
        }
    }.body);
}

test "retain drops selected keys" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));

            fetcher.retain(Keep{ .except = 1 });
            try testing.expectEqual(@as(usize, 1), fetcher.len_pending());
            try testing.expect(!fetcher.contains(key(1)));
            fetcher.retain(Keep{ .except = 10 });
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            try testing.expect(!fetcher.contains(key(10)));

            // Dropping a non-existent key has no effect.
            const before = fetcher.len();
            fetcher.retain(Keep{ .except = 99 });
            try testing.expectEqual(before, fetcher.len());

            fetcher.retain(Keep{ .except = 2 });
            try testing.expectEqual(@as(usize, 0), fetcher.len_pending());
            try testing.expect(fetcher.get_pending_deadline() == null);
        }
    }.body);
}

test "contains function" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try testing.expect(!fetcher.contains(key(1)));
            try fetcher.add_retry(key(1));
            try testing.expect(fetcher.contains(key(1)));
            try add_test_active(fetcher, 100, key(10));
            try testing.expect(fetcher.contains(key(10)));
            try testing.expect(!fetcher.contains(key(99)));
            _ = fetcher.pending.remove(key(1));
            try testing.expect(!fetcher.contains(key(1)));
            fetcher.retain(Keep{ .except = 10 });
            try testing.expect(!fetcher.contains(key(10)));
        }
    }.body);
}

test "add retry function" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try testing.expectEqual(@as(usize, 1), fetcher.len_pending());
            try testing.expect(fetcher.contains(key(1)));
            try fetcher.add_retry(key(2));
            try testing.expectEqual(@as(usize, 2), fetcher.len_pending());
            try testing.expect(fetcher.contains(key(2)));
            try testing.expect(fetcher.get_pending_deadline() != null);
        }
    }.body);
}

test "get pending deadline" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try testing.expect(fetcher.get_pending_deadline() == null);
            try fetcher.add_retry(key(1));
            try testing.expect(fetcher.get_pending_deadline() != null);
            try fetcher.add_retry(key(2));
            try testing.expect(fetcher.get_pending_deadline() != null);
            fetcher.pending.clear();
            try testing.expect(fetcher.get_pending_deadline() == null);
        }
    }.body);
}

test "get active deadline and pop active on empty" {
    try run(struct {
        fn body(env: Env) !void {
            try testing.expect(env.fetcher.get_active_deadline() == null);
            try testing.expect(try env.fetcher.pop_active() == null);
        }
    }.body);
}

test "pop response defers peer rating" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer = peer_key(1);
            try fetcher.reconcile(&.{ peer_key(0), peer });
            try add_test_active(fetcher, 100, key(10));

            // An unrelated response must leave the active request in place.
            try testing.expect(fetcher.pop_response(999, peer) == null);
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());

            // Matching the response retires the request and reports its elapsed time.
            try env.sleep(Duration.from_millis(20));
            const response = fetcher.pop_response(100, peer).?;
            try testing.expectEqual(key(10), response.key);
            try testing.expectEqual(Duration.from_millis(20), response.elapsed);
            try testing.expectEqual(@as(usize, 0), fetcher.len_active());

            // Receiving bytes does not score the peer until the response is attributed.
            const initial = (Score{}).weight();
            try testing.expectEqual(initial, peer_weight(fetcher, peer));
            try fetcher.record_response(peer, response.elapsed, 1024);
            try testing.expect(peer_weight(fetcher, peer) > initial);
        }
    }.body);
}

test "pop response requires matching peer" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer = peer_key(1);
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));

            // A response from another peer leaves the request active.
            try testing.expect(fetcher.pop_response(100, peer_key(2)) == null);
            try testing.expectEqual(@as(usize, 2), fetcher.len_active());
            try testing.expect(fetcher.active.contains(100));
            try testing.expectEqual(key(10), fetcher.requests.get(100).?.key);

            // The matching peer's response removes only that request.
            const response = fetcher.pop_response(100, peer).?;
            try testing.expectEqual(key(10), response.key);
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            try testing.expect(!fetcher.active.contains(100));
            try testing.expect(fetcher.active.contains(101));
            try testing.expectEqual(key(20), fetcher.requests.get(101).?.key);

            // A repeated response is ignored.
            try testing.expect(fetcher.pop_response(100, peer) == null);
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            try testing.expect(fetcher.active.contains(101));
        }
    }.body);
}

test "record response scores by size" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const small = peer_key(1);
            const large = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), small, large });

            // Equal response times isolate the effect of payload size.
            const elapsed = Duration.from_millis(20);
            try fetcher.record_response(small, elapsed, 1);
            try fetcher.record_response(large, elapsed, 1_000);
            try testing.expect(peer_weight(fetcher, large) > peer_weight(fetcher, small));

            // Weighted draws must reflect the larger payload's score advantage.
            const picks = try first_picks(fetcher, key(1), &.{large});
            defer gpa.free(picks);
            try testing.expect(picks[0] > draws * 9 / 10);
        }
    }.body);
}

test "empty fast reply cannot outrank real payload" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const empty = peer_key(1);
            const real = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), empty, real });

            // Repeated empty replies earn no throughput, while the slower peer serves data.
            for (0..3) |_| {
                try fetcher.record_response(empty, Duration.from_millis(1), 0);
                try fetcher.record_response(real, Duration.from_millis(50), 1024);
            }
            try testing.expectEqual(@as(u64, 1), peer_weight(fetcher, empty));
            try testing.expect(peer_weight(fetcher, real) > peer_weight(fetcher, empty));

            const picks = try first_picks(fetcher, key(1), &.{real});
            defer gpa.free(picks);
            try testing.expect(picks[0] > draws * 9 / 10);
        }
    }.body);
}

/// The retry delay and response time `failure_weight` runs with.
var failure_case: struct { retry_delay: Duration, response_time: ?Duration } = undefined;
var failure_result: u64 = 0;

fn failure_weight(env: Env) !void {
    const fetcher = env.fetcher;
    const retry_delay = failure_case.retry_delay;
    fetcher.retry_delay = retry_delay;
    const peer = peer_key(1);
    try fetcher.reconcile(&.{peer});

    // The same useful response establishes each peer's initial score.
    try fetcher.record_response(peer, Duration.from_millis(1), 1024);
    const initial = peer_weight(fetcher, peer);
    try fetcher.add_ready(key(1));
    var sender: SuccessSender = .{};
    const id, _ = try send_next(fetcher, &sender);

    // Missing replies end the wait when they arrive. Silence lasts until expiry.
    const elapsed = failure_case.response_time orelse fetcher.fetch_timeout;
    if (!elapsed.is_zero()) try env.sleep(elapsed);
    const failed = if (failure_case.response_time != null)
        try fetcher.pop_missing(id, peer)
    else
        try fetcher.pop_active();
    try testing.expectEqual(key(1), failed.?);
    const weight = peer_weight(fetcher, peer);
    try testing.expect(weight <= initial);

    // Backoff starts after the failure, in addition to the elapsed request time.
    try fetcher.add_retry(key(1));
    const expected_deadline = env.now().checked_add(retry_delay).?;
    try testing.expectEqual(expected_deadline, fetcher.get_pending_deadline().?);
    failure_result = weight;
}

test "failures charge elapsed time and retry delay" {
    const cases = [_]struct { Duration, [3]u64 }{
        .{ Duration.zero, .{ 1_024_001, 10_139, 205 } },
        .{ Duration.from_millis(100), .{ 10_139, 5_095, 201 } },
        .{ Duration.from_secs(1), .{ 1_023, 931, 171 } },
    };
    const response_times = [_]?Duration{ Duration.zero, Duration.from_millis(100), null };
    for (cases) |case| {
        const retry_delay, const expected = case;
        var weights: [3]u64 = undefined;
        for (response_times, &weights) |response_time, *weight| {
            failure_case = .{ .retry_delay = retry_delay, .response_time = response_time };
            try run_with(.{ .timeout_ns = 10 * std.time.ns_per_s }, failure_weight);
            weight.* = failure_result;
        }
        // One success and one failure: the rate divides the successful payload by the total
        // charged time, plus the base weight.
        try testing.expectEqual(expected, weights);
        try testing.expect(weights[0] > weights[1]);
        try testing.expect(weights[1] > weights[2]);
    }
}

var demote_timeout: bool = false;

fn demote_until_service(env: Env) !void {
    const fetcher = env.fetcher;
    const fast = peer_key(1);
    const steady = peer_key(2);
    try fetcher.reconcile(&.{ fast, steady });

    // Establish a fast history whose preference must disappear after a failure.
    var expected: Score = .{};
    expected.record(Duration.from_millis(1), 1024);
    try fetcher.record_response(fast, Duration.from_millis(1), 1024);
    try fetcher.record_response(steady, Duration.from_millis(50), 1024);
    const initial = peer_weight(fetcher, fast);
    try testing.expect(initial > peer_weight(fetcher, steady));

    // Both failures charge zero bytes and the wait plus the retry delay.
    try fetcher.add_targets(key(1), &.{fast});
    try fetcher.add_ready(key(1));
    var sender: SuccessSender = .{};
    const id, const peer = try send_next(fetcher, &sender);
    try testing.expect(peer.order(fast) == .eq);
    const elapsed = if (demote_timeout) fetcher.fetch_timeout else Duration.from_millis(100);
    try env.sleep(elapsed);
    const failed = if (demote_timeout)
        try fetcher.pop_active()
    else
        try fetcher.pop_missing(id, peer);
    try testing.expectEqual(key(1), failed.?);
    expected.record(elapsed.saturating_add(fetcher.retry_delay), 0);
    const demoted = expected.weight();
    try testing.expectEqual(demoted, peer_weight(fetcher, fast));
    try testing.expect(demoted < peer_weight(fetcher, steady));
    try fetcher.add_retry(key(1));

    // Neither waiting nor sampling opportunities improve the peer's score.
    try env.sleep(Duration.from_secs(3_600));
    try testing.expectEqual(demoted, peer_weight(fetcher, fast));
    const id_next, const peer_next = try send_next(fetcher, &sender);
    try testing.expectEqual(demoted, peer_weight(fetcher, fast));
    try env.sleep(Duration.from_millis(1));
    const response = fetcher.pop_response(id_next, peer_next).?;
    try testing.expectEqual(demoted, peer_weight(fetcher, fast));
    try fetcher.record_response(peer_next, response.elapsed, 1024);
    expected.record(response.elapsed, 1024);
    try testing.expectEqual(expected.weight(), peer_weight(fetcher, fast));
    try testing.expect(expected.weight() > demoted);
    try testing.expect(expected.weight() < initial);
}

test "failures demote fast peers until successful service" {
    for ([_]bool{ false, true }) |timeout| {
        demote_timeout = timeout;
        try run(demote_until_service);
    }
}

test "reconcile and block" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            try fetcher.reconcile(&.{ peer1, peer2 });

            // A blocked participant is skipped without leaving the participant set.
            try fetcher.set_blocked(&.{peer1});
            const eligible = try fetcher.eligible_peers(key(1));
            defer gpa.free(eligible);
            try testing.expectEqualSlices(PublicKey, &.{peer2}, eligible);
            try testing.expect(fetcher.index(peer1) != null);
        }
    }.body);
}

/// Asserts the exported `fetcher_peer_performance` samples are exactly `peers` with their
/// current weights.
fn expect_exported(env: Env, peers: []const PublicKey) !void {
    const text = try env.encode();
    defer gpa.free(text);
    var samples = metrics.metric_samples(text, "fetcher_peer_performance");
    var count: usize = 0;
    while (samples.next()) |sample| : (count += 1) {
        var matched = false;
        for (peers) |peer| {
            var label_buffer: [128]u8 = undefined;
            const label = try std.fmt.bufPrint(&label_buffer, "peer=\"{f}\"", .{peer});
            if (!std.mem.eql(u8, label, sample.labels)) continue;
            const value = try std.fmt.parseInt(u64, sample.value, 10);
            try testing.expectEqual(peer_weight(env.fetcher, peer), value);
            matched = true;
        }
        try testing.expect(matched);
    }
    try testing.expectEqual(peers.len, count);
}

test "reconcile prunes departed peer performance" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            // Key order places one departure on each side of the retained peer, so both
            // removal paths of the roster walk run.
            var peers = [_]PublicKey{ peer_key(1), peer_key(2), peer_key(3) };
            std.mem.sort(PublicKey, &peers, {}, struct {
                fn less(_: void, a: PublicKey, b: PublicKey) bool {
                    return a.order(b) == .lt;
                }
            }.less);
            const low, const mid, const high = peers;

            // Observed peers are exported with their current weights.
            try fetcher.reconcile(&.{ low, mid, high });
            try fetcher.record_response(low, Duration.from_millis(10), 1024);
            try fetcher.record_response(mid, Duration.from_millis(20), 1024);
            try fetcher.record_response(high, Duration.from_millis(30), 1024);
            try expect_exported(env, &.{ low, mid, high });
            const retained = peer_weight(fetcher, mid);

            // Send `low` a request that stays outstanding after it departs.
            var sender: SuccessSender = .{};
            try fetcher.add_targets(key(1), &.{low});
            try fetcher.add_ready(key(1));
            const id, const peer = try send_next(fetcher, &sender);
            try testing.expect(peer.order(low) == .eq);

            // Departure removes the gauges on both sides of the retained peer, which keeps
            // its weight through this and an identical reconcile.
            try fetcher.reconcile(&.{mid});
            try testing.expectEqual(retained, peer_weight(fetcher, mid));
            try expect_exported(env, &.{mid});
            try fetcher.reconcile(&.{mid});
            try testing.expectEqual(retained, peer_weight(fetcher, mid));
            try expect_exported(env, &.{mid});

            // A late response from a departed peer does not revive its gauge.
            try testing.expect(fetcher.pop_response(id, low) != null);
            try fetcher.record_response(low, Duration.from_millis(10), 1024);
            try expect_exported(env, &.{mid});

            // A rejoining peer starts without observations and is exported once observed.
            try fetcher.reconcile(&.{ low, mid });
            try testing.expectEqual((Score{}).weight(), peer_weight(fetcher, low));
            try expect_exported(env, &.{mid});
            try fetcher.record_response(low, Duration.from_millis(10), 1024);
            try expect_exported(env, &.{ low, mid });

            // An empty roster removes every gauge.
            try fetcher.reconcile(&.{});
            try expect_exported(env, &.{});
            try expect_cached_weights(fetcher);
        }
    }.body);
}

/// The cached sampling weights match the scores, with self and blocked peers at zero.
pub fn expect_cached_weights(fetcher: *const Fetcher) !void {
    try testing.expectEqual(fetcher.participants.items.len, fetcher.weights.len());
    var total: u128 = 0;
    for (fetcher.participants.items, 0..) |participant, position| {
        const peer = participant.peer;
        const is_me = if (fetcher.me) |me| me.order(peer) == .eq else false;
        var blocked = false;
        for (fetcher.blocked.items) |item| blocked = blocked or item.order(peer) == .eq;
        const expected = if (is_me or blocked) 0 else participant.score.weight();
        try testing.expectEqual(expected, fetcher.weights.weight(position));
        total += expected;
    }
    try testing.expectEqual(total, fetcher.weights.total());
}

test "edge cases empty state" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try expect_lens(fetcher, 0, 0, 0);
            try testing.expect(!fetcher.contains(key(1)));
            try testing.expect(fetcher.get_pending_deadline() == null);
            try testing.expect(fetcher.get_active_deadline() == null);
        }
    }.body);
}

test "retain edge cases" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            fetcher.retain(Keep{ .except = 1 });
            try testing.expectEqual(@as(usize, 0), fetcher.len());
            try fetcher.add_retry(key(1));
            fetcher.retain(Keep{ .except = 1 });
            try testing.expectEqual(@as(usize, 0), fetcher.len());
            fetcher.retain(Keep{ .except = 1 });
            try testing.expectEqual(@as(usize, 0), fetcher.len());
        }
    }.body);
}

test "retain preserves active state" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try add_test_active(fetcher, 100, key(1));
            try add_test_active(fetcher, 101, key(2));
            fetcher.retain(Keep{ .only = 1 });
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            try expect_contains_request(fetcher, 1);
            try expect_no_request(fetcher, 2);
            // The retained key keeps its original request ID.
            try testing.expect(fetcher.requests.contains(100));
        }
    }.body);
}

test "mixed operations" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try add_test_active(fetcher, 100, key(10));
            try add_test_active(fetcher, 101, key(20));
            try testing.expectEqual(@as(usize, 4), fetcher.len());
            fetcher.retain(Keep{ .except_both = .{ 1, 10 } });
            try testing.expectEqual(@as(usize, 2), fetcher.len());
            fetcher.retain(Keep{ .at_most = 20 });
            try testing.expectEqual(@as(usize, 2), fetcher.len());
            try testing.expect(fetcher.contains(key(2)));
            try testing.expect(fetcher.contains(key(20)));
            fetcher.retain(keep_none);
            try testing.expectEqual(@as(usize, 0), fetcher.len());
        }
    }.body);
}

/// Parks the env's fetcher on a target outside its peer set; returns the eligible peer.
fn make_unservable(fetcher: *Fetcher) !PublicKey {
    const peer = peer_key(1);
    try fetcher.reconcile(&.{ peer_key(0), peer });
    try fetcher.add_targets(key(1), &.{peer_key(2)});
    try fetcher.add_ready(key(1));
    return peer;
}

fn sleep_until(env: Env, deadline: SystemTime) !void {
    try env.sleep(fetcher_mod.duration_since(deadline, env.now()));
}

fn after(env: Env, delta: Duration) SystemTime {
    return env.now().checked_add(delta).?;
}

fn targets_count(fetcher: *const Fetcher) usize {
    return fetcher.targets.entries.items.len;
}

fn targets_of(fetcher: *const Fetcher, item: MockKey) ?[]const PublicKey {
    return fetcher.targets_of(item);
}

fn has_target(fetcher: *const Fetcher, item: MockKey, peer: PublicKey) bool {
    const targets = targets_of(fetcher, item) orelse return false;
    for (targets) |target| {
        if (target.order(peer) == .eq) return true;
    }
    return false;
}

fn expect_eligible(fetcher: *Fetcher, item: MockKey, expected: []const PublicKey) !void {
    const eligible = try fetcher.eligible_peers(item);
    defer gpa.free(eligible);
    try testing.expectEqualSlices(PublicKey, expected, eligible);
}

fn expect_pending_deadline(fetcher: *const Fetcher, expected: SystemTime) !void {
    try testing.expectEqual(expected, fetcher.get_pending_deadline().?);
}

test "ready vs retry" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try fetcher.add_ready(key(2));
            try expect_lens(fetcher, 2, 2, 0);
            // The ready key comes first, due now.
            try expect_pending_deadline(fetcher, env.now());
            try testing.expectEqual(key(2), fetcher.pending.pop().?.item);
            // Then the retry key with its delayed deadline.
            try expect_pending_deadline(fetcher, after(env, Duration.from_millis(100)));
            try testing.expectEqual(key(1), fetcher.pending.pop().?.item);
        }
    }.body);
}

test "ready requests precede all retries" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_retry(key(1));
            try env.sleep(Duration.from_millis(50));
            try fetcher.add_retry(key(2));
            try env.sleep(Duration.from_millis(200));
            try fetcher.add_ready(key(4));
            try fetcher.add_ready(key(3));
            for ([_]u8{ 4, 3, 1, 2 }) |value| {
                try testing.expectEqual(key(value), fetcher.pending.pop().?.item);
            }
            try testing.expect(fetcher.pending.pop() == null);
        }
    }.body);
}

test "equal deadline retries preserve arrival order" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.reconcile(&.{peer_key(1)});
            var sender: SuccessSender = .{};
            // Queue three retries out of key order, then wait until they are due.
            for ([_]u8{ 3, 1, 2 }) |value| try fetcher.add_retry(key(value));
            try env.sleep(Duration.from_millis(100));
            // Each fetch sends the earliest queued retry.
            for ([_]u8{ 3, 1, 2 }, 1..) |value, count| {
                try fetcher.fetch(&sender);
                try testing.expectEqual(count, fetcher.len_active());
                try expect_contains_request(fetcher, value);
                try testing.expect(!fetcher.pending.contains(key(value)));
            }
        }
    }.body);
}

test "waiter after empty" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.reconcile(&.{ peer_key(0), peer_key(1) });
            var sender: FailSender = .{};
            // Rejected sends leave the key pending and arm a retry deadline, even if another
            // fetch call immediately tries to send it again.
            try fetcher.add_ready(key(1));
            try fetcher.fetch(&sender);
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 1), fetcher.len_pending());
            try testing.expect(fetcher.get_pending_deadline().?.order(env.now()) == .gt);

            fetcher.retain(Keep{ .except = 1 });
            try testing.expect(fetcher.get_pending_deadline() == null);
            try env.sleep(Duration.from_secs(10));
            try fetcher.add_retry(key(2));
            try expect_pending_deadline(fetcher, after(env, Duration.from_millis(100)));
        }
    }.body);
}

test "waiter cleared on target modification" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const blocked_peer = peer_key(99);
            try fetcher.reconcile(&.{ peer_key(0), peer1 });
            var sender: FailSender = .{};
            try fetcher.set_blocked(&.{blocked_peer});

            // Targets pointing only to a blocked peer park the fetcher far in the future.
            try fetcher.add_ready(key(1));
            try fetcher.add_targets(key(1), &.{blocked_peer});
            try fetcher.fetch(&sender);
            const far = after(env, Duration.from_secs(1000));
            try testing.expect(fetcher.waiter.?.order(far) == .gt);

            // Adding a target clears the waiter.
            try fetcher.add_targets(key(1), &.{peer1});
            try testing.expect(fetcher.waiter == null);
            const deadline = fetcher.get_pending_deadline().?;
            try testing.expect(deadline.order(after(env, Duration.from_millis(100))) != .gt);

            // Clearing targets clears the waiter too.
            fetcher.clear_targets(key(1));
            try fetcher.add_targets(key(1), &.{blocked_peer});
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.waiter != null);
            fetcher.clear_targets(key(1));
            try testing.expect(fetcher.waiter == null);
        }
    }.body);
}

test "add ready clears waiter for new fetch" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            _ = try make_unservable(fetcher);
            var sender: SuccessSender = .{};
            // Key 1 cannot find its target and parks the fetcher.
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.waiter != null);
            // Fresh demand wakes the fetcher and progresses while key 1 remains pending.
            try fetcher.add_ready(key(2));
            try expect_pending_deadline(fetcher, env.now());
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.pending.contains(key(1)));
            try testing.expect(!fetcher.pending.contains(key(2)));
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
        }
    }.body);
}

test "add retry clears waiter for retry deadline" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer = try make_unservable(fetcher);
            var sender: SuccessSender = .{};
            // Key 2 can be sent even though key 1 has no available target.
            try fetcher.add_ready(key(2));
            try fetcher.fetch(&sender);
            const id = fetcher.requests.keys()[0];
            // With only key 1 pending, the queue parks until new demand arrives.
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.waiter != null);

            // A missing response wakes the queue, but key 2 waits for its retry deadline.
            try testing.expectEqual(key(2), (try fetcher.pop_missing(id, peer)).?);
            const retry_deadline = after(env, fetcher.retry_delay);
            try fetcher.add_retry(key(2));
            try expect_pending_deadline(fetcher, env.now());
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 0), fetcher.len_active());
            try testing.expect(fetcher.pending.contains(key(2)));
            try expect_pending_deadline(fetcher, retry_deadline);

            // The scheduled wakeup sends key 2 without a peer update or new demand.
            try sleep_until(env, retry_deadline);
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.pending.contains(key(1)));
            try testing.expect(!fetcher.pending.contains(key(2)));
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
        }
    }.body);
}

var reenqueue_fetch_first: bool = false;

fn reenqueue_after_timeout(env: Env) !void {
    const fetcher = env.fetcher;
    _ = try make_unservable(fetcher);
    try add_test_active(fetcher, 0, key(2));
    var sender: SuccessSender = .{};
    if (reenqueue_fetch_first) {
        try fetcher.fetch(&sender);
        try testing.expect(fetcher.waiter != null);
    }

    // Expiry requeues key 2 and clears any waiter left by key 1.
    try sleep_until(env, fetcher.get_active_deadline().?);
    const expired = (try fetcher.pop_active()).?;
    const retry_deadline = after(env, fetcher.retry_delay);
    try fetcher.add_retry(expired);

    // Key 1 is due now, but key 2 cannot be retried until its own deadline.
    try fetcher.fetch(&sender);
    try testing.expectEqual(@as(usize, 0), fetcher.len_active());
    try testing.expect(fetcher.pending.contains(key(2)));
    try expect_pending_deadline(fetcher, retry_deadline);

    // The retry proceeds at its deadline without an external wakeup.
    try sleep_until(env, retry_deadline);
    try fetcher.fetch(&sender);
    try testing.expect(fetcher.pending.contains(key(1)));
    try testing.expect(!fetcher.pending.contains(key(2)));
    try testing.expectEqual(@as(usize, 1), fetcher.len_active());
}

test "active timeout reenqueue clears waiter for retry deadline" {
    for ([_]bool{ true, false }) |fetch_first| {
        reenqueue_fetch_first = fetch_first;
        try run(reenqueue_after_timeout);
    }
}

test "rate limited key preserves later retry deadline" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peers = [_]PublicKey{ peer_key(1), peer_key(2), peer_key(3) };
            try fetcher.reconcile(&peers);
            var sender: LimitedSender = .init(env.io, p2p.Quota.per_second(1), .{ .outcome = .ok });
            defer sender.deinit();

            // Key 1 exhausts its target's quota and schedules a retry.
            try fetcher.add_targets(key(1), &.{peers[0]});
            try fetcher.add_ready(key(1));
            const id, const peer = try send_next(fetcher, &sender);
            try testing.expectEqual(key(1), (try fetcher.pop_missing(id, peer)).?);
            const first_deadline = after(env, fetcher.retry_delay);
            try fetcher.add_retry(key(1));

            // Key 2 fails later, but gains an additional target with unused quota.
            try env.sleep(Duration.from_millis(50));
            try fetcher.add_targets(key(2), &.{peers[1]});
            try fetcher.add_ready(key(2));
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            const id_second = fetcher.requests.keys()[0];
            try testing.expectEqual(key(2), (try fetcher.pop_missing(id_second, peers[1])).?);
            const second_deadline = after(env, fetcher.retry_delay);
            try fetcher.add_retry(key(2));
            try fetcher.add_targets(key(2), &.{peers[2]});

            // Key 1 becomes due first. Its rate limit extends past key 2's deadline, which
            // must remain the next wakeup without sending key 2 early.
            try sleep_until(env, first_deadline);
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 0), fetcher.len_active());
            try testing.expect(fetcher.pending.contains(key(2)));
            try expect_pending_deadline(fetcher, second_deadline);

            // Key 2 can use its additional target before key 1's quota recovers.
            try sleep_until(env, second_deadline);
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.pending.contains(key(1)));
            try testing.expect(!fetcher.pending.contains(key(2)));
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            try testing.expect(fetcher.requests.values()[0].peer.order(peers[2]) == .eq);
        }
    }.body);
}

test "add targets clears waiter for new target" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer = try make_unservable(fetcher);
            var sender: SuccessSender = .{};
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.waiter != null);
            try fetcher.add_targets(key(1), &.{peer});
            try expect_pending_deadline(fetcher, env.now());
            try fetcher.fetch(&sender);
            try testing.expect(!fetcher.pending.contains(key(1)));
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
        }
    }.body);
}

test "clear targets clears waiter for fallback" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            _ = try make_unservable(fetcher);
            var sender: SuccessSender = .{};
            try fetcher.fetch(&sender);
            try testing.expect(fetcher.waiter != null);
            fetcher.clear_targets(key(1));
            try expect_pending_deadline(fetcher, env.now());
            try fetcher.fetch(&sender);
            try testing.expect(!fetcher.pending.contains(key(1)));
            try testing.expectEqual(@as(usize, 1), fetcher.len_active());
        }
    }.body);
}

test "zero retry delay respects rate limit after send failure" {
    try run_with(.{ .timeout_ns = 3 * std.time.ns_per_s }, struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            fetcher.retry_delay = Duration.zero;
            try fetcher.reconcile(&.{peer_key(1)});
            var sender: LimitedSender = .init(env.io, p2p.Quota.per_second(1), .rejected);
            defer sender.deinit();
            try testing.expect(fetcher.request_id == null);

            // The failed send leaves the key pending and permits an immediate retry.
            try fetcher.add_ready(key(1));
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 1, 1, 0);
            const next_id = fetcher.request_id.?;
            try expect_pending_deadline(fetcher, env.now());

            // The retry finds the quota exhausted and waits for its refill deadline.
            try fetcher.fetch(&sender);
            const refill = after(env, Duration.from_secs(1));
            try testing.expectEqual(next_id, fetcher.request_id.?);
            try expect_pending_deadline(fetcher, refill);

            // Refilling permits one more failed send before the next rate-limit wait.
            try sleep_until(env, refill);
            try fetcher.fetch(&sender);
            try testing.expectEqual(next_id +% 1, fetcher.request_id.?);
            try fetcher.fetch(&sender);
            try testing.expectEqual(next_id +% 1, fetcher.request_id.?);
            try expect_pending_deadline(fetcher, refill.checked_add(Duration.from_secs(1)).?);
        }
    }.body);
}

test "waiter uses retry delay on send failure" {
    try run_with(.{ .timeout_ns = 5 * std.time.ns_per_s }, struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.reconcile(&.{ peer_key(0), peer_key(1), peer_key(2) });
            var sender: FailSender = .{};
            // Every send fails, so the key stays pending.
            try fetcher.add_ready(key(1));
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 1), fetcher.len_pending());

            // Failed sends resume after the configured retry delay.
            const pending_deadline = fetcher.get_pending_deadline().?;
            const max_expected = after(env, Duration.from_millis(110));
            try testing.expect(pending_deadline.order(max_expected) != .gt);

            // Reaching the retry deadline permits another send attempt.
            try sleep_until(env, pending_deadline);
            try fetcher.fetch(&sender);
        }
    }.body);
}

test "eligible peers follow latest set and targets" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const primary = peer_key(1);
            const secondary = peer_key(2);
            const other = peer_key(3);
            try fetcher.reconcile(&.{ peer_key(0), primary, secondary, other });

            // Without targets, every peer of the latest set except self is eligible.
            const eligible = try fetcher.eligible_peers(key(1));
            defer gpa.free(eligible);
            try testing.expectEqual(@as(usize, 3), eligible.len);
            for ([_]PublicKey{ primary, secondary, other }) |peer| {
                var found = false;
                for (eligible) |item| found = found or item.order(peer) == .eq;
                try testing.expect(found);
            }

            // Targets restrict eligibility to themselves; the untracked target is skipped.
            try fetcher.add_targets(key(1), &.{ primary, secondary, peer_key(4) });
            const targeted = try fetcher.eligible_peers(key(1));
            defer gpa.free(targeted);
            try testing.expectEqual(@as(usize, 2), targeted.len);
            const first_primary = targeted[0].order(primary) == .eq;
            try testing.expect(first_primary or targeted[1].order(primary) == .eq);
            try testing.expect(first_primary or targeted[0].order(secondary) == .eq);

            // A single target is the only eligible peer.
            try fetcher.add_targets(key(2), &.{secondary});
            try expect_eligible(fetcher, key(2), &.{secondary});
        }
    }.body);
}

test "add targets" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            const peer3 = peer_key(3);
            try testing.expectEqual(@as(usize, 0), targets_count(fetcher));
            try fetcher.add_targets(key(1), &.{peer1});
            try testing.expectEqual(@as(usize, 1), targets_count(fetcher));
            try testing.expect(has_target(fetcher, key(1), peer1));

            // More targets for the same key accumulate.
            try fetcher.add_targets(key(1), &.{peer2});
            try testing.expectEqual(@as(usize, 1), targets_count(fetcher));
            try testing.expectEqual(@as(usize, 2), targets_of(fetcher, key(1)).?.len);
            try testing.expect(has_target(fetcher, key(1), peer1));
            try testing.expect(has_target(fetcher, key(1), peer2));

            try fetcher.add_targets(key(2), &.{peer1});
            try testing.expectEqual(@as(usize, 2), targets_count(fetcher));
            try testing.expect(has_target(fetcher, key(2), peer1));

            // Adding a duplicate target is idempotent.
            try fetcher.add_targets(key(1), &.{peer1});
            try testing.expectEqual(@as(usize, 2), targets_of(fetcher, key(1)).?.len);
            try fetcher.add_targets(key(1), &.{peer3});
            try testing.expectEqual(@as(usize, 3), targets_of(fetcher, key(1)).?.len);
            try testing.expect(has_target(fetcher, key(1), peer3));

            fetcher.clear_targets(key(1));
            try testing.expect(targets_of(fetcher, key(1)) == null);
            try fetcher.add_targets(key(3), &.{peer1});
            try testing.expect(has_target(fetcher, key(3), peer1));
        }
    }.body);
}

test "targets cleanup" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            // retain() clears targets for pruned keys.
            try fetcher.add_targets(key(1), &.{peer1});
            try fetcher.add_targets(key(2), &.{peer1});
            try fetcher.add_retry(key(1));
            try fetcher.add_retry(key(2));
            try testing.expectEqual(@as(usize, 2), targets_count(fetcher));
            fetcher.retain(Keep{ .except = 1 });
            try testing.expect(targets_of(fetcher, key(1)) == null);
            try testing.expect(targets_of(fetcher, key(2)) != null);
            fetcher.retain(Keep{ .except = 2 });
            try testing.expectEqual(@as(usize, 0), targets_count(fetcher));

            // Retaining nothing clears all targets.
            try fetcher.add_targets(key(1), &.{ peer1, peer2 });
            try fetcher.add_targets(key(2), &.{peer1});
            try fetcher.add_targets(key(3), &.{peer2});
            try testing.expectEqual(@as(usize, 3), targets_count(fetcher));
            fetcher.retain(keep_none);
            try testing.expectEqual(@as(usize, 0), targets_count(fetcher));

            // retain() filters targets.
            for ([_]u8{ 1, 2, 10, 20 }) |value| try fetcher.add_targets(key(value), &.{peer1});
            try testing.expectEqual(@as(usize, 4), targets_count(fetcher));
            fetcher.retain(Keep{ .at_most = 5 });
            try testing.expectEqual(@as(usize, 2), targets_count(fetcher));
            try testing.expect(targets_of(fetcher, key(1)) != null);
            try testing.expect(targets_of(fetcher, key(2)) != null);
            try testing.expect(targets_of(fetcher, key(10)) == null);
            try testing.expect(targets_of(fetcher, key(20)) == null);
        }
    }.body);
}

test "blocked peers keep targets until unblocked" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), peer1, peer2 });
            try fetcher.add_targets(key(1), &.{peer1});
            try fetcher.add_targets(key(2), &.{ peer1, peer2 });

            // A blocked peer keeps its place in every target set but is not eligible.
            try fetcher.set_blocked(&.{peer1});
            try testing.expect(has_target(fetcher, key(1), peer1));
            try expect_eligible(fetcher, key(1), &.{});
            try expect_eligible(fetcher, key(2), &.{peer2});

            // Lifting the block makes the peer eligible again and wakes the fetcher.
            fetcher.waiter = env.now();
            try fetcher.set_blocked(&.{});
            try testing.expect(fetcher.waiter == null);
            try expect_eligible(fetcher, key(1), &.{peer1});
        }
    }.body);
}

test "target behavior on send failure" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), peer1, peer2, peer_key(3) });
            var sender: FailSender = .{};
            // Synchronous send failures leave the key pending with both targets intact.
            try fetcher.add_targets(key(2), &.{ peer1, peer2 });
            try fetcher.add_ready(key(2));
            try testing.expectEqual(@as(usize, 2), targets_of(fetcher, key(2)).?.len);
            try fetcher.fetch(&sender);
            try testing.expectEqual(@as(usize, 2), targets_of(fetcher, key(2)).?.len);
            try testing.expect(fetcher.pending.contains(key(2)));
        }
    }.body);
}

fn clear_all_targets(fetcher: *Fetcher) void {
    for (fetcher.targets.entries.items) |*entry| entry.value.deinit(gpa);
    fetcher.targets.entries.clearRetainingCapacity();
}

test "target retention on pop" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), peer1, peer2 });
            var sender: SuccessSender = .{};

            // The timeout path keeps both targets for later retries.
            try fetcher.add_targets(key(1), &.{ peer1, peer2 });
            try fetcher.add_ready(key(1));
            try fetcher.fetch(&sender);
            try env.sleep(Duration.from_millis(200));
            try testing.expectEqual(key(1), (try fetcher.pop_active()).?);
            try testing.expectEqual(@as(usize, 2), targets_of(fetcher, key(1)).?.len);
            clear_all_targets(fetcher);

            // A no-data response also leaves the target restriction in place.
            try fetcher.add_targets(key(2), &.{peer1});
            try fetcher.add_ready(key(2));
            try fetcher.fetch(&sender);
            const id = fetcher.active.peek().?.item;
            try testing.expectEqual(key(2), (try fetcher.pop_missing(id, peer1)).?);
            try testing.expect(has_target(fetcher, key(2), peer1));
            clear_all_targets(fetcher);

            // Receiving data keeps targets until the caller retires the logical fetch.
            try fetcher.add_targets(key(3), &.{peer1});
            try fetcher.add_ready(key(3));
            try fetcher.fetch(&sender);
            const id_data = fetcher.active.peek().?.item;
            try testing.expectEqual(key(3), fetcher.pop_response(id_data, peer1).?.key);
            try testing.expect(has_target(fetcher, key(3), peer1));
        }
    }.body);
}

test "no fallback when targets unavailable" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.reconcile(&.{ peer_key(0), peer_key(1), peer_key(2) });
            // Target a peer outside the current peer set.
            try fetcher.add_targets(key(1), &.{peer_key(3)});
            try fetcher.add_ready(key(1));
            var sender: SuccessSender = .{};
            try fetcher.fetch(&sender);
            // Targets remain, the key stays pending, and the fetcher parks far out.
            try testing.expect(targets_of(fetcher, key(1)) != null);
            try expect_lens(fetcher, 1, 1, 0);
            const far = after(env, Duration.from_secs(1000));
            try testing.expect(fetcher.waiter.?.order(far) == .gt);
        }
    }.body);
}

test "clear targets" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.add_targets(key(1), &.{ peer_key(1), peer_key(2) });
            try fetcher.add_targets(key(2), &.{peer_key(1)});
            try testing.expectEqual(@as(usize, 2), targets_count(fetcher));
            fetcher.clear_targets(key(1));
            try testing.expect(targets_of(fetcher, key(1)) == null);
            try testing.expect(targets_of(fetcher, key(2)) != null);
            fetcher.clear_targets(key(99));
            try testing.expectEqual(@as(usize, 1), targets_count(fetcher));
            fetcher.clear_targets(key(2));
            try testing.expectEqual(@as(usize, 0), targets_count(fetcher));
        }
    }.body);
}

fn set_retries(fetcher: *Fetcher, item: MockKey, count: u32) !void {
    (try fetcher.retries.get_or_put(gpa, item, 0)).* = count;
}

fn index_of(peers: []const PublicKey, peer: PublicKey) ?usize {
    for (peers, 0..) |item, position| {
        if (item.order(peer) == .eq) return position;
    }
    return null;
}

test "rate limited pending preserves arrival order" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            try fetcher.reconcile(&.{peer_key(1)});
            var sender: LimitedSender = .init(env.io, p2p.Quota.per_second(1), .{ .outcome = .ok });
            defer sender.deinit();

            // Exhaust the peer's token before queuing requests at the same instant.
            try fetcher.add_ready(key(99));
            try fetcher.fetch(&sender);
            try expect_contains_request(fetcher, 99);
            for ([_]u8{ 3, 1, 2 }) |value| {
                try fetcher.add_ready(key(value));
                try fetcher.fetch(&sender);
                try testing.expectEqual(@as(usize, 1), fetcher.len_active());
            }
            try testing.expectEqual(@as(usize, 3), fetcher.len_pending());
            try expect_pending_deadline(fetcher, after(env, Duration.from_secs(1)));

            // Nothing is sent before the peer's next token.
            try env.sleep(Duration.from_millis(999));
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 4, 3, 1);

            // The next token sends the earliest queued key and keeps the others pending.
            try env.sleep(Duration.from_millis(1));
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 4, 2, 2);
            try expect_contains_request(fetcher, 3);
            try testing.expect(fetcher.pending.contains(key(1)));
            try testing.expect(fetcher.pending.contains(key(2)));
        }
    }.body);
}

test "skips keys with rate limited targets" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peer1 = peer_key(1);
            const peer2 = peer_key(2);
            try fetcher.reconcile(&.{ peer_key(0), peer1, peer2 });
            var sender: LimitedSender = .init(env.io, p2p.Quota.per_second(1), .{ .outcome = .ok });
            defer sender.deinit();

            // Keys 1 and 2 target peer1 (rate-limited after the first); key 3 targets peer2.
            try fetcher.add_targets(key(1), &.{peer1});
            try fetcher.add_targets(key(2), &.{peer1});
            try fetcher.add_targets(key(3), &.{peer2});
            try fetcher.add_ready(key(1));
            try env.sleep(Duration.from_millis(1));
            try fetcher.add_ready(key(2));
            try env.sleep(Duration.from_millis(1));
            try fetcher.add_ready(key(3));

            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 3, 2, 1);
            try testing.expect(!fetcher.pending.contains(key(1)));

            // Key 2 is blocked by peer1's rate limit, so the scan skips to key 3.
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 3, 1, 2);
            try testing.expect(fetcher.pending.contains(key(2)));
            try testing.expect(!fetcher.pending.contains(key(3)));

            // Only key 2 remains, still rate-limited.
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 3, 1, 2);
            try expect_pending_deadline(fetcher, after(env, Duration.from_secs(1)));

            try env.sleep(Duration.from_secs(1));
            try fetcher.fetch(&sender);
            try expect_lens(fetcher, 3, 0, 3);
        }
    }.body);
}

test "selection weighted by service" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const fast = peer_key(1);
            const slow = peer_key(2);
            const medium = peer_key(3);
            try fetcher.reconcile(&.{ peer_key(0), fast, slow, medium });

            // Equal payload sizes isolate response latency as the source of each weight.
            try fetcher.record_response(fast, Duration.from_millis(10), 1024);
            try fetcher.record_response(slow, Duration.from_millis(500), 1024);
            try fetcher.record_response(medium, Duration.from_millis(200), 1024);

            // Enumerating the candidates visits every eligible peer exactly once.
            const peers = try fetcher.eligible_peers(key(1));
            defer gpa.free(peers);
            try testing.expectEqual(@as(usize, 3), peers.len);
            for ([_]PublicKey{ fast, slow, medium }) |peer| {
                try testing.expect(index_of(peers, peer) != null);
            }

            // Faster responses earn more first choices, while every peer stays reachable.
            const picks = try first_picks(fetcher, key(1), &.{ fast, medium, slow });
            defer gpa.free(picks);
            try testing.expect(picks[0] > draws * 8 / 10);
            try testing.expect(picks[1] > picks[2]);
            try testing.expect(picks[2] > 0);
        }
    }.body);
}

test "selection uniform without scores" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peers = [_]PublicKey{ peer_key(1), peer_key(2), peer_key(3) };
            try fetcher.reconcile(&peers);
            // Peers without observations receive equal weights, so first choices are even.
            const picks = try first_picks(fetcher, key(1), &peers);
            defer gpa.free(picks);
            for (picks) |count| {
                try testing.expect(count >= draws / 4 and count < draws * 5 / 12);
            }
        }
    }.body);
}

var flatten_targeted: bool = false;

fn retries_flatten(env: Env) !void {
    const fetcher = env.fetcher;
    var peers: [7]PublicKey = undefined;
    for (&peers, 0..) |*peer, seed| peer.* = peer_key(seed);
    try fetcher.reconcile(peers[0..6]);
    try fetcher.set_blocked(&.{peers[5]});

    // Leave the same three peers eligible in the target or shared pool. The target set also
    // contains a blocked peer and a peer outside the current roster.
    if (flatten_targeted) {
        try fetcher.add_targets(key(1), &.{ peers[1], peers[2], peers[3], peers[5], peers[6] });
    } else {
        try fetcher.set_blocked(&.{ peers[4], peers[5] });
    }

    // Give one eligible peer a large advantage and an ineligible peer an even higher score.
    try fetcher.record_response(peers[1], Duration.from_millis(1), 1024);
    try fetcher.record_response(peers[2], Duration.from_millis(100), 1024);
    try fetcher.record_response(peers[3], Duration.from_millis(100), 1024);
    try fetcher.record_response(peers[4], Duration.from_nanos(1), 1024);
    var sum: u64 = 0;
    for (peers[1..4]) |peer| sum += peer_weight(fetcher, peer);
    const weighted = @as(f64, @floatFromInt(peer_weight(fetcher, peers[1]))) /
        @as(f64, @floatFromInt(sum));

    // The early weighted bias, the even split at four retries, and the nearly uniform
    // distribution at the largest retry count.
    const cases = [_]struct { u32, f64 }{
        .{ 0, 1.0 }, .{ 1, 0.8 }, .{ 4, 0.5 }, .{ std.math.maxInt(u32), 0.0 },
    };
    var previous: usize = draws + 1;
    for (cases) |case| {
        const retries, const weighted_share = case;
        try set_retries(fetcher, key(1), retries);
        const picks = try first_picks(fetcher, key(1), &peers);
        defer gpa.free(picks);
        for (picks, 0..) |count, position| {
            const eligible = position >= 1 and position <= 3;
            try testing.expectEqual(eligible, count > 0);
        }
        const draws_f: f64 = @floatFromInt(draws);
        const expected = draws_f * (weighted_share * weighted + (1.0 - weighted_share) / 3.0);
        const count = picks[1];
        try testing.expect(@abs(@as(f64, @floatFromInt(count)) - expected) < draws_f / 12.0);
        try testing.expect(count < previous);
        previous = count;
        try expect_cached_weights(fetcher);
    }
}

test "retries flatten sampling" {
    for ([_]bool{ false, true }) |targeted| {
        flatten_targeted = targeted;
        try run_with(.{ .seed = 0 }, retries_flatten);
    }
}

const Outcome = enum { timeout, missing, partial };
var revisit_case: struct { targeted: bool, outcome: Outcome } = undefined;

fn revisit_after_outcome(env: Env) !void {
    const fetcher = env.fetcher;
    const peers = [_]PublicKey{ peer_key(1), peer_key(2), peer_key(3) };
    try fetcher.reconcile(&peers);
    const eligible: []const PublicKey = if (revisit_case.targeted) peers[0..2] else &peers;
    if (revisit_case.targeted) try fetcher.add_targets(key(1), eligible);

    // A dominant score makes the first peer the expected initial choice.
    try fetcher.record_response(peers[0], Duration.from_nanos(1), 1024);
    try fetcher.add_ready(key(1));
    var sender: SuccessSender = .{};
    const id, const peer = try send_next(fetcher, &sender);
    try testing.expect(peer.order(peers[0]) == .eq);

    // Each way an attempt can leave the key unresolved preserves the peer's eligibility.
    switch (revisit_case.outcome) {
        .timeout => {
            try sleep_until(env, fetcher.get_active_deadline().?);
            try testing.expectEqual(key(1), (try fetcher.pop_active()).?);
        },
        .missing => try testing.expectEqual(key(1), (try fetcher.pop_missing(id, peer)).?),
        .partial => {
            const response = fetcher.pop_response(id, peer).?;
            try fetcher.record_response(peer, response.elapsed, 1024);
        },
    }
    try fetcher.add_retry(key(1));
    try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(1)));

    // Every eligible peer, including the one just tried, remains available.
    const candidates = try fetcher.eligible_peers(key(1));
    defer gpa.free(candidates);
    try testing.expectEqual(eligible.len, candidates.len);
    for (eligible) |item| try testing.expect(index_of(candidates, item) != null);
    const picks = try first_picks(fetcher, key(1), &.{peer});
    defer gpa.free(picks);
    try testing.expect(picks[0] > 0);
    try expect_cached_weights(fetcher);
}

test "retry revisits peers after each outcome" {
    for ([_]bool{ false, true }) |targeted| {
        for ([_]Outcome{ .timeout, .missing, .partial }) |outcome| {
            revisit_case = .{ .targeted = targeted, .outcome = outcome };
            try run_with(.{ .seed = 0 }, revisit_after_outcome);
        }
    }
}

test "single silent target is retried" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const target = peer_key(1);
            // An eligible non-target exposes any accidental widening after a timeout.
            try fetcher.reconcile(&.{ target, peer_key(2) });
            try fetcher.add_targets(key(1), &.{target});
            var sender: SuccessSender = .{};
            try fetcher.add_ready(key(1));
            // Each timeout leads back to the sole target, with no fallback peer.
            for (0..3) |_| {
                try sleep_until(env, fetcher.get_pending_deadline().?);
                _, const peer = try send_next(fetcher, &sender);
                try testing.expect(peer.order(target) == .eq);
                try sleep_until(env, fetcher.get_active_deadline().?);
                try testing.expectEqual(key(1), (try fetcher.pop_active()).?);
                try fetcher.add_retry(key(1));
            }
        }
    }.body);
}

test "retry history lifecycle" {
    try run(struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            const peers = [_]PublicKey{ peer_key(1), peer_key(2) };
            try fetcher.reconcile(&peers);
            var sender: SuccessSender = .{};

            // A missing-data reply from the first target gives the key a retry count of one.
            try fetcher.add_targets(key(1), &.{peers[0]});
            try fetcher.add_ready(key(1));
            const id, const peer = try send_next(fetcher, &sender);
            try testing.expectEqual(key(1), (try fetcher.pop_missing(id, peer)).?);
            try fetcher.add_retry(key(1));
            try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(1)));

            // Changing the target and removing the old peer preserve that history.
            fetcher.clear_targets(key(1));
            try fetcher.add_targets(key(1), &.{peers[1]});
            try fetcher.reconcile(peers[1..]);
            try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(1)));
            try sleep_until(env, fetcher.get_pending_deadline().?);
            const id_second, const peer_second = try send_next(fetcher, &sender);
            try testing.expect(fetcher.pop_response(id_second, peer_second) != null);
            fetcher.clear(key(1));
            try testing.expect(!fetcher.has_targets(key(1)));
            try testing.expect(fetcher.retries.get(key(1)) == null);

            // Reusing a completed key starts fresh and accumulates its own retry count.
            try fetcher.add_ready(key(1));
            try testing.expect(fetcher.retries.get(key(1)) == null);
            _ = try send_next(fetcher, &sender);
            try sleep_until(env, fetcher.get_active_deadline().?);
            try testing.expectEqual(key(1), (try fetcher.pop_active()).?);
            try fetcher.add_retry(key(1));
            try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(1)));

            // A saturated counter leaves the key retryable and independently prunable.
            try set_retries(fetcher, key(1), std.math.maxInt(u32));
            try testing.expect(fetcher.pending.remove(key(1)));
            try fetcher.add_retry(key(1));
            try testing.expectEqual(std.math.maxInt(u32), fetcher.retry_count(key(1)));
            try fetcher.add_retry(key(2));
            fetcher.retain(Keep{ .only = 2 });
            try testing.expect(fetcher.retries.get(key(1)) == null);
            try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(2)));
        }
    }.body);
}

test "cached weights follow scores and blocks" {
    try run_with(.{ .seed = 0 }, struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            var peers: [4]PublicKey = undefined;
            for (&peers, 0..) |*peer, seed| peer.* = peer_key(seed);

            // An unordered roster with a duplicate exercises normalization before indexing.
            try fetcher.reconcile(&.{ peers[3], peers[1], peers[0], peers[2], peers[1] });
            try testing.expectEqual(@as(usize, 4), fetcher.participants.items.len);

            // Update every score while keeping the local node excluded.
            for (peers) |peer| try fetcher.record_response(peer, Duration.from_millis(10), 1024);
            try expect_cached_weights(fetcher);
            const roster = fetcher.participants.items.ptr;

            // A completed selection restores every weight before later observations.
            const eligible = try fetcher.eligible_peers(key(1));
            const peer = eligible[0];
            gpa.free(eligible);
            try expect_cached_weights(fetcher);
            const position = fetcher.index(peer).?;
            const before = peer_weight(fetcher, peer);
            try fetcher.update_performance(peer, fetcher.fetch_timeout, 0);
            try testing.expect(fetcher.weights.weight(position) < before);
            try expect_cached_weights(fetcher);

            // Successful service cannot revive a peer excluded by network policy.
            try fetcher.set_blocked(&peers);
            try fetcher.record_response(peer, Duration.zero, 1024);
            try testing.expect(try fetcher.candidates(key(2)) == null);
            try expect_cached_weights(fetcher);

            // Removing blocks restores current weights while the local node stays excluded.
            try fetcher.set_blocked(&.{peers[2]});
            try expect_cached_weights(fetcher);
            try fetcher.set_blocked(&.{});
            try expect_cached_weights(fetcher);
            try testing.expectEqual(roster, fetcher.participants.items.ptr);

            // Completed requests release temporary exclusions and reuse the roster.
            var sender: SuccessSender = .{};
            for (3..8) |value| {
                const item = key(@intCast(value));
                try fetcher.add_ready(item);
                const id, const sent_to = try send_next(fetcher, &sender);
                try testing.expect(fetcher.pop_response(id, sent_to) != null);
                fetcher.clear(item);
                try expect_cached_weights(fetcher);
                try testing.expectEqual(roster, fetcher.participants.items.ptr);
            }
        }
    }.body);
}

test "cached targets use only current members" {
    try run_with(.{ .seed = 0 }, struct {
        fn body(env: Env) !void {
            const fetcher = env.fetcher;
            var peers: [32]PublicKey = undefined;
            for (&peers, 0..) |*peer, seed| peer.* = peer_key(seed);
            try fetcher.reconcile(&peers);

            // A single target in a larger roster.
            const target = peers[1];
            try fetcher.add_targets(key(1), &.{target});
            try expect_eligible(fetcher, key(1), &.{target});

            // A target set larger than the roster: the extra identities are not candidates.
            var extra: [128]PublicKey = undefined;
            for (&extra, 32..) |*peer, seed| peer.* = peer_key(seed);
            try fetcher.add_targets(key(1), &extra);
            try expect_eligible(fetcher, key(1), &.{target});
            try expect_cached_weights(fetcher);

            // A request completing after its peer leaves the roster leaves the surviving
            // peer's score unchanged.
            try fetcher.record_response(peers[2], Duration.from_millis(10), 1024);
            const surviving_weight = peer_weight(fetcher, peers[2]);
            var sender: SuccessSender = .{};
            try fetcher.add_ready(key(1));
            const id, const peer = try send_next(fetcher, &sender);
            try fetcher.reconcile(&.{peers[2]});
            try testing.expect(fetcher.pop_response(id, peer) != null);
            try fetcher.record_response(peer, Duration.from_nanos(1), 1024);
            try testing.expectEqual(surviving_weight, peer_weight(fetcher, peers[2]));
            try expect_eligible(fetcher, key(1), &.{});
            try expect_cached_weights(fetcher);

            // The target restriction survives departure; a rejoining target starts fresh.
            try fetcher.reconcile(&.{ target, peers[2] });
            try testing.expectEqual((Score{}).weight(), peer_weight(fetcher, target));
            try testing.expect(has_target(fetcher, key(1), target));
            try expect_eligible(fetcher, key(1), &.{target});
            try expect_cached_weights(fetcher);
        }
    }.body);
}

var insertion_reverse: bool = false;
var insertion_selected: [10]PublicKey = undefined;

fn replay_insertion_order(env: Env) !void {
    const fetcher = env.fetcher;
    var peers: [12]PublicKey = undefined;
    for (&peers, 0..) |*peer, seed| peer.* = peer_key(seed);
    try fetcher.reconcile(&peers);
    for (peers, 1..) |peer, millis| {
        try fetcher.record_response(peer, Duration.from_millis(millis), 1024);
    }

    // Vary only insertion order. Membership, scores, and the RNG seed stay fixed.
    var blocked = [_]PublicKey{ peers[10], peers[11] };
    var targets = [_]PublicKey{ peers[1], peers[2] };
    if (insertion_reverse) {
        std.mem.reverse(PublicKey, &blocked);
        std.mem.reverse(PublicKey, &targets);
    }
    try fetcher.set_blocked(&blocked);
    try fetcher.add_targets(key(1), &targets);

    // Follow targeted retries, then widen to the shared index, keeping the retry count.
    try fetcher.add_ready(key(1));
    var sender: SuccessSender = .{};
    for (&insertion_selected, 0..) |*selected, round| {
        if (round == 4) fetcher.clear_targets(key(1));
        try sleep_until(env, fetcher.get_pending_deadline().?);
        const id, const peer = try send_next(fetcher, &sender);
        try testing.expectEqual(key(1), (try fetcher.pop_missing(id, peer)).?);
        try fetcher.add_retry(key(1));
        selected.* = peer;
        try expect_cached_weights(fetcher);
    }
}

test "cached selection is independent of set insertion order" {
    insertion_reverse = false;
    try run_with(.{ .seed = 9 }, replay_insertion_order);
    const forward = insertion_selected;
    insertion_reverse = true;
    try run_with(.{ .seed = 9 }, replay_insertion_order);
    try testing.expectEqualSlices(PublicKey, &forward, &insertion_selected);
}

var reuse_targeted: bool = false;

fn reuse_available_peer(env: Env) !void {
    const fetcher = env.fetcher;
    const a = peer_key(1);
    const b = peer_key(2);
    try fetcher.reconcile(&.{ a, b });
    var sender: LimitedSender = .init(env.io, p2p.Quota.per_second(1), .{ .outcome = .ok });
    defer sender.deinit();

    // Have B report missing data, then let its send token refill for the retry.
    try fetcher.add_targets(key(1), &.{b});
    try fetcher.add_ready(key(1));
    const id, const peer = try send_next(fetcher, &sender);
    try testing.expectEqual(key(1), (try fetcher.pop_missing(id, peer)).?);
    try fetcher.add_retry(key(1));
    try env.sleep(Duration.from_secs(1));

    // Another key consumes A's token while B is ready to accept a retry.
    try fetcher.add_targets(key(2), &.{a});
    try fetcher.add_ready(key(2));
    try fetcher.fetch(&sender);
    const weights = [2]u64{ peer_weight(fetcher, a), peer_weight(fetcher, b) };

    // Make both peers eligible for key 1 while A's token remains unavailable.
    if (reuse_targeted) try fetcher.add_targets(key(1), &.{a}) else fetcher.clear_targets(key(1));

    // Key 1 uses B's available token, leaving scores and the retry count unchanged.
    try fetcher.fetch(&sender);
    try expect_lens(fetcher, 2, 0, 2);
    for (fetcher.requests.values()) |request| {
        const expected = if (request.key.value == 1) b else a;
        try testing.expect(request.peer.order(expected) == .eq);
    }
    try testing.expectEqual(@as(u32, 1), fetcher.retry_count(key(1)));
    try testing.expectEqual(weights, [2]u64{ peer_weight(fetcher, a), peer_weight(fetcher, b) });
    try expect_cached_weights(fetcher);
}

test "retry reuses available peer while another is rate limited" {
    for (0..8) |seed| {
        for ([_]bool{ false, true }) |targeted| {
            reuse_targeted = targeted;
            try run_with(.{ .seed = seed }, reuse_available_peer);
        }
    }
}

/// Records every send and accepts only peers in the ready set (commonware `RecordingSender`).
const RecordingSender = struct {
    ready: std.ArrayList(PublicKey) = .empty,
    attempts: std.ArrayList(PublicKey) = .empty,
    /// Whether unavailable peers report a closed sender instead of rejecting the send.
    closed: bool,

    fn deinit(self: *RecordingSender) void {
        self.ready.deinit(gpa);
        self.attempts.deinit(gpa);
    }

    const Checked = struct {
        sender: *RecordingSender,
        peer: PublicKey,

        pub fn send(self: Checked, parts: []const []const u8, _: bool) Unreliable(Feedback) {
            assert(parts.len == 1);
            // Failed sends count as attempts too, making repeated visits observable.
            self.sender.attempts.append(gpa, self.peer) catch @panic("out of memory");
            if (index_of(self.sender.ready.items, self.peer) != null) return .{ .outcome = .ok };
            if (self.sender.closed) return .{ .outcome = .closed };
            return .rejected;
        }

        pub fn deinit(_: Checked) void {}
    };

    pub fn check(self: *RecordingSender, recipients: Recipients) !p2p.Check(Checked) {
        return .{ .checked = .{ .sender = self, .peer = recipients.one } };
    }
};

var local_failure_case: struct { targeted: bool, closed: bool, retries: ?u32 } = undefined;

fn local_send_failures(env: Env) !void {
    const fetcher = env.fetcher;
    const case = local_failure_case;
    const peers = [_]PublicKey{ peer_key(1), peer_key(2), peer_key(3) };
    try fetcher.reconcile(&peers);
    var sender: RecordingSender = .{ .closed = case.closed };
    defer sender.deinit();
    try sender.ready.append(gpa, peers[0]);

    // A successful fetch gives the first peer a score worth preserving.
    try fetcher.add_targets(key(0), &.{peers[0]});
    try fetcher.add_ready(key(0));
    const id, const peer = try send_next(fetcher, &sender);
    try env.sleep(Duration.from_millis(1));
    const response = fetcher.pop_response(id, peer).?;
    try fetcher.record_response(peer, response.elapsed, 1024);
    fetcher.clear(key(0));
    const before = peer_weight(fetcher, peer);
    sender.ready.clearRetainingCapacity();
    sender.attempts.clearRetainingCapacity();

    // Every send fails. A targeted key considers only its targets; an unrestricted key the
    // whole eligible roster.
    const eligible: []const PublicKey = if (case.targeted) peers[0..2] else &peers;
    if (case.targeted) try fetcher.add_targets(key(1), eligible);
    if (case.retries) |retries| try set_retries(fetcher, key(1), retries);
    try fetcher.add_ready(key(1));
    try fetcher.fetch(&sender);

    // Exact distinct attempts catch a repeated peer; score, retries, and weights hold.
    try expect_lens(fetcher, 1, 1, 0);
    try testing.expectEqual(eligible.len, sender.attempts.items.len);
    for (eligible) |item| try testing.expect(index_of(sender.attempts.items, item) != null);
    try testing.expectEqual(before, peer_weight(fetcher, peer));
    const retries_now: ?u32 = if (fetcher.retries.get(key(1))) |count| count.* else null;
    try testing.expectEqual(case.retries, retries_now);
    try expect_pending_deadline(fetcher, after(env, fetcher.retry_delay));
    try expect_cached_weights(fetcher);

    // Once the sender is available, the next call can use the same peer.
    try sender.ready.append(gpa, peer);
    sender.attempts.clearRetainingCapacity();
    try sleep_until(env, fetcher.get_pending_deadline().?);
    _, const retried = try send_next(fetcher, &sender);
    try testing.expect(retried.order(peer) == .eq);
    try testing.expect(sender.attempts.items.len <= eligible.len);
    try testing.expectEqual(before, peer_weight(fetcher, peer));
    const retries_after: ?u32 = if (fetcher.retries.get(key(1))) |count| count.* else null;
    try testing.expectEqual(case.retries, retries_after);
    try expect_cached_weights(fetcher);
}

test "local send failures are bounded and preserve scores" {
    for ([_]bool{ false, true }) |targeted| {
        for ([_]bool{ false, true }) |closed| {
            for ([_]?u32{ null, std.math.maxInt(u32) }) |retries| {
                local_failure_case = .{
                    .targeted = targeted,
                    .closed = closed,
                    .retries = retries,
                };
                try run_with(.{ .seed = 0 }, local_send_failures);
            }
        }
    }
}
