//! Tests of the lookup network's dialer (commonware `lookup/actors/dialer.rs` tests): the
//! deadline it sleeps until between dials, one dial per tick, and the release of a
//! reservation whose handshake never completes.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const runtime = @import("runtime");
const utils = @import("utils");
const metrics = runtime.telemetry.metrics;
const rate_limit = @import("../../rate_limit.zig");
const network_mod = @import("network.zig");
const harness = @import("network_test.zig");

const Net = harness.Net;
const Transport = harness.Transport;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const gpa = testing.allocator;

fn dialer_config(dial_frequency_ms: u64, cooldown: Duration) Net.Config {
    var config = harness.test_config(harness.PrivateKey.from_seed(0), 30_000, 1024);
    config.dial_frequency = .from_millis(dial_frequency_ms);
    config.peer_connection_cooldown = cooldown;
    return config;
}

const now: SystemTime = SystemTime.UNIX_EPOCH.saturating_add(.from_secs(1_000));

fn at(ms: u64) SystemTime {
    return now.saturating_add(.from_millis(ms));
}

test "the dialer waits at least dial_frequency for the tracker's next query" {
    // commonware `test_dialer_uses_tracker_next_query_deadline`: a hint 100 ms out is
    // clamped up to the 500 ms dial frequency.
    const config = dialer_config(500, .from_millis(500));
    try testing.expectEqual(at(500), Net.next_deadline(&config, now, true, at(100)));
    // A hint inside the window is taken as is.
    const slow = dialer_config(100, .from_millis(500));
    try testing.expectEqual(at(300), Net.next_deadline(&slow, now, true, at(300)));
    // And one beyond the cooldown is clamped down to it.
    try testing.expectEqual(at(500), Net.next_deadline(&slow, now, true, at(900)));
}

test "the dialer keeps dialing queued peers at dial_frequency" {
    // commonware `test_dialer_keeps_dialing_queued_peers_when_next_query_deadline_is_unknown`.
    const config = dialer_config(100, .from_secs(60));
    try testing.expectEqual(at(100), Net.next_deadline(&config, now, false, null));
    try testing.expectEqual(at(100), Net.next_deadline(&config, now, false, at(5_000)));
    // Nothing queued and no hint: ask again after the cooldown.
    try testing.expectEqual(at(60_000), Net.next_deadline(&config, now, true, null));
}

test "the dialer refreshes at dial_frequency when it exceeds the cooldown" {
    // commonware `test_dialer_does_not_panic_when_dial_frequency_exceeds_peer_connection_cooldown`.
    const config = dialer_config(200, .from_millis(50));
    try testing.expectEqual(at(200), Net.next_deadline(&config, now, true, null));
    try testing.expectEqual(at(200), Net.next_deadline(&config, now, true, at(10)));
}

test "the dialer saturates an unbounded cooldown" {
    // commonware `test_dialer_does_not_panic_with_unbounded_peer_connection_cooldown`.
    const config = dialer_config(50, .max);
    try testing.expectEqual(at(100), Net.next_deadline(&config, now, true, at(100)));
    const unbounded = Net.next_deadline(&config, now, true, null);
    try testing.expect(unbounded.order(at(1_000_000_000)) == .gt);
}

/// The total of the dialer's attempts counter over every peer.
fn attempts(scope: metrics.Scope) !u64 {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    var samples = metrics.metric_samples(text, "dialer_attempts_total");
    var total: u64 = 0;
    while (samples.next()) |sample| total += try std.fmt.parseInt(u64, sample.value, 10);
    return total;
}

/// Starts a node tracking `count` peers at addresses nobody listens on.
fn start_dialer(
    io: Io,
    transport: *Transport,
    scope: metrics.Scope,
    config: Net.Config,
    count: usize,
) !harness.Node {
    var keys: [harness.peers_max]harness.PublicKey = undefined;
    for (keys[0..count], 1..) |*key, seed| key.* = harness.PrivateKey.from_seed(seed).public_key();
    var entries: [harness.peers_max]harness.Entry = undefined;
    harness.peer_entries(keys[0..count], entries[0..count]);
    const tracked: Net.Tracker.Tracked = .init_primary(.init(entries[0..count]));
    return harness.start_network(io, transport, scope, config, 0, tracked, .per_second(100));
}

fn dials_per_tick(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var node = try start_dialer(io, transport, scope, dialer_config(100, .from_secs(60)), 10);
    defer harness.stop_node(io, &node);
    try io.sleep(.fromMilliseconds(300), .awake);
    const total = try attempts(scope);
    try testing.expect(total >= 2 and total <= 4);
}

test "the dialer dials one peer per tick" {
    // commonware `test_dialer_dials_one_peer_per_tick`: about three of ten peers in three
    // ticks, not all at once.
    try run(dials_per_tick, .{});
}

fn queued_peers(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    var node = try start_dialer(io, transport, scope, dialer_config(100, .from_secs(60)), 3);
    defer harness.stop_node(io, &node);
    try io.sleep(.fromMilliseconds(250), .awake);
    try testing.expectEqual(@as(u64, 3), try attempts(scope));
}

test "the dialer drains its queue at dial_frequency" {
    // commonware `test_dialer_keeps_dialing_queued_peers_when_next_query_deadline_is_unknown`
    // on the network: three queued peers are dialed at 0, 100, and 200 ms.
    try run(queued_peers, .{});
}

fn reserved(scope: metrics.Scope, value: i64) !bool {
    const text = try scope.encode(gpa);
    defer gpa.free(text);
    return metrics.has_metric_value(text, "directory_reserved", value);
}

fn handshake_timeout_releases(io: Io, transport: *Transport, scope: metrics.Scope) !void {
    // The peer's address is bound but never accepts, so the handshake hangs.
    const silent = try transport.bind(network_mod.to_address(harness.local_socket(8_000)));
    defer silent.deinit();
    var config = dialer_config(1_000, .from_secs(60));
    config.handshake_timeout = .from_millis(100);
    const entries: [1]harness.Entry = .{.{
        .key = harness.PrivateKey.from_seed(1).public_key(),
        .value = .{ .symmetric = harness.local_socket(8_000) },
    }};
    const tracked: Net.Tracker.Tracked = .init_primary(.init(&entries));
    const quota: rate_limit.Quota = .per_second(100);
    var node = try harness.start_network(io, transport, scope, config, 0, tracked, quota);
    defer harness.stop_node(io, &node);
    try io.sleep(.fromMilliseconds(50), .awake);
    try testing.expectEqual(@as(u64, 1), try attempts(scope));
    try testing.expect(try reserved(scope, 1));
    // The handshake timeout ends the dial well before the next one is due.
    try io.sleep(.fromMilliseconds(150), .awake);
    try testing.expect(try reserved(scope, 0));
    try testing.expectEqual(@as(u64, 1), try attempts(scope));
}

test "a dial whose handshake never completes releases its reservation" {
    // commonware `test_dial_timeout_releases_reservation`, adapted: lookup bounds a dial by
    // the handshake timeout (see p2p.md's Decisions), not a separate dial timeout.
    try run(handshake_timeout_releases, .{});
}

fn run(comptime function: anytype, args: anytype) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = 10 * std.time.ns_per_s };
    const Args = @TypeOf(args);
    try runtime.deterministic.soak(gpa, config, args, struct {
        fn run(context: Args, runner: *runtime.deterministic.Runner) anyerror!void {
            const args_all = .{ runner.io(), runner.network(), runner.metrics() } ++ context;
            try (try runner.start(function, args_all));
        }
    }.run);
}
