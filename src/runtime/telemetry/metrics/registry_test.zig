//! Registry tests: commonware's `telemetry/metrics/mod.rs` and `lib.rs` metrics tests, golden
//! expositions from prometheus-client 0.25, and a model-based seeded fuzz.

const std = @import("std");
const build_options = @import("build_options");
const utils = @import("utils");
const metrics = @import("mod.zig");
const testing = std.testing;
const gpa = testing.allocator;
const raw = metrics.raw;
const Registry = metrics.Registry;
const Scope = metrics.Scope;

fn encoded(registry: *Registry) ![]u8 {
    return registry.encode(gpa);
}

fn expect_contains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing `{s}` in:\n{s}\n", .{ needle, text });
        return error.TestExpectedContains;
    }
}

fn expect_absent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) {
        std.debug.print("unexpected `{s}` in:\n{s}\n", .{ needle, text });
        return error.TestUnexpectedContains;
    }
}

fn register_counter(
    registry: *Registry,
    name: []const u8,
    help: []const u8,
    value: u64,
) !metrics.Counter {
    var counter: raw.Counter = .{};
    counter.inc_by(value);
    return registry.register(name, help, &.{}, counter);
}

fn epoch(value: []const u8) metrics.Attribute {
    return .{ .key = "epoch", .value = value };
}

test "has_metric_value unlabeled and labeled" {
    const unlabeled = "# HELP storage_items_tracked items\nstorage_items_tracked 2\n";
    try testing.expect(metrics.has_metric_value(unlabeled, "items_tracked", 2));
    try testing.expect(metrics.has_metric_value(unlabeled, "storage_items_tracked", 2));
    try testing.expect(!metrics.has_metric_value(unlabeled, "items_tracked_extra", 2));
    try testing.expect(!metrics.has_metric_value(unlabeled, "items_tracked", 3));
    const labeled = "storage_init_items_tracked{index=\"2\"} 2";
    try testing.expect(metrics.has_metric_value(labeled, "items_tracked", 2));
    try testing.expect(metrics.has_metric_value(labeled, "storage_init_items_tracked", 2));
}

test "metric_samples" {
    const text =
        \\
        \\    # HELP storage_items_tracked items
        \\    storage_items_tracked 2
        \\    storage_init_items_tracked{index="2",path="a}b",quote="a\"b"} 3
        \\    storage_other_items_tracked{index="4"} 5 123
        \\    otheritems_tracked 6
        \\    storage_items_tracked_extra 6
        \\    storage_items_tracked{broken="label} 7
        \\    storage_items_tracked{index="8"}
        \\
    ;
    const expected = [_]metrics.Sample{
        .{ .labels = "", .value = "2" },
        .{ .labels = "index=\"2\",path=\"a}b\",quote=\"a\\\"b\"", .value = "3" },
        .{ .labels = "index=\"4\"", .value = "5" },
    };
    var samples = metrics.metric_samples(text, "items_tracked");
    for (expected) |want| {
        const got = samples.next().?;
        try testing.expectEqualStrings(want.labels, got.labels);
        try testing.expectEqualStrings(want.value, got.value);
    }
    try testing.expect(samples.next() == null);
    var init = metrics.metric_samples(text, "storage_init_items_tracked");
    try testing.expectEqualStrings("3", init.next().?.value);
    try testing.expect(init.next() == null);
}

test "no duplicate metrics across labels" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    const root: Scope = .init(&registry);
    var a = try root.child("a").register("test", "help", raw.Counter{});
    defer a.deinit();
    var b = try root.child("b").register("test", "help", raw.Counter{});
    defer b.deinit();
    try testing.expectEqual(@as(usize, 2), registry.count());
}

test "duplicate metrics reuse the existing handle" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    const root: Scope = .init(&registry);
    var metric_a = try root.child("a").register("test", "help", raw.Counter{});
    defer metric_a.deinit();
    var metric_b = try root.child("a").register("test", "help", raw.Counter{});
    defer metric_b.deinit();
    try testing.expectEqual(metric_a.metric(), metric_b.metric());
    metric_a.metric().inc();
    metric_b.metric().inc_by(2);
    const text = try encoded(&registry);
    defer gpa.free(text);
    try expect_contains(text, "a_test_total 3");
}

test "handles and clones keep a metric registered until the last is released" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var first = try register_counter(&registry, "votes", "vote count", 0);
    var first_clone = first.clone();
    var second = try register_counter(&registry, "votes", "vote count", 0);
    var second_clone = second.clone();
    first.deinit();
    second.deinit();
    try testing.expectEqual(@as(usize, 1), registry.count());
    second_clone.deinit();
    try testing.expectEqual(@as(usize, 1), registry.count());
    first_clone.deinit();
    try testing.expectEqual(@as(usize, 0), registry.count());
    try testing.expectEqual(@as(usize, 0), registry.families.items.len);
}

test "duplicate register during the last release keeps the metric" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var original = try register_counter(&registry, "votes", "vote count", 0);
    var duplicate = try register_counter(&registry, "votes", "vote count", 0);
    try testing.expectEqual(original.metric(), duplicate.metric());
    original.deinit();
    duplicate.metric().inc_by(7);
    const text = try encoded(&registry);
    defer gpa.free(text);
    try expect_contains(text, "votes_total 7");
    duplicate.deinit();
    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "detached handle publishes nowhere and frees on last release" {
    var registered = try metrics.Gauge.detached(gpa, .{});
    var clone = registered.clone();
    registered.deinit();
    clone.metric().inc();
    try testing.expectEqual(@as(i64, 1), clone.metric().get());
    clone.deinit();
}

test "encode is deterministic and sorted" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var beta = try register_counter(&registry, "beta", "beta counter", 2);
    defer beta.deinit();
    var alpha = try register_counter(&registry, "alpha", "alpha counter", 1);
    defer alpha.deinit();
    const first = try encoded(&registry);
    defer gpa.free(first);
    const second = try encoded(&registry);
    defer gpa.free(second);
    try testing.expectEqualStrings(first, second);
    const alpha_at = std.mem.indexOf(u8, first, "# TYPE alpha").?;
    const beta_at = std.mem.indexOf(u8, first, "# TYPE beta").?;
    try testing.expect(alpha_at < beta_at);
}

test "encode emits a single EOF" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var a = try register_counter(&registry, "a", "help", 1);
    defer a.deinit();
    var b = try register_counter(&registry, "b", "help", 2);
    defer b.deinit();
    const text = try encoded(&registry);
    defer gpa.free(text);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# EOF"));
    try testing.expect(std.mem.endsWith(u8, text, "# EOF\n"));
}

test "encode shares the family header across attributes" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var c1: raw.Counter = .{};
    c1.inc();
    var one = try registry.register("votes", "vote count", &.{epoch("1")}, c1);
    defer one.deinit();
    var c2: raw.Counter = .{};
    c2.inc_by(2);
    var two = try registry.register("votes", "vote count", &.{epoch("2")}, c2);
    defer two.deinit();
    const text = try encoded(&registry);
    defer gpa.free(text);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# HELP votes"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# TYPE votes"));
    try expect_contains(text, "votes_total{epoch=\"1\"} 1");
    try expect_contains(text, "votes_total{epoch=\"2\"} 2");
    try testing.expect(std.mem.startsWith(u8, text, "# HELP votes vote count.\n"));
}

test "encode suppresses an empty family" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var votes = try registry.register(
        "votes",
        "vote count",
        &.{},
        raw.Family(struct {}, raw.Counter).init(gpa),
    );
    defer votes.deinit();
    var ticks = try register_counter(&registry, "ticks", "tick count", 1);
    defer ticks.deinit();
    const text = try encoded(&registry);
    defer gpa.free(text);
    try expect_absent(text, "votes");
    try expect_contains(text, "ticks_total 1");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# EOF"));
}

test "encode matches upstream prometheus-client registry" {
    // commonware's test_encode_matches_upstream_registry; the expected text is upstream's.
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var histogram: raw.Histogram = .init(&.{ 0.1, 1.0 });
    histogram.observe(0.5);
    var gauge: raw.Gauge = .{};
    _ = gauge.set(-3);
    var counter: raw.Counter = .{};
    counter.inc_by(7);
    var latency = try registry.register("latency", "request latency seconds", &.{}, histogram);
    defer latency.deinit();
    var level = try registry.register("level", "current level", &.{}, gauge);
    defer level.deinit();
    var votes = try registry.register("votes", "number of votes", &.{}, counter);
    defer votes.deinit();
    const text = try encoded(&registry);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        \\# HELP latency request latency seconds.
        \\# TYPE latency histogram
        \\latency_sum 0.5
        \\latency_count 1
        \\latency_bucket{le="0.1"} 0
        \\latency_bucket{le="1.0"} 1
        \\latency_bucket{le="+Inf"} 1
        \\# HELP level current level.
        \\# TYPE level gauge
        \\level -3
        \\# HELP votes number of votes.
        \\# TYPE votes counter
        \\votes_total 7
        \\# EOF
        \\
    , text);
}

const Kind = enum {
    root,
    shared_blocking,
    pub fn label_value(kind: Kind) []const u8 {
        return switch (kind) {
            .root => "Root",
            .shared_blocking => "SharedBlocking",
        };
    }
};
const Request = struct { method: []const u8, status: u16, ok: bool, kind: Kind };
const Peer = struct { peer: []const u8 };

test "encode matches upstream with const labels, families, and extremes" {
    // Generated with prometheus-client 0.25 (`Registry::with_labels`, `Family`, derives).
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    const attributes: []const metrics.Attribute = &.{
        .{ .key = "epoch", .value = "5" },
        .{ .key = "region", .value = "us" },
    };
    const Requests = raw.Family(Request, raw.Counter);
    var requests = try registry.register(
        "api_requests",
        "HTTP requests",
        attributes,
        Requests.init(gpa),
    );
    defer requests.deinit();
    (try requests.metric().get_or_create(.{
        .method = "GET",
        .status = 200,
        .ok = true,
        .kind = .shared_blocking,
    })).inc_by(3);
    var latency_raw: raw.Histogram = .init(&metrics.Buckets.local);
    for ([_]f64{ 2e-5, 0.004, 0.5, 2.0 }) |value| latency_raw.observe(value);
    var latency = try registry.register("consensus_latency", "Latency", attributes, latency_raw);
    defer latency.deinit();
    var max_raw: raw.Counter = .{};
    max_raw.inc_by(std.math.maxInt(u64));
    var max = try registry.register("counter_max", "max", attributes, max_raw);
    defer max.deinit();
    var min_raw: raw.Gauge = .{};
    _ = min_raw.set(std.math.minInt(i64));
    var min = try registry.register("gauge_min", "min", attributes, min_raw);
    defer min.deinit();
    const PeerHistograms = raw.Family(Peer, raw.Histogram);
    const prototype: raw.Histogram = .init(&metrics.Buckets.network);
    const peer_family = PeerHistograms.init_with(gpa, prototype);
    var peers = try registry.register("peer_latency", "per peer", attributes, peer_family);
    defer peers.deinit();
    (try peers.metric().get_or_create(.{ .peer = "alice" })).observe(0.25);
    const zeta_family = raw.Family(Request, raw.Gauge).init(gpa);
    var zeta = try registry.register("zeta", "odd label value", attributes, zeta_family);
    defer zeta.deinit();
    _ = (try zeta.metric().get_or_create(.{
        .method = "a\"b}",
        .status = 0,
        .ok = false,
        .kind = .root,
    })).set(1);
    const text = try encoded(&registry);
    defer gpa.free(text);
    try testing.expectEqualStrings(@embedFile("testdata/golden_b.txt"), text);
}

test "encode matches upstream for empty label sets and NaN" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    const Empty = raw.Family(struct {}, raw.Counter);
    var absent = try registry.register("absent", "never sampled", &.{}, Empty.init(gpa));
    defer absent.deinit();
    var blank = try registry.register("blank", "empty label set", &.{}, Empty.init(gpa));
    defer blank.deinit();
    (try blank.metric().get_or_create(.{})).inc();
    var nan_raw: raw.Histogram = .init(&.{1.0});
    nan_raw.observe(std.math.nan(f64));
    var nan = try registry.register("nan", "NaN sample", &.{}, nan_raw);
    defer nan.deinit();
    const text = try encoded(&registry);
    defer gpa.free(text);
    try testing.expectEqualStrings(
        \\# HELP blank empty label set.
        \\# TYPE blank counter
        \\blank_total{} 1
        \\# HELP nan NaN sample.
        \\# TYPE nan histogram
        \\nan_sum NaN
        \\nan_count 1
        \\nan_bucket{le="1.0"} 0
        \\nan_bucket{le="+Inf"} 1
        \\# EOF
        \\
    , text);
}

test "shuffled duplicate drops leave no registry entries" {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var handles: std.ArrayList(metrics.Counter) = .empty;
    defer handles.deinit(gpa);
    for (0..8) |_| {
        try handles.append(gpa, try register_counter(&registry, "votes", "vote count", 0));
    }
    for ([_]usize{ 3, 0, 6, 1 }) |index| {
        var removed = handles.swapRemove(index);
        removed.deinit();
        try handles.append(gpa, try register_counter(&registry, "votes", "vote count", 0));
    }
    for (handles.items) |*handle| handle.deinit();
    try testing.expectEqual(@as(usize, 0), registry.count());
    try testing.expectEqual(@as(usize, 0), registry.families.items.len);
}

// commonware runtime/src/lib.rs metrics tests, on `Scope` (the context's metrics half).

const Fixture = struct {
    registry: Registry,

    fn init() Fixture {
        return .{ .registry = .init(gpa) };
    }

    fn root(fixture: *Fixture) Scope {
        return .init(&fixture.registry);
    }

    fn encode(fixture: *Fixture) ![]u8 {
        return fixture.registry.encode(gpa);
    }
};

test "metrics: nested context prefixes the name" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    try testing.expectEqualStrings("", context.prefix());
    var top = try context.register("test", "test", raw.Counter{});
    defer top.deinit();
    top.metric().inc();
    const nested = context.child("nested");
    var inner = try nested.register("test", "test", raw.Counter{});
    defer inner.deinit();
    inner.metric().inc();
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "\ntest_total 1\n");
    try expect_contains(text, "nested_test_total 1");
}

test "metrics: with_attribute labels and shares one descriptor" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    var epoch5 = try context.child("consensus").with_attribute("epoch", "e5")
        .register("votes", "vote count", raw.Counter{});
    defer epoch5.deinit();
    epoch5.metric().inc();
    var epoch6 = try context.child("consensus").with_attribute("epoch", "e6")
        .register("votes", "vote count", raw.Counter{});
    defer epoch6.deinit();
    epoch6.metric().inc_by(2);
    const multi = context.child("engine").with_attribute("region", "us")
        .with_attribute("instance", "i1");
    var requests = try multi.register("requests", "request count", raw.Counter{});
    defer requests.deinit();
    requests.metric().inc();
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "consensus_votes_total{epoch=\"e5\"} 1");
    try expect_contains(text, "consensus_votes_total{epoch=\"e6\"} 2");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# HELP consensus_votes"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# TYPE consensus_votes"));
    try expect_contains(text, "engine_requests_total{instance=\"i1\",region=\"us\"} 1");
}

test "metrics: attributes survive nested labels and stay sorted" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    var votes = try context.child("orchestrator").with_attribute("epoch", "e5").child("engine")
        .register("votes", "vote count", raw.Counter{});
    defer votes.deinit();
    votes.metric().inc();
    var requests = try context.child("outer").with_attribute("region", "us").child("middle")
        .with_attribute("az", "east").child("inner").register("requests", "help", raw.Counter{});
    defer requests.deinit();
    requests.metric().inc_by(2);
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "orchestrator_engine_votes_total{epoch=\"e5\"} 1");
    try expect_contains(text, "outer_middle_inner_requests_total{az=\"east\",region=\"us\"} 2");
}

test "metrics: attributes are isolated between contexts" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    const ctx_a = context.child("component_a").with_attribute("epoch", 1);
    const ctx_b = context.child("component_b").with_attribute("epoch", 2);
    var a_requests = try ctx_a.register("requests", "help", raw.Counter{});
    defer a_requests.deinit();
    var b_requests = try ctx_b.register("requests", "help", raw.Counter{});
    defer b_requests.deinit();
    var a_errors = try ctx_a.register("errors", "help", raw.Counter{});
    defer a_errors.deinit();
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "component_a_requests_total{epoch=\"1\"} 0");
    try expect_contains(text, "component_a_errors_total{epoch=\"1\"} 0");
    try expect_absent(text, "component_a_requests_total{epoch=\"2\"}");
    try expect_contains(text, "component_b_requests_total{epoch=\"2\"} 0");
    try expect_absent(text, "component_b_requests_total{epoch=\"1\"}");
}

test "metrics: attribute order does not matter" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    const service = context.child("service");
    const ab = service.with_attribute("region", "us").with_attribute("env", "prod");
    const ba = service.with_attribute("env", "prod").with_attribute("region", "us");
    var requests = try ab.register("requests", "help", raw.Counter{});
    defer requests.deinit();
    requests.metric().inc();
    var errors = try ba.register("errors", "help", raw.Counter{});
    defer errors.deinit();
    errors.metric().inc_by(2);
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "service_requests_total{env=\"prod\",region=\"us\"} 1");
    try expect_contains(text, "service_errors_total{env=\"prod\",region=\"us\"} 2");
    try expect_absent(text, "region=\"us\",env=\"prod\"");
}

test "metrics: duplicate attribute overwrites" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root().child("test").with_attribute("epoch", "old")
        .with_attribute("epoch", "new");
    var counter = try context.register("votes", "help", raw.Counter{});
    defer counter.deinit();
    counter.metric().inc();
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "test_votes_total{epoch=\"new\"} 1");
    try expect_absent(text, "old");
}

test "metrics: nested labels with attributes do not cross-contaminate" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    const scopes = [_]struct { scope: Scope, name: []const u8 }{
        .{ .scope = context.child("service_a"), .name = "requests" },
        .{ .scope = context.child("service_a").with_attribute("version", 2), .name = "requests" },
        .{ .scope = context.child("service_b").child("worker"), .name = "tasks" },
        .{
            .scope = context.child("service_b").child("worker").with_attribute("shard", 99),
            .name = "tasks",
        },
        .{ .scope = context.child("service_b").child("manager"), .name = "decisions" },
        .{ .scope = context.child("service_c"), .name = "requests" },
    };
    var handles: [scopes.len]metrics.Counter = undefined;
    for (scopes, &handles) |entry, *handle| {
        handle.* = try entry.scope.register(entry.name, "help", raw.Counter{});
    }
    defer for (&handles) |*handle| handle.deinit();
    const text = try fixture.encode();
    defer gpa.free(text);
    for ([_][]const u8{
        "service_a_requests_total 0",
        "service_a_requests_total{version=\"2\"} 0",
        "service_b_worker_tasks_total 0",
        "service_b_worker_tasks_total{shard=\"99\"} 0",
        "service_b_manager_decisions_total 0",
        "service_c_requests_total 0",
    }) |line| try expect_contains(text, line);
    for ([_][]const u8{
        "service_b_manager_decisions_total{",
        "service_c_requests_total{",
        "service_a_requests_total{shard=",
    }) |line| try expect_absent(text, line);
}

test "metrics: family with attributes merges labels" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    const RequestLabels = struct { method: []const u8, status: u16 };
    const ctx = context.child("api").with_attribute("region", "us_east")
        .with_attribute("env", "prod");
    var requests = try ctx.family(RequestLabels, raw.Counter, "requests", "HTTP requests");
    defer requests.deinit();
    (try requests.metric().get_or_create(.{ .method = "GET", .status = 200 })).inc();
    (try requests.metric().get_or_create(.{ .method = "POST", .status = 201 })).inc();
    (try requests.metric().get_or_create(.{ .method = "GET", .status = 404 })).inc();
    var plain = try context.child("api_plain")
        .family(RequestLabels, raw.Counter, "requests", "HTTP requests");
    defer plain.deinit();
    (try plain.metric().get_or_create(.{ .method = "DELETE", .status = 204 })).inc();
    const text = try fixture.encode();
    defer gpa.free(text);
    const prefix = "api_requests_total{env=\"prod\",region=\"us_east\",";
    try expect_contains(text, prefix ++ "method=\"GET\",status=\"200\"} 1");
    try expect_contains(text, prefix ++ "method=\"POST\",status=\"201\"} 1");
    try expect_contains(text, prefix ++ "method=\"GET\",status=\"404\"} 1");
    try expect_contains(text, "api_plain_requests_total{method=\"DELETE\",status=\"204\"} 1");
    try expect_absent(text, "api_plain_requests_total{env=");
}

test "metrics: register, drop, and re-register" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const context = fixture.root();
    var permanent = try context.child("permanent").counter("counter", "permanent counter");
    defer permanent.deinit();
    permanent.metric().inc();
    var votes = try context.child("engine").counter("votes", "vote count");
    votes.metric().inc();
    const before = try fixture.encode();
    defer gpa.free(before);
    try expect_contains(before, "permanent_counter_total 1");
    try expect_contains(before, "engine_votes_total 1");
    votes.deinit();
    const after = try fixture.encode();
    defer gpa.free(after);
    try expect_contains(after, "permanent_counter_total 1");
    try expect_absent(after, "engine_votes");
    var replacement = try context.child("engine").with_attribute("epoch", 1)
        .counter("votes", "vote count");
    replacement.deinit();
}

test "metrics: register with attributes, then drop each" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    const engine = fixture.root().child("engine");
    var epoch1 = try engine.with_attribute("epoch", 1).counter("votes", "vote count");
    epoch1.metric().inc();
    var epoch2 = try engine.with_attribute("epoch", 2).counter("votes", "vote count");
    epoch2.metric().inc_by(2);
    const both = try fixture.encode();
    defer gpa.free(both);
    try expect_contains(both, "engine_votes_total{epoch=\"1\"} 1");
    try expect_contains(both, "engine_votes_total{epoch=\"2\"} 2");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, both, "# HELP engine_votes"));
    epoch1.deinit();
    const one = try fixture.encode();
    defer gpa.free(one);
    try expect_absent(one, "epoch=\"1\"");
    try expect_contains(one, "engine_votes_total{epoch=\"2\"} 2");
    epoch2.deinit();
    const none = try fixture.encode();
    defer gpa.free(none);
    try expect_absent(none, "engine_votes");
}

test "metrics: a clone keeps the metric alive" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    var registered = try fixture.root().child("engine").counter("votes", "vote count");
    registered.metric().inc();
    var clone = registered.clone();
    registered.deinit();
    const alive = try fixture.encode();
    defer gpa.free(alive);
    try expect_contains(alive, "engine_votes_total 1");
    clone.deinit();
    const gone = try fixture.encode();
    defer gpa.free(gone);
    try expect_absent(gone, "engine_votes");
}

test "metrics: family per peer with attributes" {
    var fixture: Fixture = .init();
    defer fixture.registry.deinit();
    var family = try fixture.root().child("batcher").with_attribute("epoch", 1)
        .family(Peer, raw.Counter, "votes", "votes per peer");
    (try family.metric().get_or_create(.{ .peer = "alice" })).inc();
    (try family.metric().get_or_create(.{ .peer = "bob" })).inc();
    const text = try fixture.encode();
    defer gpa.free(text);
    try expect_contains(text, "batcher_votes_total{epoch=\"1\",peer=\"alice\"} 1");
    try expect_contains(text, "batcher_votes_total{epoch=\"1\",peer=\"bob\"} 1");
    family.deinit();
    const gone = try fixture.encode();
    defer gpa.free(gone);
    try expect_absent(gone, "batcher_votes");
}

test "metrics: label validation" {
    // commonware's test_metrics_label_* panic tests, on the predicate the panics check.
    try testing.expect(!metrics.is_valid_label(""));
    try testing.expect(!metrics.is_valid_label("1bad"));
    try testing.expect(!metrics.is_valid_label("bad-label"));
    try testing.expect(!metrics.is_valid_label("_bad"));
    try testing.expect(metrics.is_valid_label("good_label_1"));
    try testing.expect(std.mem.startsWith(u8, "runtime_x", metrics.metrics_prefix));
}

// Model-based fuzz: random registrations, clones, releases, and increments across a few
// names and attributes, checked against a model after every encode.

const fuzz_names = [_][]const u8{ "alpha", "beta", "gamma" };
const fuzz_samples = [_][]const u8{ "alpha_total", "beta_total", "gamma_total" };
const fuzz_epochs = [_][]const u8{ "", "1", "2" };
const key_count = fuzz_names.len * fuzz_epochs.len;

const Model = struct {
    claims: [key_count]u32 = @splat(0),
    values: [key_count]u64 = @splat(0),
};

const Live = struct { handle: metrics.Counter, key: usize };

fn fuzz_register(registry: *Registry, key: usize) !metrics.Counter {
    const name = fuzz_names[key / fuzz_epochs.len];
    const epoch_value = fuzz_epochs[key % fuzz_epochs.len];
    const attributes: []const metrics.Attribute = if (epoch_value.len == 0)
        &.{}
    else
        &.{.{ .key = "epoch", .value = epoch_value }};
    return registry.register(name, "help", attributes, raw.Counter{});
}

fn fuzz_check(registry: *Registry, model: *const Model) !void {
    const text = try registry.encode(gpa);
    defer gpa.free(text);
    try testing.expect(std.mem.endsWith(u8, text, "# EOF\n"));
    for (0..key_count) |key| {
        const name = fuzz_samples[key / fuzz_epochs.len];
        const epoch_value = fuzz_epochs[key % fuzz_epochs.len];
        var buffer: [64]u8 = undefined;
        const labels = if (epoch_value.len == 0)
            ""
        else
            try std.fmt.bufPrint(&buffer, "epoch=\"{s}\"", .{epoch_value});
        var found: u32 = 0;
        var samples = metrics.metric_samples(text, name);
        while (samples.next()) |sample| {
            if (!std.mem.eql(u8, sample.labels, labels)) continue;
            found += 1;
            var value_buffer: [24]u8 = undefined;
            const value = try std.fmt.bufPrint(&value_buffer, "{d}", .{model.values[key]});
            try testing.expectEqualStrings(value, sample.value);
        }
        try testing.expectEqual(@as(u32, @intFromBool(model.claims[key] > 0)), found);
    }
}

fn fuzz_body(random: *utils.rng.FuzzRng) !void {
    var registry: Registry = .init(gpa);
    defer registry.deinit();
    var live: std.ArrayList(Live) = .empty;
    defer live.deinit(gpa);
    defer for (live.items) |*entry| entry.handle.deinit();
    var model: Model = .{};
    for (0..64) |_| {
        const op = utils.rng.range_less_than(random, u32, 0, 5);
        if (op == 0 or live.items.len == 0) {
            const key = utils.rng.range_less_than(random, usize, 0, key_count);
            try live.append(gpa, .{ .handle = try fuzz_register(&registry, key), .key = key });
            if (model.claims[key] == 0) model.values[key] = 0;
            model.claims[key] += 1;
            continue;
        }
        const index = utils.rng.range_less_than(random, usize, 0, live.items.len);
        const entry = live.items[index];
        switch (op) {
            1 => {
                try live.append(gpa, .{ .handle = entry.handle.clone(), .key = entry.key });
                model.claims[entry.key] += 1;
            },
            2 => {
                var removed = live.swapRemove(index);
                removed.handle.deinit();
                model.claims[entry.key] -= 1;
            },
            3 => {
                const amount = utils.rng.range_less_than(random, u64, 0, 1000);
                entry.handle.metric().inc_by(amount);
                model.values[entry.key] += amount;
            },
            else => try fuzz_check(&registry, &model),
        }
    }
    try fuzz_check(&registry, &model);
}

test "registry model (seeded fuzz)" {
    var seeds = utils.rng.TestRng.init(0x7e1e_0002 ^ build_options.fuzz_seed);
    const total: u64 = 200 * @as(u64, build_options.fuzz_soak);
    var input: [256]u8 = undefined;
    for (0..total) |_| {
        seeds.fill_bytes(&input);
        var random = utils.rng.FuzzRng.init(&input);
        try fuzz_body(&random);
    }
}

test "registry model fuzz" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buffer: [256]u8 = undefined;
            const len = smith.slice(&buffer);
            var random = utils.rng.FuzzRng.init(buffer[0..len]);
            try fuzz_body(&random);
        }
    }.one, .{});
}

test "metric_samples fuzz" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buffer: [256]u8 = undefined;
            const len = smith.slice(&buffer);
            var samples = metrics.metric_samples(buffer[0..len], "x");
            var seen: usize = 0;
            while (samples.next()) |sample| : (seen += 1) {
                try testing.expect(sample.value.len > 0);
                try testing.expect(seen < len);
            }
        }
    }.one, .{});
}
