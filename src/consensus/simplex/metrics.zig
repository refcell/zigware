//! Metric label sets for simplex (commonware `consensus/src/simplex/metrics.rs`), for
//! `runtime.telemetry.metrics` families. Enum label values print commonware's variant names
//! through `label_value`; key labels print the key through its `format` (Rust `Display`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const traits = @import("../traits.zig");
const telemetry = runtime.telemetry.metrics;
const Scope = telemetry.Scope;

/// A peer label (`metrics::Peer`).
pub fn Peer(comptime P: type) type {
    return struct { peer: P };
}

/// A leader label (`metrics::Leader`).
pub fn Leader(comptime P: type) type {
    return struct { leader: P };
}

/// Variant names as commonware's derived `EncodeLabelValue` writes them.
fn pascal_label(comptime E: type) fn (E) []const u8 {
    const names = comptime names: {
        const tags = @typeInfo(E).@"enum".field_names;
        var result: [tags.len][]const u8 = undefined;
        for (tags, 0..) |tag, index| result[index] = to_pascal(tag);
        break :names result;
    };
    return struct {
        fn label(value: E) []const u8 {
            const result = names[@backingInt(value)];
            assert(result.len > 0);
            return result;
        }
    }.label;
}

fn to_pascal(comptime name: []const u8) []const u8 {
    comptime {
        var result: []const u8 = "";
        var upper = true;
        for (name) |char| {
            if (char == '_') {
                upper = true;
                continue;
            }
            result = result ++ .{if (upper) std.ascii.toUpper(char) else char};
            upper = false;
        }
        assert(result.len > 0);
        return result;
    }
}

/// A step of a pipelined handoff (`HandoffEventKind`).
pub const HandoffEventKind = enum {
    requested,
    wait_returned,
    candidate_returned,
    relayed_before_certification,
    relayed_after_certification,
    voted_before_certification,
    voted_after_certification,

    pub const label_value = pascal_label(HandoffEventKind);
};

pub const HandoffEvent = struct { event: HandoffEventKind };

/// Why a pending handoff was dropped (`HandoffAbandonedReason`).
pub const HandoffAbandonedReason = enum {
    view_exit,
    ancestry_superseded,
    ancestry_invalidated,
    parent_nullify,
    view_nullify,
    response_closed,
    ineligible_at_recording,

    pub const label_value = pascal_label(HandoffAbandonedReason);
};

pub const HandoffAbandoned = struct { reason: HandoffAbandonedReason };

/// Why a view timed out (`TimeoutReason`).
pub const TimeoutReason = enum {
    retry,
    inactivity,
    leader_nullify,
    leader_timeout,
    certification_timeout,
    stall_timeout,
    missing_proposal,
    ignored_proposal,
    invalid_proposal,
    failed_certification,

    pub const label_value = pascal_label(TimeoutReason);

    pub fn as_str(self: TimeoutReason) []const u8 {
        return self.label_value();
    }
};

/// A timeout of `leader`'s view (`metrics::Timeout`).
pub fn Timeout(comptime P: type) type {
    return struct {
        leader: P,
        reason: TimeoutReason,
    };
}

/// A consensus message kind (`MessageType`).
pub const MessageType = enum {
    notarize,
    notarization,
    nullify,
    nullification,
    finalize,
    finalization,

    pub const label_value = pascal_label(MessageType);
};

/// A sent message (`metrics::Outbound`).
pub const Outbound = struct { message: MessageType };

/// A message received from `peer` (`metrics::Inbound`).
pub fn Inbound(comptime P: type) type {
    return struct {
        peer: P,
        message: MessageType,
    };
}

/// The voter state's metrics (commonware `actors/voter/state.rs`), under `voter_state`.
pub fn StateMetrics(comptime P: type) type {
    return struct {
        const Self = @This();

        current_view: telemetry.Gauge,
        tracked_views: telemetry.Gauge,
        issuance_window_probes: telemetry.Counter,
        timeouts: telemetry.CounterFamily(Timeout(P)),
        nullifications: telemetry.CounterFamily(Leader(P)),

        pub fn register(scope: *const Scope) Allocator.Error!Self {
            var current_view = try scope.gauge("current_view", "current view");
            errdefer current_view.deinit();
            var tracked_views = try scope.gauge("tracked_views", "tracked views");
            errdefer tracked_views.deinit();
            var issuance_window_probes = try scope.counter(
                "issuance_window_probes",
                "rounds inspected for optimistic issuance anchors",
            );
            errdefer issuance_window_probes.deinit();
            const Counter = telemetry.raw.Counter;
            var timeouts = try scope.family(Timeout(P), Counter, "timeouts", "timed out views");
            errdefer timeouts.deinit();
            const nullifications =
                try scope.family(Leader(P), Counter, "nullifications", "nullifications");
            return .{
                .current_view = current_view,
                .tracked_views = tracked_views,
                .issuance_window_probes = issuance_window_probes,
                .timeouts = timeouts,
                .nullifications = nullifications,
            };
        }

        pub fn deinit(self: *Self) void {
            self.current_view.deinit();
            self.tracked_views.deinit();
            self.issuance_window_probes.deinit();
            self.timeouts.deinit();
            self.nullifications.deinit();
            self.* = undefined;
        }
    };
}

/// The voter actor's metrics (commonware `actors/voter/actor.rs`), under `voter`.
pub const VoterMetrics = struct {
    outbound_messages: telemetry.CounterFamily(Outbound),
    handoff_events: telemetry.CounterFamily(HandoffEvent),
    handoff_abandoned: telemetry.CounterFamily(HandoffAbandoned),
    notarization_latency: telemetry.Histogram,
    finalization_latency: telemetry.Histogram,
    notarization_latency_from_view_entry: telemetry.Histogram,
    finalization_latency_from_view_entry: telemetry.Histogram,

    pub fn register(scope: *const Scope) Allocator.Error!VoterMetrics {
        const Counter = telemetry.raw.Counter;
        const buckets = &traits.latency_buckets;
        var outbound = try scope.family(
            Outbound,
            Counter,
            "outbound_messages",
            "number of outbound messages",
        );
        errdefer outbound.deinit();
        var events = try scope.family(
            HandoffEvent,
            Counter,
            "handoff_events",
            "number of handoff lifecycle events, where one request can count several",
        );
        errdefer events.deinit();
        var abandoned = try scope.family(
            HandoffAbandoned,
            Counter,
            "handoff_abandoned",
            "number of handoff requests, candidates, and builds abandoned before the " ++
                "proposer votes",
        );
        errdefer abandoned.deinit();
        var notarization =
            try scope.histogram("notarization_latency", "notarization latency", buckets);
        errdefer notarization.deinit();
        var finalization =
            try scope.histogram("finalization_latency", "finalization latency", buckets);
        errdefer finalization.deinit();
        // A certificate ready before this node entered its view takes no from-entry sample.
        var notarization_from_entry = try scope.histogram(
            "notarization_latency_from_view_entry",
            "leader seconds from first local view entry to local notarization certificate " ++
                "readiness",
            buckets,
        );
        errdefer notarization_from_entry.deinit();
        const finalization_from_entry = try scope.histogram(
            "finalization_latency_from_view_entry",
            "leader seconds from first local view entry to local finalization certificate " ++
                "readiness",
            buckets,
        );
        return .{
            .outbound_messages = outbound,
            .handoff_events = events,
            .handoff_abandoned = abandoned,
            .notarization_latency = notarization,
            .finalization_latency = finalization,
            .notarization_latency_from_view_entry = notarization_from_entry,
            .finalization_latency_from_view_entry = finalization_from_entry,
        };
    }

    pub fn deinit(self: *VoterMetrics) void {
        self.outbound_messages.deinit();
        self.handoff_events.deinit();
        self.handoff_abandoned.deinit();
        self.notarization_latency.deinit();
        self.finalization_latency.deinit();
        self.notarization_latency_from_view_entry.deinit();
        self.finalization_latency_from_view_entry.deinit();
        self.* = undefined;
    }
};

/// Pending-message counts per batch (commonware's `batch_size` buckets).
const batch_size_buckets = [_]f64{ 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 };

/// The batcher's metrics (commonware `actors/batcher/actor.rs`), under `batcher`.
pub fn BatcherMetrics(comptime P: type) type {
    return struct {
        const Self = @This();

        added: telemetry.Counter,
        processed: telemetry.Counter,
        inbound_messages: telemetry.CounterFamily(Inbound(P)),
        latest_vote: telemetry.GaugeFamily(Peer(P)),
        batch_size: telemetry.Histogram,
        construct_latency: telemetry.Timed,
        construct_fallback: telemetry.Counter,

        /// Registers the metrics; every participant's `latest_vote` starts at 0.
        pub fn register(scope: *const Scope, participants: []const P) Allocator.Error!Self {
            var added = try scope.counter("added", "number of messages added to the verifier");
            errdefer added.deinit();
            var processed =
                try scope.counter("processed", "number of messages processed by the verifier");
            errdefer processed.deinit();
            const Counter = telemetry.raw.Counter;
            var inbound = try scope.family(
                Inbound(P),
                Counter,
                "inbound_messages",
                "number of inbound messages",
            );
            errdefer inbound.deinit();
            var latest_vote = try scope.family(
                Peer(P),
                telemetry.raw.Gauge,
                "latest_vote",
                "view of latest vote received per peer",
            );
            errdefer latest_vote.deinit();
            for (participants) |participant| {
                const gauge = try latest_vote.metric().get_or_create(.{ .peer = participant });
                _ = gauge.set(0);
            }
            var batch_size = try scope.histogram(
                "batch_size",
                "number of pending messages processed per batch",
                &batch_size_buckets,
            );
            errdefer batch_size.deinit();
            var construct_latency = try scope.histogram(
                "construct_latency",
                "latency of vote verification and certificate assembly",
                &telemetry.Buckets.cryptography,
            );
            errdefer construct_latency.deinit();
            const construct_fallback = try scope.counter(
                "construct_fallback",
                "number of optimistic assembly attempts returning attestation verification " ++
                    "results",
            );
            return .{
                .added = added,
                .processed = processed,
                .inbound_messages = inbound,
                .latest_vote = latest_vote,
                .batch_size = batch_size,
                .construct_latency = .init(construct_latency),
                .construct_fallback = construct_fallback,
            };
        }

        pub fn deinit(self: *Self) void {
            self.added.deinit();
            self.processed.deinit();
            self.inbound_messages.deinit();
            self.latest_vote.deinit();
            self.batch_size.deinit();
            self.construct_latency.deinit();
            self.construct_fallback.deinit();
            self.* = undefined;
        }
    };
}

/// Increments `family`'s counter for `labels`.
pub fn inc(family: anytype, labels: @TypeOf(family.metric().*).Labels) Allocator.Error!void {
    const counter = try family.metric().get_or_create(labels);
    counter.inc();
}

/// Seconds in `nanoseconds`, for latency histograms.
pub fn seconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
}

const testing = std.testing;

test "label values use commonware's variant names" {
    try testing.expectEqualStrings("LeaderNullify", TimeoutReason.leader_nullify.as_str());
    const failed = TimeoutReason.failed_certification;
    try testing.expectEqualStrings("FailedCertification", failed.as_str());
    try testing.expectEqualStrings("Notarization", MessageType.notarization.label_value());
    const event = HandoffEventKind.relayed_before_certification;
    try testing.expectEqualStrings("RelayedBeforeCertification", event.label_value());
    const ineligible = HandoffAbandonedReason.ineligible_at_recording;
    try testing.expectEqualStrings("IneligibleAtRecording", ineligible.label_value());
}

test "label sets encode in a family" {
    const metrics = runtime.telemetry.metrics;
    const Key = struct {
        byte: u8,
        pub fn format(key: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.print("{x:0>2}", .{key.byte});
        }
    };
    var registry = metrics.Registry.init(testing.allocator);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry).child("voter");
    const Counter = metrics.raw.Counter;
    var family = try scope.family(Inbound(Key), Counter, "inbound", "Inbound messages");
    defer family.deinit();
    const labels: Inbound(Key) = .{ .peer = .{ .byte = 0xab }, .message = .nullify };
    const counter = try family.metric().get_or_create(labels);
    counter.inc();
    const text = try registry.encode(testing.allocator);
    defer testing.allocator.free(text);
    const line = "voter_inbound_total{peer=\"ab\",message=\"Nullify\"} 1";
    try testing.expect(std.mem.indexOf(u8, text, line) != null);
}
