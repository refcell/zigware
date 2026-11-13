//! Metric label sets for simplex (commonware `consensus/src/simplex/metrics.rs`), for
//! `runtime.telemetry.metrics` families. Enum label values print commonware's variant names
//! through `label_value`; key labels print the key through its `format` (Rust `Display`).

const std = @import("std");
const assert = std.debug.assert;

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

const testing = std.testing;
const runtime = @import("runtime");

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
