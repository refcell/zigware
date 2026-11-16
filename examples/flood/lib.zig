//! Spam peers with random messages (commonware `examples/flood`): the configuration, the
//! deployer's hosts file, and the two long-lived tasks of `bin/flood.rs`.
//!
//! The sender paces itself to the channel quota: it asks the rate-limited sender which peers
//! are within their limit, sleeps until the earliest one frees up when none is, and otherwise
//! sends a message whose first 8 bytes are the send time (nanoseconds since the Unix epoch,
//! little-endian) and whose rest is filled from `SmallRng::seed_from_u64(0)`. The receiver
//! observes each message's age in the `latency` histogram.
//!
//! Both tasks are generic over p2p's sender and receiver interfaces, so they run on the
//! simulated network in tests and on the authenticated network in the binary.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
pub const yaml = @import("yaml.zig");

const p2p = zigware.p2p;
const metrics = zigware.runtime.telemetry.metrics;

/// Histogram buckets for latency measurement, in seconds: 1ms to 1s for cross-machine latency.
pub const latency_buckets = [_]f64{
    0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.100, 0.200, 0.500, 1.0,
};

pub const namespace = "_COMMONWARE_EXAMPLES_FLOOD";

/// Every message carries its send time in its first 8 bytes.
pub const message_size_min: u32 = 8;

/// Configuration for flood (commonware `commonware_flood::Config`), one YAML file per peer.
pub const Config = struct {
    private_key: []const u8,
    port: u16,
    allowed_peers: []const []const u8,
    bootstrappers: []const []const u8,
    worker_threads: u64,
    message_size: u32,
    /// Messages per second per peer; non-zero.
    message_rate: u32,
    /// Capacity of the network's actor mailboxes; non-zero.
    mailbox_size: u64,
    instrument: bool,

    /// Parses a config file (serde_yaml's output for the Rust struct). Strings borrow `text`;
    /// the lists are allocated in `arena`.
    pub fn parse(arena: Allocator, text: []const u8) yaml.Error!Config {
        var document = try yaml.Document.parse(arena, text);
        const root = try document.root.as_map();
        const config: Config = .{
            .private_key = try (try root.get("private_key")).string(),
            .port = try (try root.get("port")).integer(u16),
            .allowed_peers = try (try root.get("allowed_peers")).strings(arena),
            .bootstrappers = try (try root.get("bootstrappers")).strings(arena),
            .worker_threads = try (try root.get("worker_threads")).integer(u64),
            .message_size = try (try root.get("message_size")).integer(u32),
            .message_rate = try (try root.get("message_rate")).integer(u32),
            .mailbox_size = try (try root.get("mailbox_size")).integer(u64),
            .instrument = try (try root.get("instrument")).boolean(),
        };
        if (config.message_rate == 0 or config.mailbox_size == 0) return error.InvalidValue;
        return config;
    }

    /// Writes the config as serde_yaml does, field by field in declaration order.
    pub fn write(config: *const Config, writer: *Io.Writer) Io.Writer.Error!void {
        try yaml.write_string_field(writer, "private_key", config.private_key);
        try writer.print("port: {d}\n", .{config.port});
        try yaml.write_string_list(writer, "allowed_peers", config.allowed_peers);
        try yaml.write_string_list(writer, "bootstrappers", config.bootstrappers);
        try writer.print("worker_threads: {d}\n", .{config.worker_threads});
        try writer.print("message_size: {d}\n", .{config.message_size});
        try writer.print("message_rate: {d}\n", .{config.message_rate});
        try writer.print("mailbox_size: {d}\n", .{config.mailbox_size});
        try writer.print("instrument: {}\n", .{config.instrument});
    }
};

/// A deployed host (commonware `deployer::aws::Host`).
pub const Host = struct { name: []const u8, region: []const u8, ip: Io.net.IpAddress };

/// The deployer's `hosts.yaml` (commonware `deployer::aws::Hosts`). The deployer package is
/// not ported yet, so flood reads the file itself.
pub const Hosts = struct {
    monitoring_public: Io.net.IpAddress,
    monitoring_private: Io.net.IpAddress,
    hosts: []const Host,

    pub fn parse(arena: Allocator, text: []const u8) yaml.Error!Hosts {
        var document = try yaml.Document.parse(arena, text);
        const root = try document.root.as_map();
        const monitoring = try (try root.get("monitoring")).as_map();
        const items = try (try root.get("hosts")).as_list();
        const hosts = try arena.alloc(Host, items.len);
        for (items, hosts) |item, *host| {
            const fields = try item.as_map();
            host.* = .{
                .name = try (try fields.get("name")).string(),
                .region = try (try fields.get("region")).string(),
                .ip = try (try fields.get("ip")).ip(),
            };
        }
        return .{
            .monitoring_public = try (try monitoring.get("public")).ip(),
            .monitoring_private = try (try monitoring.get("private")).ip(),
            .hosts = hosts,
        };
    }
};

/// Rust `rand` 0.10's `SmallRng` on 64-bit targets: xoshiro256++ seeded with SplitMix64.
pub const SmallRng = struct {
    state: [4]u64,

    pub fn seed_from_u64(seed: u64) SmallRng {
        var state: [4]u64 = undefined;
        var counter = seed;
        for (&state) |*word| {
            counter +%= zigware.utils.GOLDEN_RATIO;
            var z = counter;
            z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
            z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
            word.* = z ^ (z >> 31);
        }
        assert(state[0] | state[1] | state[2] | state[3] != 0);
        return .{ .state = state };
    }

    pub fn next_u64(rng: *SmallRng) u64 {
        const s = &rng.state;
        const result = std.math.rotl(u64, s[0] +% s[3], 23) +% s[0];
        const t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = std.math.rotl(u64, s[3], 45);
        return result;
    }

    pub fn next_u32(rng: *SmallRng) u32 {
        return @truncate(rng.next_u64() >> 32);
    }

    /// Whole little-endian words, then the low bytes of one more word for a remainder.
    pub fn fill_bytes(rng: *SmallRng, dest: []u8) void {
        var index: usize = 0;
        while (index + 8 <= dest.len) : (index += 8) {
            std.mem.writeInt(u64, dest[index..][0..8], rng.next_u64(), .little);
        }
        if (index == dest.len) return;
        var word: [8]u8 = undefined;
        std.mem.writeInt(u64, &word, rng.next_u64(), .little);
        @memcpy(dest[index..], word[0 .. dest.len - index]);
    }
};

/// tracing's level names.
pub const Level = enum { trace, debug, info, warn, @"error" };

/// Writes one event as tracing-subscriber 0.3's JSON formatter does (commonware's flood logs
/// with `json: true`): `timestamp`, `level`, `fields` (the message, then `fields` in order),
/// then `target`. Integers and booleans are JSON values; strings are JSON strings, so pass a
/// `?debug` field already formatted.
pub fn write_json_event(
    writer: *Io.Writer,
    timestamp_ns: u64,
    level: Level,
    target: []const u8,
    message: []const u8,
    fields: anytype,
) Io.Writer.Error!void {
    try writer.writeAll("{\"timestamp\":\"");
    try write_timestamp(writer, timestamp_ns);
    const level_name = switch (level) {
        .trace => "TRACE",
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .@"error" => "ERROR",
    };
    try writer.print("\",\"level\":\"{s}\",\"fields\":{{\"message\":", .{level_name});
    try write_json_string(writer, message);
    inline for (@typeInfo(@TypeOf(fields)).@"struct".field_names) |name| {
        try writer.print(",\"{s}\":", .{name});
        const value = @field(fields, name);
        switch (@typeInfo(@TypeOf(value))) {
            .int, .comptime_int => try writer.print("{d}", .{value}),
            .bool => try writer.writeAll(if (value) "true" else "false"),
            else => try write_json_string(writer, value),
        }
    }
    try writer.writeAll("},\"target\":");
    try write_json_string(writer, target);
    try writer.writeAll("}\n");
}

/// RFC 3339 in UTC with microseconds, as tracing-subscriber prints it.
fn write_timestamp(writer: *Io.Writer, timestamp_ns: u64) Io.Writer.Error!void {
    const seconds: std.time.epoch.EpochSeconds = .{ .secs = timestamp_ns / std.time.ns_per_s };
    const year_day = seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = seconds.getDaySeconds();
    const micros = timestamp_ns % std.time.ns_per_s / std.time.ns_per_us;
    assert(micros < std.time.us_per_s);
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        micros,
    });
}

/// A JSON string as serde_json writes it.
pub fn write_json_string(writer: *Io.Writer, value: []const u8) Io.Writer.Error!void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x08 => try writer.writeAll("\\b"),
        0x0c => try writer.writeAll("\\f"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x07, 0x0b, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

/// Fills `message` with its send time and random bytes (commonware's flood sender loop body).
pub fn fill_message(message: []u8, sent_at_ns: u64, rng: *SmallRng) void {
    assert(message.len >= message_size_min);
    std.mem.writeInt(u64, message[0..8], sent_at_ns, .little);
    rng.fill_bytes(message[8..]);
}

/// The send time of a received message, or null when it is too short to carry one.
pub fn sent_ns(message: []const u8) ?u64 {
    if (message.len < message_size_min) return null;
    return std.mem.readInt(u64, message[0..8], .little);
}

fn now_ns(io: Io) u64 {
    const nanoseconds = Io.Clock.real.now(io).nanoseconds;
    assert(nanoseconds >= 0);
    return @intCast(nanoseconds);
}

/// Floods `sender`'s connected peers with `message_size`-byte messages until canceled or
/// `messages_max` messages are sent (commonware's `flood_sender` task). `sender` is a p2p
/// limited sender (`check(recipients)` returning `p2p.Check`).
pub fn run_sender(
    gpa: Allocator,
    io: Io,
    sender: anytype,
    message_size: u32,
    messages: *metrics.raw.Counter,
    messages_max: ?u64,
) !void {
    comptime p2p.assert_limited_sender(@TypeOf(sender.*));
    assert(message_size >= message_size_min);
    const message = try gpa.alloc(u8, message_size);
    defer gpa.free(message);
    var rng = SmallRng.seed_from_u64(0);
    var sent: u64 = 0;
    while (messages_max == null or sent < messages_max.?) {
        const checked = switch (try sender.check(.all)) {
            .checked => |checked| checked,
            .limited => |wait_until| {
                const raw: Io.Timestamp = .fromNanoseconds(@intCast(wait_until.nanos_since_epoch));
                const deadline: Io.Clock.Timestamp = .{ .raw = raw, .clock = .real };
                try deadline.wait(io);
                continue;
            },
        };
        fill_message(message, now_ns(io), &rng);
        if (checked.send(&.{message}, true).accepted()) {
            messages.inc();
            sent += 1;
        }
    }
}

/// Observes the latency of every message `receiver` delivers until it closes or
/// `messages_max` arrive (commonware's `flood_receiver` task).
pub fn run_receiver(
    io: Io,
    receiver: anytype,
    latency: *metrics.raw.Histogram,
    messages_max: ?u64,
) !void {
    comptime p2p.assert_receiver(@TypeOf(receiver.*));
    var received: u64 = 0;
    while (messages_max == null or received < messages_max.?) {
        var message = receiver.recv() catch |err| switch (err) {
            error.NetworkClosed => return,
            else => |other| return other,
        };
        defer message.deinit();
        received += 1;
        const sent = sent_ns(message.payload) orelse continue;
        const start: Io.Timestamp = .fromNanoseconds(sent);
        metrics.histogram.observe_between(latency, start, Io.Clock.real.now(io));
    }
}

test {
    _ = yaml;
    _ = @import("flood_test.zig");
}
