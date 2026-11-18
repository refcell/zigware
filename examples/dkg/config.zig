//! JSON node and network configuration shared by all subcommands (commonware
//! `examples/dkg/src/config.rs`).
//!
//! `node.json` holds a node's signer and its listen and dial addresses; `network.json` holds the
//! ordered participants, the committee size, and every peer's dial address. Keys are lowercase
//! hex of their codec encodings and addresses are Rust `SocketAddr` strings. Files are written
//! exactly as `serde_json::to_string_pretty` writes them (two-space indent, no trailing newline)
//! and read as serde reads them: unknown fields are ignored, missing or duplicate ones refused.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");

const codec = zigware.codec;
const formatting = zigware.formatting;
const ed25519 = zigware.cryptography.ed25519;
const IpAddr = zigware.deployer.IpAddr;

pub const PrivateKey = ed25519.PrivateKey;
pub const PublicKey = ed25519.PublicKey;

/// The largest config file read (a 64-peer `network.json` is about 13 KiB).
pub const max_file_bytes: usize = 1 << 20;

pub const Error = error{
    InvalidJson,
    InvalidHex,
    InvalidKey,
    InvalidAddress,
    EmptyParticipants,
    ZeroCommitteeSize,
    CommitteeExceedsParticipants,
};

/// Rust's `std::net::SocketAddr` as text: `a.b.c.d:port` or `[v6]:port`.
pub const SocketAddr = struct {
    ip: IpAddr,
    port: u16,

    pub fn localhost(port: u16) SocketAddr {
        return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port };
    }

    /// Rust `SocketAddr::from_str`: an IPv4 address or a bracketed IPv6 address, then a port.
    pub fn parse(text: []const u8) Error!SocketAddr {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
            return error.InvalidAddress;
        const host = text[0..colon];
        const port_text = text[colon + 1 ..];
        if (port_text.len == 0) return error.InvalidAddress;
        for (port_text) |c| if (!std.ascii.isDigit(c)) return error.InvalidAddress;
        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidAddress;
        if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
            const ip = IpAddr.parse(host[1 .. host.len - 1]) catch return error.InvalidAddress;
            if (ip != .v6) return error.InvalidAddress;
            return .{ .ip = ip, .port = port };
        }
        const ip = IpAddr.parse(host) catch return error.InvalidAddress;
        if (ip != .v4) return error.InvalidAddress;
        return .{ .ip = ip, .port = port };
    }

    /// Rust `SocketAddr`'s `Display`.
    pub fn format(self: SocketAddr, writer: *Io.Writer) Io.Writer.Error!void {
        switch (self.ip) {
            .v4 => try writer.print("{f}:{d}", .{ self.ip, self.port }),
            .v6 => try writer.print("[{f}]:{d}", .{ self.ip, self.port }),
        }
    }

    pub fn eql(a: SocketAddr, b: SocketAddr) bool {
        return a.port == b.port and a.ip.eql(b.ip);
    }

    pub fn to_io(self: SocketAddr) Io.net.IpAddress {
        return self.ip.to_io(self.port);
    }
};

/// Per-node config stored in `node.json`: signer and listen/dial addresses.
pub const NodeConfig = struct {
    signer: PrivateKey,
    listen: SocketAddr,
    dial: SocketAddr,

    const Raw = struct { signer: []const u8, listen: []const u8, dial: []const u8 };

    /// Node config with listen and dial both on localhost at `port`.
    pub fn localhost(signer: PrivateKey, port: u16) NodeConfig {
        const addr: SocketAddr = .localhost(port);
        return .{ .signer = signer, .listen = addr, .dial = addr };
    }

    /// Public key of the node's signer.
    pub fn public_key(self: *const NodeConfig) PublicKey {
        return self.signer.public_key();
    }

    /// Read the node config from `node.json` in `node_dir`.
    pub fn load(io: Io, gpa: Allocator, node_dir: Io.Dir) !NodeConfig {
        const text = try node_dir.readFileAlloc(io, "node.json", gpa, .limited(max_file_bytes));
        defer gpa.free(text);
        return parse(gpa, text);
    }

    pub fn parse(gpa: Allocator, text: []const u8) !NodeConfig {
        const parsed = try parse_json(Raw, gpa, text);
        defer parsed.deinit();
        const raw = parsed.value;
        var seed: [PrivateKey.fixed_size]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try decode_hex(gpa, raw.signer, &seed);
        return .{
            .signer = .from_bytes(seed),
            .listen = try .parse(raw.listen),
            .dial = try .parse(raw.dial),
        };
    }

    pub fn write(self: *const NodeConfig, writer: *Io.Writer) Io.Writer.Error!void {
        var seed: [PrivateKey.fixed_size]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        _ = codec.encode_to(PrivateKey, self.signer, &seed);
        try writer.print("{{\n  \"signer\": \"{f}\",\n", .{formatting.fmt_hex(&seed)});
        try writer.print("  \"listen\": \"{f}\",\n", .{self.listen});
        try writer.print("  \"dial\": \"{f}\"\n}}", .{self.dial});
    }
};

/// Dial address for one participant.
pub const PeerConfig = struct {
    public_key: PublicKey,
    dial: SocketAddr,
};

/// Shared network config stored in `network.json`: ordered participants, committee size, and
/// peer dial addresses.
pub const NetworkConfig = struct {
    participants: []const PublicKey,
    committee_size: u64,
    peers: []const PeerConfig,

    const Raw = struct {
        participants: []const []const u8,
        committee_size: u64,
        peers: []const struct { public_key: []const u8, dial: []const u8 },
    };

    /// Frees a config returned by `parse` or `load`.
    pub fn deinit(self: *NetworkConfig, gpa: Allocator) void {
        gpa.free(self.participants);
        gpa.free(self.peers);
        self.* = undefined;
    }

    /// Read the network config from `network.json` in `node_dir`.
    pub fn load(io: Io, gpa: Allocator, node_dir: Io.Dir) !NetworkConfig {
        const name = "network.json";
        const text = try node_dir.readFileAlloc(io, name, gpa, .limited(max_file_bytes));
        defer gpa.free(text);
        return parse(gpa, text);
    }

    pub fn parse(gpa: Allocator, text: []const u8) !NetworkConfig {
        const parsed = try parse_json(Raw, gpa, text);
        defer parsed.deinit();
        const raw = parsed.value;
        const participants = try gpa.alloc(PublicKey, raw.participants.len);
        errdefer gpa.free(participants);
        for (participants, raw.participants) |*key, hex| key.* = try decode_key(gpa, hex);
        const peers = try gpa.alloc(PeerConfig, raw.peers.len);
        errdefer gpa.free(peers);
        for (peers, raw.peers) |*peer, entry| peer.* = .{
            .public_key = try decode_key(gpa, entry.public_key),
            .dial = try .parse(entry.dial),
        };
        return .{
            .participants = participants,
            .committee_size = raw.committee_size,
            .peers = peers,
        };
    }

    /// Check participant and committee size invariants.
    pub fn validate(self: *const NetworkConfig) Error!void {
        if (self.participants.len == 0) return error.EmptyParticipants;
        if (self.committee_size == 0) return error.ZeroCommitteeSize;
        if (self.committee_size > self.participants.len) {
            return error.CommitteeExceedsParticipants;
        }
    }

    /// Dial addresses for every peer except `local`, in config order. Caller owns the slice.
    pub fn bootstrappers(
        self: *const NetworkConfig,
        gpa: Allocator,
        local: PublicKey,
    ) Allocator.Error![]PeerConfig {
        var out: std.ArrayList(PeerConfig) = try .initCapacity(gpa, self.peers.len);
        errdefer out.deinit(gpa);
        for (self.peers) |peer| {
            if (codec.order(PublicKey, peer.public_key, local) == .eq) continue;
            out.appendAssumeCapacity(peer);
        }
        assert(out.items.len + 1 >= self.peers.len);
        return out.toOwnedSlice(gpa);
    }

    pub fn write(self: *const NetworkConfig, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeAll("{\n  \"participants\": ");
        if (self.participants.len == 0) try writer.writeAll("[]");
        for (self.participants, 0..) |key, index| {
            const open = if (index == 0) "[\n" else ",\n";
            try writer.print("{s}    \"{f}\"", .{ open, formatting.fmt_hex(&encode_key(key)) });
        }
        if (self.participants.len > 0) try writer.writeAll("\n  ]");
        try writer.print(",\n  \"committee_size\": {d},\n  \"peers\": ", .{self.committee_size});
        if (self.peers.len == 0) try writer.writeAll("[]");
        for (self.peers, 0..) |peer, index| {
            const open = if (index == 0) "[\n" else ",\n";
            try writer.print("{s}    {{\n      \"public_key\": \"{f}\",\n", .{
                open, formatting.fmt_hex(&encode_key(peer.public_key)),
            });
            try writer.print("      \"dial\": \"{f}\"\n    }}", .{peer.dial});
        }
        if (self.peers.len > 0) try writer.writeAll("\n  ]");
        try writer.writeAll("\n}");
    }
};

/// Parses JSON as serde does for these structs: unknown fields ignored, duplicates refused.
pub fn parse_json(comptime T: type, gpa: Allocator, text: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, gpa, text, .{
        .ignore_unknown_fields = true,
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidJson,
    };
}

/// Writes `value` (anything with `write(*Io.Writer)`) to `path` in `dir`, replacing it.
pub fn write_json(io: Io, dir: Io.Dir, path: []const u8, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var file = try dir.createFile(io, path, .{});
    defer file.close(io);
    var writer = file.writer(io, &buffer);
    try value.write(&writer.interface);
    try writer.interface.flush();
}

/// The codec encoding of `key`.
pub fn encode_key(key: PublicKey) [PublicKey.fixed_size]u8 {
    var bytes: [PublicKey.fixed_size]u8 = undefined;
    const written = codec.encode_to(PublicKey, key, &bytes);
    assert(written.len == bytes.len);
    return bytes;
}

/// `PublicKey::decode(from_hex(hex))`.
pub fn decode_key(gpa: Allocator, hex: []const u8) !PublicKey {
    var bytes: [PublicKey.fixed_size]u8 = undefined;
    try decode_hex(gpa, hex, &bytes);
    return codec.decode(PublicKey, gpa, &bytes) catch error.InvalidKey;
}

/// commonware `from_hex` into exactly `out.len` bytes.
fn decode_hex(gpa: Allocator, hex: []const u8, out: []u8) !void {
    const bytes = try formatting.from_hex(gpa, hex) orelse return error.InvalidHex;
    defer {
        std.crypto.secureZero(u8, bytes);
        gpa.free(bytes);
    }
    if (bytes.len != out.len) return error.InvalidKey;
    @memcpy(out, bytes);
}
