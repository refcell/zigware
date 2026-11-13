//! Messages exchanged between discovery peers (commonware
//! `p2p/src/authenticated/discovery/types.rs`): a one-byte discriminant, then a data frame,
//! a greeting, a bit vector of known peers, or signed peer information.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const data_mod = @import("../data.zig");
const p2p_types = @import("../../types.zig");

const Data = data_mod.Data;
const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const SystemTime = utils.SystemTime;
const Unstructured = codec.arbitrary.Unstructured;
const ArbitraryError = codec.arbitrary.Error;
const max_u32_varint_size = codec.varint.max_u32_varint_size;
const max_u64_varint_size = codec.varint.max_u64_varint_size;
const UInt = codec.varint.UInt(u64);

/// A chunk size of 1 minimizes the encoded size.
pub const BitMap = utils.BitMap(1);

/// Errors from validating peer information.
pub const Error = error{ TooManyPeers, ReceivedSelf, InvalidSignature, SynchronyBound };

/// Prefix that identifies a `data` payload.
pub const data_prefix: u8 = data_mod.data_prefix;
/// Prefix that identifies a `greeting` payload.
pub const greeting_prefix: u8 = 1;
/// Prefix that identifies a `bit_vec` payload.
pub const bit_vec_prefix: u8 = 2;
/// Prefix that identifies a `peers` payload.
pub const peers_prefix: u8 = 3;

comptime {
    assert(data_prefix == 0);
    assert(greeting_prefix == 1 and bit_vec_prefix == 2 and peers_prefix == 3);
}

/// Limits on the payloads received from peers.
pub const PayloadConfig = struct {
    /// The most bits a `bit_vec` payload may carry.
    max_bit_vec: u64,
    /// The most entries a `peers` payload may carry.
    max_peers: usize,
    /// The longest message a `data` payload may carry.
    max_data_length: usize,
};

/// An upper bound on the encoded size of any greeting, bit vector, or peer list that
/// `Payload(P).read` admits under `max_bit_vec` and `max_peers`. Gossip shares its stream with
/// application data, so the stream's frame limit must admit this size.
pub fn max_gossip_size(comptime P: type, max_bit_vec: u64, max_peers: usize) usize {
    const info = Info(P).max_encode_size;
    const bit_vec = max_u64_varint_size + BitMap.encode_size_max(max_bit_vec);
    const peers = max_peers * info + max_u32_varint_size;
    return 1 + @max(info, bit_vec, peers);
}

/// The peers a peer knows about at `index`. A peer answers with `peers` when it knows of any
/// peer the sender does not.
pub const BitVec = struct {
    /// The index the bit vector applies to.
    index: u64,
    /// One bit per peer in the set at `index`.
    bits: BitMap,

    /// The most bits accepted.
    pub const Cfg = u64;

    pub fn deinit(bit_vec: *BitVec, gpa: Allocator) void {
        bit_vec.bits.deinit(gpa);
        bit_vec.* = undefined;
    }

    pub fn eql(a: *const BitVec, b: *const BitVec) bool {
        return a.index == b.index and a.bits.eql(&b.bits);
    }

    pub fn encode_size(bit_vec: BitVec) usize {
        return (UInt{ .value = bit_vec.index }).encode_size() + bit_vec.bits.encode_size();
    }

    pub fn write(bit_vec: BitVec, writer: *codec.Writer) void {
        (UInt{ .value = bit_vec.index }).write(writer);
        bit_vec.bits.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, max_bits: Cfg) codec.Error!BitVec {
        const index = (try UInt.read(gpa, reader, {})).value;
        const bits = try BitMap.read(gpa, reader, .to_inclusive(max_bits));
        return .{ .index = index, .bits = bits };
    }

    /// `#[derive(Arbitrary)]`: the index, then the bits.
    pub fn arbitrary(gpa: Allocator, u: *Unstructured) ArbitraryError!BitVec {
        const index = u.int(u64);
        return .{ .index = index, .bits = try BitMap.arbitrary(gpa, u) };
    }
};

/// A peer's signed attestation of its own ingress address at a time, so other peers can share
/// it verifiably.
pub fn Info(comptime P: type) type {
    return struct {
        /// How to dial the peer.
        ingress: Ingress,
        /// When the ingress was signed, in epoch milliseconds.
        timestamp: u64,
        /// The peer's public key.
        public_key: P,
        /// The peer's signature over the ingress and timestamp.
        signature: P.Signature,

        const Self = @This();

        /// An upper bound on the encoded size of any `Info`.
        pub const max_encode_size: usize = Ingress.max_encode_size + max_u64_varint_size +
            P.fixed_size + P.Signature.fixed_size;

        /// The signed message, `(ingress, timestamp).encode()`, fits in this many bytes.
        const signed_size_max = Ingress.max_encode_size + 8;

        /// Encodes the signed message, `(ingress, timestamp)`, into `buffer`.
        fn signed_message(
            ingress: Ingress,
            timestamp: u64,
            buffer: *[signed_size_max]u8,
        ) []const u8 {
            var writer = codec.Writer.init(buffer);
            ingress.write(&writer);
            writer.write_int(u64, timestamp);
            assert(writer.written().len == ingress.encode_size() + 8);
            return writer.written();
        }

        /// Signs `ingress` at `timestamp` with `signer`, whose `sign(namespace, message)` must
        /// produce signatures `public_key` verifies.
        pub fn sign(
            public_key: P,
            namespace: []const u8,
            ingress: Ingress,
            timestamp: u64,
            signer: anytype,
        ) Self {
            var buffer: [signed_size_max]u8 = undefined;
            const message = signed_message(ingress, timestamp, &buffer);
            return .{
                .ingress = ingress,
                .timestamp = timestamp,
                .public_key = public_key,
                .signature = signer.sign(namespace, message),
            };
        }

        /// Whether the signature covers the ingress and timestamp under `namespace`.
        pub fn verify(info: *const Self, namespace: []const u8) bool {
            var buffer: [signed_size_max]u8 = undefined;
            const message = signed_message(info.ingress, info.timestamp, &buffer);
            return info.public_key.verify(namespace, message, &info.signature);
        }

        pub fn encode_size(info: Self) usize {
            return info.ingress.encode_size() + (UInt{ .value = info.timestamp }).encode_size() +
                P.fixed_size + P.Signature.fixed_size;
        }

        pub fn write(info: Self, writer: *codec.Writer) void {
            info.ingress.write(writer);
            (UInt{ .value = info.timestamp }).write(writer);
            info.public_key.write(writer);
            info.signature.write(writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const ingress = try Ingress.read(gpa, reader, {});
            const timestamp = (try UInt.read(gpa, reader, {})).value;
            const public_key = try P.read(gpa, reader, {});
            const signature = try P.Signature.read(gpa, reader, {});
            return .{
                .ingress = ingress,
                .timestamp = timestamp,
                .public_key = public_key,
                .signature = signature,
            };
        }
    };
}

/// Validates peer gossip against the configured limits and basic safety checks.
pub fn InfoVerifier(comptime P: type) type {
    return struct {
        /// Our own public key.
        me: P,
        /// The most entries one gossip message may carry.
        peer_gossip_max_count: usize,
        /// How far in the future a timestamp may be before it is malformed.
        synchrony_bound: Duration,
        /// The namespace `Info` is signed under (borrowed).
        ip_namespace: []const u8,

        const Self = @This();

        /// Validates a gossiped peer list. Entries may come in any order and repeat (a peer may
        /// answer a bit vector with a random subset).
        pub fn validate(verifier: *const Self, now: SystemTime, infos: []const Info(P)) Error!void {
            if (infos.len > verifier.peer_gossip_max_count) return error.TooManyPeers;
            for (infos) |*info| try verifier.validate_info(now, info);
        }

        /// Validates one peer's self-signed information, such as a connection greeting.
        pub fn validate_info(
            verifier: *const Self,
            now: SystemTime,
            info: *const Info(P),
        ) Error!void {
            if (info.public_key.eql(verifier.me)) return error.ReceivedSelf;
            const bound = now.epoch().saturating_add(verifier.synchrony_bound);
            if (Duration.from_millis(info.timestamp).order(bound) == .gt) {
                return error.SynchronyBound;
            }
            if (!info.verify(verifier.ip_namespace)) return error.InvalidSignature;
        }
    };
}

/// The only message format peers exchange.
pub fn Payload(comptime P: type) type {
    return union(enum) {
        /// Application data.
        data: Data,
        /// The peer's own information: the first message on a connection, sent exactly once.
        greeting: Info(P),
        /// The peers a peer knows about; also the keep-alive ping.
        bit_vec: BitVec,
        /// Verifiable information about other peers.
        peers: []const Info(P),

        const Self = @This();

        pub const Cfg = PayloadConfig;

        /// Frees the bit vector or peer list; data borrows the frame it was read from.
        pub fn deinit(payload: *Self, gpa: Allocator) void {
            switch (payload.*) {
                .data, .greeting => {},
                .bit_vec => |*bit_vec| bit_vec.deinit(gpa),
                .peers => |peers| gpa.free(peers),
            }
            payload.* = undefined;
        }

        pub fn encode_size(payload: Self) usize {
            return 1 + switch (payload) {
                .data => |data| data.encode_size(),
                .greeting => |info| info.encode_size(),
                .bit_vec => |bit_vec| bit_vec.encode_size(),
                .peers => |peers| codec.encode_size([]const Info(P), peers),
            };
        }

        pub fn write(payload: Self, writer: *codec.Writer) void {
            switch (payload) {
                .data => |data| {
                    writer.write_byte(data_prefix);
                    data.write(writer);
                },
                .greeting => |info| {
                    writer.write_byte(greeting_prefix);
                    info.write(writer);
                },
                .bit_vec => |bit_vec| {
                    writer.write_byte(bit_vec_prefix);
                    bit_vec.write(writer);
                },
                .peers => |peers| {
                    writer.write_byte(peers_prefix);
                    codec.write([]const Info(P), peers, writer);
                },
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const prefix = try reader.read_byte();
            return switch (prefix) {
                data_prefix => .{
                    .data = try Data.read(gpa, reader, .to_inclusive(cfg.max_data_length)),
                },
                greeting_prefix => .{ .greeting = try Info(P).read(gpa, reader, {}) },
                bit_vec_prefix => .{ .bit_vec = try BitVec.read(gpa, reader, cfg.max_bit_vec) },
                peers_prefix => .{
                    .peers = try codec.read_range(
                        []const Info(P),
                        gpa,
                        reader,
                        .to_inclusive(cfg.max_peers),
                    ),
                },
                else => reader.fail(error.InvalidEnum, prefix),
            };
        }
    };
}

test {
    _ = @import("types_test.zig");
}
