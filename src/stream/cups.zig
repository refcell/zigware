//! Counter Unidirectional Packet Stream (CUPS), commonware `stream/src/cups`.
//!
//! CUPS encrypts and authenticates ordered messages using a separate cipher per direction. A
//! packet is one framed message on an ordered byte stream.
//!
//! # Setup
//!
//! `Cups` runs its handshake to obtain a confirmed secret transcript `T`. `v0` uses `T`
//! unchanged. `v1` replaces `T` with `T.fork("_COMMONWARE_STREAM_CUPS")`, then commits a
//! single-byte mode packet containing `1`. `Cipher.random(T.noise("cipher_l2d"))` derives the
//! listener-to-dialer cipher, and `Cipher.random(T.noise("cipher_d2l"))` the reverse direction.
//!
//! # Records
//!
//! Let `m` be a message of `n` bytes and `t` the cipher's tag size. `seal_i(x)` is the
//! ciphertext of `x` followed by its tag at cipher position `i`, with empty associated data.
//!
//! | Version | Header | Body | Positions per record |
//! |---------|--------|------|----------------------|
//! | v0 | `varint_u32(n + t)` | `seal_i(m)` | 1 |
//! | v1 | `seal_i(BE32(n))` | `seal_(i+1)(m)` | 2 |
//!
//! A v1 receiver authenticates the header and checks the length before requesting the body.
//! A sender that fails to seal, and a receiver that returns any error, refuse every later
//! record (`StreamClosed`). Callers discard the connection after any error.
//!
//! # Zig shape
//!
//! `Sender` and `Receiver` own their sink/stream and one buffer sized for the largest record,
//! allocated when the connection is split, so sending and receiving never allocate.
//! `Receiver.recv` returns the plaintext in that buffer, valid until the next `recv`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const cryptography = @import("cryptography");
const Transcript = cryptography.Transcript;

const framing = @import("utils/codec.zig");

/// Size of the length field in a v1 header, excluding its tag.
const v1_header_plaintext_size = 4;

const cups_namespace = "_COMMONWARE_STREAM_CUPS";
const label_cipher_l2d = "cipher_l2d";
const label_cipher_d2l = "cipher_d2l";

/// Key derivation and record format. Both peers must use the same version.
pub const Version = enum(u7) {
    /// Records framed by a visible length prefix.
    v0 = 0,
    /// Records framed by an encrypted, authenticated length header.
    v1 = 1,
};

/// Errors that can occur when sending or receiving records.
pub const Error = error{
    SealFailed,
    OpenFailed,
    RecvFailed,
    RecvTooLarge,
    InvalidVarint,
    SendFailed,
    SendTooLarge,
    /// Closed after an earlier failure.
    StreamClosed,
} || Io.Cancelable;

/// Tag size of cipher `C`, in bytes.
pub fn tag_size(comptime C: type) u32 {
    comptime cryptography.assert_cipher(C);
    return @intCast(@sizeOf(C.Tag));
}

/// Largest record payload that fits alongside its tag in a v0 length prefix.
pub fn max_payload(comptime C: type) u32 {
    return std.math.maxInt(u32) - tag_size(C);
}

fn v1_header_size(comptime C: type) usize {
    return v1_header_plaintext_size + tag_size(C);
}

/// Size of the header that precedes a record carrying `len` payload bytes.
pub fn header_len(comptime C: type, version: Version, len: usize) usize {
    assert(len <= max_payload(C)); // Payload exceeds the stream limit.
    return switch (version) {
        .v0 => codec.varint.size(u32, @as(u32, @intCast(len)) + tag_size(C)),
        .v1 => v1_header_size(C),
    };
}

/// Encoded size of a record carrying `len` payload bytes.
pub fn record_len(comptime C: type, version: Version, len: usize) usize {
    const result = header_len(C, version, len) + len + tag_size(C);
    assert(result > len);
    return result;
}

/// Derives the listener-to-dialer and dialer-to-listener ciphers from a secret transcript.
pub fn ciphers(comptime C: type, transcript: Transcript, version: Version) struct { C, C } {
    var derived = transcript;
    if (codec.Modes(1).init(.{@backingInt(version)})) |modes| {
        derived = derived.fork(cups_namespace);
        var encoded: [1]u8 = undefined;
        derived.commit(codec.encode_to(codec.Modes(1), modes, &encoded));
    }
    var l2d = derived.noise(label_cipher_l2d);
    var d2l = derived.noise(label_cipher_d2l);
    return .{ C.random(&l2d), C.random(&d2l) };
}

/// Seals `data` in place and returns its tag; a failure leaves the cipher empty.
fn seal(comptime C: type, cipher: *?C, data: []u8) Error!C.Tag {
    const sealer = if (cipher.*) |*sealer| sealer else return error.StreamClosed;
    return sealer.seal(&.{}, data) catch {
        cipher.* = null;
        return error.SealFailed;
    };
}

/// Opens `record` (ciphertext then tag) in place and returns the plaintext; a failure leaves
/// the cipher empty.
fn open(comptime C: type, cipher: *?C, record: []u8) Error![]u8 {
    const opener = if (cipher.*) |*opener| opener else return error.StreamClosed;
    const tag_length = comptime tag_size(C);
    if (record.len < tag_length) {
        cipher.* = null;
        return error.OpenFailed;
    }
    const len = record.len - tag_length;
    const tag: C.Tag = record[len..][0..tag_length].*;
    opener.open(&.{}, record[0..len], &tag) catch {
        cipher.* = null;
        return error.OpenFailed;
    };
    return record[0..len];
}

fn map_transport_error(err: anyerror, failure: Error) Error {
    if (err == error.Canceled) return error.Canceled;
    return failure;
}

fn deinit_transport(transport: anytype) void {
    const T = @typeInfo(@TypeOf(transport)).pointer.child;
    if (comptime @hasDecl(T, "deinit")) transport.deinit();
}

/// Sends CUPS records to a peer.
pub fn Sender(comptime C: type, comptime SinkType: type) type {
    return struct {
        const Self = @This();

        cipher: ?C,
        sink: SinkType,
        max_message_size: u32,
        version: Version,
        /// Holds one or more sealed records before they go to the sink.
        buffer: []u8,

        pub fn init(
            gpa: Allocator,
            cipher: C,
            sink: SinkType,
            max_message_size: u32,
            version: Version,
        ) Allocator.Error!Self {
            assert(max_message_size <= max_payload(C));
            const buffer = try gpa.alloc(u8, record_len(C, version, max_message_size));
            return .{
                .cipher = cipher,
                .sink = sink,
                .max_message_size = max_message_size,
                .version = version,
                .buffer = buffer,
            };
        }

        /// Frees the buffer, erases the cipher, and closes the sink.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.cipher) |*cipher| if (comptime @hasDecl(C, "zeroize")) cipher.zeroize();
            gpa.free(self.buffer);
            deinit_transport(&self.sink);
            self.* = undefined;
        }

        /// Encrypts and sends one message.
        pub fn send(self: *Self, message: []const u8) Error!void {
            return self.send_many(&.{message});
        }

        /// Encrypts and sends messages, one record each, packing records into as few sink calls
        /// as the buffer allows. An oversized message fails the batch with `SendTooLarge`
        /// before any record is sealed. An empty batch sends nothing.
        pub fn send_many(self: *Self, messages: []const []const u8) Error!void {
            for (messages) |message| {
                _ = try framing.validate_frame_len(message.len, self.max_message_size);
            }
            var used: usize = 0;
            for (messages) |message| {
                const len = record_len(C, self.version, message.len);
                assert(len <= self.buffer.len);
                if (used + len > self.buffer.len) {
                    try self.flush(used);
                    used = 0;
                }
                try self.append_record(self.buffer[used..][0..len], message);
                used += len;
            }
            if (used > 0) try self.flush(used);
        }

        fn flush(self: *Self, len: usize) Error!void {
            assert(len > 0 and len <= self.buffer.len);
            self.sink.send(&.{self.buffer[0..len]}) catch |err| {
                return map_transport_error(err, error.SendFailed);
            };
        }

        /// Writes the header and the sealed message into `out`, exactly one record long.
        fn append_record(self: *Self, out: []u8, message: []const u8) Error!void {
            const tag_length = tag_size(C);
            const len: u32 = @intCast(message.len);
            const header_length = header_len(C, self.version, message.len);
            switch (self.version) {
                // Callers bound `len` by `max_size`, so adding the tag cannot overflow.
                .v0 => {
                    var writer = codec.Writer.init(out[0..header_length]);
                    codec.varint.write(u32, len + tag_length, &writer);
                    assert(writer.written().len == header_length);
                },
                .v1 => {
                    const plaintext = out[0..v1_header_plaintext_size];
                    std.mem.writeInt(u32, plaintext, len, .big);
                    const tag = try seal(C, &self.cipher, plaintext);
                    @memcpy(out[v1_header_plaintext_size..header_length], &tag);
                },
            }
            const body = out[header_length..][0..message.len];
            @memcpy(body, message);
            const tag = try seal(C, &self.cipher, body);
            @memcpy(out[header_length + message.len ..][0..tag_length], &tag);
            assert(header_length + message.len + tag_length == out.len);
        }
    };
}

/// Receives CUPS records from a peer.
pub fn Receiver(comptime C: type, comptime StreamType: type) type {
    return struct {
        const Self = @This();

        cipher: ?C,
        stream: StreamType,
        max_message_size: u32,
        version: Version,
        /// Holds the largest encrypted body: `max_message_size` plus the tag.
        buffer: []u8,

        pub fn init(
            gpa: Allocator,
            cipher: C,
            stream: StreamType,
            max_message_size: u32,
            version: Version,
        ) Allocator.Error!Self {
            assert(max_message_size <= max_payload(C));
            const buffer = try gpa.alloc(u8, max_message_size + tag_size(C));
            return .{
                .cipher = cipher,
                .stream = stream,
                .max_message_size = max_message_size,
                .version = version,
                .buffer = buffer,
            };
        }

        /// Frees the buffer, erases the cipher, and closes the stream.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.cipher) |*cipher| if (comptime @hasDecl(C, "zeroize")) cipher.zeroize();
            gpa.free(self.buffer);
            deinit_transport(&self.stream);
            self.* = undefined;
        }

        /// Receives and decrypts the next message. The plaintext stays valid until the next
        /// call. Any error closes the receiver: later calls return `StreamClosed` without
        /// reading from the stream.
        pub fn recv(self: *Self) Error![]const u8 {
            if (self.cipher == null) return error.StreamClosed;
            const plaintext = self.recv_open() catch |err| {
                // Some errors leave the cipher position ahead of the stream.
                self.cipher = null;
                return err;
            };
            assert(plaintext.len <= self.max_message_size);
            return plaintext;
        }

        fn recv_open(self: *Self) Error![]u8 {
            const record = switch (self.version) {
                .v0 => try framing.recv_frame(
                    &self.stream,
                    self.buffer,
                    self.max_message_size +| tag_size(C),
                ),
                .v1 => try self.recv_v1_body(),
            };
            return open(C, &self.cipher, record);
        }

        /// Authenticates the fixed-size header, checks its length, then receives the body.
        fn recv_v1_body(self: *Self) Error![]u8 {
            var header: [v1_header_plaintext_size + @sizeOf(C.Tag)]u8 = undefined;
            self.stream.recv(&header) catch |err| {
                return map_transport_error(err, error.RecvFailed);
            };
            const plaintext = try open(C, &self.cipher, &header);
            assert(plaintext.len == v1_header_plaintext_size);
            const len = std.mem.readInt(u32, plaintext[0..v1_header_plaintext_size], .big);
            if (len > self.max_message_size) return error.RecvTooLarge;

            const body = self.buffer[0 .. len + tag_size(C)];
            self.stream.recv(body) catch |err| return map_transport_error(err, error.RecvFailed);
            return body;
        }
    };
}

/// An upgrader (commonware `Upgrader`) that runs handshake `H`, then exchanges records of one
/// `Version` sealed by cipher `C`. See `stream.Handshake` for the handshake contract.
pub fn Cups(comptime H: type, comptime C: type) type {
    comptime cryptography.assert_cipher(C);
    return struct {
        const Self = @This();
        pub const PublicKey = @typeInfo(@TypeOf(H.public_key)).@"fn".return_type.?;
        /// Largest supported plaintext message, in bytes.
        pub const max_size: u32 = max_payload(C);

        /// Handshake used to authenticate peers and agree on a secret transcript.
        handshake: H,
        /// Version used for key derivation and record framing.
        version: Version,

        pub fn init(handshake: H, version: Version) Self {
            return .{ .handshake = handshake, .version = version };
        }

        pub fn public_key(self: Self) PublicKey {
            return self.handshake.public_key();
        }

        pub fn Connection(comptime StreamType: type, comptime SinkType: type) type {
            return struct {
                sender: Sender(C, SinkType),
                receiver: Receiver(C, StreamType),

                pub fn deinit(connection: *@This(), gpa: Allocator) void {
                    connection.sender.deinit(gpa);
                    connection.receiver.deinit(gpa);
                }
            };
        }

        pub fn Accepted(comptime StreamType: type, comptime SinkType: type) type {
            return struct {
                peer: PublicKey,
                connection: Connection(StreamType, SinkType),
            };
        }

        /// Authenticates an outbound connection to `peer` and splits it into record halves.
        /// Takes ownership of `stream` and `sink`; a failure closes them.
        pub fn dial(
            self: Self,
            gpa: Allocator,
            io: Io,
            namespace: []const u8,
            max_message_size: u32,
            peer: PublicKey,
            stream: anytype,
            sink: anytype,
        ) !Connection(@TypeOf(stream), @TypeOf(sink)) {
            assert(max_message_size <= max_size); // Maximum message size exceeds stream limit.
            var owned_stream = stream;
            var owned_sink = sink;
            errdefer deinit_transport(&owned_stream);
            errdefer deinit_transport(&owned_sink);
            const transcript =
                try self.handshake.dial(io, namespace, peer, &owned_stream, &owned_sink);
            const recv_cipher, const send_cipher = ciphers(C, transcript, self.version);
            return split(
                gpa,
                self.version,
                send_cipher,
                recv_cipher,
                owned_stream,
                owned_sink,
                max_message_size,
            );
        }

        /// Authenticates an inbound connection admitted by `bouncer` (`bouncer.admit(peer)
        /// !bool`) and splits it into record halves. Takes ownership of `stream` and `sink`.
        pub fn listen(
            self: Self,
            gpa: Allocator,
            io: Io,
            namespace: []const u8,
            max_message_size: u32,
            bouncer: anytype,
            stream: anytype,
            sink: anytype,
        ) !Accepted(@TypeOf(stream), @TypeOf(sink)) {
            assert(max_message_size <= max_size); // Maximum message size exceeds stream limit.
            var owned_stream = stream;
            var owned_sink = sink;
            errdefer deinit_transport(&owned_stream);
            errdefer deinit_transport(&owned_sink);
            const accepted =
                try self.handshake.listen(io, namespace, bouncer, &owned_stream, &owned_sink);
            const send_cipher, const recv_cipher = ciphers(C, accepted.transcript, self.version);
            const connection = try split(
                gpa,
                self.version,
                send_cipher,
                recv_cipher,
                owned_stream,
                owned_sink,
                max_message_size,
            );
            return .{ .peer = accepted.peer, .connection = connection };
        }

        fn split(
            gpa: Allocator,
            version: Version,
            send_cipher: C,
            recv_cipher: C,
            stream: anytype,
            sink: anytype,
            max_message_size: u32,
        ) Allocator.Error!Connection(@TypeOf(stream), @TypeOf(sink)) {
            const sender = try Sender(C, @TypeOf(sink))
                .init(gpa, send_cipher, sink, max_message_size, version);
            errdefer gpa.free(sender.buffer);
            const receiver = try Receiver(C, @TypeOf(stream))
                .init(gpa, recv_cipher, stream, max_message_size, version);
            return .{ .sender = sender, .receiver = receiver };
        }
    };
}

test {
    _ = @import("cups_test.zig");
}
