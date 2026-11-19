//! Wire format of DKG probe messages (commonware `glue/src/dkg/probe/wire.rs` and
//! `limits.rs`).
//!
//! ```text
//! BoundaryRequest (0):   | tag (1) | epoch |
//! BoundaryResponse (1):  | tag (1) | finalization |
//! BlockRequest (2):      | tag (1) | epoch |
//! BlockResponse (3):     | tag (1) | epoch | block |
//! LatestRequest (4):     | tag (1) |
//! LatestResponse (5):    | tag (1) | finalization |
//! ```
//!
//! Senders build a `Message`; receivers split the tag first with `read_request` or
//! `read_response`. A block response's body stays encoded until its epoch and responder match
//! the outstanding request, then `read_block` decodes it against the verified commitment.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");

const Epoch = consensus.Epoch;
const marshal_limits = consensus.marshal.limits;

/// The first byte of a DKG probe message.
pub const Tag = enum(u8) {
    /// Request the boundary finalization for an epoch.
    boundary_request = 0,
    /// Response carrying a boundary finalization.
    boundary_response = 1,
    /// Request the boundary block for an epoch.
    block_request = 2,
    /// Response carrying a finalized block.
    block_response = 3,
    /// Request the receiver's latest finalization.
    latest_request = 4,
    /// Response carrying the receiver's latest finalization.
    latest_response = 5,

    pub const fixed_size: usize = 1;
    const count = @typeInfo(Tag).@"enum".field_names.len;

    pub fn write(self: Tag, writer: *codec.Writer) void {
        writer.write_byte(@backingInt(self));
    }

    pub fn encode_size(_: Tag) usize {
        return fixed_size;
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Tag {
        const byte = try reader.read_byte();
        if (byte >= count) return reader.fail(error.InvalidEnum, byte);
        return @fromBackingInt(@intCast(byte));
    }

    /// arbitrary 1.4's derive: `(u64::from(u32) * variants) >> 32`.
    pub fn arbitrary(_: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!Tag {
        const variant = (@as(u64, u.int(u32)) * count) >> 32;
        assert(variant < count);
        return @fromBackingInt(@intCast(variant));
    }
};

/// A request decoded from a peer.
pub const Request = union(enum) {
    /// The boundary finalization of an epoch.
    boundary: Epoch,
    /// The boundary block of an epoch.
    block: Epoch,
    /// The receiver's latest finalization.
    latest,
};

/// Decodes a request; null when the tag names a response.
pub fn read_request(gpa: Allocator, bytes: []const u8) codec.Error!?Request {
    var reader: codec.Reader = .init(bytes);
    const tag = try Tag.read(gpa, &reader, {});
    const request: Request = switch (tag) {
        .boundary_request => .{ .boundary = try read_epoch(gpa, &reader) },
        .block_request => .{ .block = try read_epoch(gpa, &reader) },
        .latest_request => .latest,
        .boundary_response, .block_response, .latest_response => return null,
    };
    if (reader.remaining() != 0) return error.ExtraData;
    return request;
}

fn read_epoch(gpa: Allocator, reader: *codec.Reader) codec.Error!Epoch {
    return Epoch.read(gpa, reader, {});
}

/// A DKG probe message for scheme `S` and marshal variant `V`.
pub fn Message(comptime S: type, comptime V: type) type {
    return union(Tag) {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, V.Commitment);
        pub const BlockResponse = struct {
            /// Epoch echoed from the request.
            epoch: Epoch,
            /// Boundary block of `epoch`.
            block: V.Block,
        };

        /// Request for the finalization of `epoch`'s boundary block.
        boundary_request: Epoch,
        /// Finalization of a requested boundary block.
        boundary_response: Finalization,
        /// Request for `epoch`'s boundary block.
        block_request: Epoch,
        /// A requested boundary block.
        block_response: BlockResponse,
        /// Request for the receiver's latest finalization.
        latest_request,
        /// The receiver's latest finalization.
        latest_response: Finalization,

        /// An upper bound on the encoded size of a message for committees of at most
        /// `participants` and application blocks of at most `application` encoded bytes.
        pub fn max_encode_size(participants: u32, application: usize) usize {
            // After its tag, a request carries an epoch (or nothing), a boundary or latest
            // response a finalization, and a block response an epoch and a backfill block.
            const finalization = Finalization.max_encode_size_for(participants);
            const block = Epoch.max_encode_size + V.max_backfill_block_size(application);
            return Tag.fixed_size + @max(Epoch.max_encode_size, finalization, block);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            std.meta.activeTag(self).write(writer);
            switch (self) {
                .boundary_request, .block_request => |epoch| epoch.write(writer),
                .boundary_response, .latest_response => |finalization| finalization.write(writer),
                .block_response => |response| {
                    response.epoch.write(writer);
                    response.block.write(writer);
                },
                .latest_request => {},
            }
        }

        /// The encoding, owned by the caller. Messages are encoded, not decoded (receivers
        /// use `read_request` and `read_response`), so this stands in for `codec.encode`.
        pub fn encode(self: Self, gpa: Allocator) Allocator.Error![]u8 {
            const out = try gpa.alloc(u8, self.encode_size());
            var writer: codec.Writer = .init(out);
            self.write(&writer);
            assert(writer.written().len == out.len);
            return out;
        }

        pub fn encode_size(self: Self) usize {
            return Tag.fixed_size + switch (self) {
                .boundary_request, .block_request => |epoch| epoch.encode_size(),
                .boundary_response, .latest_response => |finalization| finalization.encode_size(),
                .block_response => |response| response.epoch.encode_size() +
                    response.block.encode_size(),
                .latest_request => 0,
            };
        }
    };
}

/// A response decoded from a peer, for scheme `S` and marshal variant `V`.
pub fn Response(comptime S: type, comptime V: type) type {
    return union(enum) {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, V.Commitment);

        /// Boundary finalization response (owned).
        boundary: Finalization,
        /// A block response whose body stays encoded (borrowed from the received bytes)
        /// until the epoch and responder match the outstanding request.
        block: struct { epoch: Epoch, body: []const u8 },
        /// Latest finalization response (owned).
        latest: Finalization,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .boundary, .latest => |*finalization| finalization.deinit(gpa),
                .block => {},
            }
            self.* = undefined;
        }
    };
}

/// Decodes a response; null when the tag names a request. A block response's body borrows
/// `bytes` (see `read_block`).
pub fn read_response(
    comptime S: type,
    comptime V: type,
    gpa: Allocator,
    bytes: []const u8,
    certificate_cfg: codec.Cfg(S.Certificate),
) codec.Error!?Response(S, V) {
    const Finalization = Response(S, V).Finalization;
    var reader: codec.Reader = .init(bytes);
    const tag = try Tag.read(gpa, &reader, {});
    switch (tag) {
        .boundary_response, .latest_response => {
            const rest = bytes[bytes.len - reader.remaining() ..];
            const finalization = try codec.decode_cfg(Finalization, gpa, rest, certificate_cfg);
            return if (tag == .boundary_response)
                .{ .boundary = finalization }
            else
                .{ .latest = finalization };
        },
        .block_response => {
            const epoch = try read_epoch(gpa, &reader);
            const body = bytes[bytes.len - reader.remaining() ..];
            assert(body.len == reader.remaining());
            return .{ .block = .{ .epoch = epoch, .body = body } };
        },
        .boundary_request, .block_request, .latest_request => return null,
    }
}

/// Decodes a block response body and binds it to `commitment`, the payload of a verified
/// finalization.
pub fn read_block(
    comptime V: type,
    gpa: Allocator,
    body: []const u8,
    commitment: V.Commitment,
    block_cfg: codec.Cfg(V.ApplicationBlock),
    strategy: anytype,
) codec.Error!V.Block {
    return V.decode_block(gpa, body, block_cfg, .{ .trusted = commitment }, strategy);
}

/// An upper bound on the payloads the probe sends for committees of at most `participants`
/// and blocks decoded under `block_cfg` (commonware `limits.rs` `max_payload_size`).
pub fn max_payload_size(
    comptime V: type,
    comptime S: type,
    participants: u32,
    block_cfg: codec.Cfg(V.ApplicationBlock),
) usize {
    const application = marshal_limits.max_block_size(V.ApplicationBlock, block_cfg);
    return Message(S, V).max_encode_size(participants, application);
}
