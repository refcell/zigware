//! The probe's wire messages (commonware `glue/src/stateful/probe/mod.rs` `Tag` and `Message`,
//! and `limits.rs`).
//!
//! ```text
//! Request (tag 0):   | tag (1) |
//! Response (tag 1):  | tag (1) | finalization |
//! ```

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");

/// The first byte of a probe wire message.
pub const Tag = enum(u8) {
    /// A request for the receiver's latest finalization.
    request = 0,
    /// A response carrying a finalization.
    response = 1,

    const count = 2;

    /// arbitrary 1.4's derive: `(u64::from(u32) * variants) >> 32`.
    pub fn arbitrary(_: Allocator, u: *codec.arbitrary.Unstructured) codec.arbitrary.Error!Tag {
        const variant = (@as(u64, u.int(u32)) * count) >> 32;
        assert(variant < count);
        return @fromBackingInt(@intCast(variant));
    }
};

/// A message exchanged over the probe channel, for scheme `S` and marshal variant `V`
/// (`V.Commitment` is what finalizations certify).
pub fn Message(comptime S: type, comptime V: type) type {
    return union(Tag) {
        const Self = @This();
        pub const Finalization = consensus.simplex.types.Finalization(S, V.Commitment);
        pub const Cfg = Finalization.Cfg;

        request,
        response: Finalization,

        /// An upper bound on the encoded size for committees of at most `participants`.
        pub fn max_encode_size(participants: u32) usize {
            // After its tag, a request carries nothing and a response a finalization.
            return 1 + Finalization.max_encode_size_for(participants);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(@backingInt(std.meta.activeTag(self)));
            switch (self) {
                .request => {},
                .response => |finalization| finalization.write(writer),
            }
        }

        pub fn encode_size(self: Self) usize {
            return 1 + switch (self) {
                .request => 0,
                .response => |finalization| finalization.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            const tag = try reader.read_byte();
            return switch (tag) {
                @backingInt(Tag.request) => .request,
                @backingInt(Tag.response) => .{
                    .response = try Finalization.read(gpa, reader, cfg),
                },
                else => error.InvalidEnum,
            };
        }

        /// commonware's `Message::arbitrary`: an arbitrary `Tag`, then a response's finalization.
        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            const tag = try Tag.arbitrary(gpa, u);
            const message: Self = switch (tag) {
                .request => .request,
                .response => .{ .response = try Finalization.arbitrary(gpa, u) },
            };
            assert(std.meta.activeTag(message) == tag);
            return message;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .request => {},
                .response => |*finalization| finalization.deinit(gpa),
            }
            self.* = undefined;
        }
    };
}

/// An upper bound on the payloads the probe sends for committees of at most `participants`
/// (commonware `max_payload_size`). Compute it with the committee size given to marshal's
/// `max_payload_size`, since the probe serves marshal's finalizations.
pub fn max_payload_size(comptime V: type, comptime S: type, participants: u32) usize {
    return Message(S, V).max_encode_size(participants);
}
