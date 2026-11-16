//! The reshare recovery journal's events (commonware `glue::dkg::reshare::store::Event`).
//!
//! The journal records the public messages a restarted node would otherwise lose, one section
//! per epoch: dealer messages a player accepted, acknowledgements this node's dealer received,
//! and finalized dealer logs. Secret material never enters it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");

const fd = cryptography.bls12381.dkg.feldman_desmedt;

pub fn Event(comptime V: type, comptime P: type) type {
    return union(enum) {
        const Self = @This();
        /// The maximum number of participants.
        pub const Cfg = u32;

        /// A dealer's public message that this node's player accepted (tag 0).
        dealing: struct { dealer: P, public: fd.DealerPubMsg(V) },
        /// A player's acknowledgement that this node's dealer recorded (tag 1).
        ack: struct { player: P, ack: fd.PlayerAck(P) },
        /// A finalized dealer log (tag 2).
        log: struct { dealer: P, log: fd.DealerLog(V, P) },

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                .dealing => |*dealing| dealing.public.deinit(gpa),
                .ack => {},
                .log => |*log| log.log.deinit(gpa),
            }
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            return switch (self) {
                .dealing => |dealing| .{ .dealing = .{
                    .dealer = dealing.dealer,
                    .public = try dealing.public.clone(gpa),
                } },
                .ack => self,
                .log => |log| .{ .log = .{ .dealer = log.dealer, .log = try log.log.clone(gpa) } },
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            return switch (a) {
                .dealing => |x| x.dealer.eql(b.dealing.dealer) and x.public.eql(b.dealing.public),
                .ack => |x| x.player.eql(b.ack.player) and x.ack.eql(b.ack.ack),
                .log => |x| x.dealer.eql(b.log.dealer) and x.log.eql(b.log.log),
            };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(@backingInt(std.meta.activeTag(self)));
            switch (self) {
                .dealing => |x| {
                    codec.write(P, x.dealer, writer);
                    x.public.write(writer);
                },
                .ack => |x| {
                    codec.write(P, x.player, writer);
                    x.ack.write(writer);
                },
                .log => |x| {
                    codec.write(P, x.dealer, writer);
                    x.log.write(writer);
                },
            }
        }

        pub fn encode_size(self: Self) usize {
            const key = codec.fixed_size(P).?;
            return 1 + key + switch (self) {
                .dealing => |x| x.public.encode_size(),
                .ack => fd.PlayerAck(P).fixed_size,
                .log => |x| x.log.encode_size(),
            };
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, max: u32) codec.Error!Self {
            assert(max > 0);
            const tag = try reader.read_byte();
            if (tag > 2) return reader.fail(error.InvalidEnum, tag);
            const key = try codec.read(P, gpa, reader);
            return switch (tag) {
                0 => .{ .dealing = .{
                    .dealer = key,
                    .public = try fd.DealerPubMsg(V).read(gpa, reader, max),
                } },
                1 => .{ .ack = .{
                    .player = key,
                    .ack = try fd.PlayerAck(P).read(gpa, reader, {}),
                } },
                2 => .{ .log = .{
                    .dealer = key,
                    .log = try fd.DealerLog(V, P).read(gpa, reader, max),
                } },
                else => unreachable, // Proof: tags above 2 fail above.
            };
        }
    };
}

test "event: tags and roundtrips" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const ed25519 = cryptography.ed25519;
    const P = ed25519.PublicKey;
    const E = Event(cryptography.bls12381.primitives.MinPk, P);
    const signer = ed25519.PrivateKey.from_seed(1);
    const event: E = .{ .ack = .{ .player = signer.public_key(), .ack = .{
        .sig = signer.sign("", "ack"),
    } } };
    const bytes = try codec.encode(E, gpa, event);
    defer gpa.free(bytes);
    try testing.expectEqual(@as(u8, 1), bytes[0]);
    try testing.expectEqual(1 + 32 + 64, bytes.len);
    var decoded = try codec.decode_cfg(E, gpa, bytes, 4);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(event));
    const invalid = [_]u8{3};
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(E, gpa, &invalid, 4));
}
