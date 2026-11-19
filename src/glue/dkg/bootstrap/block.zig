//! The one-shot DKG chain's block (commonware `glue::dkg::bootstrap::Block`).
//!
//! ```text
//! +----------------------+---------------------+-------------------------+
//! | epoch (varint, 1-10) | view (varint, 1-10) | leader (32)             |
//! +----------------------+-----+---------------+-----+-------------------+
//! | parent view (varint, 1-10) | context parent (32) | block parent (32) |
//! +-----------------------+----+-------------+-------+-------------------+
//! | height (varint, 1-10) | payload flag (1) | payload                   |
//! +-----------------------+------------------+---------------------------+
//! ```
//!
//! The payload follows only when the flag is 1. The digest is the SHA-256 of the encoding;
//! it is computed when the block is built or decoded and is not itself encoded. The codec
//! configuration is `types.InfoCfg` (commonware's `(NonZeroU32, ModeVersion)`), and
//! `max_encode_size_for` bounds every block it admits (commonware `BoundedBlock`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const types = @import("../types.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const View = consensus.View;
const Sha256 = cryptography.Sha256;
const Ed25519Key = cryptography.ed25519.PublicKey;

pub fn Block(comptime V: type, comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Digest = Sha256.Digest;
        pub const Context = consensus.simplex.types.Context(Digest, Ed25519Key);
        pub const Variant = V;
        pub const PublicKey = Ed25519Key;
        pub const Directory = D;
        pub const Payload = types.Payload(V, Ed25519Key, D);
        pub const Info = types.EpochInfo(V, Ed25519Key, D);
        pub const Cfg = types.InfoCfg;

        context_value: Context,
        parent_value: Digest,
        height_value: Height,
        /// Owned by the block.
        payload_value: ?Payload,
        digest_value: Digest,

        /// Builds a block, taking ownership of `payload`.
        pub fn init(
            gpa: Allocator,
            context_value: Context,
            parent_digest: Digest,
            at: Height,
            payload_value: ?Payload,
        ) Allocator.Error!Self {
            var block: Self = .{
                .context_value = context_value,
                .parent_value = parent_digest,
                .height_value = at,
                .payload_value = payload_value,
                .digest_value = undefined,
            };
            errdefer if (block.payload_value) |*owned| owned.deinit(gpa);
            block.digest_value = try block.compute_digest(gpa);
            return block;
        }

        /// The genesis block led by `leader`: epoch zero, view zero, empty parents.
        pub fn genesis(gpa: Allocator, leader: Ed25519Key) Allocator.Error!Self {
            const empty = Digest.empty;
            const context_value: Context = .{
                .round = .new(Epoch.zero(), View.zero()),
                .leader = leader,
                .parent = .{ View.zero(), empty },
            };
            const block = try init(gpa, context_value, empty, Height.zero(), null);
            assert(block.height_value.get() == 0);
            return block;
        }

        fn compute_digest(self: *const Self, gpa: Allocator) Allocator.Error!Digest {
            const bytes = try codec.encode(Self, gpa, self.*);
            defer gpa.free(bytes);
            assert(bytes.len == self.encode_size());
            return Sha256.hash(&.{bytes});
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.payload_value) |*owned| owned.deinit(gpa);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self;
            if (self.payload_value) |owned| copy.payload_value = try owned.clone(gpa);
            return copy;
        }

        pub fn eql(a: Self, b: Self) bool {
            const payloads = if (a.payload_value) |left|
                b.payload_value != null and left.eql(b.payload_value.?)
            else
                b.payload_value == null;
            return payloads and a.digest_value.eql(b.digest_value);
        }

        pub fn digest(self: *const Self) Digest {
            return self.digest_value;
        }

        pub fn height(self: Self) Height {
            return self.height_value;
        }

        pub fn parent(self: Self) Digest {
            return self.parent_value;
        }

        pub fn context(self: Self) Context {
            return self.context_value;
        }

        /// The DKG result this block carries, if any (borrowed).
        pub fn epoch_info(self: *const Self) ?*const Info {
            if (self.payload_value) |*owned| switch (owned.*) {
                .epoch_info => |*info| return info,
                .dealer_log => return null,
            };
            return null;
        }

        /// An owned copy of the carried payload (commonware `ReshareBlock::payload`).
        pub fn payload(self: Self, gpa: Allocator) Allocator.Error!?Payload {
            const owned = self.payload_value orelse return null;
            return try owned.clone(gpa);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.context_value.write(writer);
            self.parent_value.write(writer);
            self.height_value.write(writer);
            writer.write_byte(@intFromBool(self.payload_value != null));
            if (self.payload_value) |owned| owned.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const carried = if (self.payload_value) |owned| owned.encode_size() else 0;
            return self.context_value.encode_size() + Digest.fixed_size +
                self.height_value.encode_size() + 1 + carried;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            assert(cfg.max_participants > 0);
            const context_value = try Context.read(gpa, reader, {});
            const parent_digest = try Digest.read(gpa, reader, {});
            const at = try Height.read(gpa, reader, {});
            const carried: ?Payload = if (try codec.read(bool, gpa, reader))
                try Payload.read(gpa, reader, cfg)
            else
                null;
            return init(gpa, context_value, parent_digest, at, carried);
        }

        /// The largest block the codec configuration `cfg` admits: `Payload`'s bound covers
        /// every sharing mode.
        pub fn max_encode_size_for(cfg: Cfg) usize {
            assert(cfg.max_participants > 0);
            const bound = Payload.max_encode_size_with(cfg.max_participants) +
                Context.max_encode_size + Digest.fixed_size + Height.max_encode_size + 1;
            assert(bound > Context.max_encode_size);
            return bound;
        }
    };
}
