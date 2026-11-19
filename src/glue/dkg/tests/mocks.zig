//! Shared fixtures for glue's DKG tests (commonware `glue::dkg::tests::mocks`).
//!
//! The mock block, the in-memory secret store, a static participants provider, and a
//! registrar that records the epochs it enters. Marshal-backed fixtures follow as the
//! actor tests need them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const utils = @import("utils");
const runtime = @import("runtime");
const types = @import("../types.zig");
const reshare_store = @import("../reshare/store.zig");

const Epoch = consensus.Epoch;
const Height = consensus.Height;
const Round = consensus.Round;
const View = consensus.View;
const Set = utils.ordered.Set;
const Unit = utils.sequence.Unit;
const Sha256 = cryptography.Sha256;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Summary = cryptography.transcript.Summary;
const ModeVersion = cryptography.bls12381.primitives.sharing.ModeVersion;
const mocks_network = @import("mocks_network.zig");

pub const widest_addresses = mocks_network.widest_addresses;
pub const FailingManager = mocks_network.FailingManager;
pub const DirectoryManager = mocks_network.DirectoryManager;
pub const DirectoryTrack = mocks_network.DirectoryTrack;
pub const Filter = mocks_network.Filter;
pub const FilteredReceiver = mocks_network.FilteredReceiver;

pub const TestDigest = Sha256.Digest;
pub const TestPublicKey = cryptography.ed25519.PublicKey;
pub const TestSigner = cryptography.ed25519.PrivateKey;
pub const TestContext = consensus.simplex.types.Context(TestDigest, TestPublicKey);
pub const TestBlsVariant = cryptography.bls12381.primitives.MinPk;
pub const TestBlock = MockBlock(Unit);

/// The highest sharing mode the tests decode (commonware `max_supported_mode`).
pub const max_supported_mode: ModeVersion = .v1;

/// A reshare payload kept encoded in a block, with the participant bound to decode it.
pub const EncodedPayload = struct {
    max_participants: u32,
    bytes: []u8,

    pub fn init(gpa: Allocator, max_participants: u32, payload: anytype) !EncodedPayload {
        assert(max_participants > 0);
        const bytes = try codec.encode(@TypeOf(payload), gpa, payload);
        assert(bytes.len == payload.encode_size());
        return .{ .max_participants = max_participants, .bytes = bytes };
    }

    pub fn clone(self: EncodedPayload, gpa: Allocator) Allocator.Error!EncodedPayload {
        const bytes = try gpa.dupe(u8, self.bytes);
        return .{ .max_participants = self.max_participants, .bytes = bytes };
    }

    pub fn eql(a: EncodedPayload, b: EncodedPayload) bool {
        return a.max_participants == b.max_participants and std.mem.eql(u8, a.bytes, b.bytes);
    }

    pub fn write(self: EncodedPayload, writer: *codec.Writer) void {
        assert(self.max_participants > 0);
        codec.varint.write(u32, self.max_participants, writer);
        codec.varint.write(u32, @intCast(self.bytes.len), writer);
        writer.write_bytes(self.bytes);
    }

    pub fn encode_size(self: EncodedPayload) usize {
        return codec.varint.size(u32, self.max_participants) +
            codec.varint.size(u32, @intCast(self.bytes.len)) + self.bytes.len;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader) codec.Error!EncodedPayload {
        const max_participants = try codec.varint.read(u32, reader);
        if (max_participants == 0) return error.Invalid;
        const len = try codec.varint.read(u32, reader);
        const bytes = try gpa.dupe(u8, try reader.take(len));
        assert(bytes.len == len);
        return .{ .max_participants = max_participants, .bytes = bytes };
    }
};

/// A block that may carry an encoded reshare payload (commonware `MockBlock`). Its digest
/// hashes the parent, the big-endian height, the encoded context, the big-endian timestamp,
/// and the payload when present.
pub fn MockBlock(comptime Dir: type) type {
    return struct {
        const Self = @This();
        pub const Digest = TestDigest;
        pub const Context = TestContext;
        pub const Variant = TestBlsVariant;
        pub const PublicKey = TestPublicKey;
        pub const Directory = Dir;
        pub const Payload = types.Payload(Variant, PublicKey, Dir);
        /// The block's codec configuration: none.
        pub const Cfg = void;

        context_value: TestContext,
        parent_value: Digest,
        height_value: Height,
        timestamp: u64,
        /// Owned by the block.
        encoded: ?EncodedPayload,
        digest_value: Digest,

        pub fn init(context_value: TestContext, parent_digest: Digest, at: Height, ts: u64) Self {
            return from_parts(context_value, parent_digest, at, ts, null);
        }

        /// This block with `payload` encoded into it (takes nothing; copies the encoding).
        pub fn with_payload(self: Self, gpa: Allocator, max: u32, value: Payload) !Self {
            assert(self.encoded == null);
            const encoded = try EncodedPayload.init(gpa, max, value);
            const result = from_parts(
                self.context_value,
                self.parent_value,
                self.height_value,
                self.timestamp,
                encoded,
            );
            assert(!result.digest_value.eql(self.digest_value));
            return result;
        }

        fn from_parts(
            context_value: TestContext,
            parent_digest: Digest,
            at: Height,
            ts: u64,
            encoded: ?EncodedPayload,
        ) Self {
            var context_buffer: [TestContext.max_encode_size]u8 = undefined;
            var writer: codec.Writer = .init(&context_buffer);
            context_value.write(&writer);
            var height_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &height_bytes, at.get(), .big);
            var ts_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &ts_bytes, ts, .big);
            const head = .{ parent_digest.as_slice(), &height_bytes, writer.written(), &ts_bytes };
            const digest_value = if (encoded) |carried| blk: {
                var max_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &max_bytes, carried.max_participants, .big);
                var len_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &len_bytes, @intCast(carried.bytes.len), .big);
                const tail = .{ &[_]u8{1}, &max_bytes, &len_bytes, carried.bytes };
                break :blk Sha256.hash(&(head ++ tail));
            } else Sha256.hash(&(head ++ .{&[_]u8{0}}));
            return .{
                .context_value = context_value,
                .parent_value = parent_digest,
                .height_value = at,
                .timestamp = ts,
                .encoded = encoded,
                .digest_value = digest_value,
            };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.encoded) |encoded| gpa.free(encoded.bytes);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) Allocator.Error!Self {
            var copy = self;
            if (self.encoded) |encoded| copy.encoded = try encoded.clone(gpa);
            return copy;
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

        pub fn context(self: Self) TestContext {
            return self.context_value;
        }

        /// An owned copy of the carried payload; null when absent or undecodable.
        pub fn payload(self: Self, gpa: Allocator) Allocator.Error!?Payload {
            const encoded = self.encoded orelse return null;
            const cfg: types.InfoCfg = .{
                .max_participants = encoded.max_participants,
                .max_supported_mode = max_supported_mode,
            };
            return codec.decode_cfg(Payload, gpa, encoded.bytes, cfg) catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => null,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            const payloads_equal = if (a.encoded) |left|
                b.encoded != null and left.eql(b.encoded.?)
            else
                b.encoded == null;
            return payloads_equal and a.digest_value.eql(b.digest_value);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            self.context_value.write(writer);
            self.parent_value.write(writer);
            self.height_value.write(writer);
            codec.varint.write(u64, self.timestamp, writer);
            writer.write_byte(@intFromBool(self.encoded != null));
            if (self.encoded) |encoded| encoded.write(writer);
            self.digest_value.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            const encoded_size = if (self.encoded) |encoded| encoded.encode_size() else 0;
            return self.context_value.encode_size() + Digest.fixed_size +
                self.height_value.encode_size() + codec.varint.size(u64, self.timestamp) + 1 +
                encoded_size + Digest.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const context_value = try TestContext.read(gpa, reader, {});
            const parent_digest = try Digest.read(gpa, reader, {});
            const at = try Height.read(gpa, reader, {});
            const ts = try codec.varint.read(u64, reader);
            const encoded: ?EncodedPayload = if (try codec.read(bool, gpa, reader))
                try EncodedPayload.read(gpa, reader)
            else
                null;
            errdefer if (encoded) |value| gpa.free(value.bytes);
            const digest_value = try Digest.read(gpa, reader, {});
            return .{
                .context_value = context_value,
                .parent_value = parent_digest,
                .height_value = at,
                .timestamp = ts,
                .encoded = encoded,
                .digest_value = digest_value,
            };
        }
    };
}

/// The genesis block led by `leader` (commonware `genesis_block`).
pub fn genesis_block(leader: TestPublicKey) TestBlock {
    const digest = Sha256.hash(&.{""});
    const context: TestContext = .{
        .round = .new(.zero(), .zero()),
        .leader = leader,
        .parent = .{ .zero(), digest },
    };
    return .init(context, digest, .zero(), 0);
}

/// The canonical child of `parent` (commonware `child`).
pub fn child(parent: *const TestBlock) TestBlock {
    const at = parent.height().next();
    return .init(parent.context(), parent.digest(), at, at.get());
}

/// A reshare recovery store over the in-memory secret store.
pub const TestStore = reshare_store.Store(TestBlsVariant, TestPublicKey, Unit, MemorySecretStore);

/// The storage and page cache reshare recovery stores reopen over after a restart (commonware
/// `mocks::store`, with its one-page cache and 1 KiB buffers).
pub const StoreHarness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,

    pub fn init(gpa: Allocator) !StoreHarness {
        return .{ .storage = .init(gpa), .cache_ref = try .init(gpa, 1024, 10) };
    }

    pub fn deinit(self: *StoreHarness) void {
        self.cache_ref.deinit();
        self.storage.deinit();
        self.* = undefined;
    }

    /// Opens (or reopens) the store under `partition` over `secrets`.
    pub fn open(
        self: *StoreHarness,
        gpa: Allocator,
        partition: []const u8,
        secrets: *MemorySecretStore,
    ) !TestStore {
        assert(partition.len > 0);
        return TestStore.init(gpa, self.storage.interface(), .{
            .partition_prefix = partition,
            .max_participants = 16,
            .cache_ref = &self.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        }, secrets);
    }
};

/// Secret material kept in memory (commonware's `MemorySecretStore`), recording every prune.
pub const MemorySecretStore = struct {
    gpa: Allocator,
    shares: std.ArrayList(struct { u64, Share }) = .empty,
    seeds: std.ArrayList(struct { u64, Summary }) = .empty,
    dealings: std.ArrayList(struct { u64, TestPublicKey, fd.DealerPrivMsg }) = .empty,
    prunes: std.ArrayList(u64) = .empty,
    /// Set by `stall`: the next `put_share` persists its share, then blocks on this `Io`
    /// until canceled.
    stall_io: ?Io = null,

    pub fn init(allocator: Allocator) MemorySecretStore {
        return .{ .gpa = allocator };
    }

    pub fn deinit(self: *MemorySecretStore) void {
        self.shares.deinit(self.gpa);
        self.seeds.deinit(self.gpa);
        self.dealings.deinit(self.gpa);
        self.prunes.deinit(self.gpa);
    }

    pub fn has_share(self: *const MemorySecretStore, epoch: Epoch) bool {
        for (self.shares.items) |entry| if (entry[0] == epoch.get()) return true;
        return false;
    }

    /// Makes the next `put_share` persist its share and then never return (commonware
    /// `stall`): it blocks on `io` until its task is canceled.
    pub fn stall(self: *MemorySecretStore, io: Io) void {
        assert(self.stall_io == null);
        self.stall_io = io;
    }

    pub fn put_share(self: *MemorySecretStore, epoch: Epoch, share: Share) !void {
        try self.insert_share(epoch, share);
        const io = self.stall_io orelse return;
        self.stall_io = null;
        assert(self.has_share(epoch));
        while (true) try io.sleep(.fromSeconds(3600), .awake);
    }

    fn insert_share(self: *MemorySecretStore, epoch: Epoch, share: Share) !void {
        for (self.shares.items) |*entry| if (entry[0] == epoch.get()) {
            entry[1] = share;
            return;
        };
        try self.shares.append(self.gpa, .{ epoch.get(), share });
    }

    pub fn get_share(self: *MemorySecretStore, epoch: Epoch) !?Share {
        for (self.shares.items) |entry| if (entry[0] == epoch.get()) return entry[1];
        return null;
    }

    pub fn put_seed(self: *MemorySecretStore, epoch: Epoch, seed: Summary) !void {
        for (self.seeds.items) |*entry| if (entry[0] == epoch.get()) {
            entry[1] = seed;
            return;
        };
        try self.seeds.append(self.gpa, .{ epoch.get(), seed });
    }

    pub fn get_seed(self: *MemorySecretStore, epoch: Epoch) !?Summary {
        for (self.seeds.items) |entry| if (entry[0] == epoch.get()) return entry[1];
        return null;
    }

    pub fn put_dealing(
        self: *MemorySecretStore,
        epoch: Epoch,
        dealer: TestPublicKey,
        private: fd.DealerPrivMsg,
    ) !void {
        for (self.dealings.items) |*entry| if (entry[0] == epoch.get() and entry[1].eql(dealer)) {
            entry[2] = private;
            return;
        };
        try self.dealings.append(self.gpa, .{ epoch.get(), dealer, private });
    }

    pub fn get_dealing(
        self: *MemorySecretStore,
        epoch: Epoch,
        dealer: TestPublicKey,
    ) !?fd.DealerPrivMsg {
        for (self.dealings.items) |entry| {
            if (entry[0] == epoch.get() and entry[1].eql(dealer)) return entry[2];
        }
        return null;
    }

    pub fn prune(self: *MemorySecretStore, min: Epoch) !void {
        try self.prunes.append(self.gpa, min.get());
        retain(@TypeOf(self.shares.items[0]), &self.shares, min.get());
        retain(@TypeOf(self.seeds.items[0]), &self.seeds, min.get());
        retain(@TypeOf(self.dealings.items[0]), &self.dealings, min.get());
    }

    fn retain(comptime T: type, list: *std.ArrayList(T), min: u64) void {
        var kept: usize = 0;
        for (list.items) |entry| {
            if (entry[0] < min) continue;
            list.items[kept] = entry;
            kept += 1;
        }
        list.shrinkRetainingCapacity(kept);
    }
};

/// A participants provider that returns the same set for every epoch, with a key-only
/// directory (commonware `StaticParticipants`).
pub const StaticParticipants = struct {
    pub const PublicKey = TestPublicKey;
    pub const Directory = Unit;

    participants_value: Set(TestPublicKey),

    pub fn participants(
        self: *StaticParticipants,
        io: Io,
        gpa: Allocator,
        epoch: Epoch,
    ) !Set(TestPublicKey) {
        _ = io;
        _ = epoch;
        assert(self.participants_value.len() > 0);
        return self.participants_value.clone(gpa);
    }

    pub fn directory(
        self: *StaticParticipants,
        io: Io,
        gpa: Allocator,
        epoch: Epoch,
        peers: Set(TestPublicKey),
    ) !Unit {
        _ = .{ self, io, gpa, epoch, peers };
        return .{};
    }
};

/// A registrar that records each epoch it enters (commonware `MockConsumer`).
pub const MockConsumer = struct {
    pub const Variant = TestBlsVariant;
    pub const PublicKey = TestPublicKey;

    gpa: Allocator,
    entered: std.ArrayList(u64) = .empty,

    pub fn init(gpa: Allocator) MockConsumer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *MockConsumer) void {
        self.entered.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn register(
        self: *MockConsumer,
        io: Io,
        epoch: Epoch,
        info: types.SchemeInfo(Variant, PublicKey),
    ) !void {
        _ = io;
        var owned = info;
        owned.deinit(self.gpa);
        try self.entered.append(self.gpa, epoch.get());
        assert(self.entered.items.len > 0);
    }
};

/// A marshal reader with no running actor: every read is unavailable (commonware
/// `closed_marshal_mailbox`).
pub const ClosedMarshal = struct {
    const Digested = @import("broadcast").Digested(TestBlock);

    pub fn get_block(self: ClosedMarshal, identifier: anytype) !?Digested {
        _ = .{ self, identifier };
        return null;
    }
};

/// A key-only DKG manager that records nothing and never fails.
pub const InertManager = struct {
    pub const PublicKey = TestPublicKey;
    pub const Directory = Unit;

    tracked: u32 = 0,

    pub fn track(self: *InertManager, epoch: Epoch, peers: anytype, directory: *const Unit) !void {
        _ = .{ epoch, peers, directory };
        self.tracked += 1;
        assert(self.tracked > 0);
    }
};

/// A blocker that records the peers it blocks.
pub const MockBlocker = struct {
    pub const PublicKey = TestPublicKey;

    gpa: Allocator,
    blocked: std.ArrayList(TestPublicKey) = .empty,

    pub fn init(gpa: Allocator) MockBlocker {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *MockBlocker) void {
        self.blocked.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn block(self: *MockBlocker, peer: TestPublicKey) void {
        self.blocked.append(self.gpa, peer) catch @panic("mock blocker out of memory");
        assert(self.blocked.items.len > 0);
    }
};

/// The reshare actor's type parameters over these mocks.
pub const ActorTypes = struct {
    pub const Block = TestBlock;
    pub const Ack = utils.acknowledgement.Exact;
    pub const Ancestry = consensus.marshal.ancestry.Bounded(TestBlock);
    pub const Signer = TestSigner;
    pub const Manager = InertManager;
    pub const Blocker = MockBlocker;
    pub const Provider = StaticParticipants;
    pub const SecretStore = MemorySecretStore;
    pub const Registrar = MockConsumer;
    pub const Marshal = ClosedMarshal;
    pub const Strategy = @import("parallel").Sequential;
};

comptime {
    @import("../root.zig").assert_reshare_block(TestBlock);
    @import("../root.zig").assert_secret_store(MemorySecretStore);
    @import("../root.zig").assert_participants_provider(StaticParticipants);
    @import("../root.zig").assert_registrar(MockConsumer);
}
