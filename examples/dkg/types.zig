//! Types, constants, and storage shared across the example (commonware
//! `examples/dkg/src/types.rs`).
//!
//! `Block` is the chain block: its consensus context, parent, height, the QMDB sync target its
//! state commits to, and an optional reshare payload. `Participants` rotates the committee
//! over the ordered participant list. `Secrets` keeps private DKG material in one metadata
//! partition of the node's storage. Genesis (`genesis.json`) holds the hex-encoded epoch-0
//! `EpochInfo`. Encodings and files are byte-identical to commonware's (testdata/).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const config = @import("config.zig");

const codec = zigware.codec;
const utils = zigware.utils;
const consensus = zigware.consensus;
const cryptography = zigware.cryptography;
const storage = zigware.storage;
const glue_dkg = zigware.glue.dkg;
const primitives = cryptography.bls12381.primitives;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const formatting = zigware.formatting;

pub const ed25519 = cryptography.ed25519;
pub const PublicKey = ed25519.PublicKey;
pub const MinSig = primitives.MinSig;
pub const Digest = cryptography.sha256.Digest;
pub const Sha256 = cryptography.Sha256;
pub const Epoch = consensus.Epoch;
pub const Height = consensus.Height;
pub const Set = utils.ordered.Set;
pub const Unit = utils.sequence.Unit;
pub const Share = primitives.group.Share;
pub const Summary = cryptography.transcript.Summary;
pub const DealerPrivMsg = fd.DealerPrivMsg;
pub const Context = consensus.simplex.types.Context(Digest, PublicKey);
pub const Family = storage.mmr.Family;
pub const Target = storage.qmdb.sync.Target(Family, Digest);
pub const Payload = glue_dkg.types.Payload(MinSig, PublicKey, Unit);
pub const EpochInfo = glue_dkg.types.EpochInfo(MinSig, PublicKey, Unit);

/// Globally unique namespace for every message signed by this example.
pub const namespace = "_COMMONWARE_EXAMPLES_DKG";
/// Number of blocks in each epoch.
pub const blocks_per_epoch: u64 = 64;
/// Maximum entries accepted in each DKG participant set.
pub const max_participants: u32 = 64;
/// Share derivation mode used by bootstrap and reshare ceremonies.
pub const sharing_mode: primitives.Mode = .non_zero_counter;
/// Revealed-share calculation used by bootstrap and reshare ceremonies.
pub const reveal: fd.Reveal = .v1;
/// Newest sharing mode version this binary accepts.
pub const max_supported_mode: primitives.sharing.ModeVersion = .v0;
/// Codec config of payloads and epoch infos.
pub const info_cfg: glue_dkg.types.InfoCfg = .{
    .max_participants = max_participants,
    .max_supported_mode = max_supported_mode,
};
/// Page size for storage page caches.
pub const page_size: u16 = 1024;
/// Number of pages held by each page cache.
pub const page_cache_size: usize = 16;
/// Buffer size for journal replay and writes.
pub const io_buffer_size: usize = 2048;
/// P2P channel carrying simplex votes.
pub const vote_channel: u64 = 0;
/// P2P channel carrying simplex certificates.
pub const certificate_channel: u64 = 1;
/// P2P channel for orchestrator resolver traffic.
pub const resolver_channel: u64 = 2;
/// P2P channel for marshal block backfill.
pub const backfill_channel: u64 = 3;
/// P2P channel for proposed block broadcast.
pub const broadcast_channel: u64 = 4;
/// P2P channel for QMDB state sync.
pub const qmdb_channel: u64 = 5;
/// P2P channel for private reshare dealings and acks.
pub const dkg_channel: u64 = 6;
/// P2P channel for the DKG probe.
pub const dkg_probe_channel: u64 = 7;
/// Mailbox capacity for every actor.
pub const mailbox_size: usize = 100;
/// Finalized blocks and certificates per archive section.
pub const items_per_section: u64 = 10;
/// Per-peer messages per second on every P2P channel.
pub const message_rate_per_second: u32 = 128;
/// Operations per state sync request. Validators fetch and serve the same size, since peers
/// ignore requests larger than they serve.
pub const sync_batch_size: u64 = 16;

comptime {
    assert(blocks_per_epoch > 0);
    assert(max_participants > 0);
    assert(utils.N3f1.quorum(max_participants) <= max_participants);
}

/// Chain block carrying the QMDB state root and an optional reshare payload. Owns its payload;
/// its digest (SHA-256 of the encoding) is computed once, at construction.
pub const Block = struct {
    context_value: block_context,
    parent_value: types_digest,
    height_value: Height,
    /// The state root and the range of operations it covers.
    target: Target,
    payload_value: ?Payload,
    digest_value: types_digest,

    pub const Variant = MinSig;
    pub const PublicKey = ed25519.PublicKey;
    pub const Directory = Unit;
    pub const Context = block_context;
    pub const Digest = types_digest;

    /// The encoded-size bound: the widest context, height, range, and reshare payload.
    pub const max_encode_size: usize = Payload.max_encode_size_with(max_participants) +
        block_context.max_encode_size + types_digest.fixed_size + Height.max_encode_size +
        types_digest.fixed_size + 2 * codec.varint.max_size(u64) + 1;

    /// A block taking ownership of `payload`.
    pub fn init(
        gpa: Allocator,
        context_value: block_context,
        parent_value: types_digest,
        height_value: Height,
        target: Target,
        payload_value: ?Payload,
    ) Allocator.Error!Block {
        var block: Block = .{
            .context_value = context_value,
            .parent_value = parent_value,
            .height_value = height_value,
            .target = target,
            .payload_value = payload_value,
            .digest_value = undefined,
        };
        const encoded = try codec.encode(Block, gpa, block);
        defer gpa.free(encoded);
        block.digest_value = Sha256.hash(&.{encoded});
        assert(encoded.len <= max_encode_size);
        return block;
    }

    /// The genesis block: epoch 0, view 0, an empty parent, and the epoch-0 info, which it
    /// takes ownership of.
    pub fn genesis(
        gpa: Allocator,
        leader: ed25519.PublicKey,
        info: EpochInfo,
        target: Target,
    ) Allocator.Error!Block {
        const empty: types_digest = .empty;
        const start: block_context = .{
            .round = .new(.zero(), .zero()),
            .leader = leader,
            .parent = .{ .zero(), empty },
        };
        return init(gpa, start, empty, .zero(), target, .{ .epoch_info = info });
    }

    pub fn deinit(self: *Block, gpa: Allocator) void {
        if (self.payload_value) |*value| value.deinit(gpa);
        self.* = undefined;
    }

    pub fn clone(self: Block, gpa: Allocator) Allocator.Error!Block {
        var copy = self;
        if (self.payload_value) |value| copy.payload_value = try value.clone(gpa);
        assert(copy.digest_value.eql(self.digest_value));
        return copy;
    }

    pub fn eql(a: Block, b: Block) bool {
        if (!a.digest_value.eql(b.digest_value)) return false;
        if ((a.payload_value == null) != (b.payload_value == null)) return false;
        const same_payload = a.payload_value == null or a.payload_value.?.eql(b.payload_value.?);
        return same_payload and a.context_value.eql(b.context_value) and
            a.parent_value.eql(b.parent_value) and a.height_value == b.height_value and
            a.target.eql(b.target);
    }

    pub fn digest(self: Block) types_digest {
        return self.digest_value;
    }

    pub fn height(self: Block) Height {
        return self.height_value;
    }

    pub fn parent(self: Block) types_digest {
        return self.parent_value;
    }

    pub fn context(self: Block) block_context {
        return self.context_value;
    }

    /// An owned copy of the reshare payload, if the block carries one.
    pub fn payload(self: Block, gpa: Allocator) Allocator.Error!?Payload {
        const value = self.payload_value orelse return null;
        return try value.clone(gpa);
    }

    pub fn write(self: Block, writer: *codec.Writer) void {
        self.context_value.write(writer);
        self.parent_value.write(writer);
        self.height_value.write(writer);
        self.target.write(writer);
        writer.write_byte(@intFromBool(self.payload_value != null));
        if (self.payload_value) |value| value.write(writer);
    }

    pub fn encode_size(self: Block) usize {
        const payload_size = if (self.payload_value) |value| value.encode_size() else 0;
        return self.context_value.encode_size() + types_digest.fixed_size +
            self.height_value.encode_size() + self.target.encode_size() + 1 + payload_size;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Block {
        const context_value = try block_context.read(gpa, reader, {});
        const parent_value = try codec.read(types_digest, gpa, reader);
        const height_value = try Height.read(gpa, reader, {});
        const target = try Target.read(gpa, reader, {});
        var payload_value: ?Payload = null;
        if (try codec.read(bool, gpa, reader)) {
            payload_value = try Payload.read(gpa, reader, info_cfg);
        }
        errdefer if (payload_value) |*value| value.deinit(gpa);
        return init(gpa, context_value, parent_value, height_value, target, payload_value);
    }
};

const types_digest = Digest;
const block_context = Context;

comptime {
    consensus.traits.assert_certifiable_block(Block);
    glue_dkg.assert_reshare_block(Block);
}

/// Deterministic committee rotation over the ordered participant list.
pub const Participants = struct {
    ordered: []const ed25519.PublicKey,
    committee_size: u64,

    pub const PublicKey = ed25519.PublicKey;
    pub const Directory = Unit;

    /// The rotation for a validated network config; copies its participants.
    pub fn init(gpa: Allocator, network: *const config.NetworkConfig) !Participants {
        try network.validate();
        return .{
            .ordered = try gpa.dupe(ed25519.PublicKey, network.participants),
            .committee_size = network.committee_size,
        };
    }

    pub fn deinit(self: *Participants, gpa: Allocator) void {
        gpa.free(self.ordered);
        self.* = undefined;
    }

    /// The committee for `epoch`: `committee_size` consecutive participants starting at offset
    /// `epoch % participants.len()`, with wraparound.
    pub fn get(self: *const Participants, gpa: Allocator, epoch: Epoch) !Set(ed25519.PublicKey) {
        const count = self.ordered.len;
        assert(count > 0);
        assert(self.committee_size > 0 and self.committee_size <= count);
        const players = try gpa.alloc(ed25519.PublicKey, @intCast(self.committee_size));
        const offset: usize = @intCast(epoch.get() % count);
        for (players, 0..) |*player, index| player.* = self.ordered[(offset + index) % count];
        return Set(ed25519.PublicKey).from_owned_dedup(gpa, players);
    }

    /// `ParticipantsProvider::participants`.
    pub fn participants(
        self: *Participants,
        io: Io,
        gpa: Allocator,
        epoch: Epoch,
    ) !Set(ed25519.PublicKey) {
        _ = io;
        return self.get(gpa, epoch);
    }

    /// `ParticipantsProvider::directory`: this example has no transport directory.
    pub fn directory(
        self: *Participants,
        io: Io,
        gpa: Allocator,
        epoch: Epoch,
        peers: Set(ed25519.PublicKey),
    ) !Unit {
        _ = .{ self, io, gpa, epoch, peers };
        return .{};
    }
};

comptime {
    glue_dkg.assert_participants_provider(Participants);
}

/// Key kinds in `Secrets`.
const Kind = enum(u8) { share = 0, seed = 1, dealing = 2 };

/// Size of a `Secrets` key: the kind, the big-endian epoch, and the SHA-256 digest of the
/// dealer's public key (zero for shares and seeds).
const key_size = 1 + 8 + Digest.fixed_size;
const Key = [key_size]u8;
const Store = storage.metadata.Metadata(Key, []const u8);

/// The key of the `kind` entry for `epoch` and, for a dealing, `dealer`.
fn secret_key(kind: Kind, epoch: Epoch, dealer: ?Digest) Key {
    assert((kind == .dealing) == (dealer != null));
    var key = std.mem.zeroes(Key);
    key[0] = @backingInt(kind);
    std.mem.writeInt(u64, key[1..9], epoch.get(), .big);
    if (dealer) |digest| @memcpy(key[9..], digest.as_slice());
    return key;
}

/// The epoch encoded in `key`.
fn key_epoch(key: Key) Epoch {
    return .new(std.mem.readInt(u64, key[1..9], .big));
}

/// The runtime storage partition of a `Secrets` store. The bootstrap and the validator's first
/// reshare both persist dealer seeds and received dealings for epoch 0, so each uses its own.
pub const Partition = enum {
    /// `bootstrap-secrets`, used by `bootstrap`.
    bootstrap,
    /// `secrets`, used by `validator` for the epoch-0 share that `bootstrap` hands over and
    /// for every reshare's material.
    validator,

    pub fn name(partition: Partition) []const u8 {
        return switch (partition) {
            .bootstrap => "bootstrap-secrets",
            .validator => "secrets",
        };
    }
};

/// Shares, dealer seeds, and dealings in one `Partition` of the node's storage (the glue
/// `SecretStore`). Callers share one store by pointer. Material is stored unencrypted, which
/// suits this example only. Every put and prune is synced before it returns, and every get
/// reads from memory. A failed write leaves the store unusable (later calls fail).
pub const Secrets = struct {
    io: Io,
    gpa: Allocator,
    mutex: Io.Mutex = .init,
    metadata: ?Store,

    pub const Error = Store.Error || codec.Error || error{SecretsFailed};

    /// Opens the store in `partition`, starting empty if nothing was stored.
    pub fn init(
        io: Io,
        gpa: Allocator,
        backend: zigware.runtime.storage.Storage,
        partition: Partition,
    ) Store.Error!Secrets {
        const metadata = try Store.init(gpa, backend, .{
            .partition = partition.name(),
            .codec_config = .{ .range = .full(), .item = {} },
        });
        return .{ .io = io, .gpa = gpa, .metadata = metadata };
    }

    pub fn deinit(self: *Secrets) void {
        if (self.metadata) |*metadata| metadata.deinit();
        self.* = undefined;
    }

    /// Removes the store's partition and everything in it, then frees the store.
    pub fn destroy(self: *Secrets) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var metadata = self.metadata orelse return error.SecretsFailed;
        self.metadata = null;
        try metadata.destroy();
    }

    fn get(self: *Secrets, comptime T: type, key: Key) Error!?T {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const metadata = &(self.metadata orelse return error.SecretsFailed);
        const value = metadata.get(key) orelse return null;
        return try codec.decode(T, self.gpa, value.*);
    }

    fn put(self: *Secrets, comptime T: type, key: Key, value: T) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const metadata = &(self.metadata orelse return error.SecretsFailed);
        const encoded = try codec.encode(T, self.gpa, value);
        const previous = metadata.put(key, encoded) catch |err| {
            std.crypto.secureZero(u8, encoded);
            self.gpa.free(encoded);
            return err;
        };
        if (previous) |old| self.gpa.free(old);
        try self.sync_or_fail(metadata);
    }

    /// Syncs, or on failure drops the store, which the failed sync left unusable.
    fn sync_or_fail(self: *Secrets, metadata: *Store) Error!void {
        assert(self.metadata != null);
        metadata.sync() catch |err| {
            metadata.deinit();
            self.metadata = null;
            return err;
        };
        assert(self.metadata != null);
    }

    pub fn put_share(self: *Secrets, epoch: Epoch, share: Share) Error!void {
        try self.put(Share, secret_key(.share, epoch, null), share);
    }

    pub fn get_share(self: *Secrets, epoch: Epoch) Error!?Share {
        return self.get(Share, secret_key(.share, epoch, null));
    }

    pub fn put_seed(self: *Secrets, epoch: Epoch, seed: Summary) Error!void {
        try self.put(Summary, secret_key(.seed, epoch, null), seed);
    }

    pub fn get_seed(self: *Secrets, epoch: Epoch) Error!?Summary {
        return self.get(Summary, secret_key(.seed, epoch, null));
    }

    pub fn put_dealing(
        self: *Secrets,
        epoch: Epoch,
        dealer: anytype,
        private: DealerPrivMsg,
    ) Error!void {
        const key = secret_key(.dealing, epoch, dealer_digest(dealer));
        try self.put(DealerPrivMsg, key, private);
    }

    pub fn get_dealing(self: *Secrets, epoch: Epoch, dealer: anytype) Error!?DealerPrivMsg {
        return self.get(DealerPrivMsg, secret_key(.dealing, epoch, dealer_digest(dealer)));
    }

    /// Durably drops every secret of an epoch below `min`.
    pub fn prune(self: *Secrets, min: Epoch) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const metadata = &(self.metadata orelse return error.SecretsFailed);
        metadata.retain(min, keep_from);
        try self.sync_or_fail(metadata);
    }

    fn keep_from(min: Epoch, key: Key, _: *const []const u8) bool {
        return key_epoch(key).get() >= min.get();
    }

    /// SHA-256 of the dealer's codec encoding.
    fn dealer_digest(dealer: anytype) Digest {
        const P = @TypeOf(dealer);
        var bytes: [codec.fixed_size(P).?]u8 = undefined;
        _ = codec.encode_to(P, dealer, &bytes);
        return Sha256.hash(&.{&bytes});
    }
};

comptime {
    glue_dkg.assert_secret_store(Secrets);
}

/// The genesis artifact's file name inside a node directory.
pub const genesis_file = "genesis.json";

/// Reads the genesis epoch info from `node_dir`. Caller owns the result.
pub fn read_genesis(io: Io, gpa: Allocator, node_dir: Io.Dir) !EpochInfo {
    const limit: Io.Limit = .limited(config.max_file_bytes);
    const text = try node_dir.readFileAlloc(io, genesis_file, gpa, limit);
    defer gpa.free(text);
    return parse_genesis(gpa, text);
}

/// Parses `{"epoch_info": "<hex>"}`.
pub fn parse_genesis(gpa: Allocator, text: []const u8) !EpochInfo {
    const parsed = try config.parse_json(struct { epoch_info: []const u8 }, gpa, text);
    defer parsed.deinit();
    const bytes = try formatting.from_hex(gpa, parsed.value.epoch_info) orelse
        return error.InvalidHex;
    defer gpa.free(bytes);
    return codec.decode_cfg(EpochInfo, gpa, bytes, info_cfg);
}

/// Writes the genesis epoch info into `node_dir`, overwriting an existing artifact that cannot
/// be parsed (such as one torn by a crash mid-write; `bootstrap` re-derives it from its own
/// finalized chain) and refusing to overwrite a different one.
pub fn write_genesis(io: Io, gpa: Allocator, node_dir: Io.Dir, info: EpochInfo) !void {
    const limit: Io.Limit = .limited(config.max_file_bytes);
    const existing: ?[]u8 = node_dir.readFileAlloc(io, genesis_file, gpa, limit) catch |err|
        switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
    if (existing) |text| {
        defer gpa.free(text);
        if (parse_genesis(gpa, text)) |parsed| {
            var owned = parsed;
            defer owned.deinit(gpa);
            if (!owned.eql(info)) return error.GenesisConflict;
            return;
        } else |err| if (err == error.OutOfMemory) return err;
    }
    const encoded = try codec.encode(EpochInfo, gpa, info);
    defer gpa.free(encoded);
    try config.write_json(io, node_dir, genesis_file, GenesisFile{ .encoded = encoded });
}

const GenesisFile = struct {
    encoded: []const u8,

    pub fn write(self: GenesisFile, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("{{\n  \"epoch_info\": \"{f}\"\n}}", .{formatting.fmt_hex(self.encoded)});
    }
};
