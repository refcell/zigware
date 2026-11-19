//! Tests for `types.zig`, ported from commonware's `examples/dkg/src/types.rs`, plus block and
//! genesis vectors printed by commonware's own types (testdata/).

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const config = @import("config.zig");
const types = @import("types.zig");

const codec = zigware.codec;
const ed25519 = zigware.cryptography.ed25519;
const fd = zigware.cryptography.bls12381.dkg.feldman_desmedt;
const Scalar = zigware.cryptography.bls12381.primitives.group.Scalar;
const MockStorage = zigware.runtime.buffer.mocks.Storage;
const formatting = zigware.formatting;
const Block = types.Block;
const Epoch = types.Epoch;
const gpa = testing.allocator;
const io = testing.io;

fn keys(comptime n: usize) [n]ed25519.PublicKey {
    var rng = zigware.utils.rng.TestRng.init(0);
    var out: [n]ed25519.PublicKey = undefined;
    for (&out) |*key| key.* = ed25519.PrivateKey.random(&rng).public_key();
    return out;
}

const Dealt = fd.Dealt(types.MinSig, ed25519.PublicKey);

fn deal(rng: anytype, players: types.Set(ed25519.PublicKey)) !Dealt {
    const N3f1 = zigware.utils.N3f1;
    return fd.deal(types.MinSig, ed25519.PublicKey, N3f1, gpa, rng, types.sharing_mode, players);
}

fn hash(text: []const u8) types.Digest {
    return types.Sha256.hash(&.{text});
}

fn expect_hex(expected: []const u8, bytes: []const u8) !void {
    const shown = try formatting.hex(gpa, bytes);
    defer gpa.free(shown);
    try testing.expectEqualStrings(expected, shown);
}

/// The epoch-0 info commonware's tests deal: `deal(TestRng::new(2), ...)` to `players`.
fn dealt_info(players: []const ed25519.PublicKey) !types.EpochInfo {
    var rng = zigware.utils.rng.TestRng.init(2);
    const set = try types.Set(ed25519.PublicKey).from_dedup(gpa, players);
    var dealt = try deal(&rng, set);
    errdefer dealt.output.deinit(gpa);
    dealt.shares.deinit(gpa);
    var info_players = try dealt.output.players.clone(gpa);
    errdefer info_players.deinit(gpa);
    return .{
        .outcome = .success,
        .epoch = .zero(),
        .output = dealt.output,
        .players = info_players,
        .next_players = try dealt.output.players.clone(gpa),
        .directory = .{},
    };
}

test "dkg: block encoding and digest match commonware" {
    const leader = ed25519.PrivateKey.from_seed(0).public_key();
    var block = try Block.init(gpa, .{
        .round = .new(.new(3), .new(5)),
        .leader = leader,
        .parent = .{ .new(4), hash("parent") },
    }, hash("parent"), .new(7), .init(hash("state"), 2, 9), null);
    defer block.deinit(gpa);
    const encoded = try codec.encode(Block, gpa, block);
    defer gpa.free(encoded);
    try expect_hex(std.mem.trim(u8, @embedFile("testdata/block.hex"), "\n"), encoded);
    try expect_hex(
        "8b269c2d2c5d52c1417a50cda77270376980aca4119422fd6d56d574f40fb9a5",
        block.digest().as_slice(),
    );
    var decoded = try codec.decode(Block, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(block));
    try testing.expect(try decoded.payload(gpa) == null);
}

test "dkg: genesis block and genesis.json match commonware" {
    const a = ed25519.PrivateKey.from_seed(1).public_key();
    const b = ed25519.PrivateKey.from_seed(2).public_key();
    var info = try dealt_info(&.{ a, b });
    defer info.deinit(gpa);
    const leader = ed25519.PrivateKey.from_seed(0).public_key();
    var genesis = try Block.genesis(gpa, leader, try info.clone(gpa), .init(hash("genesis"), 0, 1));
    defer genesis.deinit(gpa);
    const encoded = try codec.encode(Block, gpa, genesis);
    defer gpa.free(encoded);
    try expect_hex(@embedFile("testdata/genesis_block.hex"), encoded);
    try expect_hex(
        "2a6912ef7dfa4d30976fcba0e831924b354351b9afca8c9dcdc40e080d603e00",
        genesis.digest().as_slice(),
    );
    var payload = (try genesis.payload(gpa)).?;
    defer payload.deinit(gpa);
    try testing.expect(payload.epoch_info.eql(info));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try types.write_genesis(io, gpa, tmp.dir, info);
    const written = try tmp.dir.readFileAlloc(io, types.genesis_file, gpa, .limited(1 << 16));
    defer gpa.free(written);
    try testing.expectEqualStrings(@embedFile("testdata/genesis.json"), written);
}

test "dkg: max encode size covers widest block" {
    // The widest payload-free block decodes, and the bound adds the unused width of its range
    // and the widest reshare payload.
    const max_leaves = types.Family.max_leaves;
    const widest: types.Target = .init(hash("state"), max_leaves - 1, max_leaves);
    var block = try Block.init(gpa, .{
        .round = .new(.new(std.math.maxInt(u64)), .new(std.math.maxInt(u64))),
        .leader = keys(1)[0],
        .parent = .{ .new(std.math.maxInt(u64)), hash("parent") },
    }, hash("parent"), .new(std.math.maxInt(u64)), widest, null);
    defer block.deinit(gpa);
    const encoded = try codec.encode(Block, gpa, block);
    defer gpa.free(encoded);
    var decoded = try codec.decode(Block, gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(block));
    // `NonEmptyRange<Location>::MAX_ENCODE_SIZE` is two `u64` varints.
    const range_slack = 2 * codec.varint.max_size(u64) - 2 * codec.varint.size(u64, max_leaves);
    try testing.expectEqual(
        Block.max_encode_size,
        encoded.len + range_slack + types.Payload.max_encode_size_with(types.max_participants),
    );
    // commonware's `Block::max_encode_size(&())`.
    try testing.expectEqual(16652, Block.max_encode_size);
}

test "dkg: block decoding refuses a bad payload flag and an empty range" {
    const leader = ed25519.PrivateKey.from_seed(0).public_key();
    var block = try Block.init(gpa, .{
        .round = .new(.new(1), .new(1)),
        .leader = leader,
        .parent = .{ .new(0), hash("parent") },
    }, hash("parent"), .new(1), .init(hash("state"), 0, 1), null);
    defer block.deinit(gpa);
    const encoded = try codec.encode(Block, gpa, block);
    defer gpa.free(encoded);
    encoded[encoded.len - 1] = 2;
    try testing.expect(std.meta.isError(codec.decode(Block, gpa, encoded)));
    // The range is the two bytes before the flag: make it [1, 1).
    encoded[encoded.len - 1] = 0;
    encoded[encoded.len - 3] = 1;
    try testing.expect(std.meta.isError(codec.decode(Block, gpa, encoded)));
}

test "dkg: participants rotate with wraparound" {
    const participants = keys(4);
    const network: config.NetworkConfig = .{
        .participants = &participants,
        .committee_size = 3,
        .peers = &.{},
    };
    var provider = try types.Participants.init(gpa, &network);
    defer provider.deinit(gpa);
    var committee = try provider.get(gpa, .new(2));
    defer committee.deinit(gpa);
    var expected = try types.Set(ed25519.PublicKey).from_dedup(
        gpa,
        &.{ participants[2], participants[3], participants[0] },
    );
    defer expected.deinit(gpa);
    try testing.expect(committee.eql(expected));

    // Epochs past the participant count wrap: epoch 5 starts at participant 1.
    var wrapped = try provider.participants(io, gpa, .new(5));
    defer wrapped.deinit(gpa);
    var expected_wrapped = try types.Set(ed25519.PublicKey).from_dedup(
        gpa,
        &.{ participants[1], participants[2], participants[3] },
    );
    defer expected_wrapped.deinit(gpa);
    try testing.expect(wrapped.eql(expected_wrapped));
}

test "dkg: invalid committee size rejected" {
    const network: config.NetworkConfig = .{
        .participants = &keys(2),
        .committee_size = 3,
        .peers = &.{},
    };
    try testing.expectError(
        error.CommitteeExceedsParticipants,
        types.Participants.init(gpa, &network),
    );
}

test "dkg: genesis conflict detection" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var info = try dealt_info(&keys(2));
    defer info.deinit(gpa);
    try types.write_genesis(io, gpa, tmp.dir, info);
    try types.write_genesis(io, gpa, tmp.dir, info);
    info.epoch = .new(1);
    try testing.expectError(error.GenesisConflict, types.write_genesis(io, gpa, tmp.dir, info));
}

test "dkg: genesis replaces unreadable artifact" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var info = try dealt_info(&keys(2));
    defer info.deinit(gpa);

    // An empty or truncated artifact, as a crash mid-write leaves, is overwritten.
    try types.write_genesis(io, gpa, tmp.dir, info);
    const contents = try tmp.dir.readFileAlloc(io, types.genesis_file, gpa, .limited(1 << 16));
    defer gpa.free(contents);
    for ([_]usize{ 0, contents.len / 2 }) |len| {
        try tmp.dir.writeFile(io, .{ .sub_path = types.genesis_file, .data = contents[0..len] });
        try types.write_genesis(io, gpa, tmp.dir, info);
        var read = try types.read_genesis(io, gpa, tmp.dir);
        defer read.deinit(gpa);
        try testing.expect(read.eql(info));
    }
}

const PubMsg = fd.DealerPubMsg(types.MinSig);

/// The public message of a dealing dealt from `seed` over a singleton round (commonware
/// `public_message`). Different seeds give different messages.
fn public_message(seed: u64) !PubMsg {
    var key_rng = zigware.utils.rng.TestRng.init(0);
    const signer = ed25519.PrivateKey.random(&key_rng);
    const N3f1 = zigware.utils.N3f1;
    const dealers = try types.Set(ed25519.PublicKey).from_dedup(gpa, &.{signer.public_key()});
    const players = try dealers.clone(gpa);
    const mode = types.sharing_mode;
    var info: fd.Info(types.MinSig, ed25519.PublicKey) =
        try .init(N3f1, gpa, types.namespace, 0, null, mode, types.reveal, dealers, players);
    defer info.deinit(gpa);
    var rng = zigware.utils.rng.TestRng.init(seed);
    const Dealer = fd.Dealer(types.MinSig, ed25519.PrivateKey);
    var started = try Dealer.start(N3f1, gpa, &rng, &info, signer, null);
    started.dealer.deinit(gpa);
    for (started.priv_msgs) |*item| item.msg.zeroize();
    gpa.free(started.priv_msgs);
    return started.pub_msg;
}

/// One dealing: its dealer, the index of its public message, and its private half.
const Dealing = struct { dealer: usize, public: usize, private: fd.DealerPrivMsg };

/// A share dealt to one player, a seed, and three dealings: two dealers send a dealing with
/// the same public message, and the first dealer sends another with a second message.
const Material = struct {
    share: types.Share,
    seed: types.Summary,
    dealers: [2]ed25519.PublicKey,
    publics: [2]PubMsg,
    dealings: [3]Dealing,

    fn init() !Material {
        const participants = keys(3);
        var rng = zigware.utils.rng.TestRng.init(1);
        const set = try types.Set(ed25519.PublicKey).from_dedup(gpa, participants[0..1]);
        var dealt = try deal(&rng, set);
        defer dealt.deinit(gpa);
        var first = try public_message(1);
        errdefer first.deinit(gpa);
        var material: Material = .{
            .share = dealt.shares.get_value(participants[0]).?.*,
            .seed = undefined,
            .dealers = .{ participants[1], participants[2] },
            .publics = .{ first, try public_message(2) },
            .dealings = undefined,
        };
        rng.fill_bytes(&material.seed.bytes);
        const layout = [_][2]usize{ .{ 0, 0 }, .{ 1, 0 }, .{ 0, 1 } };
        for (layout, &material.dealings) |pair, *dealing| {
            const private: fd.DealerPrivMsg = .init(Scalar.random(&rng));
            dealing.* = .{ .dealer = pair[0], .public = pair[1], .private = private };
        }
        std.debug.assert(!material.publics[0].eql(material.publics[1]));
        return material;
    }

    fn deinit(self: *Material) void {
        for (&self.publics) |*public| public.deinit(gpa);
    }
};

fn expect_share(secrets: *types.Secrets, epoch: Epoch, expected: ?types.Share) !void {
    const got = try secrets.get_share(epoch);
    try testing.expectEqual(expected == null, got == null);
    if (expected) |share| try testing.expect(got.?.eql(share));
}

/// Expects each of `material`'s dealings stored in `epoch` (`present`) or absent.
fn expect_dealings(
    secrets: *types.Secrets,
    epoch: Epoch,
    material: *const Material,
    present: bool,
) !void {
    for (material.dealings) |dealing| {
        const dealer = material.dealers[dealing.dealer];
        const got = try secrets.get_dealing(epoch, dealer, &material.publics[dealing.public]);
        try testing.expectEqual(present, got != null);
        if (present) try testing.expect(got.?.eql(dealing.private));
    }
}

fn put_all(secrets: *types.Secrets, epoch: Epoch, material: *const Material) !void {
    try secrets.put_share(epoch, material.share);
    try secrets.put_seed(epoch, material.seed);
    for (material.dealings) |dealing| {
        const dealer = material.dealers[dealing.dealer];
        try secrets.put_dealing(epoch, dealer, &material.publics[dealing.public], dealing.private);
    }
}

// Every put survives an unclean restart, and a prune durably removes only the material below
// its epoch.
test "dkg: secrets survive restart and prune" {
    var material: Material = try .init();
    defer material.deinit();
    var backend: MockStorage = .init(gpa);
    defer backend.deinit();

    // Store material for epochs 1 and 2, with every dealing, then crash.
    {
        var secrets: types.Secrets = try .init(io, gpa, backend.interface(), .validator);
        defer secrets.deinit();
        for ([_]u64{ 1, 2 }) |epoch| try put_all(&secrets, .new(epoch), &material);
        try expect_share(&secrets, .new(1), material.share);
        backend.crash();
    }
    // Every put survives the restart. Prune below epoch 2, then crash again.
    {
        var secrets: types.Secrets = try .init(io, gpa, backend.interface(), .validator);
        defer secrets.deinit();
        for ([_]u64{ 1, 2 }) |epoch| {
            try expect_share(&secrets, .new(epoch), material.share);
            try testing.expect((try secrets.get_seed(.new(epoch))).?.eql(material.seed));
            try expect_dealings(&secrets, .new(epoch), &material, true);
        }
        try secrets.prune(.new(2));
        backend.crash();
    }
    // The prune survives the restart: epoch 1 is gone and epoch 2 remains.
    var secrets: types.Secrets = try .init(io, gpa, backend.interface(), .validator);
    defer secrets.deinit();
    try expect_share(&secrets, .new(1), null);
    try testing.expect(try secrets.get_seed(.new(1)) == null);
    try expect_share(&secrets, .new(2), material.share);
    try testing.expect((try secrets.get_seed(.new(2))).?.eql(material.seed));
    try expect_dealings(&secrets, .new(1), &material, false);
    try expect_dealings(&secrets, .new(2), &material, true);
}

// The `bootstrap` handoff copies only the epoch-0 share from the bootstrap partition into the
// validator partition, and the share survives an unclean restart.
test "dkg: handoff carries only share" {
    var material: Material = try .init();
    defer material.deinit();
    var backend: MockStorage = .init(gpa);
    defer backend.deinit();
    {
        // The engine's handle on the bootstrap store persists the ceremony's epoch-0 share,
        // seed, and dealings.
        var bootstrap: types.Secrets = try .init(io, gpa, backend.interface(), .bootstrap);
        defer bootstrap.deinit();
        try put_all(&bootstrap, .zero(), &material);

        // Hand over the share as `bootstrap` does, then crash.
        const share = (try bootstrap.get_share(.zero())).?;
        var handoff: types.Secrets = try .init(io, gpa, backend.interface(), .validator);
        defer handoff.deinit();
        try handoff.put_share(.zero(), share);
        backend.crash();
    }
    // The validator partition holds the share and none of the ceremony's seed or dealings.
    var secrets: types.Secrets = try .init(io, gpa, backend.interface(), .validator);
    defer secrets.deinit();
    try expect_share(&secrets, .zero(), material.share);
    try testing.expect(try secrets.get_seed(.zero()) == null);
    try expect_dealings(&secrets, .zero(), &material, false);
}

// Destroying the bootstrap partition erases the ceremony's share, seed, and dealing across a
// restart.
test "dkg: destroy erases bootstrap" {
    var material: Material = try .init();
    defer material.deinit();
    var backend: MockStorage = .init(gpa);
    defer backend.deinit();
    {
        var bootstrap: types.Secrets = try .init(io, gpa, backend.interface(), .bootstrap);
        try put_all(&bootstrap, .zero(), &material);
        bootstrap.deinit();

        // Reopen and erase the partition, as `validator` does.
        var reopened: types.Secrets = try .init(io, gpa, backend.interface(), .bootstrap);
        try reopened.destroy();
        reopened.deinit();
        backend.crash();
    }
    // Nothing survives in the bootstrap partition.
    var bootstrap: types.Secrets = try .init(io, gpa, backend.interface(), .bootstrap);
    defer bootstrap.deinit();
    try expect_share(&bootstrap, .zero(), null);
    try testing.expect(try bootstrap.get_seed(.zero()) == null);
    try expect_dealings(&bootstrap, .zero(), &material, false);
}
