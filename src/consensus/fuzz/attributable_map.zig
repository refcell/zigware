//! The `attributable_map` fuzz target (commonware
//! `consensus/fuzz/fuzz_targets/attributable_map.rs`): up to 64 inserts, gets, and clears on
//! an `AttributableMap` of ed25519 nullify votes agree with a model set of signers. An
//! insert succeeds exactly when its signer is in range and new.
//!
//! commonware signs one dummy message with a key from `TestRng::new(seed)` per input. The
//! map never looks at the signature, and a key per input dominates a debug-mode seeded run,
//! so this port signs with one of `Signatures.count` keys picked by the drawn seed.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cryptography = @import("cryptography");
const math = @import("math");
const utils = @import("utils");
const minifuzz = @import("invariants").minifuzz;
const consensus_types = @import("../types.zig");
const simplex = @import("../simplex/root.zig");

const Unstructured = minifuzz.Unstructured;
const Participant = consensus_types.Participant;
const Round = consensus_types.Round;
const Scheme = simplex.scheme.ed25519.Scheme(cryptography.Sha256.Digest);
const Nullify = simplex.types.Nullify(Scheme);
const Map = simplex.types.AttributableMap(Nullify);

const operations_max = 64;

/// commonware's `Operation` arms, in declaration order.
const Operation = enum { insert, get, clear };

/// The signers the map should hold. Only signers below the `u8` participant count are ever
/// inserted, so 256 slots cover every possible member.
const Model = struct {
    members: [256]bool = @splat(false),
    count: u32 = 0,

    fn contains(self: *const Model, signer: Participant) bool {
        return signer.get() < self.members.len and self.members[signer.get()];
    }

    fn add(self: *Model, signer: Participant) void {
        assert(!self.contains(signer));
        self.members[signer.get()] = true;
        self.count += 1;
    }
};

fn insert(map: *Map, model: *Model, participants: u8, vote: Nullify) !void {
    const signer = vote.signer();
    const inserted = try map.insert(testing.allocator, vote);
    if (signer.get() < participants and !model.contains(signer)) {
        try testing.expect(inserted);
        model.add(signer);
    } else {
        try testing.expect(!inserted);
    }
    try testing.expectEqual(model.count, map.len());
    try testing.expectEqual(model.count == 0, map.is_empty());
}

/// The dummy signatures: `sign("fuzz", "dummy")` by the key from `TestRng::new(seed)` for
/// each seed below `count`.
pub const Signatures = struct {
    const count = 8;

    table: [count]Scheme.Signature,

    pub fn init() Signatures {
        var signatures: Signatures = undefined;
        for (&signatures.table, 0..) |*signature, seed| {
            var rng = utils.rng.TestRng.init(seed);
            const key = cryptography.ed25519.PrivateKey.random(&rng);
            signature.* = key.sign("fuzz", "dummy");
        }
        assert(!std.meta.eql(signatures.table[0], signatures.table[1]));
        return signatures;
    }
};

/// One input: commonware's `FuzzInput { seed, participants, operations }`.
pub fn body(signatures: *const Signatures, u: *Unstructured) anyerror!void {
    const seed = try u.arbitrary(u64);
    const participants = try u.arbitrary(u8);
    const signature = signatures.table[seed % Signatures.count];

    var map = Map.init(participants);
    defer map.deinit(testing.allocator);
    var model: Model = .{};
    var operations: u32 = 0;
    while (operations < operations_max and !u.is_empty()) : (operations += 1) {
        switch (try u.arbitrary(Operation)) {
            .insert => {
                const signer: Participant = .init(try u.arbitrary(u32));
                const epoch = try u.arbitrary(u64);
                const round: Round = .new(.new(epoch), .new(try u.arbitrary(u64)));
                const vote: Nullify = .{ .round = round, .attestation = .init(signer, signature) };
                try insert(&map, &model, participants, vote);
            },
            .get => {
                const signer: Participant = .init(try u.arbitrary(u32));
                try testing.expectEqual(model.contains(signer), map.get(signer) != null);
            },
            .clear => {
                map.clear(testing.allocator);
                model = .{};
                try testing.expect(map.is_empty());
                try testing.expectEqual(0, map.len());
            },
        }
    }
    assert(operations <= operations_max);
    var count: u32 = 0;
    var it = map.iterator();
    while (it.next()) |vote| : (count += 1) try testing.expect(model.contains(vote.signer()));
    try testing.expectEqual(model.count, count);
}

test "attributable_map fuzz target (minifuzz)" {
    const signatures: Signatures = .init();
    try minifuzz.run(testing.allocator, &signatures, body);
}

test "attributable_map fuzz target (std fuzz)" {
    const signatures: Signatures = .init();
    try testing.fuzz(&signatures, math.testing.smith_body(*const Signatures, body), .{});
}
