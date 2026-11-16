//! Backfill keys and requests (commonware `marshal/resolver/handler.rs`).
//!
//! `Key(D)` is what marshal asks its resolver for, on the wire as a subject byte followed by
//! a commitment, a height, or a round. `Annotation` is the local metadata a request carries:
//! two subscribers of one key can update different stores and trust the commitment
//! differently. `Request(D)` pairs a key with the only annotation that matches it.
//!
//! `Handler(D)` is the resolver's consumer and producer: it forwards deliveries (copies of
//! the borrowed value and subscribers) and produce requests to the actor as `Message(D)`.
//! When the actor's inbox is full, overflow drops produce requests (a peer can ask a less
//! loaded peer) and deliveries whose requester left.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const resolver_api = @import("resolver");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;
const types = @import("../../types.zig");
const Cutoff = @import("../core/floor.zig").Cutoff;
const Height = types.Height;
const Round = types.Round;
const oneshot = utils.channel.oneshot;
const Produced = resolver_api.p2p.Produced;

/// The subject byte of each key.
const Subject = enum(u8) {
    block = 0,
    finalized = 1,
    notarized = 2,
};

const KeyOf = Key;

/// A raw resolver key for backfilling data.
pub fn Key(comptime D: type) type {
    return union(Subject) {
        const Self = @This();

        /// A block by consensus commitment.
        block: D,
        /// The finalization (and block) at a height.
        finalized: Height,
        /// The notarization (and block) of a round.
        notarized: Round,

        /// A subject and the widest of a commitment, a height, and a round.
        pub const max_encode_size: usize = 1 +
            @max(D.fixed_size, Height.max_encode_size, Round.max_encode_size);

        pub fn subject(self: Self) u8 {
            return @backingInt(std.meta.activeTag(self));
        }

        /// Orders by subject, then by the value within a subject.
        pub fn order(a: Self, b: Self) std.math.Order {
            const by_subject = std.math.order(a.subject(), b.subject());
            if (by_subject != .eq) return by_subject;
            return switch (a) {
                .block => |commitment| commitment.order(b.block),
                .finalized => |height| height.order(b.finalized),
                .notarized => |round| round.order(b.notarized),
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.order(b) == .eq;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            writer.write_byte(self.subject());
            switch (self) {
                .block => |commitment| commitment.write(writer),
                .finalized => |height| height.write(writer),
                .notarized => |round| round.write(writer),
            }
        }

        pub fn encode_size(self: Self) usize {
            const size: usize = 1 + switch (self) {
                .block => D.fixed_size,
                .finalized => |height| height.encode_size(),
                .notarized => |round| round.encode_size(),
            };
            assert(size <= max_encode_size);
            return size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const tag = try reader.read_byte();
            const kind = std.enums.fromInt(Subject, tag) orelse
                return reader.fail(error.InvalidEnum, tag);
            return switch (kind) {
                .block => .{ .block = try D.read(gpa, reader, {}) },
                .finalized => .{ .finalized = try Height.read(gpa, reader, {}) },
                .notarized => .{ .notarized = try Round.read(gpa, reader, {}) },
            };
        }

        pub fn arbitrary(
            gpa: Allocator,
            u: *codec.arbitrary.Unstructured,
        ) codec.arbitrary.Error!Self {
            return switch (u.int_in_range(u8, 0, 2)) {
                0 => .{ .block = try D.arbitrary(gpa, u) },
                1 => .{ .finalized = try Height.arbitrary(gpa, u) },
                2 => .{ .notarized = try Round.arbitrary(gpa, u) },
                else => unreachable, // Proof: drawn from 0 through 2.
            };
        }

        pub fn format(self: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .block => |commitment| try writer.print("Block({x})", .{commitment.as_slice()}),
                .finalized => |height| try writer.print("Finalized({f})", .{height}),
                .notarized => |round| try writer.print("Notarized({f})", .{round}),
            }
        }
    };
}

/// Metadata for a finalized block requested by commitment.
pub const Finalized = union(enum) {
    /// The finalized height is known before the request.
    by_height: Height,
    /// Only the finalization round is known (a finalization names the commitment, not the
    /// height).
    by_round: Round,

    /// Rust's derived `Ord`: by variant, then by value.
    pub fn order(a: Finalized, b: Finalized) std.math.Order {
        const by_tag = std.math.order(@backingInt(a), @backingInt(b));
        if (by_tag != .eq) return by_tag;
        return switch (a) {
            .by_height => |height| std.math.order(height.get(), b.by_height.get()),
            .by_round => |round| round.order(b.by_round),
        };
    }
};

/// The local processing metadata of a request.
pub const Annotation = union(enum) {
    /// A notarization requested by round.
    notarization: Round,
    /// A block requested by commitment without certification evidence. The height is local
    /// pruning metadata: a matching block above it is delivered but not cached. Commitment
    /// material is recomputed unless another subscriber supplies certification evidence.
    untrusted: Height,
    /// A block this node certified, or an ancestor of one: deliveries reuse commitment
    /// material. The height bounds it as for `untrusted`.
    certified: Height,
    /// A block requested by commitment for the finalized chain.
    finalized: Finalized,

    pub fn eql(a: Annotation, b: Annotation) bool {
        return std.meta.eql(a, b);
    }

    /// Rust's derived `Ord`: by variant, then by value. The resolver keeps subscribers in
    /// this order.
    pub fn order(a: Annotation, b: Annotation) std.math.Order {
        const by_tag = std.math.order(@backingInt(a), @backingInt(b));
        if (by_tag != .eq) return by_tag;
        return switch (a) {
            .notarization => |round| round.order(b.notarization),
            .untrusted => |height| std.math.order(height.get(), b.untrusted.get()),
            .certified => |height| std.math.order(height.get(), b.certified.get()),
            .finalized => |finalized| finalized.order(b.finalized),
        };
    }
};

/// A marshal backfill fetch: a key and the annotation that matches it.
pub fn Request(comptime D: type) type {
    return union(enum) {
        const Self = @This();

        /// A notarized proposal for a round.
        notarized: Round,
        /// A finalization for a height.
        finalized: Height,
        /// A block by commitment without certification evidence.
        untrusted: Committed(Height),
        /// A block this node certified, or an ancestor of one, by commitment.
        certified: Committed(Height),
        /// A finalized-chain block by commitment when its height is known. The commitment
        /// is a verified finalization's payload or an archived finalized block's parent.
        finalized_by_height: Committed(Height),
        /// A finalized-chain block by commitment when only its finalization round is known.
        finalized_by_round: Committed(Round),

        fn Committed(comptime Bound: type) type {
            return struct { commitment: D, bound: Bound };
        }

        /// Whether the request stays above a processed height `floor` (requests without a
        /// height stay).
        pub fn above_height_floor(self: Self, floor: Height) bool {
            return switch (self) {
                .untrusted, .certified, .finalized_by_height => |value| value.bound.get() >
                    floor.get(),
                .finalized => |height| height.get() > floor.get(),
                .notarized, .finalized_by_round => true,
            };
        }

        /// Whether the request stays above the processed round floor `cutoff` (requests without
        /// a round stay).
        pub fn above_round_floor(self: Self, cutoff: Cutoff) bool {
            return switch (self) {
                .notarized => |round| !cutoff.covers(round),
                .finalized_by_round => |value| !cutoff.covers(value.bound),
                .finalized, .untrusted, .certified, .finalized_by_height => true,
            };
        }

        /// The resolver key and the subscriber annotation.
        pub fn split(self: Self) struct { Key(D), Annotation } {
            return switch (self) {
                .notarized => |round| .{ .{ .notarized = round }, .{ .notarization = round } },
                .finalized => |height| .{
                    .{ .finalized = height },
                    .{ .finalized = .{ .by_height = height } },
                },
                .untrusted => |value| .{
                    .{ .block = value.commitment },
                    .{ .untrusted = value.bound },
                },
                .certified => |value| .{
                    .{ .block = value.commitment },
                    .{ .certified = value.bound },
                },
                .finalized_by_height => |value| .{
                    .{ .block = value.commitment },
                    .{ .finalized = .{ .by_height = value.bound } },
                },
                .finalized_by_round => |value| .{
                    .{ .block = value.commitment },
                    .{ .finalized = .{ .by_round = value.bound } },
                },
            };
        }
    };
}

/// Whether a pending fetch stays above the processed height `floor` (commonware
/// `above_height_floor`): height-bound requests are pruned once the floor reaches them;
/// others stay.
pub fn above_height_floor(
    comptime D: type,
    floor: Height,
    key: Key(D),
    annotation: Annotation,
) bool {
    return switch (key) {
        .finalized => |height| height.get() > floor.get(),
        .block => switch (annotation) {
            .untrusted, .certified => |height| height.get() > floor.get(),
            .finalized => |finalized| switch (finalized) {
                .by_height => |height| height.get() > floor.get(),
                .by_round => true,
            },
            .notarization => true,
        },
        .notarized => true,
    };
}

/// Whether a pending fetch stays above the processed round floor `cutoff` (commonware
/// `above_round_floor`): round-bound requests are pruned once the cutoff covers them; others
/// stay.
pub fn above_round_floor(
    comptime D: type,
    cutoff: Cutoff,
    key: Key(D),
    annotation: Annotation,
) bool {
    return switch (key) {
        .notarized => |round| !cutoff.covers(round),
        .block => switch (annotation) {
            .finalized => |finalized| switch (finalized) {
                .by_round => |round| !cutoff.covers(round),
                .by_height => true,
            },
            .notarization, .untrusted, .certified => true,
        },
        .finalized => true,
    };
}

/// A message from the resolver's consumer or producer to the marshal actor (commonware
/// `handler::Message`). It owns its value, subscribers, and responder, and the allocator that
/// frees them if the mailbox drops it.
pub fn Message(comptime D: type) type {
    return struct {
        const Self = @This();
        pub const Delivery = resolver_api.Delivery(Key(D), Annotation);
        pub const Overflow = Pending(D);

        gpa: Allocator,
        body: Body,

        pub const Body = union(enum) {
            /// A value resolved for `delivery`; the disposition goes back through `response`.
            deliver: struct {
                delivery: Delivery,
                value: []const u8,
                response: oneshot.Sender(resolver_api.Outcome),
            },
            /// A peer requests the value at `key`.
            produce: struct { key: Key(D), response: oneshot.Sender(Produced) },
        };

        /// Whether the requester stopped waiting for the response.
        pub fn response_closed(self: *const Self) bool {
            return switch (self.body) {
                inline else => |body| body.response.is_closed(),
            };
        }

        /// Releases a message the mailbox drops, closing its responder.
        pub fn discard(message: Self) void {
            switch (message.body) {
                .deliver => |body| {
                    var response = body.response;
                    response.deinit();
                    message.gpa.free(body.value);
                    message.gpa.free(body.delivery.subscribers);
                },
                .produce => |body| {
                    var response = body.response;
                    response.deinit();
                },
            }
        }

        /// The overflow policy: drops produce requests, so the serve backlog stays bounded
        /// by the ready queue (a peer can ask a less loaded peer), and keeps deliveries whose
        /// requester still waits.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message.body == .produce or message.response_closed()) return discard(message);
            errdefer discard(message);
            try overflow.messages.pushBack(gpa, message);
            assert(!overflow.is_empty());
        }
    };
}

/// Deliveries held while the actor's inbox is full (commonware `handler::Pending`).
pub fn Pending(comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(D);

        messages: std.Deque(M) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            while (self.messages.popFront()) |message| M.discard(message);
            self.messages.deinit(gpa);
            self.* = undefined;
        }

        pub fn is_empty(self: *const Self) bool {
            return self.messages.len == 0;
        }

        /// Hands the queue in order, skipping deliveries whose requester left.
        pub fn drain(self: *Self, pusher: anytype) void {
            while (self.messages.popFront()) |message| {
                if (message.response_closed()) {
                    M.discard(message);
                    continue;
                }
                if (pusher.push(message)) |rejected| {
                    self.messages.pushFrontAssumeCapacity(rejected);
                    break;
                }
            }
        }
    };
}

/// Forwards the resolver's deliveries and produce requests to the marshal actor (commonware
/// `Handler`): the resolver's `Consumer` and `Producer`.
pub fn Handler(comptime D: type) type {
    return struct {
        const Self = @This();
        const M = Message(D);
        pub const Key = KeyOf(D);
        pub const Value = []const u8;
        pub const Subscriber = Annotation;
        pub const Outcome = resolver_api.Outcome;

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(M),

        pub fn clone(self: Self) Self {
            var copy = self;
            copy.sender = self.sender.clone();
            return copy;
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Forwards a copy of `delivery` and `value` (both borrowed).
        pub fn deliver(
            self: Self,
            delivery: M.Delivery,
            value: []const u8,
        ) Allocator.Error!oneshot.Receiver(Outcome) {
            assert(delivery.subscribers.len > 0);
            const subscribers = try self.gpa.dupe(Annotation, delivery.subscribers);
            errdefer self.gpa.free(subscribers);
            const bytes = try self.gpa.dupe(u8, value);
            errdefer self.gpa.free(bytes);
            var pair = try oneshot.channel(Outcome, self.gpa, self.io);
            errdefer pair.receiver.deinit();
            _ = try self.sender.enqueue(.{ .gpa = self.gpa, .body = .{ .deliver = .{
                .delivery = .{ .key = delivery.key, .subscribers = subscribers },
                .value = bytes,
                .response = pair.sender,
            } } });
            return pair.receiver;
        }

        /// Asks the actor to serve `key`; a receiver closed without a value means no data.
        pub fn produce(self: Self, key: KeyOf(D)) Allocator.Error!oneshot.Receiver(Produced) {
            var pair = try oneshot.channel(Produced, self.gpa, self.io);
            errdefer pair.receiver.deinit();
            _ = try self.sender.enqueue(.{ .gpa = self.gpa, .body = .{ .produce = .{
                .key = key,
                .response = pair.sender,
            } } });
            return pair.receiver;
        }
    };
}

/// The actor's end of the handler mailbox and the handler that feeds it.
pub fn Channel(comptime D: type) type {
    return struct {
        receiver: actor.mailbox.Receiver(Message(D)),
        handler: Handler(D),
    };
}

/// Creates a handler and the receiver the actor reads (commonware `handler::init`), holding
/// up to `capacity` messages before overflow.
pub fn init(
    comptime D: type,
    gpa: Allocator,
    io: Io,
    scope: *const metrics.Scope,
    capacity: u32,
) Allocator.Error!Channel(D) {
    assert(capacity > 0);
    const pair = try actor.mailbox.new_with_metrics(Message(D), gpa, io, scope, capacity);
    return .{
        .receiver = pair.receiver,
        .handler = .{ .gpa = gpa, .io = io, .sender = pair.sender },
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const conformance = @import("conformance");
const Sha256 = cryptography.Sha256;
const TestKey = Key(Sha256.Digest);

test "block key encoding" {
    const commitment = Sha256.hash(&.{"test"});
    const key: TestKey = .{ .block = commitment };
    const encoded = try codec.encode(TestKey, testing.allocator, key);
    defer testing.allocator.free(encoded);
    // The subject byte and the 32-byte commitment.
    try testing.expectEqual(33, encoded.len);
    try testing.expectEqual(0, encoded[0]);
    try testing.expectEqualSlices(u8, &commitment.bytes, encoded[1..]);
    try testing.expect((try codec.decode(TestKey, testing.allocator, encoded)).eql(key));
}

test "finalized and notarized key encodings" {
    const gpa = testing.allocator;
    const finalized: TestKey = .{ .finalized = .new(12345) };
    const encoded_finalized = try codec.encode(TestKey, gpa, finalized);
    defer gpa.free(encoded_finalized);
    // Subject 1, then 12345 as a varint (0xb9 0x60).
    try testing.expectEqualSlices(u8, &.{ 1, 0xb9, 0x60 }, encoded_finalized);
    try testing.expect((try codec.decode(TestKey, gpa, encoded_finalized)).eql(finalized));

    const notarized: TestKey = .{ .notarized = .new(.new(67890), .new(12345)) };
    const encoded_notarized = try codec.encode(TestKey, gpa, notarized);
    defer gpa.free(encoded_notarized);
    // Subject 2, epoch 67890 (0xb2 0x92 0x04), view 12345 (0xb9 0x60).
    try testing.expectEqualSlices(u8, &.{ 2, 0xb2, 0x92, 0x04, 0xb9, 0x60 }, encoded_notarized);
    try testing.expect((try codec.decode(TestKey, gpa, encoded_notarized)).eql(notarized));

    try testing.expectError(error.InvalidEnum, codec.decode(TestKey, gpa, &.{ 3, 0 }));
}

test "key max encode size is the widest key" {
    // A block key (1 + 32 bytes) is wider than a notarized key at the maximum round
    // (1 + 10 + 10 bytes).
    try testing.expectEqual(33, TestKey.max_encode_size);
    const max = std.math.maxInt(u64);
    const widest = [_]TestKey{
        .{ .block = Sha256.hash(&.{"test"}) },
        .{ .finalized = .new(max) },
        .{ .notarized = .new(.new(max), .new(max)) },
    };
    var largest: usize = 0;
    for (widest) |key| largest = @max(largest, key.encode_size());
    try testing.expectEqual(TestKey.max_encode_size, largest);
}

test "keys order by subject before value" {
    const block_low: TestKey = .{ .block = Sha256.Digest.fill(0) };
    const block_high: TestKey = .{ .block = Sha256.Digest.fill(0xff) };
    const min_finalized: TestKey = .{ .finalized = .zero() };
    const max_finalized: TestKey = .{ .finalized = .new(std.math.maxInt(u64)) };
    const min_notarized: TestKey = .{ .notarized = .zero() };
    const max_notarized: TestKey = .{ .notarized = .new(.new(9), .new(9)) };
    try testing.expectEqual(.lt, block_low.order(block_high));
    try testing.expectEqual(.lt, block_high.order(min_finalized));
    try testing.expectEqual(.lt, min_finalized.order(max_finalized));
    try testing.expectEqual(.lt, max_finalized.order(min_notarized));
    try testing.expectEqual(.lt, min_notarized.order(max_notarized));
    try testing.expectEqual(.eq, max_notarized.order(max_notarized));
    try testing.expect(!min_finalized.eql(min_notarized));
}

test "requests split into matching keys and annotations" {
    const D = Sha256.Digest;
    const commitment = D.fill(4);
    const round: Round = .new(.new(1), .new(2));
    const by_round: Request(D) = .{
        .finalized_by_round = .{ .commitment = commitment, .bound = round },
    };
    const key, const annotation = by_round.split();
    try testing.expect(key.eql(.{ .block = commitment }));
    try testing.expect(annotation.eql(.{ .finalized = .{ .by_round = round } }));
    try testing.expect(by_round.above_height_floor(.new(1_000)));

    const certified = Request(D){ .certified = .{ .commitment = commitment, .bound = .new(5) } };
    try testing.expect(certified.above_height_floor(.new(4)));
    try testing.expect(!certified.above_height_floor(.new(5)));
    const certified_key, const certified_annotation = certified.split();
    try testing.expect(above_height_floor(D, .new(4), certified_key, certified_annotation));
    try testing.expect(!above_height_floor(D, .new(5), certified_key, certified_annotation));
    // Round-bound and notarized requests are kept at any height floor.
    try testing.expect(above_height_floor(D, .new(9), key, annotation));
    const finalized_key, const finalized_annotation = (Request(D){ .finalized = .new(3) }).split();
    try testing.expect(!above_height_floor(D, .new(3), finalized_key, finalized_annotation));
}

test "height floor predicate prunes height-bound requests at the floor" {
    const D = Sha256.Digest;
    const height_floor: Height = .new(100);
    const block: Key(D) = .{ .block = Sha256.hash(&.{"block"}) };
    const notarized_round: Round = .new(.new(333), .new(150));
    const kept = [_]struct { Key(D), Annotation }{
        .{ .{ .finalized = .new(200) }, .{ .finalized = .{ .by_height = .new(200) } } },
        .{ .{ .notarized = notarized_round }, .{ .notarization = notarized_round } },
        .{ block, .{ .certified = .new(101) } },
        .{ block, .{ .untrusted = .new(101) } },
    };
    for (kept) |entry| try testing.expect(above_height_floor(D, height_floor, entry[0], entry[1]));
    const pruned = [_]struct { Key(D), Annotation }{
        .{ .{ .finalized = .new(100) }, .{ .finalized = .{ .by_height = .new(100) } } },
        .{ block, .{ .finalized = .{ .by_height = .new(100) } } },
        .{ block, .{ .certified = .new(100) } },
        .{ block, .{ .untrusted = .new(100) } },
    };
    for (pruned) |entry| {
        try testing.expect(!above_height_floor(D, height_floor, entry[0], entry[1]));
    }
}

test "round floor predicate prunes covered rounds" {
    const D = Sha256.Digest;
    const cutoff: Cutoff = .{ .round = .new(.new(1), .new(10)) };
    const block: Key(D) = .{ .block = Sha256.hash(&.{"block"}) };
    const higher: Round = .new(.new(1), .new(11));
    const same: Round = .new(.new(1), .new(10));
    try testing.expect(above_round_floor(D, cutoff, .{ .notarized = higher }, .{
        .notarization = higher,
    }));
    try testing.expect(above_round_floor(D, cutoff, .{ .finalized = .new(100) }, .{
        .finalized = .{ .by_height = .new(100) },
    }));
    try testing.expect(above_round_floor(D, cutoff, block, .{
        .finalized = .{ .by_round = higher },
    }));
    try testing.expect(!above_round_floor(D, cutoff, .{ .notarized = same }, .{
        .notarization = same,
    }));
    try testing.expect(!above_round_floor(D, cutoff, block, .{
        .finalized = .{ .by_round = same },
    }));
}

test "epoch round floor predicate prunes the whole covered epoch" {
    const D = Sha256.Digest;
    const cutoff: Cutoff = .{ .epoch = .new(1) };
    const block: Key(D) = .{ .block = Sha256.hash(&.{"block"}) };
    // Every round of the covered epoch is pruned, through its last view.
    const covered = [_]Round{ .new(.new(1), .zero()), .new(.new(1), .new(std.math.maxInt(u64))) };
    for (covered) |round| {
        try testing.expect(!above_round_floor(D, cutoff, .{ .notarized = round }, .{
            .notarization = round,
        }));
        try testing.expect(!above_round_floor(D, cutoff, block, .{
            .finalized = .{ .by_round = round },
        }));
        const request: Request(D) = .{ .notarized = round };
        try testing.expect(!request.above_round_floor(cutoff));
    }
    // The next epoch's first round and height-bound requests are retained.
    const next: Round = .new(.new(2), .zero());
    try testing.expect(above_round_floor(D, cutoff, .{ .notarized = next }, .{
        .notarization = next,
    }));
    const next_by_round: Annotation = .{ .finalized = .{ .by_round = next } };
    try testing.expect(above_round_floor(D, cutoff, block, next_by_round));
    try testing.expect(above_round_floor(D, cutoff, .{ .finalized = .new(100) }, .{
        .finalized = .{ .by_height = .new(100) },
    }));
    const by_round: Request(D) = .{
        .finalized_by_round = .{ .commitment = block.block, .bound = next },
    };
    try testing.expect(by_round.above_round_floor(cutoff));
    try testing.expect((Request(D){ .finalized = .new(0) }).above_round_floor(cutoff));
}

/// A SHA-256 digest drawn as commonware's `Arbitrary`: the hash of arbitrary bytes.
const ArbitraryDigest = struct {
    inner: Sha256.Digest,

    pub const fixed_size: usize = Sha256.Digest.fixed_size;

    pub fn order(a: ArbitraryDigest, b: ArbitraryDigest) std.math.Order {
        return a.inner.order(b.inner);
    }

    pub fn as_slice(self: *const ArbitraryDigest) []const u8 {
        return self.inner.as_slice();
    }

    pub fn write(self: ArbitraryDigest, writer: *codec.Writer) void {
        self.inner.write(writer);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!ArbitraryDigest {
        return .{ .inner = try Sha256.Digest.read(gpa, reader, {}) };
    }

    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!ArbitraryDigest {
        const len = u.int_in_range(u64, 0, 256);
        const data = try gpa.alloc(u8, len);
        try u.bytes(data);
        return .{ .inner = Sha256.hash(&.{data}) };
    }
};

test "key conformance hash matches commonware" {
    const T = Key(ArbitraryDigest);
    const Commit = struct {
        pub fn commit(gpa: Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const generator = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, generator, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
    try conformance.verify(
        Commit,
        std.heap.smp_allocator,
        "commonware_consensus::marshal::resolver::handler::tests::conformance::" ++
            "CodecConformance<Key<D>>",
        conformance.default_cases,
        @embedFile("../../conformance.toml"),
    );
}

const TestMessage = Message(Sha256.Digest);

/// Accepts every drained message.
const Collector = struct {
    items: std.ArrayList(TestMessage),

    pub fn push(self: *Collector, message: TestMessage) ?TestMessage {
        self.items.appendAssumeCapacity(message);
        return null;
    }
};

fn test_deliver(
    gpa: Allocator,
    height: u64,
    response: oneshot.Sender(resolver_api.Outcome),
) !TestMessage {
    const annotation: Annotation = .{ .finalized = .{ .by_height = .new(height) } };
    return .{ .gpa = gpa, .body = .{ .deliver = .{
        .delivery = .{
            .key = .{ .finalized = .new(height) },
            .subscribers = try gpa.dupe(Annotation, &.{annotation}),
        },
        .value = try gpa.dupe(u8, "bytes"),
        .response = response,
    } } };
}

test "handle retains open deliveries only" {
    const gpa = testing.allocator;
    const io = testing.io;
    var overflow: TestMessage.Overflow = .empty;
    defer overflow.deinit(gpa);

    // An overflowed produce request is dropped and its requester sees the closed response.
    var produce = try oneshot.channel(Produced, gpa, io);
    defer produce.receiver.deinit();
    try TestMessage.handle(gpa, &overflow, .{ .gpa = gpa, .body = .{ .produce = .{
        .key = .{ .finalized = .new(1) },
        .response = produce.sender,
    } } });
    try testing.expectError(error.Closed, produce.receiver.try_recv());

    // Deliveries are retained, and drain skips one whose requester left.
    var closed = try oneshot.channel(resolver_api.Outcome, gpa, io);
    try TestMessage.handle(gpa, &overflow, try test_deliver(gpa, 2, closed.sender));
    var open = try oneshot.channel(resolver_api.Outcome, gpa, io);
    defer open.receiver.deinit();
    try TestMessage.handle(gpa, &overflow, try test_deliver(gpa, 3, open.sender));
    closed.receiver.deinit();

    var collector: Collector = .{ .items = try .initCapacity(gpa, 4) };
    defer collector.items.deinit(gpa);
    overflow.drain(&collector);
    defer for (collector.items.items) |message| TestMessage.discard(message);
    try testing.expectEqual(1, collector.items.items.len);
    const delivered = collector.items.items[0].body.deliver;
    try testing.expectEqual(3, delivered.delivery.key.finalized.get());
}

test "handler forwards copies of deliveries and produce requests" {
    const gpa = testing.allocator;
    const io = testing.io;
    var registry = metrics.Registry.init(gpa);
    defer registry.deinit();
    const scope = metrics.Scope.init(&registry);
    var channel = try init(Sha256.Digest, gpa, io, &scope, 4);
    defer channel.receiver.deinit();
    defer channel.handler.deinit();

    var value = [_]u8{ 1, 2, 3 };
    const subscribers = [_]Annotation{.{ .notarization = .new(.zero(), .new(4)) }};
    var outcome = try channel.handler.deliver(.{
        .key = .{ .notarized = .new(.zero(), .new(4)) },
        .subscribers = &subscribers,
    }, &value);
    defer outcome.deinit();
    var produced = try channel.handler.produce(.{ .finalized = .new(9) });
    defer produced.deinit();
    value[0] = 7; // The borrowed value may change once `deliver` returns.

    const delivered = try channel.receiver.try_recv();
    defer TestMessage.discard(delivered);
    const body = delivered.body.deliver;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, body.value);
    try testing.expect(body.delivery.subscribers.ptr != &subscribers);
    try testing.expect(body.delivery.subscribers[0].eql(subscribers[0]));
    var request = try channel.receiver.try_recv();
    try testing.expectEqual(9, request.body.produce.key.finalized.get());
    try request.body.produce.response.send(.{ .bytes = "served" });
    try testing.expectEqualStrings("served", (try produced.try_recv()).bytes);
}
