//! The bridge application (commonware `examples/bridge/src/application`): the automaton,
//! relay, and reporter simplex drives, talking to the indexer.
//!
//! Proposing flips a coin: heads proposes 16 random bytes, tails fetches the other network's
//! latest finalization from the indexer, checks it, and proposes it. Either way the block
//! goes to the indexer first, and only its digest goes to consensus. Verifying fetches the
//! block by digest and accepts random data or a finalization that verifies against the other
//! network. Each finalization of this network is posted to the indexer.
//!
//! commonware runs all of this in one actor that answers a mailbox in order. Here propose and
//! verify are called from the voter's request tasks and share the indexer connection under a
//! mutex, so each request and its response stay together. Reports must not block, so
//! finalizations to post go through a mailbox to `run`, which posts them in order.
//!
//! `I` is the indexer connection: `request(*I, Io, types.Inbound) Io.Cancelable!types.Outbound`
//! sends one request and returns its response (the validator's encrypted stream, or a store
//! in tests).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const lib = @import("lib.zig");
const types = @import("types.zig");
const store = @import("store.zig");

const actor = zigware.actor;
const simplex = zigware.consensus.simplex;
const traces = zigware.runtime.telemetry.traces;
const ed25519 = zigware.cryptography.ed25519;
const Sha256 = zigware.cryptography.Sha256;

/// The log target of the application's events.
pub const target = "commonware_bridge::application::actor";

/// Genesis message to use during initialization.
pub const genesis_message = "commonware is neat";

/// The initial payload of the single consensus epoch: the hash of the genesis message.
pub fn genesis() lib.Digest {
    return Sha256.hash(&.{genesis_message});
}

/// A finalization queued for the indexer.
const Post = struct {
    finalization: types.Finalization,

    pub const Overflow = std.Deque(Post);

    pub fn handle(gpa: Allocator, overflow: *Overflow, message: Post) Allocator.Error!void {
        try overflow.pushBack(gpa, message);
    }
};

pub fn Application(comptime I: type) type {
    return struct {
        const Self = @This();
        pub const Digest = lib.Digest;
        pub const PublicKey = ed25519.PublicKey;
        pub const Context = simplex.types.Context(Digest, PublicKey);
        pub const Plan = simplex.Plan(PublicKey);
        pub const Activity = simplex.types.Activity(lib.Scheme, Digest);

        gpa: Allocator,
        indexer: *I,
        /// Held for each request and response on `indexer`.
        mutex: Io.Mutex = .init,
        this_network: types.Public,
        /// Verifies the other network's certificates.
        other_network: *const lib.Scheme,
        tracer: traces.Tracer,
        posts: actor.mailbox.Pair(Post),
        /// Whether `close` released the posting sender.
        closed: bool = false,

        /// The application for the network with identity `this_network`. Holds up to
        /// `mailbox_size` finalizations to post before queueing them in overflow.
        pub fn init(
            gpa: Allocator,
            io: Io,
            indexer: *I,
            this_network: types.Public,
            other_network: *const lib.Scheme,
            tracer: traces.Tracer,
            mailbox_size: u32,
        ) Allocator.Error!Self {
            assert(mailbox_size > 0);
            assert(!this_network.eql(other_network.identity()));
            return .{
                .gpa = gpa,
                .indexer = indexer,
                .this_network = this_network,
                .other_network = other_network,
                .tracer = tracer,
                .posts = try actor.mailbox.new(Post, gpa, io, mailbox_size),
            };
        }

        pub fn deinit(self: *Self) void {
            if (!self.closed) self.posts.sender.deinit();
            self.posts.receiver.deinit();
            self.* = undefined;
        }

        /// Stops taking reports: `run` returns once it has posted the queued ones.
        pub fn close(self: *Self) void {
            assert(!self.closed);
            self.posts.sender.deinit();
            self.closed = true;
        }

        fn request(self: *Self, io: Io, inbound: types.Inbound) Io.Cancelable!types.Outbound {
            try self.mutex.lock(io);
            defer self.mutex.unlock(io);
            return self.indexer.request(io, inbound);
        }

        fn verify_other(self: *Self, io: Io, finalization: *const types.Finalization) bool {
            var seed: [8]u8 = undefined;
            io.random(&seed);
            var rng = zigware.utils.TestRng.init(std.mem.readInt(u64, &seed, .little));
            const sequential = zigware.parallel.sequential;
            return finalization.verify(self.gpa, &rng, self.other_network, sequential) catch
                @panic("out of memory");
        }

        /// Proposes random data or the other network's latest finalization, once the indexer
        /// holds the block. Returns null (no proposal) when the coin asked for a finalization
        /// and there is none yet, or the indexer refused the block.
        pub fn propose(self: *Self, io: Io, context: Context) Io.Cancelable!?Digest {
            var coin: [1]u8 = undefined;
            io.random(&coin);
            const block: types.BlockFormat = if (coin[0] & 1 == 1) random: {
                var random: [16]u8 = undefined;
                io.random(&random);
                break :random .{ .random = std.mem.readInt(u128, &random, .little) };
            } else bridge: {
                const network = self.other_network.identity();
                const response = try self.request(io, .{ .get_finalization = .{
                    .network = network,
                } });
                const finalization = switch (response) {
                    .success => {
                        self.tracer.event(.debug, "no finalization found", .{});
                        return null;
                    },
                    .finalization => |finalization| finalization,
                    .block => @panic("unexpected response"),
                };
                if (!self.verify_other(io, &finalization)) @panic("indexer is corrupt");
                break :bridge .{ .bridge = finalization };
            };
            const digest = store.block_digest(block);
            self.tracer.event(.info, "proposed", .{
                .block = Debug{ .block = block },
                .payload = digest,
            });

            const response = try self.request(io, .{ .put_block = .{
                .network = self.this_network,
                .block = block,
            } });
            const success = switch (response) {
                .success => |success| success,
                else => @panic("unexpected response"),
            };
            self.tracer.event(.debug, "block published", .{
                .round = RoundDebug{ .round = context.round },
                .success = success,
            });
            return if (success) digest else null;
        }

        /// Accepts a payload whose block the indexer holds and which is random data or a
        /// finalization of the other network.
        pub fn verify(
            self: *Self,
            io: Io,
            context: Context,
            payload: Digest,
        ) Io.Cancelable!?bool {
            _ = context; // Linking payloads to their parent would check it here.
            const response = try self.request(io, .{ .get_block = .{
                .network = self.this_network,
                .digest = payload,
            } });
            const block = switch (response) {
                .block => |block| block,
                .success => |success| {
                    if (success) @panic("unexpected response");
                    self.tracer.event(.debug, "block not found", .{});
                    return false;
                },
                .finalization => @panic("unexpected response"),
            };
            return switch (block) {
                .random => true,
                .bridge => |*finalization| self.verify_other(io, finalization),
            };
        }

        /// Sends nothing: blocks reach other validators through the indexer.
        pub fn broadcast(self: *Self, payload: Digest, plan: Plan) actor.Feedback {
            _ = self;
            _ = payload;
            _ = plan;
            return .ok;
        }

        /// Logs certificates and queues each finalization for the indexer.
        pub fn report(self: *Self, activity: Activity) actor.Feedback {
            assert(!self.closed);
            const view = activity.view().get();
            switch (activity) {
                .notarization => |notarization| self.tracer.event(.info, "notarized", .{
                    .view = view,
                    .payload = notarization.proposal.payload,
                    .signature = CertificateDebug{ .certificate = notarization.certificate },
                }),
                .finalization => |finalization| {
                    self.tracer.event(.info, "finalized", .{
                        .view = view,
                        .payload = finalization.proposal.payload,
                        .signature = CertificateDebug{ .certificate = finalization.certificate },
                    });
                    return self.posts.sender.enqueue(.{ .finalization = finalization }) catch
                        @panic("out of memory");
                },
                .nullification => |nullification| self.tracer.event(.info, "nullified", .{
                    .view = view,
                    .signature = CertificateDebug{ .certificate = nullification.certificate },
                }),
                else => {},
            }
            return .ok;
        }

        /// Posts queued finalizations to the indexer, in order, until canceled or closed.
        pub fn run(self: *Self, io: Io) Io.Cancelable!void {
            while (try self.posts.receiver.recv()) |post| {
                const view = post.finalization.view().get();
                const response = try self.request(io, .{ .put_finalization = .{
                    .network = self.this_network,
                    .finalization = post.finalization,
                } });
                const success = switch (response) {
                    .success => |success| success,
                    else => @panic("unexpected response"),
                };
                self.tracer.event(.debug, "finalization posted", .{
                    .view = view,
                    .success = success,
                });
            }
        }

        comptime {
            zigware.consensus.traits.assert_automaton(Self);
            zigware.consensus.traits.assert_relay(Self);
            zigware.consensus.traits.assert_reporter(Self);
        }
    };
}

/// A block as Rust's derived `Debug` prints it, such as `Random(42)` or
/// `Bridge(Finalization { proposal: Proposal { round: Round { ... }, ... }, ... })`.
pub const Debug = struct {
    block: types.BlockFormat,

    pub fn format(self: Debug, writer: *Io.Writer) Io.Writer.Error!void {
        switch (self.block) {
            .random => |random| try writer.print("Random({d})", .{random}),
            .bridge => |finalization| {
                const proposal = finalization.proposal;
                try writer.print("Bridge(Finalization {{ proposal: Proposal {{ round: {f}, " ++
                    "parent: View({d}), payload: {f} }}, certificate: {f} }})", .{
                    RoundDebug{ .round = proposal.round },
                    proposal.parent.get(),
                    proposal.payload,
                    CertificateDebug{ .certificate = finalization.certificate },
                });
            },
        }
    }
};

/// A round as Rust's derived `Debug` prints it.
pub const RoundDebug = struct {
    round: zigware.consensus.types.Round,

    pub fn format(self: RoundDebug, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("Round {{ epoch: Epoch({d}), view: View({d}) }}", .{
            self.round.epoch.get(), self.round.view.get(),
        });
    }
};

/// A threshold certificate as commonware's `Debug` prints it: its lazily decoded signature.
pub const CertificateDebug = struct {
    certificate: lib.Scheme.Certificate,

    pub fn format(self: CertificateDebug, writer: *Io.Writer) Io.Writer.Error!void {
        const signature = self.certificate.get() orelse
            return writer.writeAll("Certificate { signature: None }");
        const bytes = signature.to_bytes();
        try writer.print("Certificate {{ signature: Some({x}) }}", .{&bytes});
    }
};

test {
    _ = @import("application_test.zig");
}
