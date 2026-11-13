//! A mock reporter for aggregation (commonware `aggregation/mocks/reporter.rs`): an actor
//! that checks every reported ack and certificate (signature and codec round trip) and
//! tracks the highest and highest contiguous certified heights, which tests query through
//! the mailbox.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const parallel = @import("parallel");
const utils = @import("utils");
const consensus_types = @import("../../types.zig");
const types = @import("../types.zig");

const Epoch = consensus_types.Epoch;
const Height = consensus_types.Height;
const Feedback = actor.Feedback;
const oneshot = utils.channel.oneshot;

/// The highest certified height and the epoch it was certified in.
pub const Tip = struct { height: Height, epoch: Epoch };

/// The digest certified at a height, and the epoch it was certified in.
pub fn Certified(comptime D: type) type {
    return struct { digest: D, epoch: Epoch };
}

fn Message(comptime S: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();
        pub const Overflow = std.Deque(Self);

        ack: types.Ack(S, D),
        /// A clone the message owns, freed with `gpa`.
        certified: struct { gpa: Allocator, certificate: types.Certificate(S, D) },
        tip: Height,
        get_tip: oneshot.Sender(?Tip),
        get_contiguous_tip: oneshot.Sender(?Height),
        get: struct { height: Height, responder: oneshot.Sender(?Certified(D)) },

        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            overflow.pushBack(gpa, message) catch |err| {
                discard(message);
                return err;
            };
        }

        pub fn discard(message: Self) void {
            var copy = message;
            switch (copy) {
                .certified => |*value| value.certificate.deinit(value.gpa),
                .get_tip => |*responder| responder.deinit(),
                .get_contiguous_tip => |*responder| responder.deinit(),
                .get => |*value| value.responder.deinit(),
                .ack, .tip => {},
            }
        }
    };
}

/// The reporter actor. Create with `init`, run `run` in a task, and report through `Mailbox`.
pub fn Reporter(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Msg = Message(S, D);
        const Digests = std.AutoArrayHashMapUnmanaged(u64, Certified(D));

        gpa: Allocator,
        io: Io,
        /// Verifies signatures (ed25519 batch verification draws from it).
        rng: utils.rng.TestRng,
        receiver: actor.mailbox.Receiver(Msg),
        /// The verifying scheme; owned.
        scheme: S,
        /// Every certified digest by height.
        digests: Digests = .empty,
        contiguous: ?Height = null,
        highest: ?Tip = null,
        /// The epoch of the latest ack (commonware starts at 111, the tests' epoch).
        current_epoch: Epoch = .new(111),

        /// Takes ownership of `scheme`.
        pub fn init(gpa: Allocator, io: Io, scheme: S, seed: u64) Allocator.Error!struct {
            Self,
            Mailbox(S, D),
        } {
            const pair = try actor.mailbox.new(Msg, gpa, io, 1024);
            const reporter: Self = .{
                .gpa = gpa,
                .io = io,
                .rng = .init(seed),
                .receiver = pair.receiver,
                .scheme = scheme,
            };
            return .{ reporter, .{ .gpa = gpa, .io = io, .sender = pair.sender } };
        }

        pub fn deinit(self: *Self) void {
            self.receiver.deinit();
            self.scheme.deinit(self.gpa);
            self.digests.deinit(self.gpa);
            self.* = undefined;
        }

        /// Handles messages until every mailbox is gone.
        pub fn run(self: *Self) !void {
            while (try self.receiver.recv()) |message| {
                var owned = message;
                try self.handle(&owned);
            }
        }

        fn handle(self: *Self, message: *Msg) !void {
            switch (message.*) {
                .ack => |*ack| try self.handle_ack(ack),
                .certified => |*value| {
                    defer value.certificate.deinit(value.gpa);
                    try self.handle_certified(&value.certificate);
                },
                .tip => |height| self.raise_highest(height),
                .get_tip => |*responder| responder.send(self.highest) catch {},
                .get_contiguous_tip => |*responder| responder.send(self.contiguous) catch {},
                .get => |*value| {
                    const found = self.digests.get(value.height.get());
                    value.responder.send(found) catch {};
                },
            }
        }

        fn raise_highest(self: *Self, height: Height) void {
            const higher = if (self.highest) |tip| height.get() > tip.height.get() else true;
            if (higher) self.highest = .{ .height = height, .epoch = self.current_epoch };
        }

        fn handle_ack(self: *Self, ack: *const types.Ack(S, D)) !void {
            assert(try ack.verify(self.gpa, &self.rng, &self.scheme, parallel.sequential));
            const encoded = try codec.encode(types.Ack(S, D), self.gpa, ack.*);
            defer self.gpa.free(encoded);
            const decoded = try codec.decode(types.Ack(S, D), self.gpa, encoded);
            assert(decoded.eql(ack.*));
            self.current_epoch = ack.epoch;
        }

        fn handle_certified(self: *Self, certificate: *const types.Certificate(S, D)) !void {
            const Certificate = types.Certificate(S, D);
            const gpa = self.gpa;
            assert(try certificate.verify(gpa, &self.rng, &self.scheme, parallel.sequential));
            const encoded = try codec.encode(Certificate, gpa, certificate.*);
            defer gpa.free(encoded);
            const cfg = self.scheme.certificate_codec_config();
            var decoded = try codec.decode_cfg(Certificate, gpa, encoded, cfg);
            decoded.deinit(gpa);

            const height = certificate.item.height;
            const entry = try self.digests.getOrPut(gpa, height.get());
            // A conflicting digest must never be certified.
            if (entry.found_existing) {
                assert(entry.value_ptr.digest.order(certificate.item.digest) == .eq);
            }
            entry.value_ptr.* = .{ .digest = certificate.item.digest, .epoch = self.current_epoch };
            self.raise_highest(height);
            var next: u64 = if (self.contiguous) |contiguous| contiguous.get() + 1 else 0;
            while (self.digests.contains(next)) next += 1;
            if (next > 0) self.contiguous = .new(next - 1);
        }
    };
}

/// The reporter's mailbox: the engine's `Reporter`, and the tests' queries.
pub fn Mailbox(comptime S: type, comptime D: type) type {
    return struct {
        const Self = @This();
        const Msg = Message(S, D);
        pub const Activity = types.Activity(S, D);

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Msg),

        pub fn clone(self: Self) Self {
            return .{ .gpa = self.gpa, .io = self.io, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Queues `activity` (borrowed; a certificate is cloned).
        pub fn report(self: *Self, activity: Activity) Feedback {
            const message: Msg = switch (activity) {
                .ack => |ack| .{ .ack = ack },
                .tip => |height| .{ .tip = height },
                .certified => |*value| .{ .certified = .{
                    .gpa = self.gpa,
                    .certificate = value.clone(self.gpa) catch @panic("out of memory"),
                } },
            };
            return self.sender.enqueue(message) catch @panic("out of memory");
        }

        fn query(self: *Self, comptime T: type, comptime tag: anytype, extra: anytype) !T {
            const pair = try oneshot.channel(T, self.gpa, self.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            const message: Msg = switch (tag) {
                .get_tip, .get_contiguous_tip => @unionInit(Msg, @tagName(tag), pair.sender),
                .get => .{ .get = .{ .height = extra, .responder = pair.sender } },
                else => @compileError("not a query"),
            };
            const feedback = try self.sender.enqueue(message);
            assert(feedback.accepted());
            return receiver.recv();
        }

        /// The highest certified (or reported tip) height and its epoch.
        pub fn get_tip(self: *Self) !?Tip {
            return self.query(?Tip, .get_tip, {});
        }

        /// The highest height below which every height is certified.
        pub fn get_contiguous_tip(self: *Self) !?Height {
            return self.query(?Height, .get_contiguous_tip, {});
        }

        /// The digest certified at `height`.
        pub fn get(self: *Self, height: Height) !?Certified(D) {
            return self.query(?Certified(D), .get, height);
        }
    };
}
