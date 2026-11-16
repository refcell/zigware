//! Codec wrappers for a p2p `Sender` and `Receiver` (commonware `p2p/src/utils/codec.rs`).
//!
//! - `wrap(V, gpa, config, sender, receiver)` pairs a `WrappedSender` that encodes values of `V`
//!   with a `WrappedReceiver` that decodes them.
//! - `WrappedBackgroundReceiver` receives raw messages and decodes them through a
//!   `parallel` strategy. Peers that send undecodable messages are blocked, and decoded
//!   messages are forwarded to a `BackgroundReceiver`.
//!
//! # Differences from commonware
//!
//! - Payloads are byte slices, not `IoBuf`s, so decoding copies the fields it keeps instead of
//!   handing out views of the received frame. The ported view tests check values only.
//! - Commonware's `send` and `send_ref` are both `send`, which borrows the value.
//! - The background receiver's decode loop is two tasks. The receive loop submits each decode
//!   to the strategy as soon as a message arrives. A completion task awaits the decodes in
//!   arrival order and forwards each result, instead of commonware's completion-ordered
//!   `Pool`. A Zig task must be awaited, so a canceled receiver still finishes and forwards
//!   the decodes it already submitted.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const parallel = @import("parallel");
const metrics = @import("runtime").telemetry.metrics;

const p2p = @import("../root.zig");
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// The error set of function `f`'s error-union return type.
pub fn ErrorOf(comptime f: anytype) type {
    const Return = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
    return @typeInfo(Return).error_union.error_set;
}

/// A `WrappedSender` and `WrappedReceiver` sharing the value type `V`.
pub fn Wrapped(comptime S: type, comptime R: type, comptime V: type) type {
    return struct { sender: WrappedSender(S, V), receiver: WrappedReceiver(R, V) };
}

/// Wrap a `Sender` and `Receiver` with the codec of `V`. Both are moved into the result.
pub fn wrap(
    comptime V: type,
    gpa: Allocator,
    config: codec.Cfg(V),
    sender: anytype,
    receiver: anytype,
) Wrapped(@TypeOf(sender), @TypeOf(receiver), V) {
    return .{
        .sender = .init(gpa, sender),
        .receiver = .init(gpa, config, receiver),
    };
}

/// Wraps a `Sender` and encodes messages with `V`'s codec.
pub fn WrappedSender(comptime S: type, comptime V: type) type {
    p2p.assert_limited_sender(S);
    return struct {
        const Self = @This();
        pub const PublicKey = S.PublicKey;
        pub const Checked = CheckedWrappedSender(S, V);

        gpa: Allocator,
        sender: S,

        pub fn init(gpa: Allocator, sender: S) Self {
            return .{ .gpa = gpa, .sender = sender };
        }

        /// Sends `message` to `recipients`, returning the recipients attempted (caller-owned).
        pub fn send(
            self: *Self,
            recipients: p2p.Recipients(PublicKey),
            message: V,
            priority: bool,
        ) ![]PublicKey {
            const encoded = try codec.encode(V, self.gpa, message);
            defer self.gpa.free(encoded);
            return self.sender.send(recipients, &.{encoded}, priority);
        }

        /// Checks which recipients are within their rate limit, returning a checked sender
        /// for them or the time at which the send can be retried.
        pub fn check(self: *Self, recipients: p2p.Recipients(PublicKey)) !p2p.Check(Checked) {
            return switch (try self.sender.check(recipients)) {
                .limited => |time| .{ .limited = time },
                .checked => |checked| .{ .checked = .{ .gpa = self.gpa, .sender = checked } },
            };
        }

        pub fn clone(self: *const Self) Self {
            return .{ .gpa = self.gpa, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(S, "deinit")) self.sender.deinit();
            self.* = undefined;
        }
    };
}

/// A checked sender of a `WrappedSender`: encodes the message and sends it to the checked
/// recipients. `send` consumes it; release an unsent one with `deinit`.
pub fn CheckedWrappedSender(comptime S: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = S.PublicKey;

        gpa: Allocator,
        sender: S.Checked,

        pub fn recipients(self: *const Self) []const PublicKey {
            return self.sender.recipients();
        }

        /// Encodes and sends `message`. An allocation failure rejects the send.
        pub fn send(self: Self, message: V, priority: bool) Unreliable(Feedback) {
            const encoded = codec.encode(V, self.gpa, message) catch {
                self.deinit();
                return .rejected;
            };
            defer self.gpa.free(encoded);
            return self.sender.send(&.{encoded}, priority);
        }

        pub fn deinit(self: Self) void {
            if (comptime @hasDecl(S.Checked, "deinit")) self.sender.deinit();
        }
    };
}

/// A message received from `peer`, with the result of decoding it. A decoded value is owned
/// by the caller; free it with `codec.free(V, gpa, value)`.
pub fn WrappedMessage(comptime P: type, comptime V: type) type {
    return struct { peer: P, value: codec.Error!V };
}

/// Wraps a `Receiver` and decodes messages with `V`'s codec.
pub fn WrappedReceiver(comptime R: type, comptime V: type) type {
    p2p.assert_receiver(R);
    return struct {
        const Self = @This();
        pub const PublicKey = R.PublicKey;
        pub const Error = ErrorOf(R.recv);

        gpa: Allocator,
        config: codec.Cfg(V),
        receiver: R,

        pub fn init(gpa: Allocator, config: codec.Cfg(V), receiver: R) Self {
            return .{ .gpa = gpa, .config = config, .receiver = receiver };
        }

        /// Receives the next message from any peer. A message that fails to decode is
        /// returned with its decode error.
        pub fn recv(self: *Self) Error!WrappedMessage(PublicKey, V) {
            var message = try self.receiver.recv();
            defer message.deinit();
            const value = codec.decode_cfg(V, self.gpa, message.payload, self.config);
            return .{ .peer = message.peer, .value = value };
        }

        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(R, "deinit")) self.receiver.deinit();
            self.* = undefined;
        }
    };
}

/// A decoded message and the peer that sent it, queued in the background receiver's mailbox.
fn Decoded(comptime P: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Overflow = std.Deque(Self);

        peer: P,
        value: V,
        gpa: Allocator,

        /// A full mailbox rejects the message: it would likely be stale by the time the
        /// consumer reached it.
        pub fn handle(_: Allocator, _: *Overflow, message: Self) bool {
            message.discard();
            return false;
        }

        pub fn discard(message: Self) void {
            codec.free(V, message.gpa, message.value);
        }
    };
}

/// Receiver half for successfully decoded messages from a `WrappedBackgroundReceiver`.
pub fn BackgroundReceiver(comptime P: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Message = struct { peer: P, value: V };

        receiver: actor.mailbox.Receiver(Decoded(P, V)),

        /// The next decoded message (its value is owned by the caller), or null once the
        /// background receiver stopped and every decoded message has been received.
        pub fn recv(self: *Self) Io.Cancelable!?Message {
            const decoded = try self.receiver.recv() orelse return null;
            return .{ .peer = decoded.peer, .value = decoded.value };
        }

        pub fn deinit(self: *Self) void {
            self.receiver.deinit();
            self.* = undefined;
        }
    };
}

/// A background receiver that receives raw messages from a `Receiver` `R` and decodes them
/// with `V`'s codec through the strategy `T`, blocking peers through the `Blocker` `B`.
///
/// Each message's decode is submitted to the strategy as soon as it is read, so the receive
/// loop never waits on earlier decodes; the strategy's workers bound how many decodes run at
/// once. Decoded messages are forwarded through a mailbox holding as many messages as the
/// wrapped receiver's `capacity`. When the consumer falls behind and the mailbox fills,
/// further decoded messages are dropped, since they would likely be stale by the time the
/// consumer reached them.
///
/// `V` must own its decoded memory (decode into `[]const u8`, not `codec.Bytes`): each
/// payload is freed once its decode is forwarded.
pub fn WrappedBackgroundReceiver(
    comptime B: type,
    comptime R: type,
    comptime V: type,
    comptime T: type,
) type {
    p2p.assert_blocker(B);
    p2p.assert_receiver(R);
    parallel.assert_strategy(T);
    comptime assert(B.PublicKey == R.PublicKey);
    return Background(B, R, V, T);
}

fn Background(comptime B: type, comptime R: type, comptime V: type, comptime T: type) type {
    const P = R.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Receiver = BackgroundReceiver(P, V);
        const Mailbox = actor.mailbox.Sender(Decoded(P, V));
        const Message = p2p.Message(P);

        const DecodeOp = struct {
            gpa: Allocator,
            payload: []const u8,
            config: codec.Cfg(V),

            pub fn call(op: DecodeOp) codec.Error!V {
                return codec.decode_cfg(V, op.gpa, op.payload, op.config);
            }
        };

        /// A submitted decode and the message it reads, which it keeps alive.
        const Job = struct {
            task: parallel.Task(DecodeOp),
            message: Message,
        };

        gpa: Allocator,
        io: Io,
        receiver: R,
        codec_config: codec.Cfg(V),
        blocker: B,
        sender: Mailbox,
        strategy: T,
        /// Inbound decode outcomes.
        decode: metrics.status.Counter,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        /// Submitted decodes, in arrival order.
        pending: std.Deque(*Job) = .empty,
        /// Set once the receive loop stopped submitting decodes.
        closed: bool = false,
        completer: ?Io.Future(void) = null,

        /// The background receiver (not running yet: `start` runs it, `destroy` frees it
        /// unstarted) and its receiver half. Decode outcomes register in `scope` as `decode`,
        /// and the mailbox's backoff counter in `scope.child("mailbox")`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            receiver: R,
            codec_config: codec.Cfg(V),
            blocker: B,
            strategy: T,
        ) Allocator.Error!struct { background: *Self, receiver: Receiver } {
            const capacity: u32 = @intCast(receiver.capacity());
            assert(capacity > 0);
            const mailbox_scope = scope.child("mailbox");
            var pair = try actor.mailbox.new_with_metrics(
                Decoded(P, V),
                gpa,
                io,
                &mailbox_scope,
                capacity,
            );
            errdefer pair.receiver.deinit();
            errdefer pair.sender.deinit();
            var decode = try metrics.status.Counter.register(
                scope,
                "decode",
                "Inbound decode outcomes",
            );
            errdefer decode.deinit();
            const background = try gpa.create(Self);
            background.* = .{
                .gpa = gpa,
                .io = io,
                .receiver = receiver,
                .codec_config = codec_config,
                .blocker = blocker,
                .sender = pair.sender,
                .strategy = strategy,
                .decode = decode,
            };
            return .{ .background = background, .receiver = .{ .receiver = pair.receiver } };
        }

        /// Starts the background receiver. It runs until the wrapped receiver closes or the
        /// returned future is canceled, then frees itself.
        pub fn start(self: *Self) Io.ConcurrentError!Io.Future(void) {
            assert(self.completer == null);
            self.completer = self.io.concurrent(complete_loop, .{self}) catch |err| {
                self.destroy();
                return err;
            };
            return self.io.concurrent(run, .{self}) catch |err| {
                self.close();
                _ = self.completer.?.await(self.io);
                self.destroy();
                return err;
            };
        }

        /// Receives raw messages and submits their decodes until the receiver closes or the
        /// task is canceled, then waits for the submitted decodes to be forwarded.
        fn run(self: *Self) void {
            defer self.destroy();
            while (true) {
                const message = self.receiver.recv() catch break;
                self.submit(message);
            }
            self.close();
            _ = self.completer.?.await(self.io);
        }

        fn submit(self: *Self, message: Message) void {
            const job = self.gpa.create(Job) catch {
                var dropped = message;
                dropped.deinit();
                return;
            };
            job.* = .{
                .task = .init(.{
                    .gpa = self.gpa,
                    .payload = message.payload,
                    .config = self.codec_config,
                }),
                .message = message,
            };
            self.strategy.spawn(message.payload.len, &job.task);
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            assert(!self.closed);
            self.pending.pushBack(self.gpa, job) catch {
                // The decode was submitted, so it must be awaited before it is dropped.
                const result = self.strategy.block_on(&job.task);
                if (result) |value| codec.free(V, self.gpa, value) else |_| {}
                self.free_job(job);
                return;
            };
            self.condition.signal(self.io);
        }

        fn close(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.closed = true;
            self.condition.signal(self.io);
        }

        /// Awaits submitted decodes in arrival order and forwards their results, until the
        /// receive loop closed and every submitted decode was forwarded.
        fn complete_loop(self: *Self) void {
            while (self.next_job()) |job| {
                const result = self.strategy.block_on(&job.task);
                self.handle_decode_result(job.message.peer, result);
                self.free_job(job);
            }
        }

        fn next_job(self: *Self) ?*Job {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (self.pending.len == 0 and !self.closed) {
                self.condition.waitUncancelable(self.io, &self.mutex);
            }
            return self.pending.popFront();
        }

        fn handle_decode_result(self: *Self, peer: P, result: codec.Error!V) void {
            const value = result catch {
                self.decode.inc(.invalid) catch {};
                _ = self.blocker.block(peer);
                return;
            };
            const decoded: Decoded(P, V) = .{ .peer = peer, .value = value, .gpa = self.gpa };
            const accepted = self.sender.enqueue(decoded).accepted();
            self.decode.inc(if (accepted) .success else .dropped) catch {};
        }

        fn free_job(self: *Self, job: *Job) void {
            assert(job.task.is_done());
            job.message.deinit();
            self.gpa.destroy(job);
        }

        /// Frees the background receiver and everything it owns. Only for an unstarted or
        /// finished receiver: `start`'s task calls it when it ends.
        pub fn destroy(self: *Self) void {
            assert(self.pending.len == 0);
            self.pending.deinit(self.gpa);
            if (comptime @hasDecl(R, "deinit")) self.receiver.deinit();
            if (comptime @hasDecl(B, "deinit")) self.blocker.deinit();
            self.sender.deinit();
            self.decode.deinit();
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
        }
    };
}

test {
    _ = @import("codec_test.zig");
}
