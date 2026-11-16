//! Lightweight subchannels over one p2p `Sender` and `Receiver` (commonware
//! `p2p/src/utils/mux.rs`).
//!
//! Usage:
//! - Call `Muxer(S, R).init` (or `build` for a backup channel and a `GlobalSender`) to obtain
//!   a `Muxer` and a `MuxHandle`.
//! - Call `Muxer.start` (or run `Muxer.run` in a task) to demux incoming messages into
//!   per-subchannel queues.
//! - Call `MuxHandle.register` to obtain a `SubSender` and `SubReceiver` for a subchannel, even
//!   while the muxer is running.
//!
//! Each subchannel and the backup queue hold up to the wrapped receiver's `capacity`
//! messages. An entire admitted burst may target one queue. Full queues drop arriving
//! messages so other queues can continue receiving.
//!
//! ```text
//! Muxed message:
//! +---------------------------+----------------------------------------------+
//! | subchannel (varint, 1-10) | payload (wrapped sender's limit less prefix) |
//! +---------------------------+----------------------------------------------+
//! ```
//!
//! A subchannel payload may be at most the wrapped sender's limit less its prefix. A component
//! that sends on subchannels of a `Muxer` it owns includes the prefix in its largest payload.
//! An application that runs a component on a subchannel of a `Muxer` it created passes the
//! component's largest payload through `prefixed` before sizing the network with
//! `p2p.max_message_size`.
//!
//! # Differences from commonware
//!
//! - Commonware's handles send `Register` and `Deregister` control messages to the muxer
//!   task. Here the routing table is shared under a mutex, so `register` and a dropped
//!   `SubReceiver` update it directly. The muxer still stops once every handle and
//!   subchannel receiver is gone, as it does when its control channel closes.
//! - The builder's typestates (`with_backup`, `with_global_sender`) are `build`'s `Options`;
//!   the backup receiver and global sender are optional fields of its result.
//! - Payloads are byte slices: the muxer strips the prefix by copying an owned payload.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils_pkg = @import("utils");

const p2p = @import("../root.zig");
const ErrorOf = @import("codec.zig").ErrorOf;
const Channel = p2p.Channel;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;
const mpsc = utils_pkg.channel.mpsc;
const max_u64_varint_size = codec.varint.max_u64_varint_size;

/// Errors from a `SubReceiver` or a `MuxHandle`.
pub const Error = error{
    /// The subchannel is already registered.
    AlreadyRegistered,
    /// The muxer is closed.
    Closed,
    /// The muxer stopped, so the subchannel receives nothing more.
    RecvFailed,
};

/// Parse a muxed message into its subchannel and payload (a view of `message`).
pub fn parse(message: []const u8) codec.Error!struct { Channel, []const u8 } {
    var reader = codec.Reader.init(message);
    const subchannel = try codec.varint.read(u64, &reader);
    const payload = reader.rest();
    assert(payload.len < message.len);
    return .{ subchannel, payload };
}

/// Returns `payload` plus the largest subchannel prefix, so it covers a payload of that size
/// on any `Muxer` subchannel.
pub fn prefixed(payload: usize) usize {
    return payload + max_u64_varint_size;
}

/// Commonware's blanket `Sender::send` over a `LimitedSender`: sends `parts` to the
/// recipients within their rate limit and returns those attempted (caller-owned), or none
/// when every recipient is limited or the checked send is not accepted.
pub fn send(
    gpa: Allocator,
    sender: anytype,
    recipients: p2p.Recipients(@TypeOf(sender.*).PublicKey),
    parts: []const []const u8,
    priority: bool,
) ![]@TypeOf(sender.*).PublicKey {
    const P = @TypeOf(sender.*).PublicKey;
    const checked = switch (try sender.check(recipients)) {
        .limited => return gpa.alloc(P, 0),
        .checked => |checked| checked,
    };
    const attempted = gpa.dupe(P, checked.recipients()) catch |err| {
        checked.deinit();
        return err;
    };
    if (checked.send(parts, priority).accepted()) return attempted;
    gpa.free(attempted);
    return gpa.alloc(P, 0);
}

/// A message routed to a subchannel queue; a dropped one frees its payload.
fn Routed(comptime P: type) type {
    return struct {
        message: p2p.Message(P),

        pub fn discard(routed: @This()) void {
            var message = routed.message;
            message.deinit();
        }
    };
}

/// A message for a subchannel that is not registered, sent to the backup channel. The
/// receiver owns `message`; release it with `deinit`.
pub fn BackupResponse(comptime P: type) type {
    return struct {
        subchannel: Channel,
        message: p2p.Message(P),

        pub fn discard(response: @This()) void {
            var message = response.message;
            message.deinit();
        }

        pub fn deinit(response: *@This()) void {
            response.message.deinit();
        }
    };
}

/// The routing table and handle counts shared by a muxer and its handles.
fn Shared(comptime P: type) type {
    return struct {
        const Self = @This();
        const Message = p2p.Message(P);
        const RouteSender = mpsc.Sender(Routed(P));

        gpa: Allocator,
        io: Io,
        /// Each queue's capacity: the wrapped receiver's.
        capacity: usize,
        mutex: Io.Mutex = .init,
        /// Signaled when the last control handle is released.
        condition: Io.Condition = .init,
        routes: std.AutoHashMapUnmanaged(Channel, RouteSender) = .empty,
        backup: ?mpsc.Sender(BackupResponse(P)) = null,
        /// `MuxHandle`s and `SubReceiver`s (commonware's control senders).
        controls: u32 = 1,
        /// Controls plus the muxer; the last release frees the state.
        handles: u32 = 2,
        /// Set once the muxer stopped (commonware's dropped control receiver).
        stopped: bool = false,

        fn create(gpa: Allocator, io: Io, capacity: usize) Allocator.Error!*Self {
            assert(capacity > 0);
            const shared = try gpa.create(Self);
            shared.* = .{ .gpa = gpa, .io = io, .capacity = capacity };
            assert(shared.handles == shared.controls + 1);
            return shared;
        }

        fn lock(shared: *Self) void {
            shared.mutex.lockUncancelable(shared.io);
        }

        fn unlock(shared: *Self) void {
            shared.mutex.unlock(shared.io);
        }

        /// Opens a queue for `subchannel` and returns its receiver.
        fn register(
            shared: *Self,
            subchannel: Channel,
        ) (Error || Allocator.Error)!mpsc.Receiver(Routed(P)) {
            shared.lock();
            defer shared.unlock();
            if (shared.stopped) return error.Closed;
            if (shared.routes.contains(subchannel)) return error.AlreadyRegistered;
            var queue = try mpsc.channel(Routed(P), shared.gpa, shared.io, shared.capacity);
            shared.routes.put(shared.gpa, subchannel, queue.sender) catch |err| {
                queue.sender.deinit();
                queue.receiver.deinit();
                return err;
            };
            shared.acquire_locked();
            assert(shared.routes.contains(subchannel));
            return queue.receiver;
        }

        /// Removes `subchannel`'s route if it still feeds `receiver`, then drops `receiver`
        /// and releases its control handle.
        fn deregister(
            shared: *Self,
            subchannel: Channel,
            receiver: *mpsc.Receiver(Routed(P)),
        ) void {
            shared.lock();
            if (shared.routes.get(subchannel)) |route| {
                if (route.state == receiver.state) {
                    var removed = shared.routes.fetchRemove(subchannel).?.value;
                    removed.deinit();
                }
            }
            shared.unlock();
            receiver.deinit();
            shared.release(true);
        }

        fn acquire_locked(shared: *Self) void {
            assert(shared.controls > 0);
            shared.controls += 1;
            shared.handles += 1;
        }

        fn acquire(shared: *Self) void {
            shared.lock();
            defer shared.unlock();
            shared.acquire_locked();
        }

        /// Releases a control handle (`control`) or the muxer's handle.
        fn release(shared: *Self, control: bool) void {
            shared.lock();
            if (control) {
                assert(shared.controls > 0);
                shared.controls -= 1;
                if (shared.controls == 0) shared.condition.signal(shared.io);
            }
            assert(shared.handles > shared.controls);
            shared.handles -= 1;
            const last = shared.handles == 0;
            shared.unlock();
            if (!last) return;
            assert(shared.routes.count() == 0);
            shared.routes.deinit(shared.gpa);
            shared.gpa.destroy(shared);
        }

        /// Waits until every control handle is released.
        fn wait_closed(shared: *Self) Io.Cancelable!void {
            try shared.mutex.lock(shared.io);
            defer shared.unlock();
            while (shared.controls > 0) try shared.condition.wait(shared.io, &shared.mutex);
        }

        /// Routes `message` (owned) to `subchannel`'s queue, or to the backup channel when no
        /// route exists. A full or closed queue drops it; a closed route is removed.
        fn deliver(shared: *Self, subchannel: Channel, message: Message) void {
            shared.lock();
            defer shared.unlock();
            assert(!shared.stopped);
            if (shared.routes.getPtr(subchannel)) |route| {
                route.try_send(.{ .message = message }) catch |err| {
                    Routed(P).discard(.{ .message = message });
                    if (err == error.Closed) {
                        var removed = shared.routes.fetchRemove(subchannel).?.value;
                        removed.deinit();
                    }
                };
                return;
            }
            const backup = shared.backup orelse return Routed(P).discard(.{ .message = message });
            backup.try_send(.{ .subchannel = subchannel, .message = message }) catch {
                Routed(P).discard(.{ .message = message });
            };
        }

        /// Marks the muxer stopped and closes every queue, so subchannel receivers drain and
        /// then fail with `RecvFailed`.
        fn stop(shared: *Self) void {
            shared.lock();
            assert(!shared.stopped);
            shared.stopped = true;
            var routes = shared.routes.valueIterator();
            while (routes.next()) |route| route.deinit();
            shared.routes.clearRetainingCapacity();
            if (shared.backup) |*backup| backup.deinit();
            shared.backup = null;
            shared.unlock();
            shared.release(false);
        }
    };
}

/// A multiplexer of a p2p channel (sender `S`, receiver `R`) into subchannels.
pub fn Muxer(comptime S: type, comptime R: type) type {
    p2p.assert_limited_sender(S);
    p2p.assert_receiver(R);
    comptime assert(S.PublicKey == R.PublicKey);
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Handle = MuxHandle(S);
        pub const RecvError = ErrorOf(R.recv);
        pub const RunError = RecvError || Io.Cancelable || Io.ConcurrentError;

        /// Commonware's `MuxerBuilder` choices.
        pub const Options = struct {
            /// Forward messages for unregistered subchannels to a backup channel.
            backup: bool = false,
            /// Also return a `GlobalSender` over a clone of the sender.
            global_sender: bool = false,
        };

        pub const Built = struct {
            muxer: Self,
            handle: Handle,
            backup: ?mpsc.Receiver(BackupResponse(P)),
            global_sender: ?GlobalSender(S),
        };

        shared: *Shared(P),
        receiver: R,

        /// Wraps `sender` and `receiver` (both moved in), returning the muxer and a handle
        /// that registers subchannels.
        pub fn init(
            gpa: Allocator,
            io: Io,
            sender: S,
            receiver: R,
        ) Allocator.Error!struct { muxer: Self, handle: Handle } {
            const built = try build(gpa, io, sender, receiver, .{});
            assert(built.backup == null and built.global_sender == null);
            return .{ .muxer = built.muxer, .handle = built.handle };
        }

        /// `init` with a backup channel and a global sender, as `options` asks.
        pub fn build(
            gpa: Allocator,
            io: Io,
            sender: S,
            receiver: R,
            options: Options,
        ) Allocator.Error!Built {
            const shared = try Shared(P).create(gpa, io, receiver.capacity());
            var built: Built = .{
                .muxer = .{ .shared = shared, .receiver = receiver },
                .handle = .{ .shared = shared, .sender = sender },
                .backup = null,
                .global_sender = null,
            };
            if (options.backup) {
                const queue = mpsc.channel(BackupResponse(P), gpa, io, shared.capacity) catch |err|
                    {
                        built.handle.deinit();
                        built.muxer.deinit();
                        return err;
                    };
                shared.backup = queue.sender;
                built.backup = queue.receiver;
            }
            if (options.global_sender) built.global_sender = .init(gpa, sender.clone());
            assert(shared.controls == 1);
            return built;
        }

        /// Runs the demuxer in a new task (see `run`).
        pub fn start(muxer: Self) Io.ConcurrentError!Io.Future(RunError!void) {
            const io = muxer.shared.io;
            return io.concurrent(run, .{muxer}) catch |err| {
                var unstarted = muxer;
                unstarted.deinit();
                return err;
            };
        }

        /// Demultiplexes received messages into subchannel queues until the wrapped receiver
        /// fails (its error is returned) or every handle and subchannel receiver is gone.
        /// Consumes the muxer.
        pub fn run(muxer: Self) RunError!void {
            var self = muxer;
            defer self.deinit();
            const io = self.shared.io;
            const Outcome = union(enum) { closed: Io.Cancelable!void, received: RecvError!void };
            var buffer: [2]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(io, &buffer);
            defer while (select.cancel()) |_| {};
            try select.concurrent(.closed, Shared(P).wait_closed, .{self.shared});
            try select.concurrent(.received, receive_loop, .{&self});
            return switch (try select.await()) {
                inline else => |result| result,
            };
        }

        fn receive_loop(self: *Self) RecvError!void {
            while (true) {
                const message = try self.receiver.recv();
                self.route(message);
            }
        }

        /// Strips `message`'s subchannel prefix and delivers it.
        fn route(self: *Self, message: p2p.Message(P)) void {
            var routed = message;
            const subchannel, const payload = parse(routed.payload) catch {
                routed.deinit();
                return;
            };
            if (routed.gpa) |gpa| {
                const owned = gpa.dupe(u8, payload) catch {
                    routed.deinit();
                    return;
                };
                gpa.free(routed.payload);
                routed.payload = owned;
            } else {
                routed.payload = payload;
            }
            self.shared.deliver(subchannel, routed);
        }

        /// Frees an unstarted muxer (`run` frees a started one).
        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(R, "deinit")) self.receiver.deinit();
            self.shared.stop();
            self.* = undefined;
        }
    };
}

/// A handle that registers subchannels at any time, even while the muxer runs. Clone it with
/// `clone`; release each copy with `deinit`.
pub fn MuxHandle(comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Registered = struct { sender: SubSender(S), receiver: SubReceiver(P) };

        shared: *Shared(P),
        sender: S,

        /// Opens `subchannel`, returning its sender and receiver. Fails with
        /// `AlreadyRegistered` if it is open, or `Closed` once the muxer stopped.
        pub fn register(
            self: *Self,
            subchannel: Channel,
        ) (Error || Allocator.Error)!Registered {
            const receiver = try self.shared.register(subchannel);
            return .{
                .sender = .{
                    .inner = .init(self.shared.gpa, self.sender.clone()),
                    .subchannel = subchannel,
                },
                .receiver = .{
                    .shared = self.shared,
                    .receiver = receiver,
                    .subchannel = subchannel,
                },
            };
        }

        pub fn clone(self: *const Self) Self {
            self.shared.acquire();
            return .{ .shared = self.shared, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(S, "deinit")) self.sender.deinit();
            self.shared.release(true);
            self.* = undefined;
        }
    };
}

/// Sends on one subchannel (a `LimitedSender`).
pub fn SubSender(comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Checked = CheckedGlobalSender(S);

        inner: GlobalSender(S),
        subchannel: Channel,

        pub fn check(self: *Self, recipients: p2p.Recipients(P)) !p2p.Check(Checked) {
            return switch (try self.inner.check(recipients)) {
                .limited => |time| .{ .limited = time },
                .checked => |checked| .{ .checked = checked.with_subchannel(self.subchannel) },
            };
        }

        /// Sends `parts` (concatenated) to `recipients`, returning those attempted
        /// (caller-owned).
        pub fn send(
            self: *Self,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
            priority: bool,
        ) ![]P {
            return send_checked(self.inner.gpa, self, recipients, parts, priority);
        }

        pub fn clone(self: *const Self) Self {
            return .{ .inner = self.inner.clone(), .subchannel = self.subchannel };
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
            self.* = undefined;
        }
    };
}

const send_checked = send;

/// Receives the messages of one subchannel. Releasing it deregisters the subchannel.
pub fn SubReceiver(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        shared: *Shared(P),
        receiver: mpsc.Receiver(Routed(P)),
        subchannel: Channel,

        /// The next message (free it with `deinit`), or `RecvFailed` once the muxer stopped
        /// and the queue is drained.
        pub fn recv(self: *Self) (Io.Cancelable || error{RecvFailed})!p2p.Message(P) {
            const routed = try self.receiver.recv() orelse return error.RecvFailed;
            return routed.message;
        }

        /// The next message if one is queued.
        pub fn try_recv(self: *Self) mpsc.TryRecvError!p2p.Message(P) {
            return (try self.receiver.try_recv()).message;
        }

        /// Messages the subchannel queues before it drops arrivals.
        pub fn capacity(self: *const Self) usize {
            assert(self.shared.capacity > 0);
            return self.shared.capacity;
        }

        pub fn deinit(self: *Self) void {
            self.shared.deregister(self.subchannel, &self.receiver);
            self.* = undefined;
        }
    };
}

/// Sends over any subchannel.
pub fn GlobalSender(comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Checked = CheckedGlobalSender(S);

        gpa: Allocator,
        inner: S,

        pub fn init(gpa: Allocator, inner: S) Self {
            return .{ .gpa = gpa, .inner = inner };
        }

        /// Sends `parts` (concatenated) over `subchannel`. A rate-limited send is rejected.
        pub fn send(
            self: *Self,
            subchannel: Channel,
            recipients: p2p.Recipients(P),
            parts: []const []const u8,
            priority: bool,
        ) Unreliable(Feedback) {
            const result = self.check(recipients) catch return .rejected;
            return switch (result) {
                .limited => .rejected,
                .checked => |checked| checked.with_subchannel(subchannel).send(parts, priority),
            };
        }

        /// A checked sender without a subchannel; set one with `with_subchannel`.
        pub fn check(self: *Self, recipients: p2p.Recipients(P)) !p2p.Check(Checked) {
            return switch (try self.inner.check(recipients)) {
                .limited => |time| .{ .limited = time },
                .checked => |checked| .{ .checked = .{ .gpa = self.gpa, .inner = checked } },
            };
        }

        pub fn clone(self: *const Self) Self {
            return .{ .gpa = self.gpa, .inner = self.inner.clone() };
        }

        pub fn deinit(self: *Self) void {
            if (comptime @hasDecl(S, "deinit")) self.inner.deinit();
            self.* = undefined;
        }
    };
}

/// A checked sender of a `GlobalSender` or `SubSender`. `send` consumes it; release an unsent
/// one with `deinit`.
pub fn CheckedGlobalSender(comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        gpa: Allocator,
        subchannel: ?Channel = null,
        inner: S.Checked,

        /// Sets the subchannel to send on.
        pub fn with_subchannel(self: Self, subchannel: Channel) Self {
            var result = self;
            result.subchannel = subchannel;
            return result;
        }

        pub fn recipients(self: *const Self) []const P {
            return self.inner.recipients();
        }

        /// Sends `parts` behind the subchannel prefix. The subchannel must be set. An
        /// allocation failure rejects the send.
        pub fn send(self: Self, parts: []const []const u8, priority: bool) Unreliable(Feedback) {
            const subchannel = self.subchannel orelse @panic("subchannel not set");
            var prefix: [max_u64_varint_size]u8 = undefined;
            var writer = codec.Writer.init(&prefix);
            codec.varint.write(u64, subchannel, &writer);
            assert(writer.written().len >= 1);
            const all = self.gpa.alloc([]const u8, parts.len + 1) catch {
                self.deinit();
                return .rejected;
            };
            defer self.gpa.free(all);
            all[0] = writer.written();
            @memcpy(all[1..], parts);
            return self.inner.send(all, priority);
        }

        pub fn deinit(self: Self) void {
            if (comptime @hasDecl(S.Checked, "deinit")) self.inner.deinit();
        }
    };
}

test {
    _ = @import("mux_test.zig");
}
