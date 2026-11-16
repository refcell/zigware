//! The collector engine (commonware `collector/src/p2p/engine.rs`): disperses requests,
//! hands received requests to the `Handler`, sends its replies, and reports responses to
//! requests it sent to the `Monitor`.
//!
//! Event loop: tasks feed one signal (mutex and condition). A forwarder moves mailbox
//! commands into a one-command slot, two receivers move decoded requests and responses into
//! one-message slots (so network backpressure is preserved; peers sending undecodable bytes
//! are blocked), and each handler reply is awaited by its own task, which queues it. Each turn
//! handles one event in commonware's biased `select_loop!` order: mailbox commands, handler
//! replies, requests, then responses. The loop ends when every mailbox handle is gone, either
//! network receiver closes, or the task is canceled; the task then frees the engine.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const codec = @import("codec");
const p2p = @import("p2p");
const utils = @import("utils");
const metrics = @import("runtime").telemetry.metrics;

const collector = @import("../root.zig");
const ingress = @import("ingress.zig");

const SortedMap = p2p.simulated.sorted_map.SortedMap;
const oneshot = utils.channel.oneshot;

/// Calls `function` with `args`, propagating its error if it returns an error union.
fn call(function: anytype, args: anytype) !void {
    const result = @call(.auto, function, args);
    if (comptime @typeInfo(@TypeOf(result)) == .error_union) try result;
}

fn free_value(comptime T: type, gpa: Allocator, value: T) void {
    if (comptime @typeInfo(T) == .@"struct" and @hasDecl(T, "deinit")) {
        var owned = value;
        owned.deinit(gpa);
    }
}

/// Configuration for an `Engine`.
pub fn Config(comptime B: type, comptime M: type, comptime H: type) type {
    return struct {
        /// Blocks peers that send undecodable requests or responses.
        blocker: B,
        /// Notified when a response is collected (owned by the engine).
        monitor: M,
        /// Processes requests (owned by the engine).
        handler: H,
        /// The size of the mailbox.
        mailbox_size: u32,
        /// Whether to send requests with priority over other network messages.
        priority_request: bool,
        /// The codec configuration for requests.
        request_codec: codec.Cfg(H.Request),
        /// Whether to send responses with priority over other network messages.
        priority_response: bool,
        /// The codec configuration for responses.
        response_codec: codec.Cfg(H.Response),
    };
}

/// The engine for handler `H`, monitor `M`, blocker `B`, and network `N` (`N.Sender`,
/// `N.Receiver`; `N.RequestSender`, when declared, sends requests instead of `N.Sender`).
pub fn Engine(comptime H: type, comptime M: type, comptime B: type, comptime N: type) type {
    collector.assert_handler(H);
    collector.assert_monitor(M);
    p2p.assert_blocker(B);
    comptime assert(M.Response == H.Response);
    return struct {
        const Self = @This();
        const P = H.PublicKey;
        const Rq = H.Request;
        const Rs = H.Response;
        const RequestSender = if (@hasDecl(N, "RequestSender")) N.RequestSender else N.Sender;
        pub const Mailbox = ingress.Mailbox(P, Rq);
        pub const Message = ingress.Message(P, Rq);
        pub const Error = Allocator.Error || Io.ConcurrentError;
        const Peers = SortedMap(P, void);
        /// Peers sent a request for a commitment, and peers that responded.
        const Tracked = struct { sent: Peers = .empty, received: Peers = .empty };
        const Reply = struct { peer: P, response: Rs };

        gpa: Allocator,
        io: Io,
        config: Config(B, M, H),
        mailbox: actor.mailbox.Receiver(Message),
        tracked: SortedMap(Rq.Commitment, Tracked) = .empty,
        outstanding: metrics.Gauge,
        requests: metrics.Counter,
        responses: metrics.Counter,

        // Set by `start`.
        request_sender: RequestSender = undefined,
        request_receiver: N.Receiver = undefined,
        response_sender: N.Sender = undefined,
        response_receiver: N.Receiver = undefined,
        started: bool = false,

        /// Guards the slots below; every task signals `condition` when it changes them.
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        command_slot: ?Message = null,
        request_slot: ?Decoded(Rq) = null,
        response_slot: ?Decoded(Rs) = null,
        replies: std.ArrayList(Reply) = .empty,
        stopped: bool = false,
        tasks: Io.Group = .init,
        /// Tasks awaiting handler replies.
        reply_tasks: Io.Group = .init,

        fn Decoded(comptime T: type) type {
            return struct { peer: P, value: T };
        }

        /// The engine (not running yet; `start` runs it) and its mailbox. Metrics register
        /// under `scope`, the mailbox's under `scope.child("mailbox")`.
        pub fn init(
            gpa: Allocator,
            io: Io,
            scope: *const metrics.Scope,
            config: Config(B, M, H),
        ) Error!struct { engine: *Self, mailbox: Mailbox } {
            assert(config.mailbox_size > 0);
            const mailbox_scope = scope.child("mailbox");
            var pair = try actor.mailbox.new_with_metrics(
                Message,
                gpa,
                io,
                &mailbox_scope,
                config.mailbox_size,
            );
            errdefer pair.receiver.deinit();
            errdefer pair.sender.deinit();
            var outstanding = try scope.gauge("outstanding", "outstanding commitments");
            errdefer outstanding.deinit();
            var requests = try scope.counter("requests", "processed requests");
            errdefer requests.deinit();
            var responses = try scope.counter("responses", "sent responses");
            errdefer responses.deinit();
            const engine = try gpa.create(Self);
            engine.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .mailbox = pair.receiver,
                .outstanding = outstanding,
                .requests = requests,
                .responses = responses,
            };
            assert(!engine.started);
            return .{ .engine = engine, .mailbox = .{ .gpa = gpa, .sender = pair.sender } };
        }

        /// Starts the engine on its request and response channels (owned from now on). The
        /// engine frees itself when its task ends; cancel the future to stop it.
        pub fn start(
            engine: *Self,
            request_sender: RequestSender,
            request_receiver: N.Receiver,
            response_sender: N.Sender,
            response_receiver: N.Receiver,
        ) Error!Io.Future(Error!void) {
            assert(!engine.started);
            engine.request_sender = request_sender;
            engine.request_receiver = request_receiver;
            engine.response_sender = response_sender;
            engine.response_receiver = response_receiver;
            engine.started = true;
            return engine.io.concurrent(run, .{engine}) catch |err| {
                engine.destroy();
                return err;
            };
        }

        const Event = union(enum) {
            command: Message,
            reply: Reply,
            request: Decoded(Rq),
            response: Decoded(Rs),
            stopped,
        };

        fn run(engine: *Self) Error!void {
            defer engine.destroy();
            assert(engine.started);
            const io = engine.io;
            try engine.tasks.concurrent(io, forward_commands, .{engine});
            try engine.tasks.concurrent(io, receive_requests, .{engine});
            try engine.tasks.concurrent(io, receive_responses, .{engine});
            while (true) {
                const event = engine.wait_event() catch return; // canceled
                switch (event) {
                    .command => |command| try engine.handle_command(command),
                    .reply => |reply| {
                        engine.responses.metric().inc();
                        const recipients: p2p.Recipients(P) = .{ .one = reply.peer };
                        try engine.send(&engine.response_sender, Rs, recipients, reply.response);
                    },
                    .request => |request| try engine.handle_request(request),
                    .response => |response| try engine.handle_response(response),
                    .stopped => return,
                }
            }
        }

        fn wait_event(engine: *Self) Io.Cancelable!Event {
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            // Each wake re-checks every source in priority order.
            while (true) {
                if (engine.stopped) return .stopped;
                if (engine.command_slot) |command| {
                    engine.command_slot = null;
                    engine.condition.broadcast(engine.io);
                    return .{ .command = command };
                }
                if (engine.replies.items.len > 0) {
                    return .{ .reply = engine.replies.orderedRemove(0) };
                }
                if (engine.request_slot) |request| {
                    engine.request_slot = null;
                    engine.condition.broadcast(engine.io);
                    return .{ .request = request };
                }
                if (engine.response_slot) |response| {
                    engine.response_slot = null;
                    engine.condition.broadcast(engine.io);
                    return .{ .response = response };
                }
                try engine.condition.wait(engine.io, &engine.mutex);
            }
        }

        fn stop_locked(engine: *Self) void {
            engine.stopped = true;
            engine.condition.broadcast(engine.io);
        }

        /// Moves mailbox commands into `command_slot`.
        fn forward_commands(engine: *Self) void {
            while (true) {
                const received = engine.mailbox.recv() catch return; // canceled
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                const command = received orelse return engine.stop_locked();
                while (engine.command_slot != null) {
                    engine.condition.wait(engine.io, &engine.mutex) catch {
                        Message.discard(command);
                        return;
                    };
                }
                engine.command_slot = command;
                engine.condition.broadcast(engine.io);
            }
        }

        fn slot(engine: *Self, comptime T: type) *?Decoded(T) {
            return if (T == Rq) &engine.request_slot else &engine.response_slot;
        }

        fn receive_requests(engine: *Self) void {
            engine.receive(Rq, &engine.request_receiver);
        }

        fn receive_responses(engine: *Self) void {
            engine.receive(Rs, &engine.response_receiver);
        }

        /// Receives and decodes messages of type `T` into its slot, blocking peers whose
        /// messages fail to decode (commonware's wrapped receiver).
        fn receive(engine: *Self, comptime T: type, receiver: *N.Receiver) void {
            const cfg = if (T == Rq) engine.config.request_codec else engine.config.response_codec;
            while (true) {
                var raw = receiver.recv() catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        engine.mutex.lockUncancelable(engine.io);
                        defer engine.mutex.unlock(engine.io);
                        return engine.stop_locked();
                    },
                };
                defer raw.deinit();
                if (T == Rq) engine.requests.metric().inc();
                const value = codec.decode_cfg(T, engine.gpa, raw.payload, cfg) catch {
                    _ = engine.config.blocker.block(raw.peer);
                    continue;
                };
                engine.mutex.lockUncancelable(engine.io);
                defer engine.mutex.unlock(engine.io);
                const target = engine.slot(T);
                while (target.* != null) {
                    engine.condition.wait(engine.io, &engine.mutex) catch {
                        free_value(T, engine.gpa, value);
                        return;
                    };
                }
                target.* = .{ .peer = raw.peer, .value = value };
                engine.condition.broadcast(engine.io);
            }
        }

        /// Awaits the handler's reply to `peer` and queues it.
        fn await_reply(engine: *Self, peer: P, receiver: oneshot.Receiver(Rs)) void {
            var owned = receiver;
            defer owned.deinit();
            const response = owned.recv() catch return; // canceled, or no reply
            engine.mutex.lockUncancelable(engine.io);
            defer engine.mutex.unlock(engine.io);
            engine.replies.append(engine.gpa, .{ .peer = peer, .response = response }) catch {
                free_value(Rs, engine.gpa, response);
                return;
            };
            engine.condition.broadcast(engine.io);
        }

        /// Encodes and sends `value` (owned), returning the peers it reached (caller-owned).
        fn send(
            engine: *Self,
            sender: anytype,
            comptime T: type,
            recipients: p2p.Recipients(P),
            value: T,
        ) Allocator.Error!void {
            const attempted = try engine.send_attempted(sender, T, recipients, value);
            engine.gpa.free(attempted);
        }

        fn send_attempted(
            engine: *Self,
            sender: anytype,
            comptime T: type,
            recipients: p2p.Recipients(P),
            value: T,
        ) Allocator.Error![]P {
            defer free_value(T, engine.gpa, value);
            const bytes = try codec.encode(T, engine.gpa, value);
            defer engine.gpa.free(bytes);
            const priority = if (T == Rq)
                engine.config.priority_request
            else
                engine.config.priority_response;
            return sender.send(recipients, &.{bytes}, priority) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                return engine.gpa.alloc(P, 0); // a closed network reaches nobody
            };
        }

        fn handle_command(engine: *Self, command: Message) Error!void {
            switch (command) {
                .send => |send_command| {
                    defer send_command.recipients.deinit(send_command.gpa);
                    const commitment = send_command.request.commitment();
                    const attempted = try engine.send_attempted(
                        &engine.request_sender,
                        Rq,
                        send_command.recipients,
                        send_command.request,
                    );
                    defer engine.gpa.free(attempted);
                    if (attempted.len == 0) return;
                    const gpa = engine.gpa;
                    const count_before = engine.tracked.count();
                    const tracked = try engine.tracked.get_or_put(gpa, commitment, .{});
                    if (engine.tracked.count() > count_before) engine.outstanding.metric().inc();
                    for (attempted) |peer| _ = try tracked.sent.put(gpa, peer, {});
                },
                .cancel => |cancel| {
                    if (engine.tracked.remove(cancel.commitment)) |removed| {
                        var owned = removed;
                        owned.sent.deinit(engine.gpa);
                        owned.received.deinit(engine.gpa);
                    }
                    const count: i64 = @intCast(engine.tracked.count());
                    _ = engine.outstanding.metric().set(count);
                },
            }
        }

        /// Hands a request to the handler and awaits its reply in a task.
        fn handle_request(engine: *Self, request: Decoded(Rq)) Error!void {
            const pair = oneshot.channel(Rs, engine.gpa, engine.io) catch |err| {
                free_value(Rq, engine.gpa, request.value);
                return err;
            };
            var receiver = pair.receiver;
            engine.reply_tasks.concurrent(engine.io, await_reply, .{
                engine,
                request.peer,
                receiver,
            }) catch |err| {
                receiver.deinit();
                var responder = pair.sender;
                responder.deinit();
                free_value(Rq, engine.gpa, request.value);
                return err;
            };
            const handler = &engine.config.handler;
            try call(H.process, .{ handler, request.peer, request.value, pair.sender });
        }

        /// Reports a response to a request this engine sent to its peer, once per peer.
        fn handle_response(engine: *Self, response: Decoded(Rs)) Error!void {
            const gpa = engine.gpa;
            const commitment = response.value.commitment();
            const tracked = engine.tracked.get(commitment) orelse {
                free_value(Rs, gpa, response.value); // unknown commitment
                return;
            };
            const fresh = tracked.sent.contains(response.peer) and
                !tracked.received.contains(response.peer);
            if (!fresh) {
                free_value(Rs, gpa, response.value); // never sent, or a duplicate
                return;
            }
            _ = try tracked.received.put(gpa, response.peer, {});
            const count = tracked.received.count();
            const monitor = &engine.config.monitor;
            try call(M.collected, .{ monitor, response.peer, response.value, count });
        }

        /// Cancels every task and frees the engine and everything it owns.
        fn destroy(engine: *Self) void {
            const gpa = engine.gpa;
            engine.tasks.cancel(engine.io);
            engine.reply_tasks.cancel(engine.io);
            if (engine.command_slot) |command| Message.discard(command);
            if (engine.request_slot) |request| free_value(Rq, gpa, request.value);
            if (engine.response_slot) |response| free_value(Rs, gpa, response.value);
            for (engine.replies.items) |reply| free_value(Rs, gpa, reply.response);
            engine.replies.deinit(gpa);
            if (engine.started) {
                engine.request_sender.deinit();
                engine.request_receiver.deinit();
                engine.response_sender.deinit();
                engine.response_receiver.deinit();
            }
            engine.mailbox.deinit();
            for (engine.tracked.items()) |*entry| {
                entry.value.sent.deinit(gpa);
                entry.value.received.deinit(gpa);
            }
            engine.tracked.deinit(gpa);
            if (comptime @hasDecl(H, "deinit")) engine.config.handler.deinit();
            if (comptime @hasDecl(M, "deinit")) engine.config.monitor.deinit();
            engine.outstanding.deinit();
            engine.requests.deinit();
            engine.responses.deinit();
            engine.* = undefined;
            gpa.destroy(engine);
        }
    };
}
