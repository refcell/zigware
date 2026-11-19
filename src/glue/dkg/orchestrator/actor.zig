//! Consensus engine orchestration for threshold reshare epoch transitions (commonware
//! `glue::dkg::orchestrator::actor`).
//!
//! The actor runs one Simplex engine per epoch over three channels (votes, certificates, and
//! resolver), each multiplexed by epoch. It enters an epoch only after the `fence.Gate`
//! reaches it, activates the epoch's peers through the `Manager`, and loads the epoch's
//! scheme from the `Provider`. When marshal reports the active epoch's final block, the actor
//! enters the next epoch, stops the old engine, and then acknowledges the block. A vote or
//! certificate for a later epoch is a catch-up hint: the actor asks marshal for the
//! finalization of its own epoch's final block from that peer.
//!
//! The type parameters come in one comptime struct `T`, checked by `assert_types`:
//! `Context` (a `runtime.Context`), `Block` (a `dkg.assert_reshare_block` block) and `Ack`,
//! `Scheme` (the epoch signing scheme over `Block.Digest`), `Provider` (`scheme(epoch)
//! ?*const Scheme`), `Manager` (a DKG manager's `track`, usually a pointer),
//! `Marshal` (the part of marshal's mailbox the actor reads: `get_processed() !?Processed`,
//! `get_block(identifier) !?Digested(Block)`, and `hint_finalized(height, targets) !void`),
//! `Blocker`, `ElectorConfig` and `Elector` with `build_elector(config, gpa, participants)
//! !Elector`, `Automaton` (a pointer), `Relay`, `Reporter`, `Strategy`, and the raw channel
//! types `Sender` and `Receiver`. The automaton, relay, and reporter are borrowed handles
//! copied into every epoch's engine.
//!
//! Commonware panics when marshal skips the active epoch's final block, when a boundary block
//! carries no `EpochInfo` or one for another epoch, and when the provider has no scheme for
//! an entered epoch; here those are `ContractError`s and `run` returns them. The
//! `latest_epoch` gauge is not carried. `deinit` releases `marshal` when it is a value with
//! `deinit` (the actor owns it); a pointer is borrowed.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const p2p = @import("p2p");
const runtime = @import("runtime");
const utils = @import("utils");
const dkg = @import("../root.zig");
const fence = @import("../fence.zig");
const state_sync = @import("../state_sync.zig");
const types = @import("../types.zig");
const mailbox_mod = @import("mailbox.zig");

const Tracer = runtime.telemetry.traces.Tracer;
/// The tracing target of the orchestrator's events (commonware's module path).
pub const trace_target = "commonware_glue::dkg::orchestrator::actor";
const simplex = consensus.simplex;
const mux = p2p.utils.mux;
const Duration = utils.Duration;
const Epoch = consensus.Epoch;
const Height = consensus.Height;
const FixedEpocher = consensus.types.FixedEpocher;

/// Marshal or provider contract violations, where commonware panics.
pub const ContractError = error{
    /// Marshal reported a block past the active epoch's final block.
    SkippedFinalBlock,
    /// A boundary block carries no `EpochInfo`, or one for another epoch.
    MissingEpochInfo,
    /// The provider has no scheme for an epoch the actor enters.
    MissingScheme,
};

/// Why the actor could not enter an epoch; each one stops the actor.
const EnterError = error{ GateClosed, PeerSet, MuxClosed, Stopped };

/// Asserts `T` carries the orchestrator's type parameters (see the file header).
pub fn assert_types(comptime T: type) void {
    comptime {
        const decls = .{
            "Context",   "Block",         "Ack",     "Scheme",        "Provider",
            "Manager",   "Marshal",       "Blocker", "ElectorConfig", "Elector",
            "Automaton", "build_elector", "Relay",   "Reporter",      "Strategy",
            "Sender",    "Receiver",
        };
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) @compileError(@typeName(T) ++ " lacks orchestrator." ++ decl);
        }
        dkg.assert_reshare_block(T.Block);
        utils.acknowledgement.assert_acknowledgement(T.Ack);
    }
}

/// Simplex settings applied to every epoch engine (commonware `SimplexConfig`). Each field is
/// passed to the `simplex.config.Config` field of the same name, which documents it; an
/// invalid one panics when the actor enters an epoch. `elector` is built per epoch through
/// `T.build_elector`.
pub fn SimplexConfig(comptime L: type) type {
    return struct {
        elector: L,
        mailbox_size: u32,
        replay_buffer: u32,
        write_buffer: u32,
        page_cache: *runtime.buffer.paged.CacheRef,
        leader_timeout: Duration,
        certification_timeout: Duration,
        timeout_retry: Duration,
        fetch_timeout: Duration,
        fetch_retry_delay: Duration,
        view_retention: consensus.types.ViewDelta,
        skip: simplex.config.SkipPolicy,
        track_historical_votes: bool,
        forward: simplex.config.ForwardPolicy,
    };
}

/// Configuration for the `Actor` (commonware `Config`).
pub fn Config(comptime T: type) type {
    return struct {
        /// Network blocker shared with each epoch's engine.
        blocker: T.Blocker,
        /// Peer manager that activates each epoch's peers.
        manager: T.Manager,
        /// Provider of epoch-scoped signing schemes; it must hold every entered epoch's.
        provider: T.Provider,
        /// Marshal, read for the startup position and boundary blocks.
        marshal: T.Marshal,
        automaton: T.Automaton,
        relay: T.Relay,
        reporter: T.Reporter,
        strategy: T.Strategy,
        simplex: SimplexConfig(T.ElectorConfig),
        /// The actor enters an epoch only after this gate reaches it.
        gate: fence.Gate,
        /// State-sync startup plan shared with the reshare actor (borrowed).
        state_sync: *state_sync.Plan(T.Scheme, T.Block.Digest, T.Block.Variant, T.Block.Directory),
        blocks_per_epoch: u64,
        /// Maximum number of finalized-block reports buffered before overflow.
        mailbox_size: u32,
        /// Prefix of each epoch's consensus partition, `<prefix>_consensus_<epoch>` (borrowed).
        partition_prefix: []const u8,
    };
}

/// Runs one Simplex engine per epoch (see the file header).
pub fn Actor(comptime T: type) type {
    comptime assert_types(T);
    return struct {
        const Self = @This();
        pub const PublicKey = T.Scheme.PublicKey;
        pub const Digest = T.Block.Digest;
        pub const Digested = broadcast.Digested(T.Block);
        pub const Message = mailbox_mod.Message(T.Block, T.Ack);
        pub const Mailbox = mailbox_mod.Mailbox(T.Block, T.Ack);
        pub const Floor = simplex.config.Floor(T.Scheme, Digest);
        pub const Info = types.EpochInfo(T.Block.Variant, PublicKey, T.Block.Directory);
        const Payload = types.Payload(T.Block.Variant, PublicKey, T.Block.Directory);
        const Mux = mux.Muxer(T.Sender, T.Receiver);
        const Backup = utils.channel.mpsc.Receiver(mux.BackupResponse(PublicKey));

        pub const EngineParams = struct {
            pub const Context = T.Context;
            pub const Scheme = T.Scheme;
            pub const Elector = T.Elector;
            pub const Blocker = T.Blocker;
            pub const Digest = T.Block.Digest;
            pub const Automaton = T.Automaton;
            pub const Relay = T.Relay;
            pub const Reporter = T.Reporter;
            pub const Strategy = T.Strategy;
            pub const Sender = mux.SubSender(T.Sender);
            pub const Receiver = mux.SubReceiver(PublicKey);
        };
        pub const Engine = simplex.Engine(EngineParams);
        const EngineChannel = simplex.engine.Channel(EngineParams);

        /// A raw channel: a sender and a receiver of `T`'s types.
        pub const Channel = struct { sender: T.Sender, receiver: T.Receiver };

        /// The running engine of one epoch. Stopping it aborts the engine's task.
        const Active = struct {
            epoch: Epoch,
            /// `epoch`, checked against corruption of a freed epoch.
            engine_epoch: u64,
            engine: Engine,
            elector: T.Elector,
            partition: []u8,
            handle: runtime.context.Handle(Engine.RunResult),
        };

        /// The demuxers and their epoch-scoped handles.
        const Channels = struct {
            vote: Mux.Handle,
            vote_backup: Backup,
            certificate: Mux.Handle,
            certificate_backup: Backup,
            resolver: Mux.Handle,
            demuxers: [3]Io.Future(Mux.RunError!void),
        };

        const Start = struct { epoch: Epoch, floor: Floor, info: Info };

        ctx: T.Context,
        gpa: Allocator,
        io: Io,
        config: Config(T),
        epocher: FixedEpocher,
        mailbox: actor.mailbox.Receiver(Message),
        tracer: Tracer,

        /// An orchestrator and the mailbox that receives finalized blocks (commonware
        /// `Actor::new`). Install the mailbox as a marshal reporter. Takes `config`'s handles.
        pub fn init(ctx: T.Context, config: Config(T)) Allocator.Error!struct { Self, Mailbox } {
            assert(config.blocks_per_epoch > 0);
            assert(config.mailbox_size > 0);
            const gpa = ctx.gpa();
            const pair = try actor.mailbox.new(Message, gpa, ctx.io(), config.mailbox_size);
            const self: Self = .{
                .ctx = ctx,
                .gpa = gpa,
                .io = ctx.io(),
                .config = config,
                .epocher = .new(utils.NonZero(u64).init(config.blocks_per_epoch).?),
                .mailbox = pair.receiver,
                .tracer = ctx.tracer(trace_target),
            };
            return .{ self, .init(pair.sender) };
        }

        pub fn deinit(self: *Self) void {
            assert(self.config.blocks_per_epoch > 0);
            self.mailbox.deinit();
            const M = @TypeOf(self.config.marshal);
            if (comptime @typeInfo(M) != .pointer and @hasDecl(M, "deinit")) {
                self.config.marshal.deinit();
            }
            self.* = undefined;
        }

        /// Drives epoch consensus from finalized blocks and later-epoch traffic until the
        /// runtime stops, the mailbox or a backup channel closes, an engine stops, or an epoch
        /// cannot be entered (commonware `start` and `run`). Takes the three channels.
        pub fn run(self: *Self, votes: Channel, certificates: Channel, resolver: Channel) !void {
            var channels = try self.create_channels(votes, certificates, resolver);
            defer self.close_channels(&channels);
            var start = try self.resolve_start() orelse return;
            defer start.info.deinit(self.gpa);
            const info = &start.info;
            var active = self.enter_epoch(start.epoch, start.floor, info, &channels) catch |err|
                return self.startup_failed(start.epoch, err);
            defer self.stop(active);
            while (true) {
                const events = try self.next_events(active, &channels);
                var index: usize = 0;
                defer for (events.items[index..events.len]) |rest| discard(rest);
                var keep_running = true;
                while (keep_running and index < events.len) {
                    const event = events.items[index];
                    index += 1;
                    keep_running = try self.handle_event(&active, event, &channels);
                }
                if (!keep_running) return;
            }
        }

        fn startup_failed(self: *Self, epoch: Epoch, err: anyerror) anyerror!void {
            const t = self.tracer;
            switch (err) {
                error.GateClosed => t.event(.debug, "epoch gate closed before startup", .{
                    .epoch = epoch.get(),
                }),
                error.PeerSet => t.event(.warn, "failed to activate startup peer set", .{
                    .epoch = epoch,
                    .@"error" = err,
                }),
                error.MuxClosed => t.event(.debug, "consensus mux closed before startup epoch", .{
                    .epoch = epoch.get(),
                }),
                error.Stopped => t.event(.debug, "context shutdown before startup epoch", .{}),
                else => return err,
            }
            assert(err != error.OutOfMemory);
        }

        /// Starts the consensus demuxers (commonware `create_channels`). Takes the channels.
        fn create_channels(
            self: *Self,
            votes: Channel,
            certificates: Channel,
            resolver: Channel,
        ) !Channels {
            const with_backup: Mux.Options = .{ .backup = true };
            var vote = try Mux.build(self.gpa, self.io, votes.sender, votes.receiver, with_backup);
            assert(vote.backup != null);
            errdefer vote.handle.deinit();
            errdefer vote.backup.?.deinit();
            var certificate = try Mux.build(
                self.gpa,
                self.io,
                certificates.sender,
                certificates.receiver,
                with_backup,
            );
            errdefer certificate.handle.deinit();
            errdefer certificate.backup.?.deinit();
            const backfill = try Mux.init(self.gpa, self.io, resolver.sender, resolver.receiver);
            var channels: Channels = .{
                .vote = vote.handle,
                .vote_backup = vote.backup.?,
                .certificate = certificate.handle,
                .certificate_backup = certificate.backup.?,
                .resolver = backfill.handle,
                .demuxers = undefined,
            };
            channels.demuxers[0] = try vote.muxer.start();
            channels.demuxers[1] = try certificate.muxer.start();
            channels.demuxers[2] = try backfill.muxer.start();
            assert(channels.vote.shared != channels.certificate.shared);
            return channels;
        }

        fn close_channels(self: *Self, channels: *Channels) void {
            assert(channels.vote.shared != channels.resolver.shared);
            channels.vote.deinit();
            channels.certificate.deinit();
            channels.resolver.deinit();
            channels.vote_backup.deinit();
            channels.certificate_backup.deinit();
            for (&channels.demuxers) |*demuxer| {
                if (demuxer.cancel(self.io)) |_| {} else |_| {}
            }
            channels.* = undefined;
        }

        /// The startup epoch from state-sync material if the plan resolves to any, and
        /// otherwise from the boundary block of marshal's recovered epoch (commonware
        /// `resolve_start`). Null if marshal cannot supply that block.
        fn resolve_start(self: *Self) !?Start {
            const processed = try self.config.marshal.get_processed();
            const recovered: ?Epoch = if (processed) |position|
                state_sync.recovered_epoch(position, self.epocher)
            else
                null;
            const resolved = try self.config.state_sync.resolve(self.ctx.storage, recovered);
            if (resolved) |material| {
                assert(material.epochs_match());
                return .{
                    .epoch = material.info.epoch,
                    .floor = .{ .finalized = material.floor },
                    .info = material.info,
                };
            }
            return self.resolve_boundary(recovered orelse .zero());
        }

        /// `epoch` from the finalized boundary block that carries its `EpochInfo`
        /// (commonware `resolve_boundary`). Null if marshal cannot supply the block.
        fn resolve_boundary(self: *Self, epoch: Epoch) !?Start {
            const height = if (epoch.previous()) |previous|
                self.epocher.last(previous).?
            else
                Height.zero();
            var boundary = try self.config.marshal.get_block(.{ .height = height }) orelse {
                const message = "boundary block unavailable, shutting down orchestrator";
                self.tracer.event(.@"error", message, .{ .epoch = epoch, .height = height });
                return null;
            };
            defer boundary.deinit();
            var info = try self.epoch_info_of(&boundary);
            errdefer info.deinit(self.gpa);
            if (info.epoch.get() != epoch.get()) return error.MissingEpochInfo;
            assert(info.epoch.get() == epoch.get());
            return .{ .epoch = epoch, .floor = .{ .genesis = boundary.digest() }, .info = info };
        }

        /// The `EpochInfo` a boundary block carries (owned).
        fn epoch_info_of(self: *Self, block: *const Digested) !Info {
            var payload: Payload = try block.inner().payload(self.gpa) orelse
                return error.MissingEpochInfo;
            if (payload != .epoch_info) {
                payload.deinit(self.gpa);
                return error.MissingEpochInfo;
            }
            assert(payload == .epoch_info);
            return payload.epoch_info;
        }

        /// One thing the run loop reacts to; it owns what it carries.
        const Event = union(enum) {
            vote: ?mux.BackupResponse(PublicKey),
            certificate: ?mux.BackupResponse(PublicKey),
            engine,
            mailbox: ?Message,
        };

        /// Up to one event per source, in commonware's `select_loop!` order.
        const Events = struct { items: [4]Event = undefined, len: usize = 0 };

        const Outcome = union(enum) {
            vote: Io.Cancelable!?mux.BackupResponse(PublicKey),
            certificate: Io.Cancelable!?mux.BackupResponse(PublicKey),
            engine: Io.Cancelable!void,
            mailbox: Io.Cancelable!?Message,
        };

        /// The finished sources of one wait, by `Outcome` tag.
        const Collected = struct {
            slots: [4]?Event = @splat(null),

            fn collect(collected: *Collected, outcome: Outcome) void {
                const slot = &collected.slots[@backingInt(std.meta.activeTag(outcome))];
                assert(slot.* == null);
                // Built in a local: assigning through `slot` would set its tag before a
                // canceled outcome returns, leaving an undefined payload behind.
                const event: Event = switch (outcome) {
                    .vote => |result| .{ .vote = result catch return },
                    .certificate => |result| .{ .certificate = result catch return },
                    .engine => |result| blk: {
                        result catch return;
                        break :blk .engine;
                    },
                    .mailbox => |result| .{ .mailbox = result catch return },
                };
                slot.* = event;
                assert(slot.* != null);
            }

            fn events(collected: *const Collected) Events {
                var result: Events = .{};
                for (collected.slots) |slot| {
                    const event = slot orelse continue;
                    result.items[result.len] = event;
                    result.len += 1;
                }
                assert(result.len <= result.items.len);
                return result;
            }

            fn discard_all(collected: *const Collected) void {
                for (collected.slots) |slot| if (slot) |event| discard(event);
            }
        };

        fn recv_backup(receiver: *Backup) Io.Cancelable!?mux.BackupResponse(PublicKey) {
            return receiver.recv();
        }

        fn wait_engine(active: *Active) Io.Cancelable!void {
            return active.engine.wait_stopped();
        }

        fn recv_mailbox(receiver: *actor.mailbox.Receiver(Message)) Io.Cancelable!?Message {
            return receiver.recv();
        }

        /// Waits for the first of the backup channels, the engine, and the mailbox, and
        /// returns every source that finished by then.
        fn next_events(self: *Self, active: *Active, channels: *Channels) !Events {
            assert(active.epoch.get() == active.engine_epoch);
            var collected: Collected = .{};
            var buffer: [4]Outcome = undefined;
            var select: Io.Select(Outcome) = .init(self.io, &buffer);
            errdefer {
                while (select.cancel()) |outcome| collected.collect(outcome);
                collected.discard_all();
            }
            try select.concurrent(.vote, recv_backup, .{&channels.vote_backup});
            try select.concurrent(.certificate, recv_backup, .{&channels.certificate_backup});
            try select.concurrent(.engine, wait_engine, .{active});
            try select.concurrent(.mailbox, recv_mailbox, .{&self.mailbox});
            collected.collect(try select.await());
            while (select.cancel()) |outcome| collected.collect(outcome);
            const events = collected.events();
            // Every source answered canceled: this task is being canceled.
            if (events.len == 0) return error.Canceled;
            assert(events.len <= events.items.len);
            return events;
        }

        fn discard(event: Event) void {
            switch (event) {
                .vote, .certificate => |response| if (response) |value| value.discard(),
                .engine => {},
                .mailbox => |message| if (message) |value| value.discard(),
            }
        }

        /// Handles `event` (taken); false when the actor stops.
        fn handle_event(self: *Self, active: **Active, event: Event, channels: *Channels) !bool {
            assert(active.*.epoch.get() == active.*.engine_epoch);
            switch (event) {
                .vote => |response| {
                    var value = response orelse {
                        self.tracer.event(.debug, "vote mux backup channel closed, " ++
                            "shutting down orchestrator", .{});
                        return false;
                    };
                    defer value.deinit();
                    try self.handle_backup(active.*.epoch, value.subchannel, value.message.peer);
                    return true;
                },
                .certificate => |response| {
                    var value = response orelse {
                        self.tracer.event(.debug, "certificate mux backup channel closed, " ++
                            "shutting down orchestrator", .{});
                        return false;
                    };
                    defer value.deinit();
                    try self.handle_backup(active.*.epoch, value.subchannel, value.message.peer);
                    return true;
                },
                .engine => {
                    const message = "simplex engine stopped, shutting down orchestrator";
                    self.tracer.event(.debug, message, .{ .epoch = active.*.epoch.get() });
                    return false;
                },
                .mailbox => |message| {
                    const value = message orelse {
                        const text = "mailbox closed, shutting down orchestrator";
                        self.tracer.event(.debug, text, .{});
                        return false;
                    };
                    return self.handle_finalized(active, value, channels);
                },
            }
        }

        /// Asks `from` for the finalization of `ours`'s final block if `theirs` is later
        /// (commonware `handle_backup`).
        fn handle_backup(self: *Self, ours: Epoch, theirs: u64, from: PublicKey) !void {
            if (theirs <= ours.get()) {
                self.tracer.event(.debug, "received message from past epoch", .{
                    .their_epoch = theirs,
                    .our_epoch = ours,
                    .from = from,
                });
                return;
            }
            const boundary = self.epocher.last(ours).?;
            assert(boundary.get() >= ours.get());
            self.tracer.event(.debug, "received backup message from future epoch, " ++
                "ensuring boundary finalization", .{
                .from = from,
                .their_epoch = theirs,
                .our_epoch = ours,
                .boundary_height = boundary,
            });
            try self.config.marshal.hint_finalized(boundary, &.{from});
        }

        /// Handles a finalized block (taken); false when the actor stops (commonware
        /// `handle_finalized`). Acknowledges a block below the active epoch's final block at
        /// once; for the final block, enters the next epoch and acknowledges it after.
        fn handle_finalized(
            self: *Self,
            active: **Active,
            message: Message,
            channels: *Channels,
        ) !bool {
            var block = message.finalized.block;
            defer block.deinit();
            var ack = message.finalized.ack;
            errdefer ack.deinit();
            const current = active.*.epoch;
            const height = block.inner().height();
            const last = self.epocher.last(current).?;
            if (height.get() > last.get()) return error.SkippedFinalBlock;
            if (height.get() != last.get()) {
                ack.acknowledge();
                return true;
            }
            const next_epoch = current.next();
            var info = try self.epoch_info_of(&block);
            defer info.deinit(self.gpa);
            if (info.epoch.get() != next_epoch.get()) return error.MissingEpochInfo;
            var boundary = try self.config.marshal.get_block(.{ .height = height }) orelse {
                const text = "boundary block unavailable, shutting down orchestrator";
                self.tracer.event(.debug, text, .{ .height = height });
                ack.deinit();
                return false;
            };
            const floor: Floor = .{ .genesis = boundary.digest() };
            boundary.deinit();
            const next = self.enter_epoch(next_epoch, floor, &info, channels) catch |err| {
                try self.boundary_failed(next_epoch, err);
                ack.deinit();
                return false;
            };
            self.stop(active.*);
            active.* = next;
            ack.acknowledge();
            return true;
        }

        fn boundary_failed(self: *Self, epoch: Epoch, err: anyerror) anyerror!void {
            const t = self.tracer;
            const fields = .{ .next_epoch = epoch };
            switch (err) {
                error.GateClosed => {
                    t.event(.debug, "epoch gate closed before boundary transition", fields);
                },
                error.PeerSet => t.event(.warn, "failed to activate boundary peer set", .{
                    .next_epoch = epoch,
                    .@"error" = err,
                }),
                error.MuxClosed => {
                    t.event(.debug, "consensus mux closed before boundary transition", fields);
                },
                error.Stopped => {
                    t.event(.debug, "context shutdown while waiting to enter epoch", fields);
                },
                else => return err,
            }
            assert(err != error.OutOfMemory);
        }

        /// Waits for the gate to reach `epoch`, activates its peers, and starts its engine
        /// (commonware `enter_epoch`). Takes `floor`. The previous engine keeps running until
        /// the caller stops it.
        fn enter_epoch(
            self: *Self,
            epoch: Epoch,
            floor: Floor,
            info: *const Info,
            channels: *Channels,
        ) !*Active {
            var pending: ?Floor = floor;
            errdefer if (pending) |*unused| deinit_floor(self.gpa, unused);
            try self.wait_gate(epoch);
            try self.track(epoch, info);
            const scheme = self.config.provider.scheme(epoch) orelse return error.MissingScheme;
            const active = try self.gpa.create(Active);
            errdefer self.gpa.destroy(active);
            active.epoch = epoch;
            active.engine_epoch = epoch.get();
            active.partition = try std.fmt.allocPrint(self.gpa, "{s}_consensus_{d}", .{
                self.config.partition_prefix, epoch.get(),
            });
            errdefer self.gpa.free(active.partition);
            const participants: u32 = @intCast(scheme.participants().len());
            const elector_config = self.config.simplex.elector;
            active.elector = try T.build_elector(elector_config, self.gpa, participants);
            errdefer deinit_elector(self.gpa, &active.elector);
            const engine_ctx = self.ctx.child("consensus_engine");
            const taken = pending.?;
            pending = null;
            try active.engine.init(engine_ctx, self.engine_config(scheme.*, active, taken));
            errdefer active.engine.deinit();
            try self.start_engine(engine_ctx, active, channels);
            self.tracer.event(.info, "entered epoch", .{ .epoch = epoch });
            return active;
        }

        /// Registers `active`'s subchannels and spawns its engine.
        fn start_engine(self: *Self, ctx: T.Context, active: *Active, channels: *Channels) !void {
            const subchannel = active.epoch.get();
            var votes = try register(&channels.vote, subchannel);
            errdefer deinit_channel(&votes);
            var certificates = try register(&channels.certificate, subchannel);
            errdefer deinit_channel(&certificates);
            var backfill = try register(&channels.resolver, subchannel);
            errdefer deinit_channel(&backfill);
            const args = .{ &active.engine, votes, certificates, backfill };
            active.handle = try ctx.spawn(Engine.run, args);
            if (active.handle.header == null) return error.Stopped;
            assert(self.config.mailbox_size > 0);
        }

        fn register(handle: *Mux.Handle, subchannel: u64) !EngineChannel {
            const registered = handle.register(subchannel) catch |err| switch (err) {
                error.Closed => return error.MuxClosed,
                else => return err,
            };
            assert(registered.receiver.subchannel == subchannel);
            return .{ .sender = registered.sender, .receiver = registered.receiver };
        }

        fn deinit_channel(channel: *EngineChannel) void {
            channel.sender.deinit();
            channel.receiver.deinit();
        }

        fn deinit_floor(gpa: Allocator, floor: *Floor) void {
            switch (floor.*) {
                .genesis => {},
                .finalized => |*finalization| finalization.deinit(gpa),
            }
        }

        fn deinit_elector(gpa: Allocator, elector: *T.Elector) void {
            if (comptime @hasDecl(T.Elector, "deinit")) elector.deinit(gpa);
        }

        fn engine_config(
            self: *Self,
            scheme: T.Scheme,
            active: *Active,
            floor: Floor,
        ) Engine.Config {
            const settings = self.config.simplex;
            assert(settings.mailbox_size > 0);
            return .{
                .scheme = scheme,
                .elector = active.elector,
                .blocker = self.config.blocker,
                .automaton = self.config.automaton,
                .relay = self.config.relay,
                .reporter = self.config.reporter,
                .track_historical_votes = settings.track_historical_votes,
                .strategy = self.config.strategy,
                .partition = active.partition,
                .mailbox_size = settings.mailbox_size,
                .epoch = active.epoch,
                .floor = floor,
                .replay_buffer = settings.replay_buffer,
                .write_buffer = settings.write_buffer,
                .page_cache = settings.page_cache,
                .leader_timeout = settings.leader_timeout,
                .certification_timeout = settings.certification_timeout,
                .timeout_retry = settings.timeout_retry,
                .view_retention = settings.view_retention,
                .skip = settings.skip,
                .fetch_timeout = settings.fetch_timeout,
                .fetch_retry_delay = settings.fetch_retry_delay,
                .forward = settings.forward,
            };
        }

        /// Activates `info`'s peers for `epoch`.
        fn track(self: *Self, epoch: Epoch, info: *const Info) !void {
            var participants = try info.participants(self.gpa);
            defer participants.deinit(self.gpa);
            var tracked = try participants.tracked_peers(self.gpa);
            defer tracked.deinit(self.gpa);
            assert(tracked.primary.len() == participants.dealers.len());
            // The caller traces the failure, as commonware's `EnterEpochError::PeerSet` does.
            self.config.manager.track(epoch, tracked.view(), &info.directory) catch
                return error.PeerSet;
        }

        const GateOutcome = union(enum) {
            stopped: Io.Cancelable!i32,
            gate: fence.WaitError!void,
        };

        fn wait_shutdown(shutdown: *runtime.signal.Signal) Io.Cancelable!i32 {
            return shutdown.wait();
        }

        /// Waits for the gate to reach `epoch`; a stop signal wins over a marked gate.
        fn wait_gate(self: *Self, epoch: Epoch) !void {
            var shutdown = self.ctx.stopped();
            defer shutdown.deinit();
            if (shutdown.peek() != null) return error.Stopped;
            if (self.config.gate.poll(epoch)) |ready| return ready catch error.GateClosed;
            var buffer: [2]GateOutcome = undefined;
            var select: Io.Select(GateOutcome) = .init(self.io, &buffer);
            defer while (select.cancel()) |_| {};
            try select.concurrent(.stopped, wait_shutdown, .{&shutdown});
            try select.concurrent(.gate, fence.Gate.wait, .{ self.config.gate, epoch });
            switch (try select.await()) {
                .stopped => |result| {
                    _ = try result;
                    return error.Stopped;
                },
                .gate => |result| result catch |err| switch (err) {
                    error.Closed => return error.GateClosed,
                    error.Canceled => return error.Canceled,
                },
            }
        }

        /// Aborts `active`'s engine and releases it.
        fn stop(self: *Self, active: *Active) void {
            assert(active.epoch.get() == active.engine_epoch);
            // Wait out the engine even while this task is canceled: a canceled join detaches
            // the engine task, which would then run on the engine freed below.
            const protection = self.io.swapCancelProtection(.blocked);
            defer _ = self.io.swapCancelProtection(protection);
            if (active.handle.abort()) |result| {
                const text = "simplex engine stopped unexpectedly";
                result catch |err| self.tracer.event(.@"error", text, .{
                    .epoch = active.epoch,
                    .@"error" = err,
                });
            } else |_| {}
            active.engine.deinit();
            deinit_elector(self.gpa, &active.elector);
            self.gpa.free(active.partition);
            self.gpa.destroy(active);
        }
    };
}
