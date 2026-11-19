//! The `Syncer` actor and its startup helpers (commonware
//! `glue/src/stateful/actor/syncer/actor.rs`, and `resolve`/`open` from `syncer/mod.rs`).
//!
//! The syncer runs state sync from the block `resolve` picks for the selected floor, forwards
//! target updates from its `Mailbox`, and publishes the converged `Artifact` to the `Stateful`
//! actor through `completion`. Once published, every retarget is answered with the artifact.
//!
//! `P` declares:
//! - `App`, with `App.Block` (`Digest`, `digest()`, `height()`, `context()` whose `round` is
//!   its consensus round) and `App.sync_targets(*const Block) Databases.SyncTargets`.
//! - `Databases`: the database set (`db.Shared(T)`, `db.Tuple`, or a set declaring `sync`, see
//!   `state_sync.sync_set`), and `Resolvers`, the sources its sync fetches from.
//! - `Marshal`: marshal's core mailbox (or a stand-in) with `get_anchor() !?{processed,
//!   block}`, `get_block(Identifier) !?Block`, and `subscribe_by_commitment(commitment,
//!   fallback) !oneshot.Receiver(Block)`; blocks it returns are the caller's.
//! - `Finalization`, with `round()` and `proposal.payload`, and `commitment(*const Block)` its
//!   payload's type (the block digest for the standard variant).
//!
//! Where commonware panics (marshal cannot report its position or a block, state sync fails)
//! these return errors.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const utils = @import("utils");
const mailbox_mod = @import("mailbox.zig");
const db_sync = @import("../../db/sync.zig");
const state_sync = @import("../../db/state_sync.zig");

const oneshot = utils.channel.oneshot;
const ring = utils.channel.ring;
const Height = consensus.Height;
const Floor = consensus.marshal.core.Floor;
const Anchor = db_sync.Anchor;

/// Errors where commonware panics.
pub const Error = error{
    /// Marshal could not report the processed position it started with.
    MarshalAnchorMissing,
    /// Marshal could not yield the floor block or a completed sync's block.
    BlockUnavailable,
};

/// The anchor of `block` (commonware `Anchor::from_block`).
pub fn anchor_of(comptime Block: type, block: *const Block) Anchor(Block.Digest) {
    return .{ .height = block.height(), .round = block.context().round, .digest = block.digest() };
}

/// Releases a block the caller owns, if it holds memory.
fn release(gpa: Allocator, block: anytype) void {
    var owned = block;
    const Block = @TypeOf(owned);
    if (comptime @hasDecl(Block, "deinit")) {
        const takes_gpa = @typeInfo(@TypeOf(Block.deinit)).@"fn".params.len == 2;
        if (takes_gpa) owned.deinit(gpa) else owned.deinit();
    }
}

/// The block state sync starts from: `finalization`'s block, unless marshal's processed
/// position passed it, in which case the block backing that position (marshal does not
/// redeliver blocks at or below it, so starting lower would leave a gap). The caller owns it.
pub fn resolve(
    comptime P: type,
    gpa: Allocator,
    marshal: P.Marshal,
    floor: Floor,
    finalization: *const P.Finalization,
) !P.App.Block {
    const payload = finalization.proposal.payload;
    // Marshal skips a startup floor whose round its durable round floor covers. That floor's
    // block may be pruned, so a local wait for it could hang: resolve from marshal's position.
    if (floor.processed != null and floor.cutoff.covers(finalization.round())) {
        const anchored = (try marshal.get_anchor()) orelse return error.MarshalAnchorMissing;
        // Prefer the selected floor when it is the retained successor, so its delivery skips
        // application hooks. An `absent` processed position's anchor already holds the floor.
        if (anchored.processed == .block) {
            const next = anchored.processed.block.next();
            if (try marshal.get_block(.{ .height = next })) |block| {
                if (std.meta.eql(P.commitment(&block), payload)) {
                    release(gpa, anchored.block);
                    return block;
                }
                release(gpa, block);
            }
        }
        return anchored.block;
    }
    // Marshal fetches the configured floor block itself, so wait for it without another fetch.
    var subscription = try marshal.subscribe_by_commitment(payload, .wait);
    defer subscription.deinit();
    const selected = subscription.recv() catch |err| switch (err) {
        error.Closed => return error.BlockUnavailable,
        error.Canceled => return error.Canceled,
    };
    // A newly installed floor records its predecessor as processed, leaving the floor block for
    // delivery.
    const anchored = (marshal.get_anchor() catch |err| {
        release(gpa, selected);
        return err;
    }) orelse return selected;
    if (anchored.processed.height().get() > selected.height().get()) {
        release(gpa, selected);
        return anchored.block;
    }
    release(gpa, anchored.block);
    return selected;
}

/// Opens the database set at the later of the block at `completed` and the block backing
/// marshal's processed position, or at genesis when neither exists. Each database opens at
/// that block's targets, discarding any suffix beyond them.
pub fn open(
    comptime P: type,
    env: anytype,
    marshal: P.Marshal,
    db_config: P.Databases.Config,
    completed: ?Height,
) !mailbox_mod.Artifact(P.Databases, P.App.Block.Digest) {
    const gpa = env.gpa;
    const anchored = try marshal.get_anchor();
    var height: u64 = if (completed) |value| value.get() else 0;
    if (anchored) |value| height = @max(height, value.processed.height().get());
    const block = block: {
        if (anchored) |value| {
            if (value.processed.height().get() == height) break :block value.block;
            release(gpa, value.block);
        }
        const found = try marshal.get_block(.{ .height = .new(height) });
        break :block found orelse return error.BlockUnavailable;
    };
    defer release(gpa, block);
    const targets = P.App.sync_targets(&block);
    const databases = try P.Databases.open(env, db_config, targets);
    return .{ .databases = databases, .anchor = anchor_of(P.App.Block, &block) };
}

/// Configuration for `Syncer` (commonware `Config`).
pub fn Config(comptime P: type, comptime Env: type) type {
    return struct {
        /// The environment the synced databases open in.
        env: Env,
        /// Database configuration for the managed set.
        db_config: P.Databases.Config,
        /// Per-database sync engine parameters.
        sync_config: state_sync.SyncEngineConfig,
        /// Per-database resolvers used to fetch state from peers.
        resolvers: P.Resolvers,
        /// Selected state sync floor (borrowed for the syncer's lifetime).
        finalization: *const P.Finalization,
        /// Marshal's mailbox and the durable floor returned with it during initialization.
        marshal: P.Marshal,
        floor: Floor,
        /// Receives the converged artifact, which it then owns.
        completion: oneshot.Sender(mailbox_mod.Artifact(P.Databases, P.App.Block.Digest)),
    };
}

/// Runs state sync, accepts target updates, and publishes the converged artifact.
pub fn Syncer(comptime P: type, comptime Env: type) type {
    const DBs = P.Databases;
    const D = P.App.Block.Digest;
    return struct {
        const Self = @This();
        pub const Artifact = mailbox_mod.Artifact(DBs, D);
        pub const Mailbox = mailbox_mod.Mailbox(Artifact, D, DBs.SyncTargets);
        pub const Message = Mailbox.Msg;
        pub const Update = Message.Update;
        pub const Cfg = Config(P, Env);
        pub const Synced = state_sync.SetSynced(DBs, D);

        const Wake = union(enum) {
            synced: anyerror!Synced,
            message: Io.Cancelable!?Message,
        };

        gpa: Allocator,
        io: Io,
        config: Cfg,
        mailbox_rx: actor.mailbox.Receiver(Message),
        /// The published artifact. Owned by `completion`'s receiver once sent, else here.
        artifact: ?Artifact = null,
        owns_artifact: bool = false,
        completion: ?oneshot.Sender(Artifact),

        pub const Created = struct { syncer: *Self, mailbox: Mailbox };

        /// Creates the syncer and its mailbox (one slot, commonware `NZUsize!(1)`).
        pub fn create(config: Cfg) !Created {
            const gpa = config.env.gpa;
            const io = config.env.io;
            var pair = try actor.mailbox.new(Message, gpa, io, 1);
            errdefer pair.receiver.deinit();
            const self = gpa.create(Self) catch |err| {
                pair.sender.deinit();
                return err;
            };
            self.* = .{
                .gpa = gpa,
                .io = io,
                .config = config,
                .mailbox_rx = pair.receiver,
                .completion = config.completion,
            };
            return .{ .syncer = self, .mailbox = .init(gpa, io, pair.sender) };
        }

        /// Frees the syncer; an artifact nobody received is closed.
        pub fn destroy(self: *Self) void {
            if (self.completion) |*completion| completion.deinit();
            if (self.owns_artifact) self.artifact.?.databases.deinit();
            self.mailbox_rx.deinit();
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Starts the syncer. The task frees it when it returns; cancel it to stop.
        pub fn start(self: *Self) Io.ConcurrentError!Io.Future(anyerror!void) {
            return self.io.concurrent(run, .{self});
        }

        fn run(self: *Self) anyerror!void {
            defer self.destroy();
            const config = &self.config;
            const finalization = config.finalization;
            const block = try resolve(P, self.gpa, config.marshal, config.floor, finalization);
            const start_anchor = anchor_of(P.App.Block, &block);
            const targets = P.App.sync_targets(&block);
            release(self.gpa, block);
            var tips = try ring.channel(Update, self.gpa, self.io, 1);
            var tips_tx: ?ring.Sender(Update) = tips.sender;
            defer if (tips_tx) |*sender| sender.deinit();

            var buffer: [2]Wake = undefined;
            var select: Io.Select(Wake) = .init(self.io, &buffer);
            defer while (select.cancel()) |rest| discard(rest);
            const sync_args = .{ self, start_anchor, targets, tips.receiver };
            select.concurrent(.synced, sync, sync_args) catch |err| {
                tips.receiver.deinit();
                return err;
            };
            try select.concurrent(.message, recv, .{&self.mailbox_rx});
            while (true) {
                const wake = select.await() catch return;
                switch (wake) {
                    .synced => |result| {
                        self.publish(try result);
                        // No coordinator remains to record a queued update. Dropping the
                        // sender drops that update, so its caller retries and gets the artifact.
                        // (The sync already dropped the receiver, which discards it too.)
                        tips_tx.?.deinit();
                        tips_tx = null;
                    },
                    .message => |result| {
                        const message = (result catch return) orelse return;
                        try self.handle(&select, &tips_tx, message);
                        try select.concurrent(.message, recv, .{&self.mailbox_rx});
                    },
                }
            }
        }

        fn sync(
            self: *Self,
            start_anchor: Anchor(D),
            targets: DBs.SyncTargets,
            tip_updates: ring.Receiver(Update),
        ) anyerror!Synced {
            const config = &self.config;
            return state_sync.sync_set(
                DBs,
                D,
                config.env,
                config.db_config,
                config.resolvers,
                start_anchor,
                targets,
                tip_updates,
                config.sync_config,
            );
        }

        fn recv(receiver: *actor.mailbox.Receiver(Message)) Io.Cancelable!?Message {
            return receiver.recv();
        }

        fn discard(wake: Wake) void {
            switch (wake) {
                .synced => |result| if (result) |synced| {
                    var databases = synced.databases;
                    databases.deinit();
                } else |_| {},
                .message => |result| if (result catch null) |message| Message.discard(message),
            }
        }

        /// Answers a retarget: the artifact once published, else forwards the update.
        fn handle(
            self: *Self,
            select: *Io.Select(Wake),
            tips_tx: *?ring.Sender(Update),
            message: Message,
        ) anyerror!void {
            var retarget = message.retarget;
            if (self.artifact) |artifact| {
                retarget.update.discard();
                retarget.response.send(artifact) catch {}; // The caller left.
                return;
            }
            // Proof: the sender lives until the artifact is published.
            if (tips_tx.*.?.send_lossy(retarget.update)) {
                retarget.response.send(null) catch {}; // The caller left.
                return;
            }
            // A closed target channel means state sync accepts no more targets: wait for its
            // result instead of failing.
            const wake = select.await() catch |err| {
                retarget.response.deinit();
                return err;
            };
            assert(wake == .synced);
            const synced = wake.synced catch |err| {
                retarget.response.deinit();
                return err;
            };
            self.publish(synced);
            tips_tx.*.?.deinit();
            tips_tx.* = null;
            retarget.response.send(self.artifact) catch {}; // The caller left.
        }

        fn publish(self: *Self, synced: Synced) void {
            assert(self.artifact == null);
            const published: Artifact = .{ .databases = synced.databases, .anchor = synced.anchor };
            self.artifact = published;
            var completion = self.completion.?;
            self.completion = null;
            completion.send(published) catch {
                self.owns_artifact = true; // Nobody receives it.
            };
        }
    };
}

test {
    std.testing.refAllDecls(@This());
}
