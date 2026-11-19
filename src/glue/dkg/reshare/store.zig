//! Crash-recovery storage for the reshare actor (commonware `glue::dkg::reshare::store`).
//!
//! A restarted actor does not re-receive P2P messages, and marshal does not redeliver finalized
//! blocks it already processed. `Store` journals the public messages a restarted node would
//! otherwise lose:
//!
//! - public dealer messages, so a player can rebuild the acknowledgements it already sent (the
//!   matching private dealings are recovered from the secret store),
//! - player acknowledgements received by this node's dealer, so a restarted dealer resends only
//!   unacknowledged dealings,
//! - finalized dealer logs observed during inclusion.
//!
//! Secret material never enters the journal: shares, private dealings, and the dealer RNG seed
//! are held only through the secret store. The current epoch is held only in memory.
//!
//! Commonware panics when storage fails; here those are errors. The secret store `SS` is a
//! `dkg.assert_secret_store` type whose methods may fail (`!void` / `!?T`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const utils = @import("utils");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const types = @import("../types.zig");
const Event = @import("event.zig").Event;

const Epoch = consensus.Epoch;
const fd = cryptography.bls12381.dkg.feldman_desmedt;
const Share = cryptography.bls12381.primitives.group.Share;
const Summary = cryptography.transcript.Summary;
const Transcript = cryptography.transcript.Transcript;
const Storage = runtime.storage.Storage;
const CacheRef = runtime.buffer.paged.CacheRef;
const Order = std.math.Order;

/// Inserts `item` into `list`, kept sorted by `item.key`; false when the key is present.
fn insert_sorted(comptime T: type, gpa: Allocator, list: *std.ArrayList(T), item: T) !bool {
    const K = @FieldType(T, "key");
    const index = std.sort.lowerBound(T, list.items, item.key, struct {
        fn order(key: K, entry: T) Order {
            return codec.order(K, key, entry.key);
        }
    }.order);
    if (index < list.items.len and codec.order(K, list.items[index].key, item.key) == .eq) {
        return false;
    }
    try list.insert(gpa, index, item);
    assert(list.items[index].key.eql(item.key));
    return true;
}

fn find_sorted(comptime T: type, items: []const T, key: @FieldType(T, "key")) ?*const T {
    const K = @FieldType(T, "key");
    const index = std.sort.binarySearch(T, items, key, struct {
        fn order(target: K, entry: T) Order {
            return codec.order(K, target, entry.key);
        }
    }.order) orelse return null;
    return &items[index];
}

/// Crash-recovery store for the reshare actor of keys `P`, variant `V`, and directory `D`.
pub fn Store(comptime V: type, comptime P: type, comptime D: type, comptime SS: type) type {
    return struct {
        const Self = @This();
        pub const Journal = storage.journal.segmented.variable.Journal(Event(V, P));
        pub const Info = types.EpochInfo(V, P, D);
        pub const Error = Journal.Error || Allocator.Error;

        pub const DealingEntry = struct {
            key: P,
            public: fd.DealerPubMsg(V),
            private: fd.DealerPrivMsg,
        };
        pub const AckEntry = struct { key: P, ack: fd.PlayerAck(P) };
        pub const LogEntry = struct { key: P, log: fd.DealerLog(V, P) };

        const Cache = struct {
            epoch: u64,
            dealings: std.ArrayList(DealingEntry) = .empty,
            acks: std.ArrayList(AckEntry) = .empty,
            logs: std.ArrayList(LogEntry) = .empty,

            fn deinit(entry: *Cache, gpa: Allocator) void {
                for (entry.dealings.items) |*item| {
                    item.public.deinit(gpa);
                    item.private.zeroize();
                }
                for (entry.logs.items) |*item| item.log.deinit(gpa);
                entry.dealings.deinit(gpa);
                entry.acks.deinit(gpa);
                entry.logs.deinit(gpa);
            }
        };

        pub const Config = struct {
            partition_prefix: []const u8,
            max_participants: u32,
            cache_ref: *CacheRef,
            write_buffer: usize,
            replay_buffer: usize,
        };

        gpa: Allocator,
        secret_store: *SS,
        events: Journal,
        current: ?Info = null,
        /// Per-epoch caches, sorted by epoch.
        epochs: std.ArrayList(Cache) = .empty,

        /// Opens the recovery journal under `config.partition_prefix` and replays it. A
        /// journaled dealing is restored only if its private half is in `secret_store`.
        pub fn init(
            gpa: Allocator,
            store_storage: Storage,
            config: Config,
            secret_store: *SS,
        ) !Self {
            assert(config.max_participants > 0);
            const prefix = config.partition_prefix;
            const partition = try std.mem.concat(gpa, u8, &.{ prefix, "_events" });
            defer gpa.free(partition);
            var recovery = try Journal.init(gpa, store_storage, .{
                .partition = partition,
                .codec_config = config.max_participants,
                .cache_ref = config.cache_ref,
                .write_buffer = config.write_buffer,
                .replay_buffer = config.replay_buffer,
            });
            var self: Self = .{ .gpa = gpa, .secret_store = secret_store, .events = undefined };
            self.replay_all(&recovery) catch |err| {
                recovery.deinit();
                self.free_caches();
                return err;
            };
            // `finish` consumes the recovery, also on error.
            self.events = recovery.finish() catch |err| {
                self.free_caches();
                return err;
            };
            return self;
        }

        fn replay_all(self: *Self, recovery: *Journal.Recovery) !void {
            while (try recovery.next()) |replayed| {
                var event = replayed.item;
                errdefer event.deinit(self.gpa);
                try self.replay(.new(replayed.section), event);
            }
        }

        fn replay(self: *Self, epoch: Epoch, event: Event(V, P)) !void {
            const target = try self.epoch_cache(epoch);
            switch (event) {
                .dealing => |dealing| {
                    // A journaled message is restored only with the private half received
                    // with it: an interrupted dealing leaves its public message behind, so
                    // one dealer can have several journaled messages (commonware #5721).
                    const secrets = self.secret_store;
                    const stored = try secrets.get_dealing(epoch, dealing.dealer, &dealing.public);
                    const private = stored orelse {
                        var public = dealing.public;
                        public.deinit(self.gpa);
                        return;
                    };
                    const entry: DealingEntry = .{
                        .key = dealing.dealer,
                        .public = dealing.public,
                        .private = private,
                    };
                    if (!try insert_sorted(DealingEntry, self.gpa, &target.dealings, entry)) {
                        var duplicate = entry;
                        duplicate.public.deinit(self.gpa);
                    }
                },
                .ack => |ack| {
                    const entry: AckEntry = .{ .key = ack.player, .ack = ack.ack };
                    _ = try insert_sorted(AckEntry, self.gpa, &target.acks, entry);
                },
                .log => |log| {
                    const entry: LogEntry = .{ .key = log.dealer, .log = log.log };
                    if (!try insert_sorted(LogEntry, self.gpa, &target.logs, entry)) {
                        var duplicate = entry;
                        duplicate.log.deinit(self.gpa);
                    }
                },
            }
        }

        fn free_caches(self: *Self) void {
            for (self.epochs.items) |*entry| entry.deinit(self.gpa);
            self.epochs.deinit(self.gpa);
        }

        /// Closes the journal and frees the caches (Rust drops the store).
        pub fn deinit(self: *Self) void {
            self.events.deinit();
            self.free_caches();
            if (self.current) |*info| info.deinit(self.gpa);
            self.* = undefined;
        }

        /// The epoch most recently committed with `commit_epoch` (null until one is committed
        /// after startup).
        pub fn current_info(self: *const Self) ?*const Info {
            return if (self.current) |*info| info else null;
        }

        /// The share for `epoch`, if any.
        pub fn share(self: *Self, epoch: Epoch) !?Share {
            return self.secret_store.get_share(epoch);
        }

        /// The persisted dealer RNG seed for `epoch`, if any. A seed exists only for an epoch
        /// this node previously entered; reusing it keeps dealer randomness identical across a
        /// restart.
        pub fn seed(self: *Self, epoch: Epoch) !?Summary {
            return self.secret_store.get_seed(epoch);
        }

        /// The persisted dealer RNG seed for `epoch`, or a fresh random one from `rng`.
        pub fn seed_or_random(self: *Self, epoch: Epoch, rng: std.Random) !Summary {
            return try self.seed(epoch) orelse Summary.random(rng);
        }

        pub fn put_seed(self: *Self, epoch: Epoch, rng_seed: Summary) !void {
            try self.secret_store.put_seed(epoch, rng_seed);
        }

        /// Durably stores `held_share` (if any) and `rng_seed` for `info.epoch`, then makes
        /// `info` (taking ownership) the current epoch. `info` is held only in memory.
        pub fn commit_epoch(self: *Self, info: Info, rng_seed: Summary, held_share: ?Share) !void {
            var owned = info;
            errdefer owned.deinit(self.gpa);
            if (held_share) |value| try self.secret_store.put_share(info.epoch, value);
            try self.secret_store.put_seed(info.epoch, rng_seed);
            if (self.current) |*previous| previous.deinit(self.gpa);
            self.current = owned;
            assert(self.current.?.epoch == info.epoch);
        }

        /// Prunes public recovery data and secret material older than `min`.
        pub fn prune(self: *Self, min: Epoch) !void {
            var kept: usize = 0;
            for (self.epochs.items) |*entry| {
                if (entry.epoch < min.get()) {
                    entry.deinit(self.gpa);
                } else {
                    self.epochs.items[kept] = entry.*;
                    kept += 1;
                }
            }
            self.epochs.shrinkRetainingCapacity(kept);
            _ = try self.events.prune(min.get());
            try self.secret_store.prune(min);
        }

        fn epoch_cache(self: *Self, epoch: Epoch) Allocator.Error!*Cache {
            const items = self.epochs.items;
            var index: usize = 0;
            while (index < items.len and items[index].epoch < epoch.get()) index += 1;
            if (index < items.len and items[index].epoch == epoch.get()) return &items[index];
            try self.epochs.insert(self.gpa, index, .{ .epoch = epoch.get() });
            assert(self.epochs.items[index].epoch == epoch.get());
            return &self.epochs.items[index];
        }

        fn find_cache(self: *const Self, epoch: Epoch) ?*const Cache {
            for (self.epochs.items) |*entry| if (entry.epoch == epoch.get()) return entry;
            return null;
        }

        /// The finalized dealer logs for `epoch`, sorted by dealer (borrowed).
        pub fn logs(self: *const Self, epoch: Epoch) []const LogEntry {
            const found = self.find_cache(epoch) orelse return &.{};
            return found.logs.items;
        }

        /// Whether a finalized log from `dealer` is recorded for `epoch`.
        pub fn has_log(self: *const Self, epoch: Epoch, dealer: P) bool {
            return find_sorted(LogEntry, self.logs(epoch), dealer) != null;
        }

        /// The dealings recorded for `epoch`, sorted by dealer (borrowed).
        pub fn dealings(self: *const Self, epoch: Epoch) []const DealingEntry {
            const found = self.find_cache(epoch) orelse return &.{};
            return found.dealings.items;
        }

        /// The acknowledgements recorded for `epoch`, sorted by player (borrowed).
        pub fn acks(self: *const Self, epoch: Epoch) []const AckEntry {
            const found = self.find_cache(epoch) orelse return &.{};
            return found.acks.items;
        }

        fn append_synced(self: *Self, epoch: Epoch, event: Event(V, P)) Journal.Error!void {
            _ = try self.events.append(epoch.get(), event);
            try self.events.sync(&.{epoch.get()});
        }

        /// Durably records a dealing the player accepted (copying `public`), returning false
        /// without writing if one from `dealer` is already recorded for `epoch`. Both halves
        /// are durable when this returns.
        pub fn append_dealing(
            self: *Self,
            epoch: Epoch,
            dealer: P,
            public: fd.DealerPubMsg(V),
            private: fd.DealerPrivMsg,
        ) !bool {
            if (find_sorted(DealingEntry, self.dealings(epoch), dealer) != null) return false;
            // Replay restores a dealing only when both halves survived, and finds the private
            // half by its public message, so a crash between the two writes drops the dealing
            // instead of pairing it with another dealing's half.
            try self.secret_store.put_dealing(epoch, dealer, &public, private);
            try self.append_synced(epoch, .{ .dealing = .{ .dealer = dealer, .public = public } });
            const copy = try public.clone(self.gpa);
            const entry: DealingEntry = .{ .key = dealer, .public = copy, .private = private };
            const list = &(try self.epoch_cache(epoch)).dealings;
            const inserted = try insert_sorted(DealingEntry, self.gpa, list, entry);
            assert(inserted);
            return true;
        }

        /// Durably records `ack`, returning false without writing if one from `player` is
        /// already recorded for `epoch`.
        pub fn append_ack(self: *Self, epoch: Epoch, player: P, ack: fd.PlayerAck(P)) !bool {
            if (find_sorted(AckEntry, self.acks(epoch), player) != null) return false;
            try self.append_synced(epoch, .{ .ack = .{ .player = player, .ack = ack } });
            const entry: AckEntry = .{ .key = player, .ack = ack };
            const list = &(try self.epoch_cache(epoch)).acks;
            const inserted = try insert_sorted(AckEntry, self.gpa, list, entry);
            assert(inserted);
            return true;
        }

        /// Durably records a finalized dealer log (copying `log`), returning false without
        /// writing if one from `dealer` is already recorded for `epoch`.
        pub fn append_log(self: *Self, epoch: Epoch, dealer: P, log: fd.DealerLog(V, P)) !bool {
            if (self.has_log(epoch, dealer)) return false;
            try self.append_synced(epoch, .{ .log = .{ .dealer = dealer, .log = log } });
            const entry: LogEntry = .{ .key = dealer, .log = try log.clone(self.gpa) };
            const list = &(try self.epoch_cache(epoch)).logs;
            const inserted = try insert_sorted(LogEntry, self.gpa, list, entry);
            assert(inserted);
            return true;
        }

        /// Rebuilds this node's dealer for `epoch` from `rng_seed`, replaying the recorded
        /// acknowledgements. Null if this dealer's log is already recorded for `epoch`. The
        /// dealer borrows `info`.
        pub fn create_dealer(
            self: *const Self,
            comptime M: type,
            comptime S: type,
            epoch: Epoch,
            signer: S,
            info: *const fd.Info(V, P),
            held_share: ?Share,
            rng_seed: Summary,
        ) !?Dealer(V, S) {
            if (self.has_log(epoch, signer.public_key())) return null;
            var noise = Transcript.resume_from(rng_seed, .v1).noise("dealer-rng");
            const Crypto = fd.Dealer(V, S);
            const started = try Crypto.start(M, self.gpa, &noise, info, signer, held_share);
            var dealer: Dealer(V, S) = .{
                .gpa = self.gpa,
                .dealer = started.dealer,
                .public = started.pub_msg,
                .unsent = .fromOwnedSlice(started.priv_msgs),
            };
            errdefer dealer.deinit();
            for (self.acks(epoch)) |entry| {
                const index = dealer.unsent_index(entry.key) orelse continue;
                dealer.dealer.?.receive_player_ack(entry.key, entry.ack) catch continue;
                var removed = dealer.unsent.orderedRemove(index);
                removed.msg.zeroize();
            }
            return dealer;
        }

        /// Rebuilds this node's player for `epoch` from the recorded dealings and finalized
        /// logs (null as `create_player_with_logs` describes). The player borrows `info`.
        pub fn create_player(
            self: *const Self,
            comptime M: type,
            comptime S: type,
            epoch: Epoch,
            signer: S,
            info: *const fd.Info(V, P),
        ) !?Player(V, S) {
            const entries = self.logs(epoch);
            const pairs = try self.gpa.alloc(LogPair, entries.len);
            defer self.gpa.free(pairs);
            for (entries, pairs) |entry, *pair| pair.* = .{ entry.key, entry.log };
            return self.create_player_with_logs(M, S, epoch, signer, info, pairs);
        }

        pub const LogPair = utils.ordered.Map(P, fd.DealerLog(V, P)).Pair;

        /// Like `create_player`, but from `logs` instead of the recorded finalized logs.
        /// Null when a log carries this node's acknowledgement but the matching private
        /// dealing is absent from the secret store (for example after restoring a backup
        /// taken before the acknowledgement was sent): the node enters the epoch as an
        /// observer. Other resume errors fail.
        pub fn create_player_with_logs(
            self: *const Self,
            comptime M: type,
            comptime S: type,
            epoch: Epoch,
            signer: S,
            info: *const fd.Info(V, P),
            logs_in: []const LogPair,
        ) !?Player(V, S) {
            const recorded = self.dealings(epoch);
            const Persisted = fd.PersistedDealing(V, P);
            const msgs = try self.gpa.alloc(Persisted, recorded.len);
            defer self.gpa.free(msgs);
            for (recorded, msgs) |entry, *msg| {
                msg.* = .{
                    .dealer = entry.key,
                    .pub_msg = entry.public,
                    .priv_msg = entry.private,
                };
            }
            const Crypto = fd.Player(V, S);
            const resumed = Crypto.resume_from(M, self.gpa, info, signer, logs_in, msgs) catch |err|
                switch (err) {
                    error.MissingPlayerDealing => return null,
                    else => return err,
                };
            return .{ .gpa = self.gpa, .player = resumed.player, .acks = resumed.acks };
        }
    };
}

/// Successful outcome of processing a player acknowledgement.
pub const AckOutcome = enum {
    /// The acknowledgement was newly persisted.
    recorded,
    /// The acknowledgement was already recorded.
    duplicate,
};

/// Dealer state for one epoch. Borrows the round's `Info`.
pub fn Dealer(comptime V: type, comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();
        const Unsent = fd.PrivMsgFor(P);

        gpa: Allocator,
        dealer: ?fd.Dealer(V, S),
        public: fd.DealerPubMsg(V),
        /// The dealing of each player whose acknowledgement is not recorded, sorted by player.
        unsent: std.ArrayList(Unsent),
        finalized: ?fd.SignedDealerLog(V, P) = null,

        pub fn deinit(self: *Self) void {
            if (self.dealer) |*dealer| dealer.deinit(self.gpa);
            self.public.deinit(self.gpa);
            for (self.unsent.items) |*item| item.msg.zeroize();
            self.unsent.deinit(self.gpa);
            if (self.finalized) |*log| log.deinit(self.gpa);
            self.* = undefined;
        }

        fn unsent_index(self: *const Self, player: P) ?usize {
            for (self.unsent.items, 0..) |item, index| if (item.player.eql(player)) return index;
            return null;
        }

        /// Whether the recorded acknowledgements form a quorum of `players`.
        pub fn has_acknowledgement_quorum(
            self: *const Self,
            comptime M: type,
            players: usize,
        ) bool {
            return self.unsent.items.len <= M.max_faults(players);
        }

        /// Records `ack` from `player`: `recorded` for a new acknowledgement (durable when this
        /// returns) and `duplicate` for one already recorded. `UnexpectedPlayer` names a sender
        /// outside the round's players, `InvalidAck` a signature that does not match this
        /// dealer's transcript. Panics after the dealer finalized.
        pub fn handle(
            self: *Self,
            store: anytype,
            epoch: Epoch,
            player: P,
            ack: fd.PlayerAck(P),
        ) !AckOutcome {
            const dealer = if (self.dealer) |*dealer| dealer else {
                @panic("acknowledgements are handled only before dealer finalization");
            };
            try dealer.receive_player_ack(player, ack);
            const index = self.unsent_index(player) orelse return .duplicate;
            var removed = self.unsent.orderedRemove(index);
            removed.msg.zeroize();
            if (!try store.append_ack(epoch, player, ack)) {
                @panic("pending acknowledgement must not already be persisted");
            }
            return .recorded;
        }

        /// Signs this dealer's log: true on the first call, false afterward.
        pub fn finalize(self: *Self, comptime M: type) Allocator.Error!bool {
            if (self.finalized != null) return false;
            var dealer = self.dealer orelse return false;
            self.dealer = null;
            self.finalized = try dealer.finalize(M, self.gpa);
            return true;
        }

        /// Drops the signed log, once it is included in a finalized block.
        pub fn clear_finalized(self: *Self) void {
            if (self.finalized) |*log| log.deinit(self.gpa);
            self.finalized = null;
        }

        /// The dealing for each player whose acknowledgement is not yet recorded (borrowed);
        /// every player receives `public` with it.
        pub fn shares_to_distribute(self: *const Self) []const Unsent {
            return self.unsent.items;
        }
    };
}

/// Player state for one epoch. Borrows the round's `Info`.
pub fn Player(comptime V: type, comptime S: type) type {
    const P = S.PublicKey;
    return struct {
        const Self = @This();

        gpa: Allocator,
        player: fd.Player(V, S),
        acks: utils.ordered.Map(P, fd.PlayerAck(P)),

        pub fn deinit(self: *Self) void {
            self.player.deinit(self.gpa);
            self.acks.deinit(self.gpa);
            self.* = undefined;
        }

        /// Handles a dealing from `dealer`, durably recording it before returning the
        /// acknowledgement. A dealer already processed gets its cached acknowledgement without
        /// the new message being validated; a new message that fails validation returns the
        /// `DealerMessageError` and is not recorded.
        pub fn handle(
            self: *Self,
            store: anytype,
            epoch: Epoch,
            dealer: P,
            public: fd.DealerPubMsg(V),
            private: fd.DealerPrivMsg,
        ) !fd.PlayerAck(P) {
            if (self.acks.get_value(dealer)) |ack| return ack.*;
            const processed = try self.player.dealer_message(
                utils.N3f1,
                self.gpa,
                dealer,
                public,
                private,
            );
            const ack = processed orelse
                @panic("processed dealer must have a cached acknowledgement");
            _ = try store.append_dealing(epoch, dealer, public, private);
            try self.insert_ack(dealer, ack);
            return ack;
        }

        fn insert_ack(self: *Self, dealer: P, ack: fd.PlayerAck(P)) !void {
            const Acks = utils.ordered.Map(P, fd.PlayerAck(P));
            const count = self.acks.len();
            const pairs = try self.gpa.alloc(Acks.Pair, count + 1);
            defer self.gpa.free(pairs);
            for (self.acks.keys.items, self.acks.values, pairs[0..count]) |key, value, *pair| {
                pair.* = .{ key, value };
            }
            pairs[count] = .{ dealer, ack };
            const updated = try Acks.from_dedup(self.gpa, pairs);
            self.acks.deinit(self.gpa);
            self.acks = updated;
            assert(self.acks.len() == count + 1);
        }
    };
}

test {
    _ = @import("store_test.zig");
}
