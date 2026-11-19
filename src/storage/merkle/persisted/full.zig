//! A Merkle structure (MMR or MMB) backed by a fixed-item journal of node digests.
//!
//! Port of commonware's `storage/src/merkle/persisted/full.rs`. The journal stores every
//! unpruned node; a metadata store keeps the pruning boundary (as a leaf location) and the
//! digests pinned at it, which the root and proofs still need after their journal blobs are
//! pruned. A memory-resident `Mem` caches every node not yet flushed to the journal, plus the
//! pins of both its own boundary and the structure's pruning boundary.
//!
//! Metadata keys are `utils.sequence.PrefixedU64` (commonware's `prefixed_u64::U64`): prefix 0
//! holds pinned nodes by position, prefix 1 (key 0) holds the pruning boundary as a big-endian
//! leaf location.
//!
//! Commonware's mutators take the structure by value and drop it on error. Here mutators take
//! `*Self`; after an error only `deinit` may follow (state not yet durable is lost, durable
//! state stays recoverable). Syncs complete synchronously, so `start_sync` is `sync` without
//! the completion handle.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const Completion = runtime.storage.Completion;
const utils = @import("utils");
const merkle = @import("../mod.zig");
const mem_module = @import("../mem.zig");
const verification = @import("../verification.zig");
const fixed = @import("../../journal/contiguous/fixed.zig");
const metadata = @import("../../metadata/mod.zig");
const authenticated = @import("../../journal/authenticated.zig");

const Storage = runtime.storage.Storage;
const Key = utils.sequence.PrefixedU64;
const Bounds = @import("../../journal/contiguous/mod.zig").Bounds;
const max_pins = merkle.max_pinned_nodes;

/// Metadata key prefix of pinned nodes (keyed by position).
pub const node_prefix: u8 = 0;
/// Metadata key prefix of the pruning boundary (a leaf location, key 0).
pub const pruned_to_prefix: u8 = 1;

/// Configuration of a journaled Merkle structure.
pub const Config = struct {
    /// Partition of the node journal.
    journal_partition: []const u8,
    /// Partition of the metadata holding the pruning boundary and its pins. Fixed for the
    /// life of the journal: a pruned journal whose metadata has no boundary is cleared on open
    /// as the remnant of an interrupted `destroy`.
    metadata_partition: []const u8,
    /// The maximum number of nodes in each journal blob.
    items_per_blob: u64,
    /// Write buffer size of each journal blob.
    write_buffer: usize,
    /// Buffer size for sequential reads during recovery.
    replay_buffer: usize,
    /// The page cache of the journal's blobs.
    cache_ref: *runtime.buffer.paged.CacheRef,

    pub fn journal(self: *const Config) fixed.Config {
        return .{
            .partition = self.journal_partition,
            .items_per_blob = self.items_per_blob,
            .cache_ref = self.cache_ref,
            .write_buffer = self.write_buffer,
            .replay_buffer = self.replay_buffer,
        };
    }
};

/// The leaves a recovery may retain.
pub const Retain = union(enum) {
    /// Every leaf the persisted structure can reconstruct.
    all,
    /// At most this many leaves; the persisted pruning boundary must not exceed it.
    at_most: u64,
    /// No leaf: the persisted boundary and pins are cleared first.
    nothing,
};

fn be_bytes(value: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return bytes;
}

pub fn Merkle(comptime F: type, comptime Digest: type) type {
    merkle.check_family(F);
    return struct {
        const Self = @This();
        pub const Mem = mem_module.Mem(F, Digest);
        pub const Journal = fixed.Journal(Digest);
        pub const JournalRecovery = Journal.RecoveryType;
        pub const Store = metadata.Metadata(Key, []const u8);
        pub const Proof = Mem.Proof;
        pub const MerkleizedBatch = Mem.MerkleizedBatch;
        pub const Error = merkle.Error || fixed.Error || Store.Error || Allocator.Error;

        gpa: Allocator,
        /// Every node not yet flushed, plus the pins of both boundaries.
        mem: Mem,
        /// The position pruning has reached (0 if never pruned).
        pruned_to_pos: u64,
        /// Every unpruned node.
        journal: Journal,
        /// The pruning boundary and its pinned nodes.
        metadata: Store,
        /// Whether flushed nodes or a started sync still need a full journal sync.
        journal_dirty: bool = false,

        /// Closes the structure without syncing (unflushed nodes are lost).
        pub fn deinit(self: *Self) void {
            self.journal.deinit();
            self.metadata.deinit();
            self.mem.deinit(self.gpa);
            self.* = undefined;
        }

        /// Total node count, irrespective of pruning; the next leaf's position.
        pub fn size(self: *const Self) u64 {
            return self.mem.size();
        }

        pub fn leaves(self: *const Self) u64 {
            return self.mem.leaves();
        }

        /// `[oldest retained leaf, leaf count)`.
        pub fn bounds(self: *const Self) merkle.Range {
            const start = F.position_to_location(self.pruned_to_pos).?; // Pruned at a leaf.
            return .{ .start = start, .end = self.mem.leaves() };
        }

        /// Opens the structure, recovering every leaf it can reconstruct.
        pub fn init(gpa: Allocator, storage: Storage, hasher: anytype, cfg: Config) Error!Self {
            var recovery = try Recovery.prepare(gpa, storage, hasher, cfg, .all);
            return recovery.finish();
        }

        /// Opens the structure retaining at most `max_leaves` leaves, durably discarding the
        /// rest. The cap must permit the persisted pruning boundary.
        pub fn init_at_most(
            gpa: Allocator,
            storage: Storage,
            hasher: anytype,
            cfg: Config,
            max_leaves: u64,
        ) Error!Self {
            const retain: Retain = .{ .at_most = max_leaves };
            var recovery = try Recovery.prepare(gpa, storage, hasher, cfg, retain);
            return recovery.finish();
        }

        /// `init_sync`'s configuration (commonware's `SyncConfig`).
        pub const SyncConfig = struct {
            config: Config,
            /// The leaf range to sync; must not be empty.
            range: merkle.Range,
            /// The pins at `range.start`, in `merkle.nodes_to_pin` order, or null to take them
            /// from metadata (first) or the journal.
            pinned_nodes: ?[]const Digest = null,
        };

        /// Opens the structure for state sync of `cfg.range`, reusing what local storage holds:
        /// - fresh start: retained data ends before the range start; discard it and start empty
        ///   at the range start;
        /// - prune and reuse: the range contains retained data; prune it to the range start;
        /// - ahead: retained data extends past the range end; truncate to the range end;
        /// - incompatible: retained data starts after the range start; discard it.
        /// Without `pinned_nodes`, boundary pins already in metadata take precedence over
        /// journal nodes. If interrupted, retry with the same range and pins.
        pub fn init_sync(gpa: Allocator, storage: Storage, cfg: SyncConfig) Error!Self {
            assert(cfg.range.start < cfg.range.end); // The sync range must not be empty.
            const prune_loc = cfg.range.start;
            const prune_pos = try merkle.position_from_location(F, prune_loc);
            const end_pos = try merkle.position_from_location(F, cfg.range.end);
            var store = try open_metadata(gpa, storage, cfg.config);
            errdefer store.deinit();
            var positions_buffer: [max_pins]u64 = undefined;
            const pins = merkle.nodes_to_pin(F, prune_loc, &positions_buffer);
            // Without caller pins, every pin missing from metadata must come from the journal:
            // probe the highest, so the journal stays unopened when it lies past every blob.
            const probe = if (cfg.pinned_nodes == null)
                highest_missing_pin(&store, pins) orelse prune_pos
            else
                prune_pos;
            const journal_cfg = cfg.config.journal();
            var stored = try authenticated.Stored(Journal).open(
                gpa,
                storage,
                journal_cfg,
                probe,
                end_pos,
            );
            errdefer switch (stored) {
                .opened => |*recovery| recovery.deinit(),
                .unopened => {},
            };
            const opened: ?*JournalRecovery = switch (stored) {
                .opened => |*recovery| recovery,
                .unopened => null,
            };
            // An opened journal starts at or below the sync start and ends at most at the
            // range end. A complete tree ending at or before the sync start cannot serve the
            // range, so it is reset unless the journal is already empty there.
            const span: Bounds = if (opened) |recovery|
                recovery.get_bounds()
            else
                .{ .start = prune_pos, .end = prune_pos };
            const journal_size = @max(F.to_nearest_size(span.end), prune_pos);
            const reset = journal_size == prune_pos and
                (span.start != prune_pos or span.end != prune_pos);
            try persist_sync_boundary(gpa, &store, opened, pins, prune_loc, cfg.pinned_nodes);
            // Build the in-memory structure before pruning or reset removes pin sources.
            const journal_leaves = F.position_to_location(journal_size).?;
            var mem = try pinned(gpa, &store, opened, journal_leaves, prune_loc);
            errdefer mem.deinit(gpa);
            // Pins must be durable before reset or pruning removes their journal sources.
            try store.sync();
            var recovery = switch (stored) {
                .opened => |opened_recovery| opened_recovery,
                .unopened => try Journal.clear(gpa, storage, journal_cfg, prune_pos),
            };
            stored = .unopened; // The recovery is owned below.
            const journal = try publish_sync_journal(&recovery, reset, prune_pos, journal_size);
            assert(mem.size() == journal_size);
            return .{
                .gpa = gpa,
                .mem = mem,
                .pruned_to_pos = prune_pos,
                .journal = journal,
                .metadata = store,
            };
        }

        /// The highest-positioned pin among `pins` that metadata lacks.
        fn highest_missing_pin(store: *const Store, pins: []const u64) ?u64 {
            var highest: ?u64 = null;
            for (pins) |position| {
                if (store.get(Key.init(node_prefix, position)) != null) continue;
                highest = @max(highest orelse position, position);
            }
            assert(highest == null or std.mem.indexOfScalar(u64, pins, highest.?) != null);
            return highest;
        }

        /// Stages the sync boundary and its pins in metadata, dropping every other pin: an
        /// interrupted sync can leave metadata ahead of the journal, and recovery must not
        /// prefer abandoned pins over journal nodes.
        fn persist_sync_boundary(
            gpa: Allocator,
            store: *Store,
            journal: ?*JournalRecovery,
            pins: []const u64,
            prune_loc: u64,
            pinned_nodes: ?[]const Digest,
        ) Error!void {
            store.retain(pins, keep_boundary_pin);
            try put_owned(gpa, store, Key.init(pruned_to_prefix, 0), &be_bytes(prune_loc));
            if (pinned_nodes) |digests| {
                if (digests.len != pins.len) return error.InvalidPinnedNodes;
                for (pins, digests) |position, digest| {
                    try put_owned(gpa, store, Key.init(node_prefix, position), &digest.bytes);
                }
            } else {
                // Recovery may delete the journal nodes supplying these pins: preserve each
                // in metadata before syncing it and removing its source.
                for (pins) |position| {
                    const digest = try get_from_recovery(store, journal, position);
                    try put_owned(gpa, store, Key.init(node_prefix, position), &digest.bytes);
                }
            }
            assert(store.get(Key.init(pruned_to_prefix, 0)) != null);
        }

        fn keep_boundary_pin(pins: []const u64, key: Key, _: *const []const u8) bool {
            if (key.prefix() != node_prefix) return true;
            return std.mem.indexOfScalar(u64, pins, key.value()) != null;
        }

        /// Resets or truncates the sync journal, prunes it to the boundary, and publishes it.
        /// Consumes the recovery, also on error.
        fn publish_sync_journal(
            recovery: *JournalRecovery,
            reset: bool,
            prune_pos: u64,
            journal_size: u64,
        ) Error!Journal {
            assert(journal_size >= prune_pos);
            const prepared: Error!void = prepared: {
                if (reset) {
                    recovery.clear_to_size(prune_pos) catch |err| break :prepared err;
                } else {
                    recovery.truncate(journal_size) catch |err| break :prepared err;
                }
                _ = recovery.prune(prune_pos) catch |err| break :prepared err;
            };
            prepared catch |err| {
                recovery.deinit();
                return err;
            };
            return recovery.finish(journal_size);
        }

        /// A validated prefix whose storage is not truncated yet (commonware's `Recovery`).
        pub const Recovery = struct {
            gpa: Allocator,
            journal: JournalRecovery,
            metadata: Store,
            /// The complete tree rebuilt from tip pins, plus any recoverable orphan leaf.
            mem: Mem,
            /// Node count of the greatest complete prefix of the recovered journal.
            retained_size: u64,
            /// The persisted pruning boundary as a node position.
            metadata_prune_pos: u64,
            /// The stricter of the persisted boundary and the journal's leaf-aligned start.
            effective_prune_pos: u64,

            pub fn deinit(self: *Recovery) void {
                self.journal.deinit();
                self.metadata.deinit();
                self.mem.deinit(self.gpa);
                self.* = undefined;
            }

            /// Leaves available before replay.
            pub fn leaves(self: *const Recovery) u64 {
                return self.mem.leaves();
            }

            /// Validates the reconstruction anchors before any history is deleted. A
            /// persisted boundary beyond the recovered journal fails with `MissingNode`. A
            /// pruned journal with no persisted boundary lost its pins, so it is cleared.
            pub fn prepare(
                gpa: Allocator,
                storage: Storage,
                hasher: anytype,
                cfg: Config,
                retain: Retain,
            ) Error!Recovery {
                const max_leaves: ?u64 = switch (retain) {
                    .all => null,
                    .at_most => |cap| cap,
                    .nothing => 0,
                };
                var store = try open_metadata(gpa, storage, cfg);
                errdefer store.deinit();
                // One commit drops the boundary together with its pins.
                if (retain == .nothing and store.count() > 0) {
                    store.clear();
                    try store.sync();
                }
                const persisted = try read_pruned_to(&store);
                const metadata_prune_pos = try merkle.position_from_location(F, persisted orelse 0);
                if (max_leaves) |cap| if (cap < (persisted orelse 0)) return error.ElementPruned;
                var journal = try open_journal(gpa, storage, cfg, persisted == null, max_leaves);
                errdefer journal.deinit();
                const anchors = try reconcile(&journal, metadata_prune_pos);
                const retained_leaves = F.position_to_location(anchors.retained_size).?;
                const prune_loc = F.position_to_location(anchors.effective_prune_pos).?;
                var mem = try pinned(gpa, &store, &journal, retained_leaves, prune_loc);
                errdefer mem.deinit(gpa);
                // An intact orphan leaf rebuilds the parents it lacks, within the leaf cap.
                const orphan = anchors.retained_size != journal.size() and
                    (max_leaves == null or retained_leaves < max_leaves.?);
                if (orphan) {
                    if (journal.item(anchors.retained_size)) |leaf| {
                        try mem.add_leaf_digest(gpa, hasher, leaf);
                    } else |_| {}
                }
                return .{
                    .gpa = gpa,
                    .journal = journal,
                    .metadata = store,
                    .mem = mem,
                    .retained_size = anchors.retained_size,
                    .metadata_prune_pos = metadata_prune_pos,
                    .effective_prune_pos = anchors.effective_prune_pos,
                };
            }

            /// Truncates the journal to the validated prefix, applies the durable pruning
            /// boundary, and publishes the structure. Consumes the recovery, also on error.
            pub fn finish(self: *Recovery) Error!Self {
                const gpa = self.gpa;
                self.prepare_publish() catch |err| {
                    self.deinit();
                    return err;
                };
                const journal = self.journal.publish(self.retained_size) catch |err| {
                    self.metadata.deinit();
                    self.mem.deinit(gpa);
                    return err;
                };
                var result: Self = .{
                    .gpa = gpa,
                    .mem = self.mem,
                    .pruned_to_pos = self.effective_prune_pos,
                    .journal = journal,
                    .metadata = self.metadata,
                };
                self.* = undefined;
                errdefer result.deinit();
                try result.sync();
                return result;
            }

            fn prepare_publish(self: *Recovery) Error!void {
                try self.journal.truncate(self.retained_size);
                if (self.metadata_prune_pos > self.journal.pruning_boundary()) {
                    _ = try self.journal.prune(self.metadata_prune_pos);
                }
                assert(self.journal.size() <= self.retained_size);
            }
        };

        const Anchors = struct { retained_size: u64, effective_prune_pos: u64 };

        /// The greatest complete tree in the journal and the effective pruning boundary.
        fn reconcile(journal: *const JournalRecovery, metadata_prune_pos: u64) Error!Anchors {
            // Journal pruning is blob-aligned and may fall between complete trees: round its
            // start up to a leaf position, then honor the stricter durable boundary.
            const boundary = journal.pruning_boundary();
            const floor = F.to_nearest_size(boundary);
            const aligned = if (floor == boundary)
                boundary
            else
                try merkle.position_from_location(F, F.position_to_location(floor).? + 1);
            const effective_prune_pos = @max(metadata_prune_pos, aligned);
            const retained_size = F.to_nearest_size(journal.size());
            if (effective_prune_pos > retained_size) return error.MissingNode;
            assert(F.is_valid_size(retained_size));
            return .{ .retained_size = retained_size, .effective_prune_pos = effective_prune_pos };
        }

        fn open_metadata(gpa: Allocator, storage: Storage, cfg: Config) Error!Store {
            return Store.init(gpa, storage, .{
                .partition = cfg.metadata_partition,
                .codec_config = .{ .range = .full(), .item = {} },
            });
        }

        /// Opens the journal for recovery, capped at the node count of `max_leaves`. A pruned
        /// journal without a persisted boundary (`unanchored`) is cleared unread.
        fn open_journal(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            unanchored: bool,
            max_leaves: ?u64,
        ) Error!JournalRecovery {
            const journal_cfg = cfg.journal();
            if (unanchored) {
                const span = try Journal.span(gpa, storage, journal_cfg);
                if (span.start > 0) return Journal.clear(gpa, storage, journal_cfg, 0);
            }
            // An unrepresentably large cap cannot constrain a representable tree.
            const node_cap: ?u64 = if (max_leaves) |cap|
                merkle.position_from_location(F, cap) catch std.math.maxInt(u64)
            else
                null;
            return Journal.recover(gpa, storage, journal_cfg, node_cap);
        }

        /// The persisted pruning boundary (a leaf location), if any.
        fn read_pruned_to(store: *const Store) Error!?u64 {
            const bytes = store.get(Key.init(pruned_to_prefix, 0)) orelse return null;
            if (bytes.len != 8) return error.DataCorrupted; // Invalid pruning boundary.
            const location = std.mem.readInt(u64, bytes.*[0..8], .big);
            if (!merkle.location_is_valid(F, location)) return error.DataCorrupted;
            return location;
        }

        fn decode_digest(bytes: []const u8) Error!Digest {
            if (bytes.len != Digest.fixed_size) return error.DataCorrupted;
            return codec.decode_fixed(Digest, bytes[0..Digest.fixed_size]) catch
                error.DataCorrupted;
        }

        /// A pinned node from metadata or recovery-owned journal storage.
        fn get_from_recovery(
            store: *const Store,
            journal: ?*JournalRecovery,
            position: u64,
        ) Error!Digest {
            if (store.get(Key.init(node_prefix, position))) |bytes| {
                return decode_digest(bytes.*);
            }
            const source = journal orelse return error.MissingNode;
            return source.item(position) catch |err| switch (err) {
                error.ItemPruned, error.ItemOutOfRange => error.MissingNode,
                else => |e| e,
            };
        }

        /// An empty tree of `tip` leaves from its pins, plus the pins of `prune_loc`.
        fn pinned(
            gpa: Allocator,
            store: *const Store,
            journal: ?*JournalRecovery,
            tip: u64,
            prune_loc: u64,
        ) Error!Mem {
            assert(prune_loc <= tip);
            var positions_buffer: [max_pins]u64 = undefined;
            var digests: [max_pins]Digest = undefined;
            const tip_positions = merkle.nodes_to_pin(F, tip, &positions_buffer);
            for (tip_positions, digests[0..tip_positions.len]) |position, *digest| {
                digest.* = try get_from_recovery(store, journal, position);
            }
            var mem = try Mem.init(gpa, &.{}, tip, digests[0..tip_positions.len]);
            errdefer mem.deinit(gpa);
            const extra = merkle.nodes_to_pin(F, prune_loc, &positions_buffer);
            for (extra, digests[0..extra.len]) |position, *digest| {
                digest.* = try get_from_recovery(store, journal, position);
            }
            mem.add_pinned_nodes(extra, digests[0..extra.len]);
            return mem;
        }

        /// The node at `position`, or null if it is pruned.
        pub fn get_node(self: *const Self, position: u64) Error!?Digest {
            if (self.mem.get_node(position)) |node| return node;
            return self.journal.read(position) catch |err| switch (err) {
                error.ItemPruned => null,
                else => |e| e,
            };
        }

        /// The nodes at strictly increasing `positions` into `out`. Fails with `ElementPruned`
        /// at the first position below the journal's pruning boundary.
        pub fn get_nodes(self: *const Self, positions: []const u64, out: []Digest) Error!void {
            assert(positions.len == out.len);
            const start = self.journal.pruning_boundary();
            var journal_positions: std.ArrayList(u64) = .empty;
            defer journal_positions.deinit(self.gpa);
            var journal_slots: std.ArrayList(usize) = .empty;
            defer journal_slots.deinit(self.gpa);
            for (positions, out, 0..) |position, *node, slot| {
                if (slot > 0) assert(positions[slot - 1] < position);
                if (self.mem.get_node(position)) |digest| {
                    node.* = digest;
                } else if (position >= start) {
                    try journal_positions.append(self.gpa, position);
                    try journal_slots.append(self.gpa, slot);
                } else {
                    return error.ElementPruned;
                }
            }
            if (journal_positions.items.len == 0) return;
            const items = try self.gpa.alloc(Digest, journal_positions.items.len);
            defer self.gpa.free(items);
            try self.journal.read_many(journal_positions.items, items);
            for (journal_slots.items, items) |slot, item| out[slot] = item;
        }

        /// The pins that authenticate a lower leaf boundary at `location`, in pin order.
        pub fn pinned_nodes_at(
            self: *const Self,
            location: u64,
            out: *[max_pins]Digest,
        ) Error![]Digest {
            if (!merkle.location_is_valid(F, location)) return error.LocationOverflow;
            var positions_buffer: [max_pins]u64 = undefined;
            const positions = merkle.nodes_to_pin(F, location, &positions_buffer);
            for (positions, out[0..positions.len]) |position, *digest| {
                digest.* = try self.get_node(position) orelse return error.ElementPruned;
            }
            return out[0..positions.len];
        }

        /// Flushes cached nodes to the journal without making them durable. Flushed nodes
        /// leave memory and stay readable through the journal, but need `sync` to survive a
        /// crash.
        pub fn flush(self: *Self) Error!void {
            try self.flush_internal();
        }

        /// Flushes cached nodes to the journal and makes them durable.
        pub fn sync(self: *Self) Error!void {
            try self.flush_internal();
            // Persist nodes from this or earlier flushes.
            if (self.journal_dirty) {
                try self.journal.sync();
                self.journal_dirty = false;
            }
        }

        /// Flushes cached nodes and starts making them durable, returning a completion (one
        /// reference, owned by the caller) that covers only the nodes flushed so far. A later
        /// `sync` still performs a full durable sync.
        pub fn start_sync(self: *Self) Error!Completion {
            try self.flush_internal();
            const completion = try self.journal.start_sync();
            self.journal_dirty = true;
            assert(self.journal.size() <= self.mem.size());
            return completion;
        }

        /// Wait for an outstanding `start_sync`, surfacing its failure.
        pub fn wait_for_sync(self: *Self) Error!void {
            try self.journal.wait_for_sync();
            assert(self.journal.size() <= self.mem.size());
        }

        /// Appends the cached nodes the journal lacks, then prunes them from memory, keeping
        /// the pins of the pruning boundary.
        fn flush_internal(self: *Self) Error!void {
            const journal_size = self.journal.size();
            const mem_size = self.mem.size();
            assert(journal_size <= mem_size); // The journal never runs ahead of memory.
            if (journal_size == mem_size) return;
            const target_leaves = self.mem.leaves();
            // Pins of the pruning boundary, to restore after `mem.prune` replaces them.
            var positions_buffer: [max_pins]u64 = undefined;
            const prune_loc = F.position_to_location(self.pruned_to_pos).?;
            const positions = merkle.nodes_to_pin(F, prune_loc, &positions_buffer);
            var digests: [max_pins]Digest = undefined;
            for (positions, digests[0..positions.len]) |position, *digest| {
                digest.* = self.mem.get_node(position).?; // Pins are always cached.
            }
            _ = try self.journal.append_many(self.mem.nodes_from(journal_size));
            self.journal_dirty = true;
            // The nodes are readable from the journal now, so memory may drop them.
            self.mem.prune(target_leaves) catch unreachable; // `target_leaves` is in bounds.
            self.mem.add_pinned_nodes(positions, digests[0..positions.len]);
            assert(self.journal.size() == mem_size);
        }

        /// Prunes every node not needed to prove leaves at or after `location`. Syncs first,
        /// and persists the new boundary and its pins before pruning the journal, so no failure
        /// leaves the structure unrecoverable.
        pub fn prune(self: *Self, location: u64) Error!void {
            const position = try merkle.position_from_location(F, location);
            if (location > self.mem.leaves()) return error.LeafOutOfBounds;
            if (position <= self.pruned_to_pos) return;
            try self.sync();
            var positions_buffer: [max_pins]u64 = undefined;
            var digests: [max_pins]Digest = undefined;
            const pins = try self.update_metadata(position, &positions_buffer, &digests);
            _ = try self.journal.prune(position);
            self.mem.add_pinned_nodes(pins.positions, pins.digests);
            self.pruned_to_pos = position;
        }

        /// Prunes as much as possible.
        pub fn prune_all(self: *Self) Error!void {
            const count = self.mem.leaves();
            if (count != 0) try self.prune(count);
        }

        const Pins = struct { positions: []const u64, digests: []const Digest };

        /// Persists the pins of `prune_to_pos` and the boundary itself, returning the pins.
        fn update_metadata(
            self: *Self,
            prune_to_pos: u64,
            positions_buffer: *[max_pins]u64,
            digests: *[max_pins]Digest,
        ) Error!Pins {
            assert(prune_to_pos >= self.pruned_to_pos);
            const prune_loc = F.position_to_location(prune_to_pos).?;
            const positions = merkle.nodes_to_pin(F, prune_loc, positions_buffer);
            for (positions, digests[0..positions.len]) |position, *digest| {
                // At or past the current boundary, every pin is retained.
                digest.* = (try self.get_node(position)).?;
                try self.put_metadata(Key.init(node_prefix, position), &digest.bytes);
            }
            try self.put_metadata(Key.init(pruned_to_prefix, 0), &be_bytes(prune_loc));
            try self.metadata.sync();
            return .{ .positions = positions, .digests = digests[0..positions.len] };
        }

        fn put_metadata(self: *Self, key: Key, bytes: []const u8) Error!void {
            try put_owned(self.gpa, &self.metadata, key, bytes);
        }

        /// Stores a copy of `bytes` under `key`, freeing any value it replaces.
        fn put_owned(gpa: Allocator, store: *Store, key: Key, bytes: []const u8) Error!void {
            const owned = try gpa.dupe(u8, bytes);
            const previous = store.put(key, owned) catch |err| {
                gpa.free(owned);
                return err;
            };
            if (previous) |old| gpa.free(old);
            assert(store.get(key) != null);
        }

        /// The root, with the oldest `inactive_peaks` peaks folded.
        pub fn root(self: *const Self, hasher: anytype, inactive_peaks: usize) Error!Digest {
            return self.mem.root(hasher, inactive_peaks);
        }

        /// Removes the structure's storage and frees it, also on error. An interrupted destroy
        /// reopens as the tree a crash would recover, or empty; a retried destroy empties it.
        pub fn destroy(self: *Self) Error!void {
            // The metadata goes first: a journal that outlives an interruption reopens whole
            // while its start is zero, and once pruned, `prepare` discards it unanchored. A
            // failed started sync surfaces first and removes nothing.
            self.wait_for_sync() catch |err| {
                self.deinit();
                return err;
            };
            self.mem.deinit(self.gpa);
            self.metadata.destroy() catch |err| {
                self.journal.deinit();
                self.* = undefined;
                return err;
            };
            defer self.* = undefined;
            try self.journal.destroy();
        }

        /// Test helper: syncs at most `write_limit` cached nodes, then drops the structure
        /// (a partial write).
        pub fn simulate_partial_sync(self: *Self, write_limit: usize) Error!void {
            defer self.deinit();
            if (write_limit == 0) return;
            const pending = self.mem.nodes_from(self.journal.size());
            const count = @min(write_limit, pending.len);
            for (pending[0..count]) |node| _ = try self.journal.append(node);
            try self.journal.sync();
        }

        /// Test helper: persists a new pruning boundary without pruning the journal, then drops
        /// the structure (a crash between the two).
        pub fn simulate_pruning_failure(self: *Self, prune_to: u64) Error!void {
            defer self.deinit();
            const prune_to_pos = try merkle.position_from_location(F, prune_to);
            assert(prune_to_pos <= self.mem.size());
            try self.sync();
            var positions_buffer: [max_pins]u64 = undefined;
            var digests: [max_pins]Digest = undefined;
            _ = try self.update_metadata(prune_to_pos, &positions_buffer, &digests);
        }

        /// Applies a merkleized batch (see `Mem.apply_batch`).
        pub fn apply_batch(self: *Self, batch: *const MerkleizedBatch) Error!void {
            try self.mem.apply_batch(self.gpa, batch);
        }

        /// A root batch representing the committed state (commonware's `to_batch`).
        pub fn to_batch(self: *const Self) Allocator.Error!*MerkleizedBatch {
            return MerkleizedBatch.from_mem(self.gpa, &self.mem);
        }

        /// A speculative batch that only appends: `sync` persists appended nodes only, so an
        /// overwrite of a journaled node would be lost on recovery.
        pub fn new_batch(self: *const Self) Allocator.Error!AppendBatch {
            return .{ .inner = try self.mem.new_batch(self.gpa) };
        }

        /// An append-only wrapper of `batch.Unmerkleized`.
        pub const AppendBatch = struct {
            inner: Mem.Batch,

            pub fn deinit(self: *AppendBatch, gpa: Allocator) void {
                self.inner.deinit(gpa);
            }

            pub fn leaves(self: *const AppendBatch) u64 {
                return self.inner.leaves();
            }

            pub fn add(
                self: *AppendBatch,
                gpa: Allocator,
                hasher: anytype,
                bytes: []const u8,
            ) !void {
                try self.inner.add(gpa, hasher, bytes);
            }

            pub fn add_leaf_digest(self: *AppendBatch, gpa: Allocator, digest: Digest) !void {
                try self.inner.add_leaf_digest(gpa, digest);
            }

            pub fn add_many(
                self: *AppendBatch,
                gpa: Allocator,
                hasher: anytype,
                comptime Item: type,
                items: []const Item,
            ) !void {
                try self.inner.add_many(gpa, hasher, Item, items);
            }

            /// Merkleizes against the structure's committed nodes. Consumes the batch.
            pub fn merkleize(
                self: *AppendBatch,
                structure: *const Self,
                hasher: anytype,
            ) !*MerkleizedBatch {
                return self.inner.merkleize(structure.gpa, &structure.mem, hasher);
            }
        };

        /// An inclusion proof for the element at `location` against the state with `leaves`
        /// leaves. Caller owns the proof.
        pub fn historical_proof(
            self: *const Self,
            hasher: anytype,
            historical_leaves: u64,
            location: u64,
            inactive_peaks: usize,
        ) Error!Proof {
            if (location >= F.max_leaves) return error.LocationOverflow;
            const range: merkle.Range = .{ .start = location, .end = location + 1 };
            return self.historical_range_proof(hasher, historical_leaves, range, inactive_peaks);
        }

        /// An inclusion proof for `range` against the state with `historical_leaves` leaves,
        /// reading nodes from memory and the journal. Caller owns the proof.
        pub fn historical_range_proof(
            self: *const Self,
            hasher: anytype,
            historical_leaves: u64,
            range: merkle.Range,
            inactive_peaks: usize,
        ) Error!Proof {
            if (historical_leaves > self.leaves()) return error.RangeOutOfBounds;
            return verification.historical_range_proof(
                F,
                self.gpa,
                hasher,
                self,
                historical_leaves,
                range,
                inactive_peaks,
            );
        }

        /// An inclusion proof for the element at `location` against the current root.
        pub fn proof(
            self: *const Self,
            hasher: anytype,
            location: u64,
            inactive_peaks: usize,
        ) Error!Proof {
            return self.historical_proof(hasher, self.leaves(), location, inactive_peaks);
        }

        /// An inclusion proof for `range` against the current root.
        pub fn range_proof(
            self: *const Self,
            hasher: anytype,
            range: merkle.Range,
            inactive_peaks: usize,
        ) Error!Proof {
            return self.historical_range_proof(hasher, self.leaves(), range, inactive_peaks);
        }
    };
}

test {
    _ = @import("full_test.zig");
    _ = @import("full_sync_test.zig");
    _ = @import("full_fuzz_test.zig");
    _ = @import("full_proof_test.zig");
    _ = @import("full_init_test.zig");
    _ = @import("full_blob_test.zig");
    _ = @import("mmr_full_test.zig");
}
