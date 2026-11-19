//! Marshal's per-epoch prunable caches (commonware `marshal/core/cache.rs`).
//!
//! Each epoch opens five prunable archives keyed by block digest: verified, notarized, and
//! certified blocks, notarizations, and finalizations. View-indexed archives are pruned by
//! round (older epochs are destroyed whole), the certified archive by height. A metadata store
//! records the floor and ceiling epochs that may hold data, so a restart reopens only them.
//!
//! Marshal waits on the archives' `start_sync` completions at once (async start_sync rollout
//! step 6 pipelines them), so commonware's sync handles become plain calls: a returned
//! `put_*` is durable.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const storage = @import("storage");
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");

const Epoch = types.Epoch;
const Height = types.Height;
const Round = types.Round;
const View = types.View;
const Scope = runtime.telemetry.metrics.Scope;

const cached_epochs_key: u8 = 0;

/// Every archive an epoch opens, in `Cache` field order.
pub const archives = [_][]const u8{
    "verified",
    "notarized",
    "certified",
    "notarizations",
    "finalizations",
};

/// Configuration of the prunable archives.
pub const Config = struct {
    partition_prefix: []const u8,
    prunable_items_per_section: u64,
    replay_buffer: usize,
    key_write_buffer: usize,
    value_write_buffer: usize,
    key_page_cache: *runtime.buffer.paged.CacheRef,
};

/// Room for one formatted partition name.
const partition_size_max = 192;

/// The `kind` partition (`metadata`, `key`, or `value`) of the `name` archive for `epoch`.
pub fn partition(
    buffer: *[partition_size_max]u8,
    prefix: []const u8,
    epoch: Epoch,
    name: []const u8,
    kind: []const u8,
) []const u8 {
    return std.fmt.bufPrint(buffer, "{s}-cache-{d}-{s}-{s}", .{
        prefix,
        epoch.get(),
        name,
        kind,
    }) catch @panic("cache partition name too long");
}

/// The per-epoch caches of variant `V` under scheme `S`.
pub fn Manager(comptime V: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Digest = V.Block.Digest;
        pub const Key = @FieldType(Digest, "bytes");
        pub const Notarization = simplex_types.Notarization(S, V.Commitment);
        pub const Finalization = simplex_types.Finalization(S, V.Commitment);

        const Translator = storage.translator.TwoCap;
        const BlockArchive = storage.archive.prunable.Archive(Translator, Key, V.StoredBlock);
        const NotarizationArchive = Archive(Notarization);
        const FinalizationArchive = Archive(Finalization);

        fn Archive(comptime T: type) type {
            return storage.archive.prunable.Archive(Translator, Key, T);
        }
        /// The floor and ceiling epochs (inclusive) that may hold data. A write above the
        /// ceiling raises it without creating the epochs in between.
        const Range = struct { Epoch, Epoch };

        /// The prunable archives of one epoch.
        const Cache = struct {
            /// Verify-stage candidate blocks by view (multi-put: equivocation can land several).
            verified_blocks: BlockArchive,
            /// Notarized blocks by view.
            notarized_blocks: BlockArchive,
            /// Certified blocks, and uncertified ancestors fetched during optimistic
            /// verification, by height.
            certified_blocks: BlockArchive,
            notarizations: NotarizationArchive,
            finalizations: FinalizationArchive,

            fn deinit(cache: *Cache) void {
                cache.verified_blocks.deinit();
                cache.notarized_blocks.deinit();
                cache.certified_blocks.deinit();
                cache.notarizations.deinit();
                cache.finalizations.deinit();
            }

            /// Destroys every archive. On failure the archives not yet destroyed are closed
            /// (a destroyed archive has released itself), so the cache needs no `deinit`.
            fn destroy(cache: *Cache) !void {
                var destroyed: u8 = 0;
                errdefer {
                    assert(destroyed < 5);
                    if (destroyed < 1) cache.notarized_blocks.deinit();
                    if (destroyed < 2) cache.certified_blocks.deinit();
                    if (destroyed < 3) cache.notarizations.deinit();
                    if (destroyed < 4) cache.finalizations.deinit();
                }
                try cache.verified_blocks.destroy();
                destroyed = 1;
                try cache.notarized_blocks.destroy();
                destroyed = 2;
                try cache.certified_blocks.destroy();
                destroyed = 3;
                try cache.notarizations.destroy();
                destroyed = 4;
                try cache.finalizations.destroy();
            }
        };

        const Entry = struct { epoch: Epoch, cache: *Cache };

        gpa: Allocator,
        storage: runtime.storage.Storage,
        scope: Scope,
        config: Config,
        block_codec_config: codec.Cfg(V.ApplicationBlock),
        metadata: storage.metadata.Metadata(u8, Range),
        /// The open epochs, ascending.
        caches: std.ArrayList(Entry),

        /// Opens the metadata store; `load_persisted_epochs` then reopens stored epochs.
        pub fn init(
            gpa: Allocator,
            store: runtime.storage.Storage,
            scope: Scope,
            config: Config,
            block_codec_config: codec.Cfg(V.ApplicationBlock),
        ) !Self {
            var name: [partition_size_max]u8 = undefined;
            const metadata_partition = std.fmt.bufPrint(&name, "{s}-metadata", .{
                config.partition_prefix,
            }) catch @panic("cache partition name too long");
            const metadata: storage.metadata.Metadata(u8, Range) = try .init(gpa, store, .{
                .partition = metadata_partition,
                .codec_config = .{ {}, {} },
            });
            return .{
                .gpa = gpa,
                .storage = store,
                .scope = scope,
                .config = config,
                .block_codec_config = block_codec_config,
                .metadata = metadata,
                .caches = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.caches.items) |entry| {
                entry.cache.deinit();
                self.gpa.destroy(entry.cache);
            }
            self.caches.deinit(self.gpa);
            self.metadata.deinit();
            self.* = undefined;
        }

        /// Opens every epoch of the metadata range that already has a partition on disk, so
        /// lookups by digest find blocks written before the last shutdown.
        pub fn load_persisted_epochs(self: *Self) !void {
            const floor, const ceiling = self.get_metadata();
            var epoch = floor;
            while (epoch.get() <= ceiling.get()) : (epoch = epoch.next()) {
                if (self.find(epoch) == null and try self.epoch_persisted(epoch)) {
                    _ = try self.init_epoch(epoch);
                }
                if (epoch.get() == std.math.maxInt(u64)) break;
            }
        }

        /// Whether any partition of `epoch`'s archives exists. Only a missing partition counts
        /// as absent; an empty partition or another scan error counts as present, so opening
        /// the archives applies their own error handling (and the next prune past the epoch
        /// destroys what an interrupted destroy left).
        fn epoch_persisted(self: *const Self, epoch: Epoch) !bool {
            for (archives) |archive| {
                for ([_][]const u8{ "metadata", "key", "value" }) |kind| {
                    var buffer: [partition_size_max]u8 = undefined;
                    const prefix = self.config.partition_prefix;
                    const name = partition(&buffer, prefix, epoch, archive, kind);
                    var names = self.storage.scan(self.gpa, name) catch |err| switch (err) {
                        error.PartitionMissing => continue,
                        else => return true,
                    };
                    names.deinit(self.gpa);
                    return true;
                }
            }
            return false;
        }

        fn get_metadata(self: *const Self) Range {
            const range = self.metadata.get(cached_epochs_key) orelse return .{ .zero(), .zero() };
            assert(range.*[0].get() <= range.*[1].get());
            return range.*;
        }

        fn set_metadata(self: *Self, floor: Epoch, ceiling: Epoch) !void {
            assert(floor.get() <= ceiling.get());
            try self.metadata.put_sync(cached_epochs_key, .{ floor, ceiling });
        }

        fn find(self: *const Self, epoch: Epoch) ?*Cache {
            for (self.caches.items) |entry| {
                if (entry.epoch.get() == epoch.get()) return entry.cache;
            }
            return null;
        }

        /// The cache of `epoch`, opened on first use, or null when the epoch was pruned.
        fn with_epoch(self: *Self, epoch: Epoch) !?*Cache {
            if (self.find(epoch)) |cache| return cache;
            const floor, const ceiling = self.get_metadata();
            if (epoch.get() < floor.get()) return null;
            if (epoch.get() > ceiling.get()) try self.set_metadata(floor, epoch);
            return try self.init_epoch(epoch);
        }

        fn init_epoch(self: *Self, epoch: Epoch) !*Cache {
            assert(self.find(epoch) == null);
            try self.caches.ensureUnusedCapacity(self.gpa, 1);
            const cache = try self.gpa.create(Cache);
            errdefer self.gpa.destroy(cache);
            const scope = self.scope.child("cache").with_attribute("epoch", epoch.get());
            cache.verified_blocks = try self.init_archive(scope, epoch, 0);
            errdefer cache.verified_blocks.deinit();
            cache.notarized_blocks = try self.init_archive(scope, epoch, 1);
            errdefer cache.notarized_blocks.deinit();
            cache.certified_blocks = try self.init_archive(scope, epoch, 2);
            errdefer cache.certified_blocks.deinit();
            cache.notarizations = try self.init_archive(scope, epoch, 3);
            errdefer cache.notarizations.deinit();
            cache.finalizations = try self.init_archive(scope, epoch, 4);
            var index: usize = self.caches.items.len;
            while (index > 0 and self.caches.items[index - 1].epoch.get() > epoch.get()) {
                index -= 1;
            }
            self.caches.insertAssumeCapacity(index, .{ .epoch = epoch, .cache = cache });
            return cache;
        }

        /// The value type of the `archives[archive]` archive.
        fn ValueAt(comptime archive: usize) type {
            return switch (archive) {
                0, 1, 2 => V.StoredBlock,
                3 => Notarization,
                4 => Finalization,
                else => unreachable,
            };
        }

        /// The `archives[archive]` archive of `epoch`, holding blocks or certificates.
        fn init_archive(
            self: *Self,
            scope: Scope,
            epoch: Epoch,
            comptime archive: usize,
        ) !Archive(ValueAt(archive)) {
            const T = ValueAt(archive);
            const codec_config: codec.Cfg(T) = switch (archive) {
                0, 1, 2 => self.block_codec_config,
                else => S.certificate_codec_config_unbounded(),
            };
            const name = archives[archive];
            const prefix = self.config.partition_prefix;
            var metadata_name: [partition_size_max]u8 = undefined;
            var key_name: [partition_size_max]u8 = undefined;
            var value_name: [partition_size_max]u8 = undefined;
            return Archive(T).init(self.gpa, self.storage, scope.child(name), .{
                .translator = .{},
                .metadata_partition = partition(&metadata_name, prefix, epoch, name, "metadata"),
                .key_partition = partition(&key_name, prefix, epoch, name, "key"),
                .key_cache_ref = self.config.key_page_cache,
                .value_partition = partition(&value_name, prefix, epoch, name, "value"),
                .codec_config = codec_config,
                .items_per_section = self.config.prunable_items_per_section,
                .key_write_buffer = self.config.key_write_buffer,
                .value_write_buffer = self.config.value_write_buffer,
                .replay_buffer = self.config.replay_buffer,
            });
        }

        /// Stores `block` (borrowed) in `archive` at `index` under `digest`, then syncs.
        fn put_block(
            self: *Self,
            archive: *BlockArchive,
            index: u64,
            digest: Digest,
            block: *const V.Block,
            multi: bool,
        ) !void {
            const stored = try V.into_stored(self.gpa, block);
            defer codec.free(V.StoredBlock, self.gpa, stored);
            if (multi) {
                try archive.put_multi_sync(index, digest.bytes, stored);
            } else {
                try archive.put_sync(index, digest.bytes, stored);
            }
        }

        /// Adds a verify-stage candidate block and syncs it.
        ///
        /// Callers may start this after structural validation and before the application
        /// verdict, so presence here does not mean the application accepted the block. No
        /// certificate pins a round to one candidate yet (an equivocating or restarting leader
        /// can land several at one view), so candidates use multi-put: a digest already stored
        /// at this view is not duplicated, and its existing write is synced.
        pub fn put_verified(
            self: *Self,
            round: Round,
            digest: Digest,
            block: *const V.Block,
        ) !void {
            const cache = try self.with_epoch(round.epoch) orelse return;
            const view = round.view.get();
            if (try cache.verified_blocks.has_at(view, &digest.bytes)) {
                return cache.verified_blocks.sync();
            }
            try self.put_block(&cache.verified_blocks, view, digest, block, true);
        }

        /// Adds a block to the height-indexed certified archive, whether or not it is certified.
        /// A block in an epoch below the floor (pruned) or above the ceiling is not stored.
        pub fn put_certified(
            self: *Self,
            epoch: Epoch,
            height: Height,
            digest: Digest,
            block: *const V.Block,
        ) !void {
            // Startup reopens every epoch from the floor to the ceiling, and `epoch` derives
            // from the block's own height, which can be an unchecked claim: it must not raise
            // the ceiling (commonware #5717).
            _, const ceiling = self.get_metadata();
            if (epoch.get() > ceiling.get()) return;
            const cache = try self.with_epoch(epoch) orelse return;
            if (try cache.certified_blocks.has_at(height.get(), &digest.bytes)) return;
            try self.put_block(&cache.certified_blocks, height.get(), digest, block, true);
        }

        /// Adds a notarized block and syncs it.
        pub fn put_notarized(
            self: *Self,
            round: Round,
            digest: Digest,
            block: *const V.Block,
        ) !void {
            const cache = try self.with_epoch(round.epoch) orelse return;
            try self.put_block(&cache.notarized_blocks, round.view.get(), digest, block, false);
        }

        /// Syncs every write the round's verified-block archive accepted. An absent epoch has
        /// nothing to sync.
        pub fn start_sync_verified(self: *Self, round: Round) !void {
            const cache = self.find(round.epoch) orelse return;
            try (try cache.verified_blocks.start_sync()).wait_release();
        }

        /// Syncs every write the round's notarization archive accepted.
        pub fn start_sync_notarizations(self: *Self, round: Round) !void {
            const cache = self.find(round.epoch) orelse return;
            try (try cache.notarizations.start_sync()).wait_release();
        }

        /// Adds a notarization and syncs it.
        pub fn put_notarization(
            self: *Self,
            round: Round,
            digest: Digest,
            notarization: *const Notarization,
        ) !void {
            const cache = try self.with_epoch(round.epoch) orelse return;
            try cache.notarizations.put_sync(round.view.get(), digest.bytes, notarization.*);
        }

        /// Adds a finalization and syncs it. The blocking sync is intentional: an application
        /// that writes an external store once it observes a finalization may rely on the
        /// certificate staying readable from marshal after a restart.
        pub fn put_finalization(
            self: *Self,
            round: Round,
            digest: Digest,
            finalization: *const Finalization,
        ) !void {
            const cache = try self.with_epoch(round.epoch) orelse return;
            try cache.finalizations.put_sync(round.view.get(), digest.bytes, finalization.*);
        }

        /// The notarization at `round`; free it with `deinit`.
        pub fn get_notarization(self: *Self, round: Round) !?Notarization {
            const cache = self.find(round.epoch) orelse return null;
            return cache.notarizations.get(.{ .index = round.view.get() });
        }

        /// Whether the verified archive holds `digest` at `round`.
        pub fn has_verified(self: *Self, round: Round, digest: Digest) !bool {
            const cache = self.find(round.epoch) orelse return false;
            return cache.verified_blocks.has_at(round.view.get(), &digest.bytes);
        }

        /// The first block stored in the verified archive at `round` (an equivocating or
        /// restarting leader can leave several; look up by digest for a particular one). Free
        /// it with `codec.free`.
        pub fn get_verified(self: *Self, round: Round) !?V.StoredBlock {
            const cache = self.find(round.epoch) orelse return null;
            return cache.verified_blocks.get(.{ .index = round.view.get() });
        }

        /// The cached finalization of the block `digest`, newest epoch first. For blocks and
        /// certificates marshal admitted, a digest maps to one payload commitment.
        pub fn get_finalization_for(self: *Self, digest: Digest) !?Finalization {
            var index = self.caches.items.len;
            while (index > 0) {
                index -= 1;
                const cache = self.caches.items[index].cache;
                if (try cache.finalizations.get(.{ .key = &digest.bytes })) |found| return found;
            }
            return null;
        }

        /// A block under `digest` in the verified, notarized, or certified archives, newest
        /// epoch first, that `predicate.matches(*const V.Block)` accepts. Each candidate is
        /// restored from `digest`; the caller owns the result.
        pub fn find_block_matching(
            self: *Self,
            digest: Digest,
            predicate: anytype,
        ) !?V.Block {
            var index = self.caches.items.len;
            while (index > 0) {
                index -= 1;
                const cache = self.caches.items[index].cache;
                const candidates = [_]*BlockArchive{
                    &cache.verified_blocks,
                    &cache.notarized_blocks,
                    &cache.certified_blocks,
                };
                for (candidates) |archive| {
                    const stored = try archive.get(.{ .key = &digest.bytes }) orelse continue;
                    var block = V.restore(self.gpa, stored, digest) catch |err| {
                        codec.free(V.StoredBlock, self.gpa, stored);
                        return err;
                    };
                    if (predicate.matches(&block)) return block;
                    V.deinit_block(self.gpa, &block);
                }
            }
            return null;
        }

        /// Prunes the view-indexed caches below `round`: every epoch below its epoch is
        /// destroyed, and its epoch is pruned in whole sections, so entries just below the
        /// round's view, in the section that holds it, can remain.
        pub fn prune_by_view(self: *Self, round: Round) !void {
            const new_floor = round.epoch;
            while (self.caches.items.len > 0) {
                const entry = self.caches.items[0];
                if (entry.epoch.get() >= new_floor.get()) break;
                _ = self.caches.orderedRemove(0);
                defer self.gpa.destroy(entry.cache);
                try entry.cache.destroy();
            }
            const floor, const ceiling = self.get_metadata();
            if (new_floor.get() > floor.get()) {
                const new_ceiling = if (ceiling.get() > new_floor.get()) ceiling else new_floor;
                try self.set_metadata(new_floor, new_ceiling);
            }
            const cache = self.find(new_floor) orelse return;
            const min_view = round.view.get();
            try cache.verified_blocks.prune(min_view);
            try cache.notarized_blocks.prune(min_view);
            try cache.notarizations.prune(min_view);
            try cache.finalizations.prune(min_view);
        }

        /// Prunes height-indexed certified blocks below `height`.
        pub fn prune_by_height(self: *Self, height: Height) !void {
            for (self.caches.items) |entry| try entry.cache.certified_blocks.prune(height.get());
        }

        /// The open epochs, ascending (for tests and metrics).
        pub fn open_epochs(self: *const Self, out: []Epoch) []Epoch {
            const count = @min(out.len, self.caches.items.len);
            for (out[0..count], self.caches.items[0..count]) |*epoch, entry| {
                epoch.* = entry.epoch;
            }
            return out[0..count];
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const broadcast = @import("broadcast");
const mocks_block = @import("../mocks/block.zig");
const simplex_scheme = @import("../../simplex/root.zig").scheme;
const Standard = @import("../standard/variant.zig").Standard;

const Sha256 = cryptography.Sha256;
const TestBlock = mocks_block.EmptyBlock(Sha256);
const TestVariant = Standard(TestBlock);
const TestScheme = simplex_scheme.ed25519.Scheme(Sha256.Digest);
const TestManager = Manager(TestVariant, TestScheme);

const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: runtime.telemetry.metrics.Registry,

    fn init(self: *Harness) !void {
        self.* = .{
            .storage = runtime.buffer.mocks.Storage.init(testing.allocator),
            .cache_ref = try runtime.buffer.paged.CacheRef.init(testing.allocator, 1024, 10),
            .registry = runtime.telemetry.metrics.Registry.init(testing.allocator),
        };
    }

    fn deinit(self: *Harness) void {
        self.registry.deinit();
        self.cache_ref.deinit();
        self.storage.deinit();
    }

    fn open(self: *Harness) !TestManager {
        var manager: TestManager = try .init(
            testing.allocator,
            self.storage.interface(),
            Scope.init(&self.registry),
            .{
                .partition_prefix = "marshal",
                .prunable_items_per_section = 2,
                .replay_buffer = 1024,
                .key_write_buffer = 1024,
                .value_write_buffer = 1024,
                .key_page_cache = &self.cache_ref,
            },
            {},
        );
        errdefer manager.deinit();
        try manager.load_persisted_epochs();
        return manager;
    }
};

fn test_block(height: u64) !broadcast.Digested(TestBlock) {
    return .compute(testing.allocator, .init(.fill(0), .new(height), height * 10));
}

/// Accepts blocks at one height.
const AtHeight = struct {
    height: u64,

    pub fn matches(self: AtHeight, block: *const TestVariant.Block) bool {
        return block.inner().height().get() == self.height;
    }
};

test "blocks round trip through the epoch caches and survive a restart" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var block = try test_block(3);
    defer block.deinit();
    const round: Round = .new(.new(2), .new(7));

    var manager = try harness.open();
    try manager.put_verified(round, block.digest(), &block);
    // A second put of the same candidate is not duplicated.
    try manager.put_verified(round, block.digest(), &block);
    try manager.put_notarized(.new(.new(3), .new(1)), block.digest(), &block);
    try testing.expect(try manager.has_verified(round, block.digest()));
    try testing.expect(!try manager.has_verified(.new(.new(2), .new(8)), block.digest()));
    const stored = (try manager.get_verified(round)).?;
    try testing.expect(stored.eql(block.inner().*));
    var epochs: [4]Epoch = undefined;
    try testing.expectEqual(2, manager.open_epochs(&epochs).len);
    manager.deinit();

    // A restart reopens the stored epochs, so digest lookups find the blocks.
    manager = try harness.open();
    defer manager.deinit();
    try testing.expectEqual(2, manager.open_epochs(&epochs).len);
    var found = (try manager.find_block_matching(block.digest(), AtHeight{ .height = 3 })).?;
    defer found.deinit();
    try testing.expect(found.digest().eql(block.digest()));
    try testing.expectEqual(null, try manager.find_block_matching(block.digest(), AtHeight{
        .height = 4,
    }));
    try testing.expectEqual(null, try manager.find_block_matching(.fill(9), AtHeight{
        .height = 3,
    }));
}

test "pruning by view destroys older epochs and refuses their writes" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var block = try test_block(1);
    defer block.deinit();

    var manager = try harness.open();
    defer manager.deinit();
    try manager.put_verified(.new(.new(1), .new(4)), block.digest(), &block);
    try manager.put_certified(.new(1), .new(1), block.digest(), &block);
    try manager.put_verified(.new(.new(2), .new(1)), block.digest(), &block);
    try manager.put_verified(.new(.new(2), .new(6)), block.digest(), &block);

    try manager.prune_by_view(.new(.new(2), .new(5)));
    var epochs: [4]Epoch = undefined;
    const open = manager.open_epochs(&epochs);
    try testing.expectEqual(1, open.len);
    try testing.expectEqual(2, open[0].get());
    // Whole sections below view 5 are gone; the section holding view 6 stays.
    try testing.expect(!try manager.has_verified(.new(.new(2), .new(1)), block.digest()));
    try testing.expect(try manager.has_verified(.new(.new(2), .new(6)), block.digest()));

    // Writes to a pruned epoch are dropped without reopening it.
    try manager.put_verified(.new(.new(1), .new(9)), block.digest(), &block);
    try testing.expectEqual(1, manager.open_epochs(&epochs).len);
    // A write above the ceiling opens its epoch.
    try manager.put_verified(.new(.new(5), .new(0)), block.digest(), &block);
    try testing.expectEqual(2, manager.open_epochs(&epochs).len);
    // A certified write above the ceiling is dropped: its epoch comes from a claimed height.
    try manager.put_certified(.new(9), .new(90), block.digest(), &block);
    try testing.expectEqual(2, manager.open_epochs(&epochs).len);
    try manager.prune_by_height(.new(10));
}
