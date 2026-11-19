//! The reshare harness's stateful application (commonware `glue::dkg::tests::reshare::harness`'s
//! `App`): every block writes its height under one key of an unordered fixed QMDB. The
//! `reshare.Application` wrapper above it selects and validates the reshare payload, so this
//! application only executes state. `finalized` records the processed height in the ledger
//! and parks while the ledger holds this participant at or below the block's height.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const reshare = @import("../../reshare/root.zig");
const stateful = @import("../../../stateful/mod.zig");
const testing_mod = @import("../../../stateful/actor/processor/testing.zig");
const support = @import("support.zig");

const Height = consensus.Height;
const Sha256 = cryptography.Sha256;
const Key = cryptography.ed25519.PublicKey;

/// commonware's `Qmdb`: an unordered fixed `any` database of SHA-256 keys and values over a
/// `TwoCap` index.
pub const Any = testing_mod.Any;
/// commonware's `Database`.
pub const Database = Any.Shared;

/// How often a held application rechecks its hold (commonware sleeps 25 ms).
const hold_poll_ms = 25;

/// commonware `u64_to_digest`: `value` big-endian in the first eight bytes.
pub fn u64_to_digest(value: u64) Sha256.Digest {
    var result: Sha256.Digest = .fill(0);
    std.mem.writeInt(u64, result.bytes[0..8], value, .big);
    return result;
}

/// The application over block type `B` (`state_sync_block.Block(V, D)`).
pub fn App(comptime B: type) type {
    return struct {
        const Self = @This();
        pub const Block = B;
        pub const Context = B.Context;
        pub const Merkleized = Any.Merkleized;
        /// The reshare payload the wrapper selected (commonware's `ReshareInput`).
        pub const Input = reshare.application.InputOf(B.Payload);
        pub const Captured = void;
        const Proposed = stateful.actor.processor.Proposed(Self);

        gpa: Allocator,
        /// Borrowed; outlives the application.
        genesis_block: *const B,
        /// Borrowed; outlives the application.
        ledger: *support.Ledger,
        key: Key,

        pub fn deinit_input(input: *Input) void {
            input.deinit();
            assert(input.payload == null);
        }

        pub fn genesis(self: *const Self, gpa: Allocator) Allocator.Error!B {
            assert(self.genesis_block.height().get() == 0);
            return self.genesis_block.clone(gpa);
        }

        /// commonware `App::execute`: writes `height` under `Sha256("height")` and merkleizes.
        /// Consumes `batches`, also on error.
        fn execute(height: Height, batches: Any.Unmerkleized) !Any.Merkleized {
            var batch = batches;
            errdefer batch.deinit();
            assert(height.get() > 0);
            try batch.write(Sha256.hash(&.{"height"}), u64_to_digest(height.get()));
            return batch.merkleize();
        }

        /// The sync target a merkleized batch reaches: its root over `[floor, tip)`.
        fn target_of(merkleized: *const Any.Merkleized) Any.SyncTarget {
            const bounds = &merkleized.inner.bounds;
            assert(bounds.inactivity_floor < bounds.tip.size);
            return .init(merkleized.root(), bounds.inactivity_floor, bounds.tip.size);
        }

        /// Builds on the parent at the head of `ancestry` with the wrapper's payload; null when
        /// the parent is gone. Consumes `batches` and `input`.
        pub fn propose(
            self: *Self,
            _: Io,
            context: Context,
            ancestry: anytype,
            batches: Any.Unmerkleized,
            input: Input,
        ) !?Proposed {
            var owned = batches;
            var carried = input;
            var parent = (ancestry.next() catch |err| {
                owned.deinit();
                deinit_input(&carried);
                return err;
            }) orelse {
                owned.deinit();
                deinit_input(&carried);
                return null;
            };
            defer parent.deinit();
            const height = parent.inner().height().next();
            var merkleized = execute(height, owned) catch |err| {
                deinit_input(&carried);
                return err;
            };
            errdefer merkleized.deinit();
            const target = target_of(&merkleized);
            // `B.init` takes the payload, also on error.
            const block = try B.init(
                self.gpa,
                context,
                parent.digest(),
                height,
                target,
                carried.take(),
            );
            assert(block.height().get() == parent.inner().height().get() + 1);
            return .{ .block = block, .merkleized = merkleized };
        }

        /// Re-executes the block at the head of `ancestry`; null when it is gone. Consumes
        /// `batches`.
        pub fn process(
            _: *Self,
            _: Io,
            _: Context,
            ancestry: anytype,
            batches: Any.Unmerkleized,
            _: anytype,
        ) !?Any.Merkleized {
            var owned = batches;
            const head = ancestry.peek() orelse {
                owned.deinit();
                return null;
            };
            return try execute(head.inner().height(), owned);
        }

        pub fn capture(
            _: *Self,
            _: Io,
            _: Context,
            _: *const B,
            _: *const Any.Merkleized,
            _: anytype,
        ) !Captured {}

        /// Records the processed height, then parks while held at it, so a processed-height
        /// crash observes the hold deterministically.
        pub fn finalized(
            self: *Self,
            io: Io,
            _: Context,
            block: *const B,
            _: Captured,
            _: anytype,
        ) !void {
            const height = block.height().get();
            self.ledger.record_processed(self.key, height);
            assert(self.ledger.processed_of(self.key) >= height);
            while (self.ledger.held(self.key, height)) {
                try io.sleep(.fromMilliseconds(hold_poll_ms), .awake);
            }
        }

        pub fn sync_targets(block: *const B) Any.SyncTarget {
            assert(block.target.start < block.target.end);
            return block.target;
        }
    };
}
