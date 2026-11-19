//! Acquisition and execution steps for speculative requests (commonware
//! `glue/src/stateful/actor/processor/verifier.rs`).
//!
//! A `Verifier` turns a verification, or a proposal's parent recovery, into steps the actor can
//! interleave with maintenance: `prepare` acquires the blocks a request needs without touching
//! the application, `next` hands out one block to process at a time, and `process` processes
//! that block once for every concurrent request that needs it.
//!
//! Where commonware's verification future stays pending forever (it abstains until its caller
//! cancels), `prepare` returns `error.Waiting`: the caller must not answer the request and
//! drops it once its caller cancels. `P.Provider` (marshal's mailbox in production) also
//! declares `canonical_digest(*Provider, Height) !?Digest`, the finalized block at a height if
//! it is stored locally.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const execution_mod = @import("execution.zig");
const pruning = @import("pruning.zig");

const Height = consensus.Height;
const ancestry_mod = consensus.marshal.ancestry;

/// A verification that cannot finish yet: its ancestry or the canonical block is missing.
pub const WaitError = error{Waiting};

pub fn Verifier(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Execution = execution_mod.Execution(P);
        pub const App = P.App;
        pub const Provider = P.Provider;
        pub const Ancestry = Execution.Ancestry;
        pub const Digested = Execution.Digested;
        pub const Digest = Execution.Digest;
        pub const Step = pruning.ExecutionStep(Digest);

        app: App,
        execution: *Execution,

        /// A request's acquired ancestry and the steps left before it completes.
        pub const Prepared = struct {
            /// The request's block (or a proposal's parent), then its ancestors. The final
            /// verification step takes it, leaving an empty ancestry.
            ancestry: Ancestry,
            /// Missing blocks still to process before the request's own block.
            replay: ?Execution.ReplayPath,
            /// Whether the request's own block still needs processing after the path.
            verify: bool,

            pub fn deinit(prepared: *Prepared, gpa: Allocator) void {
                prepared.ancestry.deinit();
                if (prepared.replay) |*path| path.deinit(gpa);
                prepared.* = undefined;
            }

            /// The ancestry a proposal builds on (taken); the rest is released.
            pub fn finish(prepared: *Prepared, gpa: Allocator) Ancestry {
                const ancestry = prepared.ancestry;
                if (prepared.replay) |*path| path.deinit(gpa);
                prepared.* = undefined;
                return ancestry;
            }
        };

        /// One block to process, and the ancestry its processing reads.
        pub const Next = struct { step: Step, ancestry: Ancestry };

        /// `blocks` (taken, newest first) in front of `tail` (taken).
        fn prefixed(self: *Self, blocks: []const Digested, tail: Ancestry) !Ancestry {
            const gpa = self.execution.gpa;
            var owned = tail;
            const joined = ancestry_mod.with_prefix(Ancestry, gpa, blocks, owned) catch |err| {
                for (blocks) |block| block.discard();
                owned.deinit();
                return err;
            };
            return Ancestry.init(gpa, joined);
        }

        /// Whether a verification of `block` needs no execution, and if so its verdict: a
        /// cached block is valid, and a block at or below the anchor's height is valid only
        /// when it is the canonical block there.
        fn settled(self: *Self, provider: *Provider, block: *const Digested) !?bool {
            const digest = block.digest();
            if (self.execution.pending_contains(digest)) return true;
            const anchor = self.execution.branch_anchor();
            const height = block.inner().height();
            if (height.get() > anchor.height.get()) return null;
            if (height.get() == anchor.height.get()) return std.meta.eql(digest, anchor.digest);
            const canonical = try provider.canonical_digest(height) orelse return error.Waiting;
            return std.meta.eql(canonical, digest);
        }

        /// Acquires a request's block (taken with `ancestry`), its parent when `verify` is set,
        /// and the missing path to cached or applied state, without the application or batches.
        /// `error.Invalid` rejects; `error.Incomplete` ends a recovery whose ancestry ran out;
        /// `error.Waiting` leaves a verification unanswered.
        pub fn prepare(
            self: *Self,
            provider: *Provider,
            ancestry: Ancestry,
            verify: bool,
        ) !Prepared {
            var rest = ancestry;
            var block = (rest.next() catch |err| {
                rest.deinit();
                return err;
            }) orelse {
                rest.deinit();
                return if (verify) error.Waiting else error.Incomplete;
            };
            if (verify) {
                const verdict = self.settled(provider, &block) catch |err| {
                    block.deinit();
                    rest.deinit();
                    return err;
                };
                if (verdict) |valid| {
                    if (!valid) {
                        block.deinit();
                        rest.deinit();
                        return error.Invalid;
                    }
                    const settled_ancestry = try self.prefixed(&.{block}, rest);
                    return .{ .ancestry = settled_ancestry, .replay = null, .verify = false };
                }
            }
            return self.acquire(provider, block, rest, verify);
        }

        /// The rest of `prepare`: the parent (when verifying) and the replay path.
        fn acquire(
            self: *Self,
            provider: *Provider,
            block: Digested,
            rest: Ancestry,
            verify: bool,
        ) !Prepared {
            var tail = rest;
            var target: Digested = undefined;
            var joined: Ancestry = undefined;
            if (verify) {
                var parent = (tail.next() catch |err| {
                    block.discard();
                    tail.deinit();
                    return err;
                }) orelse {
                    block.discard();
                    tail.deinit();
                    return error.Waiting;
                };
                target = parent.clone();
                joined = self.prefixed(&.{ block, parent }, tail) catch |err| {
                    parent.deinit();
                    target.deinit();
                    return err;
                };
            } else {
                target = block.clone();
                joined = self.prefixed(&.{block}, tail) catch |err| {
                    target.deinit();
                    return err;
                };
            }
            errdefer joined.deinit();
            if (self.execution.known_digest(target.digest())) {
                target.deinit();
                return .{ .ancestry = joined, .replay = null, .verify = verify };
            }
            const path = self.execution.prepare_replay(provider, target) catch |err| {
                if (err == error.Incomplete and verify) return error.Waiting;
                return err;
            };
            return .{ .ancestry = joined, .replay = path, .verify = verify };
        }

        /// The next step: each block on the missing path in height order, then the request's
        /// own block when verifying; null once the request has no step left.
        pub fn next(self: *Self, provider: *const Provider, prepared: *Prepared) !?Next {
            const ancestry = replayed: {
                if (prepared.replay) |*path| {
                    const replayed = try self.execution.next_replay(provider, path);
                    if (replayed) |stream| break :replayed stream;
                    path.deinit(self.execution.gpa);
                    prepared.replay = null;
                }
                if (!prepared.verify) return null;
                prepared.verify = false;
                // The step takes the acquired ancestry: cloning a stream with a pending parent
                // fetch would subscribe to that parent again.
                const empty = try Ancestry.from_blocks(self.execution.gpa, &.{});
                const taken = prepared.ancestry;
                prepared.ancestry = empty;
                break :replayed taken;
            };
            const block = (ancestry.peek() orelse unreachable).inner(); // Steps start on a block.
            const step: Step = .{
                .digest = ancestry.peek().?.digest(),
                .parent = block.parent(),
                .round = block.context().round,
            };
            assert(!std.meta.eql(step.digest, step.parent));
            return .{ .step = step, .ancestry = ancestry };
        }

        /// Processes one step's block (its ancestry taken) as a candidate, sharing the call with
        /// concurrent requests for the same block, and caches a valid result.
        pub fn process(self: *Self, ancestry: Ancestry) !void {
            return self.execution.process_shared(self.app, ancestry);
        }
    };
}
