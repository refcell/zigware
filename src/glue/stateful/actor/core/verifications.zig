//! Concurrent speculative requests for the processing loop (commonware
//! `glue/src/stateful/actor/core/verifications.rs`).
//!
//! A verification, or a proposal whose parent state may be missing, becomes a `Work` the
//! `Verifications` handler runs alongside the actor's other duties. A request first acquires
//! its blocks and the missing path back to known state, then runs one execution step per
//! missing block (`Verifier.next`), and finally answers its caller or, for a proposal, queues a
//! build. Maintenance (`pause`) stops acquisition and waits only for the execution steps it
//! cannot retain, so unrelated requests keep going.
//!
//! Each phase runs as a task started with `io.concurrent` that posts its work to a completion
//! list when it ends (commonware polls the phases' futures). Only the actor's task calls the
//! handler.
//!
//! # Answers
//!
//! A verification answers `true` once every step succeeds and `false` only when its block or
//! ancestry is invalid (`error.Invalid`, `error.Incomplete`), as commonware's `reject`. Every
//! other outcome answers nothing: the oneshot is dropped unsent, which consensus reads as no
//! verdict and leaves to its timeout. That covers `error.Waiting` (commonware's verification
//! that stays pending until its caller cancels), cancellation, and a failure to allocate or to
//! start a task (as marshal's wrappers do, 70c082e). A waiting block must never be voted
//! against. A proposal declines where a verification rejects.
//!
//! `P` declares what `Verifier(P)` needs, plus `Recover`: a proposal waiting for its parent's
//! state, with an `ancestry: Verifier.Ancestry` field (its parent first), `is_cancelled(*const)
//! bool`, `decline(*Recover)` (answers that no block was built, consuming it), and
//! `deinit(*Recover)` (releases it unanswered).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const pruning = @import("../processor/pruning.zig");
const verifier_mod = @import("../processor/verifier.zig");

const oneshot = utils.channel.oneshot;

/// How a finished request is answered.
pub const Answer = enum { accept, reject, abstain };

/// The answer for a failed phase: invalid data rejects, everything else abstains.
pub fn answer_for(err: anyerror) Answer {
    return switch (err) {
        error.Invalid, error.Incomplete => .reject,
        else => .abstain,
    };
}

pub fn Verifications(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Verifier = verifier_mod.Verifier(P);
        pub const Ancestry = Verifier.Ancestry;
        pub const Prepared = Verifier.Prepared;
        pub const Provider = P.Provider;
        pub const Recover = P.Recover;
        pub const Step = Verifier.Step;
        pub const Boundary = pruning.FinalizationBoundary(Verifier.Digest);

        /// A verification: the caller's ancestry (its block first) and its verdict's sender.
        pub const Verify = struct {
            ancestry: Ancestry,
            verification: oneshot.Sender(bool),
        };

        /// A speculative request (commonware `Request`).
        pub const Request = union(enum) {
            verify: Verify,
            recover: Recover,

            pub fn is_cancelled(request: *const Request) bool {
                return switch (request.*) {
                    .verify => |*verify| verify.verification.is_closed(),
                    .recover => |*recover| recover.is_cancelled(),
                };
            }

            /// Answers and releases the request.
            fn respond(request: *Request, answer: Answer) void {
                assert(answer != .accept or request.* == .verify);
                switch (request.*) {
                    .verify => |*verify| {
                        verify.ancestry.deinit();
                        switch (answer) {
                            // Dropped unsent: consensus reads no verdict.
                            .abstain => verify.verification.deinit(),
                            // `send` releases the sender; a caller that left needs no answer.
                            else => verify.verification.send(answer == .accept) catch {},
                        }
                    },
                    .recover => |*recover| switch (answer) {
                        .reject => recover.decline(),
                        else => recover.deinit(),
                    },
                }
                request.* = undefined;
            }

            fn ancestry(request: *const Request) !Ancestry {
                return switch (request.*) {
                    .verify => |*verify| verify.ancestry.clone(),
                    .recover => |*recover| recover.ancestry.clone(),
                };
            }
        };

        /// Which execution steps the actor's current operation admits.
        pub const Admission = union(enum) {
            open,
            finalizing: Boundary,
            pruning,

            fn disposition(admission: *const Admission, step: *const Step) pruning.Disposition {
                return switch (admission.*) {
                    .open => .retain,
                    .finalizing => |*boundary| boundary.disposition(step),
                    .pruning => .join,
                };
            }
        };

        const Phase = union(enum) {
            /// A finished step held through pruning.
            ready: Prepared,
            /// Acquiring the blocks; `paused` while maintenance holds acquisition.
            acquiring: struct { paused: bool },
            /// Running one execution step; `held` resumes once it ends.
            executing: struct { step: Step, held: Prepared },
        };

        const Work = struct {
            handler: *Self,
            request: Request,
            phase: Phase,
            /// A copy of the handler's provider, for the acquisition task.
            provider: Provider,
            /// The phase task's input, taken by the task.
            input: ?Ancestry = null,
            future: ?Io.Future(void) = null,
            /// Written by the task before it posts the work.
            outcome: ?anyerror!?Prepared = null,
        };

        gpa: Allocator,
        io: Io,
        verifier: Verifier,
        provider: Provider,
        admission: Admission = .open,
        /// Every live work, in any phase.
        works: std.ArrayList(*Work) = .empty,
        /// Guards `done`, which the tasks post to.
        mutex: Io.Mutex = .init,
        /// Signals the actor, the only waiter.
        condition: Io.Condition = .init,
        /// Works whose phase task ended; capacity for every live work.
        done: std.ArrayList(*Work) = .empty,
        /// Recovered proposals ready to build, in completion order.
        builds: std.ArrayList(Recover) = .empty,

        pub fn init(gpa: Allocator, io: Io, verifier: Verifier, provider: Provider) Self {
            return .{ .gpa = gpa, .io = io, .verifier = verifier, .provider = provider };
        }

        /// Stops every phase task and releases every request unanswered.
        pub fn deinit(self: *Self) void {
            for (self.works.items) |work| {
                if (work.future) |*future| future.cancel(self.io);
            }
            // Each pass releases the last work, which leaves the list.
            while (self.works.getLastOrNull()) |work| {
                work.future = null;
                discard_phase(self.gpa, work);
                self.release(work, .abstain);
            }
            for (self.builds.items) |*recover| recover.deinit();
            self.works.deinit(self.gpa);
            self.done.deinit(self.gpa);
            self.builds.deinit(self.gpa);
            if (self.admission == .finalizing) self.admission.finalizing.deinit(self.gpa);
            if (comptime @hasDecl(Provider, "deinit")) self.provider.deinit();
            self.* = undefined;
        }

        /// Live requests in any phase.
        pub fn len(self: *const Self) usize {
            return self.works.items.len;
        }

        fn copy_provider(self: *const Self) Provider {
            if (comptime @hasDecl(Provider, "clone")) return self.provider.clone();
            return self.provider;
        }

        /// Starts acquiring `request`'s blocks (taken); a cancelled request is dropped.
        pub fn schedule(self: *Self, request: Request) void {
            assert(self.admission == .open);
            var owned = request;
            if (owned.is_cancelled()) return owned.respond(.abstain);
            const work = self.gpa.create(Work) catch return owned.respond(.abstain);
            work.* = .{
                .handler = self,
                .request = owned,
                .phase = .{ .acquiring = .{ .paused = false } },
                .provider = self.copy_provider(),
            };
            self.works.append(self.gpa, work) catch {
                work.request.respond(.abstain);
                self.destroy(work);
                return;
            };
            self.start_acquisition(work);
        }

        fn start_acquisition(self: *Self, work: *Work) void {
            assert(work.phase == .acquiring and work.future == null);
            work.input = work.request.ancestry() catch return self.release(work, .abstain);
            self.spawn(work, acquire_task);
        }

        /// Starts `task` on `work`, or releases the request unanswered when it cannot start.
        fn spawn(self: *Self, work: *Work, comptime task: fn (*Work) void) void {
            work.outcome = null;
            self.done.ensureTotalCapacity(self.gpa, self.works.items.len) catch
                return self.release(work, .abstain);
            work.future = self.io.concurrent(task, .{work}) catch
                return self.release(work, .abstain);
        }

        fn acquire_task(work: *Work) void {
            const handler = work.handler;
            var verifier = handler.verifier;
            const ancestry = work.input.?;
            work.input = null;
            const verify = work.request == .verify;
            const result = verifier.prepare(&work.provider, ancestry, verify);
            work.outcome = if (result) |prepared| prepared else |err| err;
            handler.post(work);
        }

        fn execute_task(work: *Work) void {
            const handler = work.handler;
            var verifier = handler.verifier;
            const ancestry = work.input.?;
            work.input = null;
            // An explicit type: a bare `null` would clear the outer optional (no outcome).
            const processed = verifier.process(ancestry);
            const outcome: anyerror!?Prepared = if (processed) |_| null else |err| err;
            work.outcome = outcome;
            handler.post(work);
        }

        fn post(self: *Self, work: *Work) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Proof: `spawn` reserved a slot for every live work, and each posts once per phase.
            self.done.appendAssumeCapacity(work);
            self.condition.signal(self.io);
        }

        /// Takes the next finished work, waiting for one when `wait` is set.
        fn take(self: *Self, wait: bool) Io.Cancelable!?*Work {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (self.done.items.len == 0) {
                if (!wait) return null;
                try self.condition.wait(self.io, &self.mutex);
            }
            return self.done.orderedRemove(0);
        }

        /// Waits until some request's phase has ended, without handling it (the actor then calls
        /// `complete_ready`). With no live request it waits until cancelled. At most one task
        /// waits at a time (the condition counts signals).
        pub fn wait_ready(self: *Self) Io.Cancelable!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Each pass waits for one post.
            while (self.done.items.len == 0) try self.condition.wait(self.io, &self.mutex);
            assert(self.done.items.len > 0);
        }

        /// Handles every request whose phase already ended.
        pub fn complete_ready(self: *Self) void {
            // Each pass handles one posted work; posts are bounded by the live works.
            while (self.take(false) catch unreachable) |work| self.complete(work); // No wait.
        }

        /// Waits for the next request's phase to end and handles it.
        pub fn complete_next(self: *Self) Io.Cancelable!void {
            assert(self.works.items.len > 0);
            const work = (try self.take(true)).?;
            self.complete(work);
        }

        /// Joins `work`'s finished task and takes its outcome.
        fn join(self: *Self, work: *Work) anyerror!?Prepared {
            if (work.future) |*future| future.await(self.io);
            work.future = null;
            const outcome = work.outcome.?;
            work.outcome = null;
            return outcome;
        }

        /// Handles a request whose phase ended: a cancelled request is dropped, a failed phase
        /// answers by its error, a finished step is classified under the admission, and an
        /// admitted request advances.
        fn complete(self: *Self, work: *Work) void {
            const outcome = self.join(work);
            const step: ?Step = switch (work.phase) {
                .executing => |executing| executing.step,
                else => null,
            };
            const held: ?Prepared = switch (work.phase) {
                .executing => |executing| executing.held,
                else => null,
            };
            const result = outcome catch |err| {
                if (held) |prepared| discard_prepared(self.gpa, prepared);
                const cancelled = work.request.is_cancelled();
                return self.release(work, if (cancelled) .abstain else answer_for(err));
            };
            var prepared = held orelse result.?;
            if (work.request.is_cancelled()) {
                prepared.deinit(self.gpa);
                return self.release(work, .abstain);
            }
            if (step) |*finished| switch (self.admission.disposition(finished)) {
                .join => if (self.admission == .pruning) {
                    work.phase = .{ .ready = prepared };
                    return;
                },
                .reject => {
                    prepared.deinit(self.gpa);
                    return self.release(work, .reject);
                },
                .retain => if (self.admission == .finalizing) {
                    self.admission.finalizing.completed(self.gpa, finished) catch {
                        prepared.deinit(self.gpa);
                        return self.release(work, .abstain);
                    };
                },
            };
            self.advance(work, prepared);
        }

        /// Releases what a stopped work's phase still holds (shutdown only).
        fn discard_phase(gpa: Allocator, work: *Work) void {
            if (work.outcome) |outcome| {
                if (outcome) |result| {
                    if (result) |prepared| discard_prepared(gpa, prepared);
                } else |_| {}
            }
            work.outcome = null;
            switch (work.phase) {
                .executing => |executing| discard_prepared(gpa, executing.held),
                else => {},
            }
            work.phase = .{ .acquiring = .{ .paused = true } };
        }

        fn discard_prepared(gpa: Allocator, prepared: Prepared) void {
            var owned = prepared;
            owned.deinit(gpa);
        }

        /// Starts the request's next step (taking `prepared`), or answers it once none is left.
        /// A next step the admission does not retain rejects the request.
        fn advance(self: *Self, work: *Work, prepared: Prepared) void {
            var owned = prepared;
            if (work.request.is_cancelled()) {
                owned.deinit(self.gpa);
                return self.release(work, .abstain);
            }
            const next = self.verifier.next(&self.provider, &owned) catch {
                owned.deinit(self.gpa);
                return self.release(work, .abstain);
            };
            if (next) |step| {
                var ancestry = step.ancestry;
                if (self.admission.disposition(&step.step) != .retain) {
                    ancestry.deinit();
                    owned.deinit(self.gpa);
                    return self.release(work, .reject);
                }
                work.phase = .{ .executing = .{ .step = step.step, .held = owned } };
                work.input = ancestry;
                return self.spawn(work, execute_task);
            }
            self.finish(work, owned);
        }

        /// Answers a request with no step left: a verification accepts, and a recovered
        /// proposal queues its build with the ancestry it acquired.
        fn finish(self: *Self, work: *Work, prepared: Prepared) void {
            var owned = prepared;
            const ancestry = owned.finish(self.gpa);
            switch (work.request) {
                .verify => {
                    var stale = ancestry;
                    stale.deinit();
                    return self.release(work, .accept);
                },
                .recover => |*recover| {
                    recover.ancestry.deinit();
                    recover.ancestry = ancestry;
                    self.builds.append(self.gpa, recover.*) catch
                        return self.release(work, .abstain);
                    work.request = undefined;
                    self.unlink(work);
                },
            }
        }

        /// Answers `work`'s request, releases its phase state, and frees it.
        fn release(self: *Self, work: *Work, answer: Answer) void {
            assert(work.future == null);
            work.request.respond(answer);
            switch (work.phase) {
                .ready => |*prepared| prepared.deinit(self.gpa),
                .executing => {}, // `complete` took the held state.
                .acquiring => {},
            }
            self.unlink(work);
        }

        fn unlink(self: *Self, work: *Work) void {
            if (work.input) |*input| input.deinit();
            if (comptime @hasDecl(Provider, "deinit")) work.provider.deinit();
            for (self.works.items, 0..) |live, index| {
                if (live != work) continue;
                _ = self.works.swapRemove(index);
                break;
            }
            self.destroy(work);
        }

        fn destroy(self: *Self, work: *Work) void {
            self.gpa.destroy(work);
        }

        /// Pauses every acquisition and waits for each running step the next maintenance does
        /// not retain. `boundary` (taken) is the block about to be finalized, or null for
        /// pruning, which retains nothing.
        pub fn pause(self: *Self, boundary: ?Boundary) Io.Cancelable!void {
            assert(self.admission == .open);
            self.admission = if (boundary) |value| .{ .finalizing = value } else .pruning;
            var pending: usize = 0;
            for (self.works.items) |work| switch (work.phase) {
                .ready => {},
                .acquiring => |*acquiring| if (!acquiring.paused) self.park(work),
                .executing => |*executing| {
                    pending += @intFromBool(self.admission.disposition(&executing.step) != .retain);
                },
            };
            // Each counted completion releases one step. A step starts only once its parent is
            // cached, so a retained step's completion never makes a counted step retained.
            while (pending > 0) {
                const work = (try self.take(true)).?;
                const selected = switch (work.phase) {
                    .executing => |*executing| blk: {
                        break :blk self.admission.disposition(&executing.step) != .retain;
                    },
                    else => false,
                };
                self.complete(work);
                pending -= @intFromBool(selected);
            }
        }

        /// Stops `work`'s acquisition and drops what it acquired: maintenance changes the
        /// branch it walked toward, so `resume` starts it over.
        fn park(self: *Self, work: *Work) void {
            if (work.future) |*future| future.cancel(self.io);
            work.future = null;
            {
                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                for (self.done.items, 0..) |posted, index| {
                    if (posted != work) continue;
                    _ = self.done.orderedRemove(index);
                    break;
                }
            }
            if (work.outcome) |outcome| {
                if (outcome) |result| {
                    if (result) |prepared| discard_prepared(self.gpa, prepared);
                } else |_| {}
            }
            work.outcome = null;
            work.phase = .{ .acquiring = .{ .paused = true } };
        }

        /// Reopens admission after maintenance: parked requests advance, and paused
        /// acquisitions start over unless their callers left.
        pub fn @"resume"(self: *Self) void {
            assert(self.admission != .open);
            if (self.admission == .finalizing) self.admission.finalizing.deinit(self.gpa);
            self.admission = .open;
            // Walk backwards: a resumed work only removes itself (a swap brings in a work
            // already visited) or stays.
            var index = self.works.items.len;
            while (index > 0) : (index -= 1) {
                if (index - 1 >= self.works.items.len) continue;
                self.resume_work(self.works.items[index - 1]);
            }
        }

        fn resume_work(self: *Self, work: *Work) void {
            switch (work.phase) {
                .ready => |prepared| {
                    work.phase = .{ .acquiring = .{ .paused = false } };
                    self.advance(work, prepared);
                },
                .acquiring => |acquiring| {
                    if (!acquiring.paused) return;
                    if (work.request.is_cancelled()) return self.release(work, .abstain);
                    work.phase = .{ .acquiring = .{ .paused = false } };
                    self.start_acquisition(work);
                },
                .executing => {},
            }
        }
    };
}
