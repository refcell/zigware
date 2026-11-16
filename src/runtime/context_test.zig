//! Tests of `Context` (commonware `runtime/src/lib.rs` tests that go through the context), on
//! the deterministic and the production runtime.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const deterministic = @import("deterministic.zig");
const context = @import("context.zig");
const telemetry = @import("telemetry/mod.zig");
const Counter = telemetry.metrics.raw.Counter;

const production = @import("production/runner.zig");

const Task = context.Handle(anyerror!void);

/// Runs the suite's case `name` on the deterministic and the production runner, as commonware
/// runs these tests on each runtime.
fn run(comptime name: []const u8) !void {
    {
        var runner = try deterministic.Runner.init(testing.allocator, .{});
        defer runner.deinit();
        try (try runner.start_context(@field(Suite(deterministic.Context), name), .{}));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [128]u8 = undefined;
    const directory = std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path}) catch
        unreachable; // The buffer fits the fixed-length temporary path.
    var runner: production.Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = directory });
    defer runner.deinit();
    try (try runner.start_context(@field(Suite(production.Context), name), .{}));
}

test "clock sleep" {
    try run("clock sleep");
}

test "clock sleep until" {
    try run("clock sleep until");
}

test "clock sleep until far future" {
    try run("clock sleep until far future");
}

test "clock timeout" {
    try run("clock timeout");
}

test "root finishes" {
    try run("root finishes");
}

test "spawn after abort" {
    try run("spawn after abort");
}

test "spawn abort" {
    try run("spawn abort");
}

test "spawn" {
    try run("spawn");
}

test "spawn abort on parent abort" {
    try run("spawn abort on parent abort");
}

test "spawn abort on parent completion" {
    try run("spawn abort on parent completion");
}

test "spawn cascading abort" {
    try run("spawn cascading abort");
}

test "child survives sibling completion" {
    try run("child survives sibling completion");
}

test "spawn clone chain" {
    try run("spawn clone chain");
}

test "spawn sparse clone chain" {
    try run("spawn sparse clone chain");
}

test "detached tasks keep running and are reaped" {
    try run("detached tasks keep running and are reaped");
}

test "shutdown" {
    try run("shutdown");
}

test "shutdown multiple signals" {
    try run("shutdown multiple signals");
}

test "shutdown timeout" {
    try run("shutdown timeout");
}

test "shutdown multiple stop calls" {
    try run("shutdown multiple stop calls");
}

test "unfulfilled shutdown" {
    try run("unfulfilled shutdown");
}

test "metrics" {
    try run("metrics");
}

test "storage operations (test_storage_operations)" {
    try run("storage operations");
}

test "blob read write (test_blob_read_write)" {
    try run("blob read write");
}

test "blob resize (test_blob_resize)" {
    try run("blob resize");
}

test "many partition read write (test_many_partition_read_write)" {
    try run("many partition read write");
}

test "blob read past length (test_blob_read_past_length)" {
    try run("blob read past length");
}

test "duplicate open returns error (test_duplicate_open_returns_error)" {
    try run("duplicate open returns error");
}

test "register and encode" {
    try run("register and encode");
}

test "count running tasks (test_count_running_tasks)" {
    try run("count running tasks");
}

test "task metrics ignore attributes (test_metrics_spawn_attribute_cardinality)" {
    try run("task metrics ignore attributes");
}

test "tasks_running drops after completion (tasks_running_decreased_after_completion)" {
    try run("tasks_running drops after completion");
}

test "tasks_running holds after detach (tasks_running_unchanged_when_handle_dropped)" {
    try run("tasks_running holds after detach");
}

test "tasks_running drops on abort (tasks_running_decreased_immediately_on_abort_via_handle)" {
    try run("tasks_running drops on abort");
}

/// A detached parent whose child needs 100 ms of cleanup once canceled: while the parent's
/// own abort awaits that cleanup, the parent has returned but not reported `ended`.
fn Draining(comptime Context: type) type {
    return struct {
        var cleaned: std.atomic.Value(bool) = .init(false);

        fn child(ctx: Context) anyerror!void {
            var never: Io.Event = .unset;
            never.wait(ctx.io()) catch |err| switch (err) {
                error.Canceled => {},
            };
            // A cancel at the end of the run would cut this short.
            ctx.sleep(.fromMilliseconds(100)) catch return;
            cleaned.store(true, .release);
        }

        fn parent(ctx: Context, started: *Io.Event) anyerror!void {
            const handle = try ctx.child("cleanup").spawn(child, .{});
            handle.detach();
            started.set(ctx.io());
        }

        fn body(ctx: Context) anyerror!void {
            cleaned.store(false, .release);
            var started: Io.Event = .unset;
            const handle = try ctx.child("parent").spawn(parent, .{&started});
            handle.detach();
            try started.wait(ctx.io());
        }
    };
}

test "a run ends only after every task has ended" {
    {
        var runner = try deterministic.Runner.init(testing.allocator, .{});
        defer runner.deinit();
        const Case = Draining(deterministic.Context);
        try (try runner.start_context(Case.body, .{}));
        try testing.expect(Case.cleaned.load(.acquire));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [128]u8 = undefined;
    const directory = std.fmt.bufPrint(&buffer, ".zig-cache/tmp/{s}/runner", .{tmp.sub_path}) catch
        unreachable; // The buffer fits the fixed-length temporary path.
    var runner: production.Runner = undefined;
    try runner.init(testing.allocator, .{ .storage_directory = directory });
    defer runner.deinit();
    const Case = Draining(production.Context);
    try (try runner.start_context(Case.body, .{}));
    try testing.expect(Case.cleaned.load(.acquire));
}

fn Suite(comptime Context: type) type {
    return struct {
        /// A task that waits until it is aborted (commonware `pending()`).
        fn pending(ctx: Context) anyerror!void {
            var never: Io.Event = .unset;
            try never.wait(ctx.io());
            return error.Unreachable;
        }

        fn nothing(ctx: Context) anyerror!void {
            _ = ctx;
        }

        fn ms(milliseconds: i64) Io.Duration {
            return .fromMilliseconds(milliseconds);
        }

        pub const @"clock sleep" = struct {
            fn body(ctx: Context) !void {
                const start = ctx.current();
                try ctx.sleep(ms(10));
                try testing.expect(start.durationTo(ctx.current()).toMilliseconds() >= 10);
            }
        }.body;

        pub const @"clock sleep until" = struct {
            fn body(ctx: Context) !void {
                const now = ctx.current();
                try ctx.sleep_until(now.addDuration(ms(100)));
                try testing.expect(now.durationTo(ctx.current()).toMilliseconds() >= 100);
            }
        }.body;

        pub const @"clock sleep until far future" = struct {
            fn body(ctx: Context) !void {
                const limit: Io.Timestamp = .fromNanoseconds(std.math.maxInt(i96));
                const result = ctx.timeout(ms(1), Context.sleep_until, .{ &ctx, limit });
                try testing.expectError(error.Timeout, result);
            }
        }.body;

        pub const @"clock timeout" = struct {
            fn success() []const u8 {
                return "success";
            }

            fn never(io: Io) Io.Cancelable!void {
                var event: Io.Event = .unset;
                try event.wait(io);
            }

            fn body(ctx: Context) !void {
                // The function returns before the timeout.
                try testing.expectEqualStrings("success", try ctx.timeout(ms(100), success, .{}));
                // The function outlasts the timeout.
                try testing.expectError(error.Timeout, ctx.timeout(ms(50), never, .{ctx.io()}));
                // A sleep shorter than the timeout completes.
                try (try ctx.timeout(ms(100), Context.sleep, .{ &ctx, ms(50) }));
            }
        }.body;

        pub const @"root finishes" = struct {
            fn spin(ctx: Context) anyerror!void {
                for (0..1_000_000) |_| try ctx.sleep(ms(1));
            }

            fn body(ctx: Context) !void {
                const handle = try ctx.spawn(spin, .{});
                handle.detach();
            }
        }.body;

        pub const @"spawn after abort" = struct {
            fn body(ctx: Context) !void {
                const child = ctx.child("child");
                const parent = try ctx.spawn(pending, .{});
                try testing.expectError(error.Closed, parent.abort());
                const handle = try child.spawn(pending, .{});
                try testing.expectError(error.Closed, handle.join());
            }
        }.body;

        pub const @"spawn abort" = struct {
            fn spin(ctx: Context) anyerror!void {
                for (0..1_000_000) |_| try ctx.sleep(ms(1));
            }

            fn body(ctx: Context) !void {
                const handle = try ctx.spawn(spin, .{});
                try testing.expectError(error.Closed, handle.abort());
            }
        }.body;

        const Family = struct {
            child: ?Task = null,
            initialized: Io.Event = .unset,
            complete: Io.Event = .unset,

            /// Spawns `child_function` from its own context, then waits for `complete`.
            fn parent(
                ctx: Context,
                family: *Family,
                comptime child_function: fn (Context) anyerror!void,
            ) anyerror!void {
                const io = ctx.io();
                family.child = try ctx.spawn(child_function, .{});
                family.initialized.set(io);
                try family.complete.wait(io);
            }
        };

        pub const spawn = struct {
            fn body(ctx: Context) !void {
                var family: Family = .{};
                const parent = try ctx.spawn(Family.parent, .{ &family, nothing });
                try family.initialized.wait(ctx.io());
                try (try family.child.?.join());
                family.complete.set(ctx.io());
                try (try parent.join());
            }
        }.body;

        pub const @"spawn abort on parent abort" = struct {
            fn body(ctx: Context) !void {
                var family: Family = .{};
                const parent = try ctx.spawn(Family.parent, .{ &family, pending });
                try family.initialized.wait(ctx.io());
                try testing.expectError(error.Closed, parent.abort());
                try testing.expectError(error.Closed, family.child.?.join());
            }
        }.body;

        pub const @"spawn abort on parent completion" = struct {
            fn body(ctx: Context) !void {
                var family: Family = .{};
                const parent = try ctx.spawn(Family.parent, .{ &family, pending });
                family.complete.set(ctx.io());
                try (try parent.join());
                try testing.expectError(error.Closed, family.child.?.join());
            }
        }.body;

        const Cascade = struct {
            children: [3]Context,
            grandchildren: [3][2]Context,
            /// Children at 0..3, then each child's grandchildren (tasks fill their own slots).
            handles: [9]?Task = @splat(null),
            initialized_buffer: [9]u8 = undefined,
            initialized: Io.Queue(u8),

            fn push(cascade: *Cascade, io: Io, slot: usize, handle: Task) !void {
                std.debug.assert(cascade.handles[slot] == null);
                cascade.handles[slot] = handle;
                try cascade.initialized.putOne(io, 0);
            }

            fn root(ctx: Context, cascade: *Cascade) anyerror!void {
                for (cascade.children, 0..) |child, index| {
                    const handle = try child.spawn(child_task, .{ cascade, index });
                    try cascade.push(ctx.io(), index, handle);
                }
                return pending(ctx);
            }

            fn child_task(ctx: Context, cascade: *Cascade, index: usize) anyerror!void {
                for (cascade.grandchildren[index], 0..) |grandchild, offset| {
                    const handle = try grandchild.spawn(pending, .{});
                    try cascade.push(ctx.io(), 3 + 2 * index + offset, handle);
                }
                return pending(ctx);
            }
        };

        pub const @"spawn cascading abort" = struct {
            fn body(ctx: Context) !void {
                //          root
                //     /     |     \
                //   c0      c1      c2
                //  /  \    /  \    /  \
                // g0  g1  g2  g3  g4  g5
                var cascade: Cascade = .{
                    .children = undefined,
                    .grandchildren = undefined,
                    .initialized = undefined,
                };
                cascade.initialized = .init(&cascade.initialized_buffer);
                const labels = [3][]const u8{ "c0", "c1", "c2" };
                for (labels, 0..) |label, index| {
                    cascade.children[index] = ctx.child(label);
                    cascade.grandchildren[index][0] = cascade.children[index].child("g0");
                    cascade.grandchildren[index][1] = cascade.children[index].child("g1");
                }
                const root_task = try ctx.spawn(Cascade.root, .{&cascade});
                for (0..9) |_| _ = try cascade.initialized.getOne(ctx.io());
                try testing.expectError(error.Closed, root_task.abort());
                for (cascade.handles) |handle| {
                    try testing.expectError(error.Closed, handle.?.join());
                }
            }
        }.body;

        const Siblings = struct {
            child: ?Task = null,
            sibling: ?Task = null,
            child_started: Io.Event = .unset,
            child_complete: Io.Event = .unset,
            sibling_started: Io.Event = .unset,
            sibling_complete: Io.Event = .unset,
            parent_complete: Io.Event = .unset,
            /// Set once the parent stored both handles.
            handles_ready: Io.Event = .unset,

            fn task(ctx: Context, started: *Io.Event, complete: *Io.Event) anyerror!void {
                started.set(ctx.io());
                try complete.wait(ctx.io());
            }

            fn parent(ctx: Context, siblings: *Siblings) anyerror!void {
                siblings.child = try ctx.child("child").spawn(
                    task,
                    .{ &siblings.child_started, &siblings.child_complete },
                );
                siblings.sibling = try ctx.child("sibling").spawn(
                    task,
                    .{ &siblings.sibling_started, &siblings.sibling_complete },
                );
                siblings.handles_ready.set(ctx.io());
                try siblings.parent_complete.wait(ctx.io());
            }
        };

        pub const @"child survives sibling completion" = struct {
            fn body(ctx: Context) !void {
                const io = ctx.io();
                var siblings: Siblings = .{};
                const parent = try ctx.spawn(Siblings.parent, .{&siblings});
                try siblings.child_started.wait(io);
                try siblings.sibling_started.wait(io);
                try siblings.handles_ready.wait(io);
                // The sibling finishes; the child keeps running.
                siblings.sibling_complete.set(io);
                try (try siblings.sibling.?.join());
                siblings.child_complete.set(io);
                try (try siblings.child.?.join());
                siblings.parent_complete.set(io);
                try (try parent.join());
            }
        }.body;

        const Chain = struct {
            handles: [2]?Task = .{ null, null },
            started: [3]Io.Event = @splat(.unset),

            fn level(ctx: Context, chain: *Chain, depth: usize) anyerror!void {
                if (depth < 2) {
                    const labels = [2][]const u8{ "child", "grandchild" };
                    const handle = try ctx.child(labels[depth]).spawn(level, .{ chain, depth + 1 });
                    chain.handles[depth] = handle;
                }
                chain.started[depth].set(ctx.io());
                return pending(ctx);
            }

            fn sparse(ctx: Context, chain: *Chain) anyerror!void {
                const leaf = ctx.child("clone1").child("clone2").child("clone3");
                chain.handles[0] = try leaf.spawn(level, .{ chain, 2 });
                chain.started[0].set(ctx.io());
                return pending(ctx);
            }
        };

        pub const @"spawn clone chain" = struct {
            fn body(ctx: Context) !void {
                var chain: Chain = .{};
                const parent = try ctx.child("parent").spawn(Chain.level, .{ &chain, 0 });
                for (&chain.started) |*started| try started.wait(ctx.io());
                try testing.expectError(error.Closed, parent.abort());
                try testing.expectError(error.Closed, chain.handles[0].?.join());
                try testing.expectError(error.Closed, chain.handles[1].?.join());
            }
        }.body;

        pub const @"spawn sparse clone chain" = struct {
            fn body(ctx: Context) !void {
                var chain: Chain = .{};
                const parent = try ctx.child("parent").spawn(Chain.sparse, .{&chain});
                try chain.started[0].wait(ctx.io());
                try chain.started[2].wait(ctx.io());
                try testing.expectError(error.Closed, parent.abort());
                try testing.expectError(error.Closed, chain.handles[0].?.join());
            }
        }.body;

        pub const @"detached tasks keep running and are reaped" = struct {
            fn body(ctx: Context) !void {
                var done: Io.Event = .unset;
                const handle = try ctx.child("detached").spawn(Siblings.task, .{ &done, &done });
                handle.detach();
                try done.wait(ctx.io());
                // A later spawn reaps the finished, detached task.
                try (try (try ctx.child("next").spawn(nothing, .{})).join());
            }
        }.body;

        fn await_stop(ctx: Context, expected: i32) anyerror!void {
            var signal = ctx.stopped();
            defer signal.deinit();
            try testing.expectEqual(expected, try signal.wait());
        }

        pub const shutdown = struct {
            fn body(ctx: Context) !void {
                const kill = 9;
                const before = try ctx.child("before").spawn(await_stop, .{kill});
                try ctx.child("stop").stop(kill, null);
                // `stopped` after `stop` resolves at once.
                const after = try ctx.child("after").spawn(await_stop, .{kill});
                try (try before.join());
                try (try after.join());
            }
        }.body;

        const Cleanup = struct {
            counter: std.atomic.Value(u32) = .init(0),
            started_buffer: [3]u8 = undefined,
            started: Io.Queue(u8) = undefined,

            fn task(ctx: Context, cleanup: *Cleanup, duration: Io.Duration) anyerror!void {
                var signal = ctx.stopped();
                defer signal.deinit();
                try cleanup.started.putOne(ctx.io(), 0);
                try testing.expectEqual(@as(i32, 42), try signal.wait());
                try ctx.sleep(duration);
                _ = cleanup.counter.fetchAdd(1, .monotonic);
            }
        };

        pub const @"shutdown multiple signals" = struct {
            fn body(ctx: Context) !void {
                var cleanup: Cleanup = .{};
                cleanup.started = .init(&cleanup.started_buffer);
                var tasks: [3]Task = undefined;
                for (&tasks, 1..) |*task, index| {
                    const duration = ms(10 * @as(i64, @intCast(index)));
                    task.* = try ctx.child("cleanup").spawn(Cleanup.task, .{ &cleanup, duration });
                }
                for (0..3) |_| _ = try cleanup.started.getOne(ctx.io());
                try ctx.stop(42, null);
                try testing.expectEqual(@as(u32, 3), cleanup.counter.load(.monotonic));
                for (tasks) |task| try (try task.join());
            }
        }.body;

        pub const @"shutdown timeout" = struct {
            fn hold(ctx: Context, started: *Io.Event) anyerror!void {
                var signal = ctx.stopped();
                defer signal.deinit();
                started.set(ctx.io());
                return pending(ctx);
            }

            fn body(ctx: Context) !void {
                var started: Io.Event = .unset;
                const handle = try ctx.child("signal").spawn(hold, .{&started});
                handle.detach();
                try started.wait(ctx.io());
                try testing.expectError(error.Timeout, ctx.stop(42, ms(100)));
            }
        }.body;

        pub const @"shutdown multiple stop calls" = struct {
            fn stop(ctx: Context, value: i32) anyerror!void {
                try ctx.stop(value, null);
            }

            fn body(ctx: Context) !void {
                var cleanup: Cleanup = .{};
                cleanup.started = .init(&cleanup.started_buffer);
                const blocking = ctx.child("blocking_task");
                const task = try blocking.spawn(Cleanup.task, .{ &cleanup, ms(50) });
                _ = try cleanup.started.getOne(ctx.io());
                // The second stop's value is ignored; both wait for the task's cleanup.
                const stop1 = try ctx.child("stop").spawn(stop, .{42});
                try await_stop(ctx, 42);
                const stop2 = try ctx.child("stop").spawn(stop, .{43});
                try testing.expectEqual(@as(u32, 0), cleanup.counter.load(.monotonic));
                try (try stop1.join());
                try (try stop2.join());
                try await_stop(ctx, 42);
                try (try task.join());
                try testing.expectEqual(@as(u32, 1), cleanup.counter.load(.monotonic));
                // A stop after completion returns at once.
                try ctx.stop(43, null);
            }
        }.body;

        pub const @"unfulfilled shutdown" = struct {
            fn body(ctx: Context) !void {
                const handle = try ctx.child("before").spawn(await_stop, .{42});
                handle.detach();
                try ctx.sleep(ms(1));
            }
        }.body;

        fn expect_contains(text: []const u8, needle: []const u8) !void {
            if (std.mem.indexOf(u8, text, needle) == null) {
                std.debug.print("missing {s} in:\n{s}\n", .{ needle, text });
                return error.TestExpectedEqual;
            }
        }

        pub const metrics = struct {
            fn body(ctx: Context) !void {
                try testing.expectEqualStrings("", ctx.scope.prefix());
                var counter = try ctx.register("test", "test", Counter{});
                defer counter.deinit();
                counter.metric().inc();
                const text = try ctx.encode(testing.allocator);
                defer testing.allocator.free(text);
                try expect_contains(text, "test_total 1");

                const nested = ctx.child("nested");
                var nested_counter = try nested.register("test", "test", Counter{});
                defer nested_counter.deinit();
                nested_counter.metric().inc();
                const nested_text = try nested.encode(testing.allocator);
                defer testing.allocator.free(nested_text);
                try expect_contains(nested_text, "nested_test_total 1");
                try expect_contains(nested_text, "test_total 1");
            }
        }.body;

        /// commonware `count_running_tasks`: running tasks whose label starts with `prefix`.
        fn running(ctx: Context, prefix: []const u8) !u64 {
            const text = try ctx.encode(testing.allocator);
            defer testing.allocator.free(text);
            return telemetry.metrics.task.count_running_tasks(text, prefix);
        }

        pub const @"count running tasks" = struct {
            fn body(ctx: Context) !void {
                try testing.expectEqual(@as(u64, 0), try running(ctx, "worker"));
                const first = try ctx.child("worker").spawn(pending, .{});
                try testing.expectEqual(@as(u64, 1), try running(ctx, "worker"));
                try testing.expectEqual(@as(u64, 0), try running(ctx, "other"));
                // A nested label shares the prefix.
                const nested = try ctx.child("worker").child("child").spawn(pending, .{});
                try testing.expectEqual(@as(u64, 2), try running(ctx, "worker"));
                try testing.expectError(error.Closed, first.abort());
                try testing.expectEqual(@as(u64, 1), try running(ctx, "worker"));
                try testing.expectError(error.Closed, nested.abort());
                try testing.expectEqual(@as(u64, 0), try running(ctx, "worker"));
            }
        }.body;

        fn round_value(ctx: Context, round: u64) anyerror!u64 {
            _ = ctx;
            return round;
        }

        pub const @"task metrics ignore attributes" = struct {
            const rounds = 128;

            fn body(ctx: Context) !void {
                var handles: [rounds]context.Handle(anyerror!u64) = undefined;
                for (&handles, 0..) |*handle, round| {
                    const scoped = ctx.child("deferred_verify").with_attribute("round", round);
                    handle.* = try scoped.spawn(round_value, .{@as(u64, round)});
                }
                for (handles, 0..) |handle, round| {
                    try testing.expectEqual(@as(u64, round), try (try handle.join()));
                }
                try testing.expectEqual(@as(u64, 0), try running(ctx, "deferred_verify"));
                const text = try ctx.encode(testing.allocator);
                defer testing.allocator.free(text);
                // One series each (spawned and running), however many attribute values the
                // tasks were spawned with.
                const label = "{name=\"deferred_verify\",kind=\"Task\",execution=\"Shared\"}";
                const spawned_key = "runtime_tasks_spawned_total{name=\"deferred_verify\"";
                const running_key = "runtime_tasks_running{name=\"deferred_verify\"";
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, spawned_key));
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, running_key));
                try expect_contains(text, "runtime_tasks_spawned_total" ++ label ++ " 128\n");
                try expect_contains(text, "runtime_tasks_running" ++ label ++ " 0\n");
            }
        }.body;

        fn finished(ctx: Context) anyerror![]const u8 {
            _ = ctx;
            return "done";
        }

        /// `runtime_tasks_running` for exactly `name`.
        fn running_exactly(ctx: Context, comptime name: []const u8) !?i64 {
            const text = try ctx.encode(testing.allocator);
            defer testing.allocator.free(text);
            const prefix = "runtime_tasks_running{name=\"" ++ name ++ "\",";
            const at = std.mem.indexOf(u8, text, prefix) orelse return null;
            const line_end = std.mem.indexOfScalarPos(u8, text, at, '\n').?;
            const space = std.mem.lastIndexOfScalar(u8, text[at..line_end], ' ').?;
            return try std.fmt.parseInt(i64, text[at + space + 1 .. line_end], 10);
        }

        pub const @"tasks_running drops after completion" = struct {
            fn body(ctx: Context) !void {
                const label = "tasks_running_after_completion";
                const handle = try ctx.child(label).spawn(finished, .{});
                try testing.expectEqualStrings("done", try (try handle.join()));
                try testing.expectEqual(@as(?i64, 0), try running_exactly(ctx, label));
            }
        }.body;

        pub const @"tasks_running holds after detach" = struct {
            fn body(ctx: Context) !void {
                const label = "tasks_running_unchanged";
                const handle = try ctx.child(label).spawn(pending, .{});
                try testing.expectEqual(@as(?i64, 1), try running_exactly(ctx, label));
                handle.detach();
                try testing.expectEqual(@as(?i64, 1), try running_exactly(ctx, label));
            }
        }.body;

        pub const @"tasks_running drops on abort" = struct {
            fn body(ctx: Context) !void {
                const label = "tasks_running_abort_via_handle";
                const handle = try ctx.child(label).spawn(pending, .{});
                try testing.expectEqual(@as(?i64, 1), try running_exactly(ctx, label));
                try testing.expectError(error.Closed, handle.abort());
                try testing.expectEqual(@as(?i64, 0), try running_exactly(ctx, label));
            }
        }.body;

        fn expect_read(blob: anytype, offset: u64, expected: []const u8) !void {
            var buffer: [64]u8 = undefined;
            const out = buffer[0..expected.len];
            try blob.read_at(offset, out);
            try testing.expectEqualSlices(u8, expected, out);
        }

        pub const @"storage operations" = struct {
            fn body(ctx: Context) !void {
                const storage = ctx.storage;
                const opened = try storage.open("test_partition", "test_blob");
                try testing.expectEqual(@as(u64, 0), opened.len);
                const data = "Hello, Storage!";
                try opened.blob.write_at(0, data, .{});
                try opened.blob.sync();
                try expect_read(opened.blob, 0, data);
                var names = try storage.scan(testing.allocator, "test_partition");
                try testing.expect(names.contains("test_blob"));
                names.deinit(testing.allocator);
                opened.blob.close();
                const reopened = try storage.open("test_partition", "test_blob");
                try testing.expectEqual(@as(u64, data.len), reopened.len);
                try expect_read(reopened.blob, 7, "Storage");
                try reopened.blob.sync();
                reopened.blob.close();
                try storage.remove("test_partition", "test_blob");
                names = try storage.scan(testing.allocator, "test_partition");
                try testing.expect(!names.contains("test_blob"));
                names.deinit(testing.allocator);
                try storage.remove("test_partition", null);
                const missing = storage.scan(testing.allocator, "test_partition");
                try testing.expectError(error.PartitionMissing, missing);
            }
        }.body;

        pub const @"blob read write" = struct {
            fn body(ctx: Context) !void {
                const blob = (try ctx.storage.open("test_partition", "test_blob_rw")).blob;
                defer blob.close();
                try blob.write_at(0, "Hello", .{});
                try blob.write_at(5, "World", .{});
                try expect_read(blob, 0, "HelloWorld");
                var buffer: [10]u8 = undefined;
                try testing.expectError(error.BlobInsufficientLength, blob.read_at(10, &buffer));
                try blob.write_at(5, "Store", .{});
                try expect_read(blob, 0, "HelloStore");
                try testing.expectError(error.BlobInsufficientLength, blob.read_at(10, &buffer));
            }
        }.body;

        pub const @"blob resize" = struct {
            fn reopen(ctx: Context, expected_len: u64) !@import("storage.zig").Blob {
                const opened = try ctx.storage.open("test_partition_resize", "test_blob_resize");
                try testing.expectEqual(expected_len, opened.len);
                return opened.blob;
            }

            fn body(ctx: Context) !void {
                const data = "some data";
                var blob = try reopen(ctx, 0);
                try blob.write_at(0, data, .{});
                try blob.sync();
                blob.close();
                blob = try reopen(ctx, data.len);
                try blob.resize(data.len * 2);
                try blob.sync();
                blob.close();
                blob = try reopen(ctx, data.len * 2);
                try expect_read(blob, 0, data);
                const zeros: [data.len]u8 = @splat(0);
                try expect_read(blob, data.len, &zeros);
                try blob.resize(data.len);
                try blob.sync();
                blob.close();
                blob = try reopen(ctx, data.len);
                try expect_read(blob, 0, data);
                try blob.sync();
                blob.close();
            }
        }.body;

        pub const @"many partition read write" = struct {
            fn body(ctx: Context) !void {
                const partitions = [_][]const u8{ "partition1", "partition2", "partition3" };
                for (partitions, 0..) |partition, additional| {
                    const blob = (try ctx.storage.open(partition, "test_blob_rw")).blob;
                    defer blob.close();
                    try blob.write_at(0, "Hello", .{});
                    try blob.write_at(5 + additional, "World", .{});
                    try blob.sync();
                }
                for (partitions, 0..) |partition, additional| {
                    const opened = try ctx.storage.open(partition, "test_blob_rw");
                    defer opened.blob.close();
                    try testing.expectEqual(@as(u64, 10 + additional), opened.len);
                    try expect_read(opened.blob, 0, "Hello");
                    try expect_read(opened.blob, 5 + additional, "World");
                }
            }
        }.body;

        pub const @"blob read past length" = struct {
            fn body(ctx: Context) !void {
                const blob = (try ctx.storage.open("test_partition", "test_blob_rw")).blob;
                defer blob.close();
                var buffer: [20]u8 = undefined;
                const short = error.BlobInsufficientLength;
                try testing.expectError(short, blob.read_at(0, buffer[0..10]));
                try blob.write_at(0, "Hello, Storage!", .{});
                try testing.expectError(short, blob.read_at(0, &buffer));
            }
        }.body;

        pub const @"duplicate open returns error" = struct {
            fn body(ctx: Context) !void {
                const storage = ctx.storage;
                const partition = "duplicate_open";
                const first = (try storage.open(partition, "blob")).blob;
                try first.write_at(0, "old", .{});
                try testing.expectError(error.BlobAlreadyOpen, storage.open(partition, "blob"));
                const versioned = storage.open_versioned(partition, "blob", .only(0));
                try testing.expectError(error.BlobAlreadyOpen, versioned);
                try expect_read(first, 0, "old");
                try first.write_at(0, "new", .{});
                try first.sync();
                first.close();
                const old = try storage.open(partition, "blob");
                try testing.expectEqual(@as(u64, 3), old.len);
                try expect_read(old.blob, 0, "new");
                // A removed blob opens afresh while a handle to the old one is still open.
                try storage.remove(partition, "blob");
                const current = try storage.open(partition, "blob");
                try testing.expectEqual(@as(u64, 0), current.len);
                old.blob.close();
                try testing.expectError(error.BlobAlreadyOpen, storage.open(partition, "blob"));
                try current.blob.write_at(0, "replacement", .{});
                try current.blob.sync();
                current.blob.close();
                const reopened = try storage.open(partition, "blob");
                defer reopened.blob.close();
                try testing.expectEqual(@as(u64, 11), reopened.len);
                try expect_read(reopened.blob, 0, "replacement");
            }
        }.body;

        pub const @"register and encode" = struct {
            fn body(ctx: Context) !void {
                const engine = ctx.child("engine");
                var votes = try engine.register("votes", "vote count", Counter{});
                defer votes.deinit();
                votes.metric().inc();
                var root = try ctx.register("root", "root metric", Counter{});
                defer root.deinit();
                root.metric().inc();
                const text = try ctx.encode(testing.allocator);
                defer testing.allocator.free(text);
                try expect_contains(text, "engine_votes_total 1");
                try expect_contains(text, "root_total 1");
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# EOF"));
                try testing.expect(std.mem.endsWith(u8, text, "# EOF\n"));
            }
        }.body;
    };
}

test "register and encode are audited" {
    var digests: [2][8]u8 = undefined;
    for (&digests, 0..) |*digest, index| {
        var runner = try deterministic.Runner.init(testing.allocator, .{});
        defer runner.deinit();
        try (try runner.start_context(struct {
            fn body(ctx: deterministic.Context, attribute: u32) !void {
                const scoped = ctx.with_attribute("shard", attribute);
                var counter = try scoped.register("ops", "ops", Counter{});
                defer counter.deinit();
                const text = try ctx.encode(testing.allocator);
                testing.allocator.free(text);
            }
        }.body, .{@as(u32, @intCast(index))}));
        digest.* = runner.auditor.state();
    }
    // Attribute values feed the audit.
    try testing.expect(!std.mem.eql(u8, &digests[0], &digests[1]));
}

test "task polls count each task's resumes under its label (runtime_task_polls)" {
    const Body = struct {
        fn nap(io: Io) Io.Cancelable!void {
            try io.sleep(.fromMilliseconds(1), .awake);
        }

        fn worker(ctx: deterministic.Context) anyerror!void {
            for (0..3) |_| try ctx.sleep(.fromMilliseconds(1));
            // A plain fiber the task starts is part of the task.
            var inner = try ctx.io().concurrent(nap, .{ctx.io()});
            try inner.await(ctx.io());
        }

        fn body(ctx: deterministic.Context) !void {
            const handle = try ctx.child("worker").spawn(worker, .{});
            try (try handle.join());
        }
    };
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start_context(Body.body, .{}));
    const polls = runner.task_polls.?.metric();
    const label = telemetry.metrics.task.Label;
    // Start, three wakes, the inner fiber's start and wake, and the await's wake.
    const worker = polls.get(label.task("worker", .shared)).?.get();
    try testing.expect(worker >= 6);
    try testing.expect(polls.get(label.root()).?.get() >= 2);
    try testing.expectEqual(@as(usize, 2), polls.count());
    const text = try runner.metrics().encode(testing.allocator);
    defer testing.allocator.free(text);
    const root_series = "runtime_task_polls_total{name=\"\",kind=\"Root\",execution=\"Shared\"} ";
    try testing.expect(std.mem.indexOf(u8, text, root_series) != null);
}

test "task labels feed the audit" {
    var digests: [2][8]u8 = undefined;
    for (&digests, [_][]const u8{ "alpha", "bravo" }) |*digest, name| {
        var runner = try deterministic.Runner.init(testing.allocator, .{});
        defer runner.deinit();
        try (try runner.start_context(struct {
            fn nothing(ctx: deterministic.Context) anyerror!void {
                _ = ctx;
            }

            fn body(ctx: deterministic.Context, label: []const u8) !void {
                const handle = try ctx.child(label).spawn(nothing, .{});
                try (try handle.join());
            }
        }.body, .{name}));
        digest.* = runner.auditor.state();
    }
    try testing.expect(!std.mem.eql(u8, &digests[0], &digests[1]));
}
