//! Tests of `Context` (commonware `runtime/src/lib.rs` tests that go through the context), on
//! the deterministic runtime.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const deterministic = @import("deterministic.zig");
const context = @import("context.zig");
const metrics = @import("telemetry/mod.zig").metrics;

const Context = deterministic.Context;
const Task = context.Handle(anyerror!void);

fn run(comptime body: fn (Context) anyerror!void) !void {
    var runner = try deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try (try runner.start_context(body, .{}));
}

/// A task that waits until it is aborted (commonware `pending()`).
fn pending(ctx: Context) anyerror!void {
    var never: Io.Event = .unset;
    try never.wait(ctx.io());
    return error.Unreachable;
}

fn nothing(ctx: Context) anyerror!void {
    _ = ctx;
}

fn wait_event(ctx: Context, event: *Io.Event) anyerror!void {
    try event.wait(ctx.io());
}

fn ms(milliseconds: i64) Io.Duration {
    return .fromMilliseconds(milliseconds);
}

test "clock sleep" {
    try run(struct {
        fn body(ctx: Context) !void {
            const start = ctx.current();
            try ctx.sleep(ms(10));
            try testing.expect(start.durationTo(ctx.current()).toMilliseconds() >= 10);
        }
    }.body);
}

test "clock sleep until" {
    try run(struct {
        fn body(ctx: Context) !void {
            const now = ctx.current();
            try ctx.sleep_until(now.addDuration(ms(100)));
            try testing.expect(now.durationTo(ctx.current()).toMilliseconds() >= 100);
        }
    }.body);
}

test "clock sleep until far future" {
    try run(struct {
        fn body(ctx: Context) !void {
            const limit: Io.Timestamp = .fromNanoseconds(std.math.maxInt(i96));
            const result = ctx.timeout(ms(1), Context.sleep_until, .{ &ctx, limit });
            try testing.expectError(error.Timeout, result);
        }
    }.body);
}

test "clock timeout" {
    try run(struct {
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
    }.body);
}

test "root finishes" {
    try run(struct {
        fn spin(ctx: Context) anyerror!void {
            for (0..1_000_000) |_| try ctx.sleep(ms(1));
        }

        fn body(ctx: Context) !void {
            const handle = try ctx.spawn(spin, .{});
            handle.detach();
        }
    }.body);
}

test "spawn after abort" {
    try run(struct {
        fn body(ctx: Context) !void {
            const child = ctx.child("child");
            const parent = try ctx.spawn(pending, .{});
            try testing.expectError(error.Closed, parent.abort());
            const handle = try child.spawn(pending, .{});
            try testing.expectError(error.Closed, handle.join());
        }
    }.body);
}

test "spawn abort" {
    try run(struct {
        fn spin(ctx: Context) anyerror!void {
            for (0..1_000_000) |_| try ctx.sleep(ms(1));
        }

        fn body(ctx: Context) !void {
            const handle = try ctx.spawn(spin, .{});
            try testing.expectError(error.Closed, handle.abort());
        }
    }.body);
}

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

test "spawn" {
    try run(struct {
        fn body(ctx: Context) !void {
            var family: Family = .{};
            const parent = try ctx.spawn(Family.parent, .{ &family, nothing });
            try family.initialized.wait(ctx.io());
            try (try family.child.?.join());
            family.complete.set(ctx.io());
            try (try parent.join());
        }
    }.body);
}

test "spawn abort on parent abort" {
    try run(struct {
        fn body(ctx: Context) !void {
            var family: Family = .{};
            const parent = try ctx.spawn(Family.parent, .{ &family, pending });
            try family.initialized.wait(ctx.io());
            try testing.expectError(error.Closed, parent.abort());
            try testing.expectError(error.Closed, family.child.?.join());
        }
    }.body);
}

test "spawn abort on parent completion" {
    try run(struct {
        fn body(ctx: Context) !void {
            var family: Family = .{};
            const parent = try ctx.spawn(Family.parent, .{ &family, pending });
            family.complete.set(ctx.io());
            try (try parent.join());
            try testing.expectError(error.Closed, family.child.?.join());
        }
    }.body);
}

const Cascade = struct {
    children: [3]Context,
    grandchildren: [3][2]Context,
    handles: [9]Task = undefined,
    handle_count: u32 = 0,
    initialized_buffer: [9]u8 = undefined,
    initialized: Io.Queue(u8),

    fn push(cascade: *Cascade, io: Io, handle: Task) !void {
        std.debug.assert(cascade.handle_count < cascade.handles.len);
        cascade.handles[cascade.handle_count] = handle;
        cascade.handle_count += 1;
        try cascade.initialized.putOne(io, 0);
    }

    fn root(ctx: Context, cascade: *Cascade) anyerror!void {
        for (cascade.children, 0..) |child, index| {
            const handle = try child.spawn(child_task, .{ cascade, index });
            try cascade.push(ctx.io(), handle);
        }
        return pending(ctx);
    }

    fn child_task(ctx: Context, cascade: *Cascade, index: usize) anyerror!void {
        for (cascade.grandchildren[index]) |grandchild| {
            try cascade.push(ctx.io(), try grandchild.spawn(pending, .{}));
        }
        return pending(ctx);
    }
};

test "spawn cascading abort" {
    try run(struct {
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
            try testing.expectEqual(@as(u32, 9), cascade.handle_count);
            try testing.expectError(error.Closed, root_task.abort());
            for (cascade.handles) |handle| {
                try testing.expectError(error.Closed, handle.join());
            }
        }
    }.body);
}

const Siblings = struct {
    child: ?Task = null,
    sibling: ?Task = null,
    child_started: Io.Event = .unset,
    child_complete: Io.Event = .unset,
    sibling_started: Io.Event = .unset,
    sibling_complete: Io.Event = .unset,
    parent_complete: Io.Event = .unset,

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
        try siblings.parent_complete.wait(ctx.io());
    }
};

test "child survives sibling completion" {
    try run(struct {
        fn body(ctx: Context) !void {
            const io = ctx.io();
            var siblings: Siblings = .{};
            const parent = try ctx.spawn(Siblings.parent, .{&siblings});
            try siblings.child_started.wait(io);
            try siblings.sibling_started.wait(io);
            // The sibling finishes; the child keeps running.
            siblings.sibling_complete.set(io);
            try (try siblings.sibling.?.join());
            siblings.child_complete.set(io);
            try (try siblings.child.?.join());
            siblings.parent_complete.set(io);
            try (try parent.join());
        }
    }.body);
}

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
        return pending(ctx);
    }
};

test "spawn clone chain" {
    try run(struct {
        fn body(ctx: Context) !void {
            var chain: Chain = .{};
            const parent = try ctx.child("parent").spawn(Chain.level, .{ &chain, 0 });
            for (&chain.started) |*started| try started.wait(ctx.io());
            try testing.expectError(error.Closed, parent.abort());
            try testing.expectError(error.Closed, chain.handles[0].?.join());
            try testing.expectError(error.Closed, chain.handles[1].?.join());
        }
    }.body);
}

test "spawn sparse clone chain" {
    try run(struct {
        fn body(ctx: Context) !void {
            var chain: Chain = .{};
            const parent = try ctx.child("parent").spawn(Chain.sparse, .{&chain});
            try chain.started[2].wait(ctx.io());
            try testing.expectError(error.Closed, parent.abort());
            try testing.expectError(error.Closed, chain.handles[0].?.join());
        }
    }.body);
}

test "detached tasks keep running and are reaped" {
    try run(struct {
        fn body(ctx: Context) !void {
            var done: Io.Event = .unset;
            const handle = try ctx.child("detached").spawn(Siblings.task, .{ &done, &done });
            handle.detach();
            try done.wait(ctx.io());
            // A later spawn reaps the finished, detached task.
            try (try (try ctx.child("next").spawn(nothing, .{})).join());
        }
    }.body);
}

fn await_stop(ctx: Context, expected: i32) anyerror!void {
    var signal = ctx.stopped();
    defer signal.deinit();
    try testing.expectEqual(expected, try signal.wait());
}

test "shutdown" {
    try run(struct {
        fn body(ctx: Context) !void {
            const kill = 9;
            const before = try ctx.child("before").spawn(await_stop, .{kill});
            try ctx.child("stop").stop(kill, null);
            // `stopped` after `stop` resolves at once.
            const after = try ctx.child("after").spawn(await_stop, .{kill});
            try (try before.join());
            try (try after.join());
        }
    }.body);
}

const Cleanup = struct {
    counter: u32 = 0,
    started_buffer: [3]u8 = undefined,
    started: Io.Queue(u8) = undefined,

    fn task(ctx: Context, cleanup: *Cleanup, duration: Io.Duration) anyerror!void {
        var signal = ctx.stopped();
        defer signal.deinit();
        try cleanup.started.putOne(ctx.io(), 0);
        try testing.expectEqual(@as(i32, 42), try signal.wait());
        try ctx.sleep(duration);
        cleanup.counter += 1;
    }
};

test "shutdown multiple signals" {
    try run(struct {
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
            try testing.expectEqual(@as(u32, 3), cleanup.counter);
            for (tasks) |task| try (try task.join());
        }
    }.body);
}

test "shutdown timeout" {
    try run(struct {
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
    }.body);
}

test "shutdown multiple stop calls" {
    try run(struct {
        fn stop(ctx: Context, value: i32) anyerror!void {
            try ctx.stop(value, null);
        }

        fn body(ctx: Context) !void {
            var cleanup: Cleanup = .{};
            cleanup.started = .init(&cleanup.started_buffer);
            const task = try ctx.child("blocking_task").spawn(Cleanup.task, .{ &cleanup, ms(50) });
            _ = try cleanup.started.getOne(ctx.io());
            // The second stop's value is ignored; both wait for the task's cleanup.
            const stop1 = try ctx.child("stop").spawn(stop, .{42});
            try ctx.sleep(ms(1));
            const stop2 = try ctx.child("stop").spawn(stop, .{43});
            try ctx.sleep(ms(1));
            try testing.expectEqual(@as(u32, 0), cleanup.counter);
            try (try stop1.join());
            try (try stop2.join());
            try await_stop(ctx, 42);
            try (try task.join());
            try testing.expectEqual(@as(u32, 1), cleanup.counter);
            // A stop after completion returns at once.
            try ctx.stop(43, null);
        }
    }.body);
}

test "unfulfilled shutdown" {
    try run(struct {
        fn body(ctx: Context) !void {
            const handle = try ctx.child("before").spawn(await_stop, .{42});
            handle.detach();
            try ctx.sleep(ms(1));
        }
    }.body);
}

fn expect_contains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing {s} in:\n{s}\n", .{ needle, text });
        return error.TestExpectedEqual;
    }
}

test "metrics" {
    try run(struct {
        fn body(ctx: Context) !void {
            try testing.expectEqualStrings("", ctx.scope.prefix());
            var counter = try ctx.register("test", "test", metrics.raw.Counter{});
            defer counter.deinit();
            counter.metric().inc();
            const text = try ctx.encode(testing.allocator);
            defer testing.allocator.free(text);
            try expect_contains(text, "test_total 1");

            const nested = ctx.child("nested");
            var nested_counter = try nested.register("test", "test", metrics.raw.Counter{});
            defer nested_counter.deinit();
            nested_counter.metric().inc();
            const nested_text = try nested.encode(testing.allocator);
            defer testing.allocator.free(nested_text);
            try expect_contains(nested_text, "nested_test_total 1");
            try expect_contains(nested_text, "test_total 1");
        }
    }.body);
}

test "register and encode" {
    try run(struct {
        fn body(ctx: Context) !void {
            const engine = ctx.child("engine");
            var votes = try engine.register("votes", "vote count", metrics.raw.Counter{});
            defer votes.deinit();
            votes.metric().inc();
            var root = try ctx.register("root", "root metric", metrics.raw.Counter{});
            defer root.deinit();
            root.metric().inc();
            const text = try ctx.encode(testing.allocator);
            defer testing.allocator.free(text);
            try expect_contains(text, "engine_votes_total 1");
            try expect_contains(text, "root_total 1");
            try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "# EOF"));
            try testing.expect(std.mem.endsWith(u8, text, "# EOF\n"));
        }
    }.body);
}

test "register and encode are audited" {
    var digests: [2][8]u8 = undefined;
    for (&digests, 0..) |*digest, index| {
        var runner = try deterministic.Runner.init(testing.allocator, .{});
        defer runner.deinit();
        try (try runner.start_context(struct {
            fn body(ctx: Context, attribute: u32) !void {
                const scoped = ctx.with_attribute("shard", attribute);
                var counter = try scoped.register("ops", "ops", metrics.raw.Counter{});
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
