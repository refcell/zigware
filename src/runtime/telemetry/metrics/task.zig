//! Labels for per-task runtime metrics (commonware `metrics::task`): `runtime_tasks_spawned`,
//! `runtime_tasks_running`, and `runtime_task_polls` are families keyed by `Label`. Context
//! attributes never reach these labels, so spawning with a varying attribute does not grow
//! their cardinality.

const std = @import("std");
const metrics_mod = @import("mod.zig");
const assert = std.debug.assert;

/// The type of task.
pub const Kind = enum {
    root,
    task,

    pub fn label_value(kind: Kind) []const u8 {
        return switch (kind) {
            .root => "Root",
            .task => "Task",
        };
    }
};

/// Whether a task runs on a dedicated thread or the shared runtime.
pub const Execution = enum {
    /// Runs on the shared runtime.
    shared,
    /// Runs on the shared runtime but may block.
    shared_blocking,
    /// Runs on a dedicated thread.
    dedicated,

    pub fn label_value(execution: Execution) []const u8 {
        return switch (execution) {
            .shared => "Shared",
            .shared_blocking => "SharedBlocking",
            .dedicated => "Dedicated",
        };
    }
};

/// The task label set, encoded `name="...",kind="...",execution="..."`.
pub const Label = struct {
    name: []const u8,
    kind: Kind,
    execution: Execution,

    /// The root task's label.
    pub fn root() Label {
        return .{ .name = "", .kind = .root, .execution = .shared };
    }

    /// A spawned task's label; `name` is the spawning context's label prefix.
    pub fn task(name: []const u8, execution: Execution) Label {
        return .{ .name = name, .kind = .task, .execution = execution };
    }
};

/// Sums `runtime_tasks_running` over tasks (not the root) whose name starts with `prefix`
/// (commonware `count_running_tasks`, a test utility), from encoded metrics.
pub fn count_running_tasks(text: []const u8, prefix: []const u8) u64 {
    var total: u64 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "runtime_tasks_running{")) continue;
        if (std.mem.indexOf(u8, line, "kind=\"Task\"") == null) continue;
        const name_at = std.mem.indexOf(u8, line, "name=\"") orelse continue;
        const name_rest = line[name_at + "name=\"".len ..];
        const name_end = std.mem.indexOfScalar(u8, name_rest, '"') orelse continue;
        if (!std.mem.startsWith(u8, name_rest[0..name_end], prefix)) continue;
        const trimmed = std.mem.trimEnd(u8, line, &std.ascii.whitespace);
        const value_at = std.mem.lastIndexOfScalar(u8, trimmed, ' ') orelse continue;
        const value = std.fmt.parseInt(u64, trimmed[value_at + 1 ..], 10) catch continue;
        total += value;
    }
    return total;
}

const testing = std.testing;
const raw = metrics_mod.raw;

test "task labels encode like commonware's" {
    var registry_value: metrics_mod.Registry = .init(testing.allocator);
    defer registry_value.deinit();
    const root = metrics_mod.Scope.init(&registry_value);
    const runtime = root.sub_registry(metrics_mod.metrics_prefix);
    var spawned = try runtime.family(Label, raw.Counter, "tasks_spawned", "Total tasks spawned");
    defer spawned.deinit();
    var running = try runtime.family(Label, raw.Gauge, "tasks_running", "Tasks running");
    defer running.deinit();
    (try spawned.metric().get_or_create(.root())).inc();
    for (0..128) |_| {
        (try spawned.metric().get_or_create(.task("deferred_verify", .shared))).inc();
    }
    (try running.metric().get_or_create(.task("worker", .shared))).inc();
    (try running.metric().get_or_create(.task("worker_child", .dedicated))).inc();
    (try running.metric().get_or_create(.task("other", .shared_blocking))).inc();
    (try running.metric().get_or_create(.task("deferred_verify", .shared))).inc_by(0);
    const text = try registry_value.encode(testing.allocator);
    defer testing.allocator.free(text);
    const expected = "runtime_tasks_spawned_total" ++
        "{name=\"deferred_verify\",kind=\"Task\",execution=\"Shared\"} 128\n";
    try testing.expect(std.mem.indexOf(u8, text, expected) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        text,
        "runtime_tasks_spawned_total{name=\"\",kind=\"Root\",execution=\"Shared\"} 1\n",
    ) != null);
    try testing.expectEqual(@as(u64, 2), count_running_tasks(text, "worker"));
    try testing.expectEqual(@as(u64, 1), count_running_tasks(text, "other"));
    try testing.expectEqual(@as(u64, 0), count_running_tasks(text, "deferred"));
    try testing.expectEqual(@as(u64, 0), count_running_tasks(text, "missing"));
}

comptime {
    assert(@typeInfo(Label).@"struct".field_names.len == 3);
}
