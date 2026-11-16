//! Benchmark output lines (the parsing half of commonware's `bench/src/bin/runner.rs`): the
//! JSON summaries Gungraun prints, and the custom metric lines `bench.Benchmark.metrics_json`
//! appends to `COMMONWARE_BENCH_METRICS_PATH`. Also `Metrics`, a name-ordered metric map
//! (commonware's `BTreeMap<String, u64>`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const json = std.json;
const toml = @import("toml.zig");

const Diagnostic = toml.Diagnostic;
pub const Error = toml.Error;

/// Values ordered by name, each name once (commonware's `BTreeMap<String, V>`).
pub fn Map(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { name: []const u8, value: V };

        entries: std.ArrayList(Entry) = .empty,

        pub fn items(map: *const Self) []const Entry {
            return map.entries.items;
        }

        pub fn get(map: *const Self, name: []const u8) ?V {
            const place = map.find(name);
            if (!place.found) return null;
            return map.entries.items[place.index].value;
        }

        pub fn contains(map: *const Self, name: []const u8) bool {
            return map.find(name).found;
        }

        /// Sets `name` to `value`, returning the value it replaced, if any.
        pub fn put(map: *Self, gpa: Allocator, name: []const u8, value: V) Allocator.Error!?V {
            const place = map.find(name);
            if (!place.found) {
                try map.entries.insert(gpa, place.index, .{ .name = name, .value = value });
                assert(map.find(name).found);
                return null;
            }
            const previous = map.entries.items[place.index].value;
            map.entries.items[place.index].value = value;
            return previous;
        }

        const Place = struct { found: bool, index: usize };

        /// The index of `name`, or where to insert it.
        fn find(map: *const Self, name: []const u8) Place {
            const entries = map.entries.items;
            var low: usize = 0;
            var high: usize = entries.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (std.mem.order(u8, entries[middle].name, name)) {
                    .eq => return .{ .found = true, .index = middle },
                    .lt => low = middle + 1,
                    .gt => high = middle,
                }
            }
            return .{ .found = false, .index = low };
        }
    };
}

pub const Metrics = Map(u64);

/// A custom metric line.
pub const Custom = struct {
    enabled: bool,
    benchmark: []const u8,
    metrics: json.ObjectMap,
};

/// A Gungraun summary line.
pub const Summary = struct {
    module_path: ?[]const u8 = null,
    id: ?[]const u8 = null,
    profiles: ?[]const json.Value = null,

    /// Whether `pattern` matches the module path, `module_path::id`, or the id.
    pub fn matches(summary: *const Summary, gpa: Allocator, pattern: []const u8) bool {
        if (summary.module_path) |module_path| {
            if (glob(pattern, module_path)) return true;
            if (summary.id) |id| {
                const joined = std.fmt.allocPrint(gpa, "{s}::{s}", .{ module_path, id }) catch
                    return false;
                defer gpa.free(joined);
                if (glob(pattern, joined)) return true;
            }
        }
        if (summary.id) |id| return glob(pattern, id);
        return false;
    }

    /// The current value of each `selected` callgrind metric.
    pub fn callgrind_metrics(
        summary: *const Summary,
        gpa: Allocator,
        diagnostic: *Diagnostic,
        selected: []const []const u8,
    ) Error!Metrics {
        const callgrind = try summary.callgrind_summary(diagnostic);
        var metrics: Metrics = .{};
        for (selected) |metric| {
            const value = current_metric_value(callgrind.get(metric)) orelse
                return diagnostic.fail("Gungraun result is missing `{s}`", .{metric});
            _ = try metrics.put(gpa, metric, value);
        }
        return metrics;
    }

    fn callgrind_summary(
        summary: *const Summary,
        diagnostic: *Diagnostic,
    ) error{Invalid}!json.ObjectMap {
        const profiles = summary.profiles orelse
            return diagnostic.fail("Gungraun result is missing `profiles`", .{});
        for (profiles) |profile| {
            const tool = field(profile, "tool") orelse continue;
            if (tool != .string or !std.mem.eql(u8, tool.string, "Callgrind")) continue;
            var value = profile;
            for ([_][]const u8{ "summaries", "total", "summary", "Callgrind" }) |key| {
                value = field(value, key) orelse break;
            } else if (value == .object) return value.object;
        }
        return diagnostic.fail("Gungraun result is missing total Callgrind metrics", .{});
    }
};

pub const Line = union(enum) {
    custom: Custom,
    summary: Summary,
};

/// Parses every line of `text` that starts with `{` (after trimming) as a JSON output line.
pub fn parse_lines(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    text: []const u8,
    source: []const u8,
) Error![]Line {
    var lines: std.ArrayList(Line) = .empty;
    var iterator = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 0;
    while (iterator.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, "{")) continue;
        const value = json.parseFromSliceLeaky(json.Value, gpa, line, .{}) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return diagnostic.fail("invalid JSON in {s}:{d}", .{ source, number });
        };
        const parsed = decode_line(value) orelse
            return diagnostic.fail("invalid JSON in {s}:{d}", .{ source, number });
        try lines.append(gpa, parsed);
    }
    return lines.items;
}

/// Decodes a line as a custom metric line when it has that shape, else as a summary line
/// (serde's untagged enum, in declaration order).
fn decode_line(value: json.Value) ?Line {
    if (value != .object) return null;
    const object = value.object;
    custom: {
        const enabled = object.get("commonware_bench_metrics") orelse break :custom;
        const benchmark = object.get("benchmark") orelse break :custom;
        const metrics = object.get("metrics") orelse break :custom;
        if (enabled != .bool or benchmark != .string or metrics != .object) break :custom;
        return .{ .custom = .{
            .enabled = enabled.bool,
            .benchmark = benchmark.string,
            .metrics = metrics.object,
        } };
    }
    var summary: Summary = .{};
    if (object.get("module_path")) |module_path| switch (module_path) {
        .null => {},
        .string => |text| summary.module_path = text,
        else => return null,
    };
    if (object.get("id")) |id| switch (id) {
        .null => {},
        .string => |text| summary.id = text,
        else => return null,
    };
    if (object.get("profiles")) |profiles| switch (profiles) {
        .null => {},
        .array => |array| summary.profiles = array.items,
        else => return null,
    };
    return .{ .summary = summary };
}

/// The custom metrics `lines` report for `benchmark`; a later line's value wins.
pub fn custom_metrics(
    gpa: Allocator,
    diagnostic: *Diagnostic,
    lines: []const Line,
    benchmark: []const u8,
) Error!Metrics {
    var parsed: Metrics = .{};
    for (lines) |line| {
        if (line != .custom) continue;
        const custom = line.custom;
        if (!custom.enabled or !std.mem.eql(u8, custom.benchmark, benchmark)) continue;
        var entries = custom.metrics.iterator();
        while (entries.next()) |entry| {
            const name = entry.key_ptr.*;
            if (name.len == 0) {
                return diagnostic.fail("custom metric entry has an invalid metric name", .{});
            }
            const value = metric_value(entry.value_ptr.*) orelse
                return diagnostic.fail("custom metric `{s}` must be an integer", .{name});
            _ = try parsed.put(gpa, name, value);
        }
    }
    return parsed;
}

fn field(value: json.Value, key: []const u8) ?json.Value {
    if (value != .object) return null;
    return value.object.get(key);
}

/// The current run's value of a Gungraun metric: `Left`, or the first of `Both`.
fn current_metric_value(summary: ?json.Value) ?u64 {
    const metrics = field(summary orelse return null, "metrics") orelse return null;
    if (metrics != .object) return null;
    if (metrics.object.get("Left")) |left| {
        if (metric_value(left)) |value| return value;
    }
    const both = metrics.object.get("Both") orelse return null;
    if (both != .array or both.array.items.len == 0) return null;
    return metric_value(both.array.items[0]);
}

/// A non-negative integer, bare or as `{"Int": n}`.
fn metric_value(value: json.Value) ?u64 {
    switch (value) {
        .integer => |integer| return std.math.cast(u64, integer),
        .number_string => |text| return std.fmt.parseInt(u64, text, 10) catch null,
        else => {},
    }
    return metric_value_int(field(value, "Int") orelse return null);
}

fn metric_value_int(value: json.Value) ?u64 {
    return switch (value) {
        .integer => |integer| std.math.cast(u64, integer),
        .number_string => |text| std.fmt.parseInt(u64, text, 10) catch null,
        else => null,
    };
}

/// Matches `text` against a glob `pattern` of `*`, `?`, `[set]`, and `[!set]` (with ranges),
/// like the `glob` crate's `Pattern::matches` with default options. A malformed set never
/// matches. Iterative: on a mismatch it retries from the last `*` one character later.
pub fn glob(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_text: usize = 0;
    while (t < text.len) {
        if (p < pattern.len) {
            switch (pattern[p]) {
                '*' => {
                    star = p;
                    star_text = t;
                    p += 1;
                    continue;
                },
                '?' => {
                    p += 1;
                    t += 1;
                    continue;
                },
                '[' => if (set_match(pattern[p..], text[t])) |width| {
                    if (width.matched) {
                        p += width.len;
                        t += 1;
                        continue;
                    }
                } else return false,
                else => if (pattern[p] == text[t]) {
                    p += 1;
                    t += 1;
                    continue;
                },
            }
        }
        const restart = star orelse return false;
        p = restart + 1;
        star_text += 1;
        t = star_text;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const SetMatch = struct { len: usize, matched: bool };

/// Matches `char` against the set at the start of `pattern` (`[...]`), or null if malformed.
fn set_match(pattern: []const u8, char: u8) ?SetMatch {
    assert(pattern[0] == '[');
    var index: usize = 1;
    const negated = index < pattern.len and pattern[index] == '!';
    if (negated) index += 1;
    var matched = false;
    var first = true;
    while (index < pattern.len) {
        const low = pattern[index];
        if (low == ']' and !first) {
            return .{ .len = index + 1, .matched = matched != negated };
        }
        first = false;
        if (index + 2 < pattern.len and pattern[index + 1] == '-' and pattern[index + 2] != ']') {
            const high = pattern[index + 2];
            if (char >= low and char <= high) matched = true;
            index += 3;
        } else {
            if (char == low) matched = true;
            index += 1;
        }
    }
    return null;
}
