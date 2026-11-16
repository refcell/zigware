//! Wall-clock stamps for chat, chrono's `%m/%d %H:%M:%S`: in UTC for log lines (tracing's JSON
//! timestamp is UTC) and in local time for messages (chrono's `Local`), with the local zone
//! read from a TZif file and its POSIX TZ footer rule for times past the last transition.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// `MM/DD HH:MM:SS`.
pub const stamp_size = 14;
pub const Stamp = [stamp_size]u8;

const seconds_per_day = 86_400;

/// Formats `seconds` since the Unix epoch, already shifted to the wanted zone.
pub fn stamp(seconds: i64) Stamp {
    const days = @divFloor(seconds, seconds_per_day);
    const second_of_day: u32 = @intCast(@mod(seconds, seconds_per_day));
    const date = civil_from_days(days);
    var result: Stamp = undefined;
    const written = std.fmt.bufPrint(&result, "{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        date.month,
        date.day,
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60,
    }) catch unreachable; // Every field has exactly two digits.
    assert(written.len == stamp_size);
    assert(second_of_day < seconds_per_day);
    return result;
}

const Date = struct { year: i64, month: u8, day: u8 };

/// Howard Hinnant's `civil_from_days`: the proleptic Gregorian date `days` after 1970-01-01.
fn civil_from_days(days: i64) Date {
    const shifted = days + 719_468;
    const era = @divFloor(shifted, 146_097);
    const day_of_era = shifted - era * 146_097;
    assert(day_of_era >= 0 and day_of_era < 146_097);
    const year_of_era = @divFloor(
        day_of_era - @divFloor(day_of_era, 1460) + @divFloor(day_of_era, 36_524) -
            @divFloor(day_of_era, 146_096),
        365,
    );
    const day_of_year = day_of_era -
        (365 * year_of_era + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100));
    const month_index = @divFloor(5 * day_of_year + 2, 153);
    const day: u8 = @intCast(day_of_year - @divFloor(153 * month_index + 2, 5) + 1);
    const month: u8 = @intCast(if (month_index < 10) month_index + 3 else month_index - 9);
    assert(month >= 1 and month <= 12);
    assert(day >= 1 and day <= 31);
    const year = year_of_era + era * 400 + @intFromBool(month <= 2);
    return .{ .year = year, .month = month, .day = day };
}

/// Hinnant's `days_from_civil`: days from 1970-01-01 to `year`-`month`-`day`.
fn days_from_civil(year: i64, month: u8, day: u8) i64 {
    assert(month >= 1 and month <= 12);
    assert(day >= 1 and day <= 31);
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const year_of_era = y - era * 400;
    const m: i64 = month;
    const day_of_year = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

fn is_leap(year: i64) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn month_length(year: i64, month: u8) u8 {
    assert(month >= 1 and month <= 12);
    const lengths = [12]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return lengths[month - 1] + @intFromBool(month == 2 and is_leap(year));
}

/// A POSIX TZ rule (the TZif footer), such as `EST5EDT,M3.2.0,M11.1.0`. Offsets are seconds
/// east of UTC.
pub const Rule = struct {
    standard_offset: i32,
    dst: ?Dst,

    pub const Dst = struct {
        offset: i32,
        start: Transition,
        end: Transition,
    };

    /// When a change happens: a date form and the local time of day it happens at.
    pub const Transition = struct {
        date: union(enum) {
            /// `Mm.w.d`: day `d` (0 is Sunday) of week `w` (5 is the last) of month `m`.
            month_week_day: struct { month: u8, week: u8, weekday: u8 },
            /// `Jn`: day 1 to 365, never counting February 29.
            julian: u16,
            /// `n`: day 0 to 365, counting February 29.
            zero_based: u16,
        },
        time_seconds: i32 = 2 * 3600,

        /// Seconds from the epoch to the local midnight of this date in `year`.
        fn day_start(transition: Transition, year: i64) i64 {
            const january_first = days_from_civil(year, 1, 1);
            const days: i64 = switch (transition.date) {
                .julian => |day| january_first + day - 1 +
                    @intFromBool(is_leap(year) and day >= 60),
                .zero_based => |day| january_first + day,
                .month_week_day => |rule| month_week_day(year, rule.month, rule.week, rule.weekday),
            };
            assert(days >= january_first);
            return days * seconds_per_day;
        }
    };

    /// The offset in effect at `utc_seconds`.
    pub fn offset_at(rule: Rule, utc_seconds: i64) i32 {
        const dst = rule.dst orelse return rule.standard_offset;
        const local_days = @divFloor(utc_seconds + rule.standard_offset, seconds_per_day);
        const year = civil_from_days(local_days).year;
        const start = dst.start.day_start(year) + dst.start.time_seconds - rule.standard_offset;
        const end = dst.end.day_start(year) + dst.end.time_seconds - dst.offset;
        const in_dst = if (start < end)
            utc_seconds >= start and utc_seconds < end
        else
            !(utc_seconds >= end and utc_seconds < start);
        return if (in_dst) dst.offset else rule.standard_offset;
    }
};

fn month_week_day(year: i64, month: u8, week: u8, weekday: u8) i64 {
    assert(week >= 1 and week <= 5);
    assert(weekday <= 6);
    const first = days_from_civil(year, month, 1);
    // 1970-01-01 was a Thursday (weekday 4).
    const first_weekday: u8 = @intCast(@mod(first + 4, 7));
    var day: u8 = 1 + (weekday + 7 - first_weekday) % 7 + 7 * (week - 1);
    while (day > month_length(year, month)) day -= 7;
    return first + day - 1;
}

pub const ParseError = error{InvalidRule};

/// Parses a POSIX TZ rule string.
pub fn parse_rule(text: []const u8) ParseError!Rule {
    var cursor: Cursor = .{ .text = text };
    try cursor.name();
    const standard_offset = -try cursor.offset();
    if (cursor.done()) return .{ .standard_offset = standard_offset, .dst = null };
    try cursor.name();
    var dst_offset = standard_offset + 3600;
    if (!cursor.done() and cursor.peek() != ',') dst_offset = -try cursor.offset();
    try cursor.expect(',');
    const start = try cursor.transition();
    try cursor.expect(',');
    const end = try cursor.transition();
    if (!cursor.done()) return error.InvalidRule;
    assert(cursor.index == text.len);
    return .{
        .standard_offset = standard_offset,
        .dst = .{ .offset = dst_offset, .start = start, .end = end },
    };
}

const Cursor = struct {
    text: []const u8,
    index: usize = 0,

    fn done(cursor: *const Cursor) bool {
        return cursor.index == cursor.text.len;
    }

    fn peek(cursor: *const Cursor) u8 {
        assert(!cursor.done());
        return cursor.text[cursor.index];
    }

    fn expect(cursor: *Cursor, byte: u8) ParseError!void {
        if (cursor.done() or cursor.peek() != byte) return error.InvalidRule;
        cursor.index += 1;
    }

    /// A zone name: three or more letters, or `<...>` holding letters, digits, `+`, and `-`.
    fn name(cursor: *Cursor) ParseError!void {
        const start = cursor.index;
        if (!cursor.done() and cursor.peek() == '<') {
            cursor.index += 1;
            while (!cursor.done() and cursor.peek() != '>') : (cursor.index += 1) {
                const byte = cursor.peek();
                if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '-') {
                    return error.InvalidRule;
                }
            }
            try cursor.expect('>');
            if (cursor.index - start < 5) return error.InvalidRule;
            return;
        }
        while (!cursor.done() and std.ascii.isAlphabetic(cursor.peek())) cursor.index += 1;
        if (cursor.index - start < 3) return error.InvalidRule;
    }

    /// `[+-]hh[:mm[:ss]]` as seconds, with the sign as written.
    fn offset(cursor: *Cursor) ParseError!i32 {
        var sign: i32 = 1;
        if (!cursor.done() and (cursor.peek() == '+' or cursor.peek() == '-')) {
            if (cursor.peek() == '-') sign = -1;
            cursor.index += 1;
        }
        const scales = [3]i32{ 3600, 60, 1 };
        var seconds: i32 = 0;
        for (scales, 0..) |scale, part| {
            if (part > 0) {
                if (cursor.done() or cursor.peek() != ':') break;
                cursor.index += 1;
            }
            const value = try cursor.number(if (part == 0) 167 else 59);
            seconds += @as(i32, value) * scale;
        }
        assert(seconds >= 0);
        return sign * seconds;
    }

    /// One to three decimal digits no greater than `max`.
    fn number(cursor: *Cursor, max: u16) ParseError!u16 {
        const start = cursor.index;
        var value: u16 = 0;
        while (!cursor.done() and std.ascii.isDigit(cursor.peek())) : (cursor.index += 1) {
            if (cursor.index - start == 3) return error.InvalidRule;
            value = value * 10 + (cursor.peek() - '0');
        }
        if (cursor.index == start or value > max) return error.InvalidRule;
        assert(value <= max);
        return value;
    }

    fn transition(cursor: *Cursor) ParseError!Rule.Transition {
        if (cursor.done()) return error.InvalidRule;
        var result: Rule.Transition = .{ .date = undefined };
        if (cursor.peek() == 'M') {
            cursor.index += 1;
            const month: u8 = @intCast(try cursor.number(12));
            try cursor.expect('.');
            const week: u8 = @intCast(try cursor.number(5));
            try cursor.expect('.');
            const weekday: u8 = @intCast(try cursor.number(6));
            if (month == 0 or week == 0) return error.InvalidRule;
            result.date = .{
                .month_week_day = .{ .month = month, .week = week, .weekday = weekday },
            };
        } else if (cursor.peek() == 'J') {
            cursor.index += 1;
            const day = try cursor.number(365);
            if (day == 0) return error.InvalidRule;
            result.date = .{ .julian = day };
        } else {
            result.date = .{ .zero_based = try cursor.number(365) };
        }
        if (!cursor.done() and cursor.peek() == '/') {
            cursor.index += 1;
            result.time_seconds = try cursor.offset();
        }
        return result;
    }
};

/// The local zone: TZif transitions, then the footer rule past the last one.
pub const Zone = struct {
    tz: ?std.tz.Tz = null,
    rule: ?Rule = null,

    pub const utc: Zone = .{};

    /// Reads the zone chrono's `Local` uses: `$TZ` naming a zoneinfo file (`:Europe/Paris`,
    /// `Europe/Paris`, or an absolute path), else `/etc/localtime`, else UTC.
    pub fn load(gpa: Allocator, io: Io, tz_env: ?[]const u8) Zone {
        var path_buffer: [256]u8 = undefined;
        const path = if (tz_env) |env| zone_path(&path_buffer, env) else "/etc/localtime";
        const file = Io.Dir.openFileAbsolute(io, path orelse return .utc, .{}) catch return .utc;
        defer file.close(io);
        var read_buffer: [4096]u8 = undefined;
        var reader = file.reader(io, &read_buffer);
        var tz = std.tz.Tz.parse(gpa, &reader.interface) catch return .utc;
        const rule = if (tz.footer) |footer| parse_rule(footer) catch null else null;
        if (tz.transitions.len == 0 and tz.timetypes.len == 0 and rule == null) {
            tz.deinit();
            return .utc;
        }
        return .{ .tz = tz, .rule = rule };
    }

    pub fn deinit(zone: *Zone) void {
        if (zone.tz) |*tz| tz.deinit();
        zone.* = undefined;
    }

    /// Seconds east of UTC at `utc_seconds`.
    pub fn offset_at(zone: *const Zone, utc_seconds: i64) i32 {
        const tz = zone.tz orelse return if (zone.rule) |rule| rule.offset_at(utc_seconds) else 0;
        const transitions = tz.transitions;
        if (transitions.len == 0 or utc_seconds < transitions[0].ts) {
            if (transitions.len == 0) {
                if (zone.rule) |rule| return rule.offset_at(utc_seconds);
            }
            return if (tz.timetypes.len > 0) tz.timetypes[0].offset else 0;
        }
        const last = transitions[transitions.len - 1];
        if (utc_seconds >= last.ts) {
            if (zone.rule) |rule| return rule.offset_at(utc_seconds);
            return last.timetype.offset;
        }
        var low: usize = 0;
        var high: usize = transitions.len - 1;
        while (high - low > 1) {
            const middle = low + (high - low) / 2;
            if (transitions[middle].ts <= utc_seconds) low = middle else high = middle;
        }
        assert(transitions[low].ts <= utc_seconds and utc_seconds < transitions[high].ts);
        return transitions[low].timetype.offset;
    }

    /// The local stamp for `utc_seconds`.
    pub fn local_stamp(zone: *const Zone, utc_seconds: i64) Stamp {
        return stamp(utc_seconds + zone.offset_at(utc_seconds));
    }
};

fn zone_path(buffer: []u8, env: []const u8) ?[]const u8 {
    const name = if (std.mem.startsWith(u8, env, ":")) env[1..] else env;
    if (name.len == 0) return null;
    if (std.fs.path.isAbsolute(name)) return name;
    if (std.mem.indexOf(u8, name, "..") != null) return null;
    return std.fmt.bufPrint(buffer, "/usr/share/zoneinfo/{s}", .{name}) catch null;
}
