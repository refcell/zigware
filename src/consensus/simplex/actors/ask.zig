//! What the voter asks the resolver for (commonware `actors/mod.rs` `Ask`, `Kind`, `Until`).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");

/// The certificate kind requested.
pub const Kind = enum {
    nullification,
    notarization,

    pub fn as_str(self: Kind) []const u8 {
        return @tagName(self);
    }
};

/// How long a request stays wanted.
pub const Until = enum { floor, finalization };

pub const Ask = struct {
    kind: Kind,
    until: Until,

    pub fn backfill() Ask {
        return .{ .kind = .nullification, .until = .floor };
    }

    pub fn ancestry(kind: Kind) Ask {
        return .{ .kind = kind, .until = .finalization };
    }

    /// Asks never travel; this codec (kind, then until, one byte each) only gives the
    /// resolver its `Ord`, which it reaches through codec.
    pub const fixed_size: usize = 2;

    pub fn write(self: Ask, writer: *codec.Writer) void {
        writer.write_byte(@backingInt(self.kind));
        writer.write_byte(@backingInt(self.until));
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!Ask {
        const kind = std.enums.fromInt(Kind, try reader.read_byte()) orelse return error.Invalid;
        const until = std.enums.fromInt(Until, try reader.read_byte()) orelse return error.Invalid;
        return .{ .kind = kind, .until = until };
    }

    pub fn order(a: Ask, b: Ask) std.math.Order {
        const kinds = std.math.order(@backingInt(a.kind), @backingInt(b.kind));
        if (kinds != .eq) return kinds;
        return std.math.order(@backingInt(a.until), @backingInt(b.until));
    }
};

test "ask orders by kind then until" {
    comptime assert(@backingInt(Kind.nullification) < @backingInt(Kind.notarization));
    try std.testing.expectEqual(.lt, Ask.backfill().order(Ask.ancestry(.notarization)));
    try std.testing.expectEqual(.gt, Ask.ancestry(.nullification).order(Ask.backfill()));
    try std.testing.expectEqualStrings("notarization", Kind.notarization.as_str());
}
