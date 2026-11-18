//! The consensus traits of commonware's `consensus/src/lib.rs` as comptime interfaces.
//!
//! Each `assert_*` function checks a type at compile time:
//!
//! - `Epochable`, `Viewable`, `Heightable`: `x.epoch() Epoch`, `x.view() View`,
//!   `x.height() Height`. `Roundable` is both of the first two; `round(x)` builds the `Round`.
//! - `Block`: `Heightable`, `B.Digest`, `b.digest() Digest`, `b.parent() Digest`, and a codec
//!   encoding that is canonical (`encode(decode(bytes)) == bytes`).
//! - `CertifiableBlock`: a `Block` with `B.Context` and `b.context() Context`.
//! - `Automaton`: `A.Context`, `A.Digest`, `a.propose(io, context) Cancelable!?Digest`, and
//!   `a.verify(io, context, payload) Cancelable!?bool`.
//! - `CertifiableAutomaton`: an `Automaton` that may declare
//!   `a.prepare(io, context) Cancelable!?Handoff(Digest)` and
//!   `a.certify(io, round, payload) Cancelable!?bool`; `prepare` and `certify` below supply
//!   commonware's defaults (`Handoff.wait`, always certify) when it does not.
//! - `Relay`: `R.Digest`, `R.PublicKey`, `R.Plan`, `r.broadcast(payload, plan) Feedback`.
//! - `Reporter`: `R.Activity`, `r.report(activity) Feedback`.
//! - `Monitor`: `M.Index`, `m.subscribe() ...` (latest index and a subscription).
//!
//! Rust returns a oneshot receiver from `propose`, `verify`, `prepare`, and `certify`; here
//! they block on the runtime's `std.Io`, and the caller runs them with `io.async` to wait on
//! several at once. A null result is a closed channel: the application declined, or
//! verification can never conclude (for example on shutdown).

const std = @import("std");
const assert = std.debug.assert;
const actor = @import("actor");
const types = @import("types.zig");

pub const Feedback = actor.Feedback;

/// Histogram buckets in seconds for consensus latency (commonware `LATENCY`).
pub const latency_buckets = [36]f64{
    0.05, 0.1,  0.125, 0.15, 0.16, 0.17, 0.18, 0.19, 0.2,  0.21, 0.22, 0.23,
    0.24, 0.25, 0.26,  0.27, 0.28, 0.29, 0.3,  0.31, 0.32, 0.33, 0.34, 0.35,
    0.36, 0.37, 0.38,  0.39, 0.4,  0.45, 0.5,  0.6,  0.7,  0.8,  0.9,  1.0,
};

fn assert_decls(
    comptime T: type,
    comptime decls: []const []const u8,
    comptime trait: []const u8,
) void {
    comptime {
        for (decls) |decl| {
            if (!@hasDecl(T, decl)) {
                @compileError(@typeName(T) ++ " lacks " ++ trait ++ "." ++ decl);
            }
        }
    }
}

pub fn assert_epochable(comptime T: type) void {
    assert_decls(T, &.{"epoch"}, "Epochable");
}

pub fn assert_viewable(comptime T: type) void {
    assert_decls(T, &.{"view"}, "Viewable");
}

pub fn assert_heightable(comptime T: type) void {
    assert_decls(T, &.{"height"}, "Heightable");
}

/// `Roundable::round`: the round of anything `Epochable` and `Viewable`.
pub fn round(value: anytype) types.Round {
    const T = switch (@typeInfo(@TypeOf(value))) {
        .pointer => |info| info.child,
        else => @TypeOf(value),
    };
    comptime assert_epochable(T);
    comptime assert_viewable(T);
    return .new(value.epoch(), value.view());
}

pub fn assert_block(comptime B: type) void {
    comptime {
        assert_heightable(B);
        assert_decls(B, &.{ "Digest", "digest", "parent", "write", "read" }, "Block");
    }
}

pub fn assert_certifiable_block(comptime B: type) void {
    comptime {
        assert_block(B);
        assert_decls(B, &.{ "Context", "context" }, "CertifiableBlock");
    }
}

pub fn assert_automaton(comptime A: type) void {
    assert_decls(A, &.{ "Context", "Digest", "propose", "verify" }, "Automaton");
}

pub fn assert_certifiable_automaton(comptime A: type) void {
    assert_automaton(A);
}

pub fn assert_relay(comptime R: type) void {
    assert_decls(R, &.{ "Digest", "PublicKey", "Plan", "broadcast" }, "Relay");
}

pub fn assert_reporter(comptime R: type) void {
    assert_decls(R, &.{ "Activity", "report" }, "Reporter");
}

pub fn assert_monitor(comptime M: type) void {
    assert_decls(M, &.{ "Index", "subscribe" }, "Monitor");
}

/// An application's answer to a handoff proposal request (commonware `Handoff<D>`).
pub fn Handoff(comptime D: type) type {
    return union(enum) {
        const Self = @This();

        /// Relay the candidate and vote without waiting for the parent to certify.
        vote: D,
        /// Relay the candidate, but withhold the vote until the parent certifies.
        stage: D,
        /// Request an ordinary proposal once the parent certifies.
        wait,

        pub fn is_wait(self: Self) bool {
            return self == .wait;
        }

        /// Applies `f` to the payload, keeping the decision (`Handoff::map`).
        pub fn map(self: Self, comptime T: type, context: anytype, comptime f: anytype) Handoff(T) {
            return switch (self) {
                .vote => |payload| .{ .vote = f(context, payload) },
                .stage => |payload| .{ .stage = f(context, payload) },
                .wait => .wait,
            };
        }
    };
}

/// `CertifiableAutomaton::prepare`, or its default (`Handoff.wait`) when `A` has none.
pub fn prepare(
    automaton: anytype,
    io: std.Io,
    context: Child(@TypeOf(automaton)).Context,
) std.Io.Cancelable!?Handoff(Child(@TypeOf(automaton)).Digest) {
    const A = Child(@TypeOf(automaton));
    comptime assert_certifiable_automaton(A);
    if (comptime @hasDecl(A, "prepare")) return automaton.prepare(io, context);
    return .wait;
}

/// `CertifiableAutomaton::certify`, or its default (always certify) when `A` has none.
pub fn certify(
    automaton: anytype,
    io: std.Io,
    at: types.Round,
    payload: Child(@TypeOf(automaton)).Digest,
) std.Io.Cancelable!?bool {
    const A = Child(@TypeOf(automaton));
    comptime assert_certifiable_automaton(A);
    if (comptime @hasDecl(A, "certify")) return automaton.certify(io, at, payload);
    return true;
}

fn Child(comptime P: type) type {
    return switch (@typeInfo(P)) {
        .pointer => |info| info.child,
        else => P,
    };
}

const testing = std.testing;

test "round of an epochable and viewable value" {
    const Message = struct {
        at: types.Round,
        pub fn epoch(self: @This()) types.Epoch {
            return self.at.epoch;
        }
        pub fn view(self: @This()) types.View {
            return self.at.view;
        }
    };
    const message: Message = .{ .at = .new(.new(3), .new(9)) };
    try testing.expectEqual(types.Round.new(.new(3), .new(9)), round(message));
    try testing.expectEqual(types.Round.new(.new(3), .new(9)), round(&message));
}

test "handoff map keeps the decision" {
    const H = Handoff(u8);
    const double = struct {
        fn f(_: void, value: u8) u16 {
            return @as(u16, value) * 2;
        }
    }.f;
    try testing.expectEqual(Handoff(u16){ .vote = 10 }, (H{ .vote = 5 }).map(u16, {}, double));
    try testing.expectEqual(Handoff(u16){ .stage = 4 }, (H{ .stage = 2 }).map(u16, {}, double));
    try testing.expectEqual(Handoff(u16).wait, (H{ .wait = {} }).map(u16, {}, double));
    try testing.expect((H{ .wait = {} }).is_wait() and !(H{ .vote = 1 }).is_wait());
}

test "certifiable automaton defaults" {
    const Plain = struct {
        pub const Context = void;
        pub const Digest = u8;
        pub fn propose(_: *@This(), _: std.Io, _: void) std.Io.Cancelable!?u8 {
            return 1;
        }
        pub fn verify(_: *@This(), _: std.Io, _: void, _: u8) std.Io.Cancelable!?bool {
            return true;
        }
    };
    const Custom = struct {
        pub const Context = void;
        pub const Digest = u8;
        pub const propose = Plain.propose;
        pub const verify = Plain.verify;
        pub fn prepare(_: *@This(), _: std.Io, _: void) std.Io.Cancelable!?Handoff(u8) {
            return .{ .stage = 7 };
        }
        pub fn certify(_: *@This(), _: std.Io, _: types.Round, d: u8) std.Io.Cancelable!?bool {
            return d != 0;
        }
    };
    var plain: Plain = .{};
    var custom: Custom = .{};
    const io = testing.io;
    try testing.expectEqual(Handoff(u8).wait, (try prepare(&plain, io, {})).?);
    try testing.expectEqual(true, (try certify(&plain, io, .zero(), 0)).?);
    try testing.expectEqual(Handoff(u8){ .stage = 7 }, (try prepare(&custom, io, {})).?);
    try testing.expectEqual(false, (try certify(&custom, io, .zero(), 0)).?);
}
