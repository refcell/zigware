//! Configuration for the simplex engine (commonware `simplex/config.rs`).
//!
//! Commonware's `Config<S, L, B, D, A, R, F, T>` takes eight type parameters; here they are the
//! declarations of one comptime parameter type `P`:
//!
//! - `P.Scheme`: the signing scheme (`cryptography.certificate.assert_scheme`). `config.check`
//!   uses `participants().len()` and
//!   `verify_certificate(gpa, rng, Subject(D), *const Certificate, strategy) !bool`.
//! - `P.Elector`: the elector configuration (`elector.RoundRobin(H)`, `elector.Random(H)`).
//! - `P.Blocker`, `P.Digest`, `P.Automaton`, `P.Relay`, `P.Reporter`, `P.Strategy`.
//!
//! `check` returns the first violated rule (commonware's assertion message) so tests can see
//! it; `assert_valid` panics with it, as commonware does.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");
const utils = @import("utils");
const consensus_types = @import("../types.zig");
const types = @import("types.zig");

const Duration = utils.Duration;
const Epoch = consensus_types.Epoch;
const View = consensus_types.View;
const ViewDelta = consensus_types.ViewDelta;

/// How many consecutive views a skip may cover.
pub const SkipBudget = union(enum) {
    /// One view per participant (the default).
    participants,
    /// A fixed number of views, never zero.
    fixed: u64,

    pub fn resolve(self: SkipBudget, participants: u64) u64 {
        return switch (self) {
            .participants => participants,
            .fixed => |budget| budget: {
                assert(budget > 0);
                break :budget budget;
            },
        };
    }
};

/// Whether a participant that falls behind skips ahead after a timeout.
pub const SkipPolicy = union(enum) {
    disabled,
    enabled: struct { timeout: Duration, budget: SkipBudget = .participants },
};

/// Which peers a participant forwards certificates to.
pub const ForwardPolicy = enum {
    disabled,
    silent_voters,
    silent_leader,

    pub fn is_enabled(self: ForwardPolicy) bool {
        return self != .disabled;
    }
};

/// Where a participant starts: genesis with its payload, or a finalization in the epoch.
pub fn Floor(comptime S: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();

        genesis: D,
        finalized: types.Finalization(S, D),

        pub fn view(self: Self) View {
            return switch (self) {
                .genesis => .zero(),
                .finalized => |finalization| finalization.view(),
            };
        }

        /// The first rule the floor breaks, or null.
        pub fn check(
            self: *const Self,
            gpa: std.mem.Allocator,
            epoch: Epoch,
            rng: anytype,
            scheme: anytype,
            strategy: anytype,
        ) std.mem.Allocator.Error!?[]const u8 {
            const finalization = switch (self.*) {
                .genesis => return null,
                .finalized => |*finalization| finalization,
            };
            if (finalization.epoch() != epoch) {
                return "floor finalization must be in the configured epoch";
            }
            if (finalization.view().is_zero()) return "use Floor::Genesis for the genesis view";
            const subject: types.Subject(D) = .{ .finalize = &finalization.proposal };
            const certificate = &finalization.certificate;
            if (!try scheme.verify_certificate(gpa, rng, subject, certificate, strategy)) {
                return "floor finalization must verify";
            }
            return null;
        }
    };
}

pub fn Config(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Signs and verifies votes and certificates.
        scheme: P.Scheme,
        /// Elects the leader of each round.
        elector: P.Elector,
        /// Blocks peers that send invalid messages.
        blocker: P.Blocker,
        /// Proposes, verifies, and certifies payloads.
        automaton: P.Automaton,
        /// Broadcasts payloads.
        relay: P.Relay,
        /// Receives activity.
        reporter: P.Reporter,
        /// Whether to keep votes of finalized views for reporting.
        track_historical_votes: bool,
        /// Runs verification work.
        strategy: P.Strategy,
        /// Storage partition of the journal.
        partition: []const u8,
        /// Capacity of each actor mailbox.
        mailbox_size: u32,
        epoch: Epoch,
        floor: Floor(P.Scheme, P.Digest),
        replay_buffer: u32,
        write_buffer: u32,
        page_cache: *runtime.buffer.paged.CacheRef,
        /// How long to wait for the leader's proposal before voting to nullify.
        leader_timeout: Duration,
        /// How long to wait for a certificate before voting to nullify.
        certification_timeout: Duration,
        /// How often to rebroadcast a nullify vote.
        timeout_retry: Duration,
        /// Views kept after finalization.
        view_retention: ViewDelta,
        skip: SkipPolicy,
        fetch_timeout: Duration,
        fetch_retry_delay: Duration,
        forward: ForwardPolicy,

        /// The first rule the configuration breaks, or null. The timeouts must satisfy
        /// `certification > leader > 0`, and when skipping is enabled, the skip timeout must
        /// exceed both the certification timeout and the retry interval.
        pub fn check(
            self: *const Self,
            gpa: std.mem.Allocator,
            rng: anytype,
        ) std.mem.Allocator.Error!?[]const u8 {
            if (self.scheme.participants().len() == 0) {
                return "there must be at least one participant";
            }
            if (self.leader_timeout.is_zero()) return "leader timeout must be greater than zero";
            if (self.certification_timeout.order(self.leader_timeout) != .gt) {
                return "certification timeout must be greater than leader timeout";
            }
            switch (self.skip) {
                .disabled => {},
                .enabled => |skip| {
                    if (skip.timeout.order(self.certification_timeout) != .gt) {
                        return "skip timeout must be greater than certification timeout";
                    }
                    if (skip.timeout.order(self.timeout_retry) != .gt) {
                        return "skip timeout must be greater than timeout retry";
                    }
                },
            }
            if (self.timeout_retry.is_zero()) {
                return "timeout retry broadcast must be greater than zero";
            }
            if (self.view_retention.is_zero()) {
                return "view retention timeout must be greater than zero";
            }
            if (self.fetch_timeout.is_zero()) return "fetch timeout must be greater than zero";
            if (self.mailbox_size == 0) return "mailbox size must be greater than zero";
            return self.floor.check(gpa, self.epoch, rng, &self.scheme, self.strategy);
        }

        /// Panics with the first rule the configuration breaks (commonware `Config::assert`).
        pub fn assert_valid(self: *const Self, gpa: std.mem.Allocator, rng: anytype) void {
            const broken = self.check(gpa, rng) catch @panic("out of memory checking config");
            if (broken) |message| @panic(message);
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");

test "skip budget resolves" {
    try testing.expectEqual(4, (SkipBudget{ .participants = {} }).resolve(4));
    try testing.expectEqual(7, (SkipBudget{ .participants = {} }).resolve(7));
    try testing.expectEqual(9, (SkipBudget{ .fixed = 9 }).resolve(4));
    try testing.expect(ForwardPolicy.silent_leader.is_enabled());
    try testing.expect(!ForwardPolicy.disabled.is_enabled());
}

const MockScheme = struct {
    participants_list: []const u32,
    certificates_valid: bool,

    pub const Signature = Certificate;
    pub const Certificate = struct {
        byte: u8,
        pub const fixed_size: usize = 1;
        pub fn eql(a: *const Certificate, b: *const Certificate) bool {
            return a.byte == b.byte;
        }
        pub fn write(self: Certificate, writer: *@import("codec").Writer) void {
            writer.write_byte(self.byte);
        }
        pub fn read(
            _: std.mem.Allocator,
            reader: *@import("codec").Reader,
            _: void,
        ) @import("codec").Error!Certificate {
            return .{ .byte = try reader.read_byte() };
        }
    };

    const Participants = struct {
        list: []const u32,
        pub fn len(self: *const Participants) usize {
            return self.list.len;
        }
    };

    pub fn participants(self: *const MockScheme) Participants {
        return .{ .list = self.participants_list };
    }

    pub fn verify_certificate(
        self: *const MockScheme,
        _: std.mem.Allocator,
        _: anytype,
        subject: types.Subject(Digest),
        _: *const Certificate,
        _: anytype,
    ) std.mem.Allocator.Error!bool {
        assert(subject == .finalize);
        return self.certificates_valid;
    }
};

const Digest = cryptography.Sha256.Digest;

const Parameters = struct {
    pub const Scheme = MockScheme;
    pub const Elector = void;
    pub const Blocker = void;
    pub const Digest = cryptography.Sha256.Digest;
    pub const Automaton = void;
    pub const Relay = void;
    pub const Reporter = void;
    pub const Strategy = void;
};

fn check(config: *const Config(Parameters)) std.mem.Allocator.Error!?[]const u8 {
    return config.check(testing.allocator, {});
}

fn valid_config(cache: *runtime.buffer.paged.CacheRef) Config(Parameters) {
    return .{
        .scheme = .{ .participants_list = &.{ 0, 1, 2, 3 }, .certificates_valid = true },
        .elector = {},
        .blocker = {},
        .automaton = {},
        .relay = {},
        .reporter = {},
        .track_historical_votes = false,
        .strategy = {},
        .partition = "simplex",
        .mailbox_size = 1024,
        .epoch = .new(3),
        .floor = .{ .genesis = .empty },
        .replay_buffer = 1024,
        .write_buffer = 1024,
        .page_cache = cache,
        .leader_timeout = .from_secs(1),
        .certification_timeout = .from_secs(2),
        .timeout_retry = .from_secs(10),
        .view_retention = .new(10),
        .skip = .disabled,
        .fetch_timeout = .from_secs(1),
        .fetch_retry_delay = .from_millis(100),
        .forward = .disabled,
    };
}

test "config check names the violated rule" {
    var cache = try runtime.buffer.paged.CacheRef.init(testing.allocator, 64, 4);
    defer cache.deinit();
    var config = valid_config(&cache);
    try testing.expectEqual(null, (try check(&config)));
    config.assert_valid(testing.allocator, {});

    config.certification_timeout = .from_secs(1);
    try testing.expectEqualStrings(
        "certification timeout must be greater than leader timeout",
        (try check(&config)).?,
    );
    config.certification_timeout = .from_secs(2);
    config.skip = .{ .enabled = .{ .timeout = .from_secs(5) } };
    try testing.expectEqualStrings(
        "skip timeout must be greater than timeout retry",
        (try check(&config)).?,
    );
    config.skip = .{ .enabled = .{ .timeout = .from_secs(20) } };
    try testing.expectEqual(null, (try check(&config)));
    config.view_retention = .zero();
    try testing.expectEqualStrings(
        "view retention timeout must be greater than zero",
        (try check(&config)).?,
    );
}

test "config floor must be a verified finalization in the epoch" {
    var cache = try runtime.buffer.paged.CacheRef.init(testing.allocator, 64, 4);
    defer cache.deinit();
    var config = valid_config(&cache);
    const at = consensus_types.Round.new(.new(3), .new(7));
    config.floor = .{ .finalized = .{
        .proposal = .init(at, .new(6), .fill(1)),
        .certificate = .{ .byte = 0 },
    } };
    try testing.expectEqual(View.new(7), config.floor.view());
    try testing.expectEqual(null, (try check(&config)));
    config.scheme.certificates_valid = false;
    try testing.expectEqualStrings("floor finalization must verify", (try check(&config)).?);
    config.scheme.certificates_valid = true;
    config.epoch = .new(4);
    try testing.expectEqualStrings(
        "floor finalization must be in the configured epoch",
        (try check(&config)).?,
    );
    config.epoch = .new(3);
    config.floor.finalized.proposal.round.view = .zero();
    const genesis_message = "use Floor::Genesis for the genesis view";
    try testing.expectEqualStrings(genesis_message, (try check(&config)).?);
}
