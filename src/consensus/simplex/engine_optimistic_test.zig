//! commonware `simplex/mod.rs`'s stable-leader, pipelined-handoff, and large DSTs, on
//! engine_test.zig's harness. Each runs on the fixture commonware runs it on (ed25519 unless
//! noted); the instantiations for other fixtures skip them.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const consensus_types = @import("../types.zig");
const engine_test = @import("engine_test.zig");
const application_mod = @import("mocks/application.zig");
const utils = @import("utils");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const elector_mod = @import("elector.zig");
const mock_scheme = @import("mocks/scheme.zig");

/// commonware `scheme_mocks::fixture` with round robin, which `one_offline_stable_leader` and
/// `1k` run on.
/// It hosts only this file's DSTs: engine_test.zig's run on commonware's fixtures.
pub const MockFixture = struct {
    pub const harness_only = {};
    const Digest = cryptography.Sha256.Digest;
    pub const Scheme = mock_scheme.Scheme(Digest);
    pub const Elector = elector_mod.RoundRobinElector;

    pub fn fixture(rng: anytype, n: u32) !cryptography.certificate.mocks.Fixture(Scheme) {
        return mock_scheme.fixture(Digest, testing.allocator, rng, "consensus", n);
    }

    pub fn elector(n: u32) !Elector {
        const RoundRobin = elector_mod.RoundRobin(cryptography.Sha256);
        return RoundRobin.default().build(testing.allocator, n);
    }

    pub fn deinit_elector(value: *Elector) void {
        value.deinit(testing.allocator);
    }
};

pub fn Suite(comptime F: type) type {
    return struct {
        const E = engine_test.Suite(F);
        const ed25519 = F == engine_test.Ed25519Fixture;
        const mocks = F == MockFixture;
        /// commonware runs the stable-leader variants in its slow group; Debug runs without
        /// `-Dslow-tests` skip them.
        const slow_variants = builtin.mode != .debug or build_options.slow_tests;
        const Context = E.Context;
        const Harness = E.Harness;
        const RoundRobin = E.RoundRobin;
        const HandoffKind = E.HandoffKind;
        const View = consensus_types.View;
        /// The last measured view: Debug runs without `-Dslow-tests` measure fewer views.
        const last_view: u64 = if (E.quick) 40 else 100;

        /// commonware `CLUSTER_LEADER_TIMEOUT` and `CLUSTER_CERTIFICATION_TIMEOUT`, with the
        /// cluster's 12 s skip timeout.
        const cluster_timeouts: Harness.Timeouts = .{
            .leader_ms = 1500,
            .certification_ms = 3500,
            .retry_ms = 10_000,
            .skip_ms = 12_000,
        };

        fn unit_latency(_: usize) application_mod.Latency {
            return .{ .mean = 1, .std_dev = 0 };
        }

        fn term(length: u32, stall_s: u64, optimistic_views: u64) RoundRobin {
            const value: consensus_types.TermLength = .new(utils.NonZero(u32).init(length).?);
            const stall: E.Duration = .from_secs(stall_s);
            return RoundRobin.default().with_term(value, stall, .new(optimistic_views));
        }

        /// commonware `setup_round_robin_cluster`: five validators over `link`, proposing in
        /// `propose_ms`, verifying and certifying in 1 ms. Returns the view 1 leader's index.
        fn start_cluster(
            harness: *Harness,
            ctx: Context,
            link: E.Link,
            round_robin: RoundRobin,
            propose_ms: f64,
            handoff: HandoffKind,
        ) !usize {
            try harness.start_network(ctx, 5, link, .honest, cluster_timeouts);
            harness.round_robin = round_robin;
            harness.handoff = handoff;
            harness.propose_latency = .{ .mean = propose_ms, .std_dev = 0 };
            harness.verify_latency = .{ .mean = 1, .std_dev = 0 };
            harness.certify_latency = unit_latency;
            for (0..5) |index| try harness.start_validator(index);
            var schedule = try round_robin.build(E.gpa, 5);
            defer schedule.deinit(E.gpa);
            return schedule.elect(.new(E.epoch, .new(1)), {}).get();
        }

        fn now_ns(ctx: Context) u64 {
            return @intCast(ctx.current().nanoseconds);
        }

        /// Sleeps in `step_ms` steps until `done(reporter, view)`, at most `limit_s` seconds.
        fn wait_until(
            ctx: Context,
            reporter: *E.Reporter,
            view: u64,
            comptime done: fn (*E.Reporter, View) bool,
            comptime step_ms: i64,
            limit_s: u64,
        ) !void {
            const deadline = now_ns(ctx) + limit_s * std.time.ns_per_s;
            while (!done(reporter, .new(view))) {
                if (now_ns(ctx) >= deadline) return error.TestTimedOut;
                try ctx.sleep(.fromMilliseconds(step_ms));
            }
        }

        fn notarized_by_self(reporter: *E.Reporter, view: View) bool {
            return reporter.votes(view).notarize != 0;
        }

        fn notarized(reporter: *E.Reporter, view: View) bool {
            return reporter.notarized(view);
        }

        /// Every reporter saw no invalid activity, no faults, and no nullify votes.
        fn check_clean(harness: *Harness) !void {
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_invalid();
                validator.reporter.assert_no_faults();
                try testing.expectEqual(0, validator.reporter.nullifies.count());
            }
        }

        /// commonware `stable_leader_optimistic_blocks_faster_than_network_latency`: a 128-view
        /// term with 128 optimistic views notarizes 100 views (40 when quick) in less than a
        /// link latency each.
        fn faster_than_latency_scenario(ctx: Context) !void {
            const latency_ms = 100;
            const required = last_view;
            var harness: Harness = undefined;
            const link = E.link_ms(latency_ms, 0, 1.0);
            const leader = try start_cluster(&harness, ctx, link, term(128, 20, 128), 10, .wait);
            defer harness.deinit();
            const reporter = &harness.validators[leader].reporter;
            const start = now_ns(ctx);
            try wait_until(ctx, reporter, required, notarized_by_self, 10, 30);
            const average_ns = (now_ns(ctx) - start) / required;
            try testing.expect(average_ns < latency_ms * std.time.ns_per_ms);
            for (harness.validators) |*validator| validator.reporter.assert_no_invalid();
        }

        test "stable leader optimistic blocks faster than network latency" {
            if (comptime !ed25519) return error.SkipZigTest;
            _ = try E.run_seeded(0, faster_than_latency_scenario, .{});
        }

        /// commonware `pipelined_handoff_reduces_boundary_latency`: with two-view terms and voted
        /// handoffs, each term-start view notarizes within two link latencies of its parent.
        fn boundary_latency_scenario(ctx: Context) !void {
            const latency_ms = 100;
            const first = 10;
            const last = last_view;
            const term_length: consensus_types.TermLength =
                .new(utils.NonZero(u32).init(2).?);
            var harness: Harness = undefined;
            const link = E.link_ms(latency_ms, 0, 1.0);
            _ = try start_cluster(&harness, ctx, link, term(2, 20, 4), 10, .vote);
            defer harness.deinit();
            const reporter = &harness.validators[0].reporter;
            var observed_ns: [last - first + 1]u64 = undefined;
            for (&observed_ns, first..) |*at, view| {
                try wait_until(ctx, reporter, view, notarized, 1, 30);
                at.* = now_ns(ctx);
            }
            var boundaries: u32 = 0;
            for (observed_ns[1..], observed_ns[0 .. observed_ns.len - 1], first + 1..) |
                at,
                parent_at,
                view,
            | {
                if (!View.new(view).is_term_start(term_length)) continue;
                boundaries += 1;
                try testing.expect(at - parent_at < 2 * latency_ms * std.time.ns_per_ms);
            }
            try testing.expectEqual((last - first) / 2, boundaries);
            try check_clean(&harness);
        }

        test "pipelined handoff reduces boundary latency" {
            if (comptime !ed25519) return error.SkipZigTest;
            _ = try E.run_seeded(0, boundary_latency_scenario, .{});
        }

        /// commonware `pipelined_handoff_halves_rotating_view_time`: rotating leaders with voted
        /// handoffs average under 1.5 link latencies per view across views 10 to 100 (40 when
        /// quick).
        fn rotating_view_time_scenario(ctx: Context) !void {
            const latency_ms = 100;
            const first = 10;
            const last = last_view;
            var harness: Harness = undefined;
            const link = E.link_ms(latency_ms, 0, 1.0);
            _ = try start_cluster(&harness, ctx, link, RoundRobin.default(), 10, .vote);
            defer harness.deinit();
            const reporter = &harness.validators[0].reporter;
            try wait_until(ctx, reporter, first, notarized, 1, 60);
            const start = now_ns(ctx);
            try wait_until(ctx, reporter, last, notarized, 1, 60);
            const average_ns = (now_ns(ctx) - start) / (last - first);
            try testing.expect(average_ns < 3 * latency_ms * std.time.ns_per_ms / 2);
            try check_clean(&harness);
        }

        test "pipelined handoff halves rotating view time" {
            if (comptime !ed25519) return error.SkipZigTest;
            _ = try E.run_seeded(0, rotating_view_time_scenario, .{});
        }

        /// Every reporter finalized `view`.
        fn all_finalized(harness: *Harness, view: u64) bool {
            for (harness.validators) |*validator| {
                if (validator.reporter.finalized(.new(view)) == null) return false;
            }
            return true;
        }

        /// commonware `stable_leader_finalizes_full_term_without_nullification`: a 1 s link puts
        /// the leader timeout below a certification round trip, so a 1000-view term finalizes
        /// without nullification only through optimistic pipelining.
        fn full_term_scenario(ctx: Context) !void {
            const required = 1000;
            var harness: Harness = undefined;
            const link = E.link_ms(1000, 1, 1.0);
            const round_robin = term(1000, 6, 100);
            const leader = try start_cluster(&harness, ctx, link, round_robin, 1, .wait);
            defer harness.deinit();
            const deadline = now_ns(ctx) + 25 * std.time.ns_per_s;
            while (!all_finalized(&harness, required)) {
                if (now_ns(ctx) >= deadline) return error.TestTimedOut;
                try ctx.sleep(.fromMilliseconds(10));
            }
            const leader_reporter = &harness.validators[leader].reporter;
            try testing.expect(notarized_by_self(leader_reporter, .new(required)));
            var tip = (try leader_reporter.notarization(.new(required))) orelse
                return error.TipNotarizationMissing;
            defer tip.deinit(E.gpa);
            try testing.expectEqual(required - 1, tip.proposal.parent.get());
            try check_clean(&harness);
            for (harness.validators) |*validator| {
                try testing.expectEqual(0, validator.reporter.nullifications.count());
                var finalization = (try validator.reporter.finalization(.new(required))) orelse
                    return error.TipFinalizationMissing;
                defer finalization.deinit(E.gpa);
                try testing.expectEqual(required, finalization.proposal.round.view.get());
                try testing.expectEqual(required - 1, finalization.proposal.parent.get());
            }
            const blocked = try harness.oracle().blocked(E.gpa);
            defer E.gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        test "stable leader finalizes full term without nullification" {
            if (comptime !ed25519 or !build_options.slow_tests) return error.SkipZigTest;
            _ = try E.run_seeded(0, full_term_scenario, .{});
        }

        /// commonware's stable-leader optimistic variants: five-view terms, a 13 s stall timeout,
        /// and two optimistic views.
        fn optimistic_terms() RoundRobin {
            return term(5, 13, 2);
        }

        test "unclean shutdown with a stable leader optimistic" {
            if (comptime !ed25519 or !slow_variants) return error.SkipZigTest;
            var runner = try runtime.deterministic.Runner.init(E.gpa, .{ .seed = 0 });
            defer runner.deinit();
            const restarts_max = 200;
            const required: u64 = if (E.quick) 15 else 100;
            const args = .{ required, optimistic_terms() };
            const restarts = for (0..restarts_max) |restart| {
                if (try (try runner.start_context(E.unclean_run, args))) break restart;
            } else return error.TestUnexpectedResult;
            try testing.expect(restarts > 0);
        }

        test "backfill with a stable leader optimistic" {
            if (comptime !ed25519 or !slow_variants) return error.SkipZigTest;
            // A long stall timeout keeps the healthy prefix (one validator offline) from
            // stall-nullifying.
            _ = try E.run_seeded(0, E.backfill_scenario, .{term(5, 51, 2)});
        }

        test "one offline with a stable leader" {
            if (comptime !mocks or !slow_variants) return error.SkipZigTest;
            _ = try E.run_seeded(0, E.one_offline_scenario, .{term(3, 12, 0)});
        }

        test "partition with a stable leader optimistic" {
            if (comptime !ed25519 or !slow_variants) return error.SkipZigTest;
            _ = try E.run_seeded(0, E.partition, .{optimistic_terms()});
        }

        test "slow and lossy links with a stable leader optimistic" {
            if (comptime !ed25519 or !slow_variants) return error.SkipZigTest;
            const required: u64 = if (E.quick) 10 else 20;
            _ = try E.run_seeded(6, E.slow_and_lossy_links, .{ required, optimistic_terms() });
        }

        test "equivocator is blocked with a stable leader optimistic" {
            if (comptime !ed25519 or !slow_variants) return error.SkipZigTest;
            const detected = for (0..5) |seed| {
                var runner = try runtime.deterministic.Runner.init(E.gpa, .{ .seed = seed });
                defer runner.deinit();
                const args = .{optimistic_terms()};
                if (try (try runner.start_context(E.equivocator_run, args))) break true;
            } else false;
            try testing.expect(detected);
        }

        /// commonware `1k`: ten validators on lossy links with jittered application latencies
        /// finalize 1000 views without faults, invalid activity, or blocks.
        fn thousand_scenario(ctx: Context) !void {
            const required = 1000;
            var harness: Harness = undefined;
            try harness.start_network(ctx, 10, E.link_ms(80, 10, 0.98), .honest, .{});
            defer harness.deinit();
            harness.propose_latency = .{ .mean = 100, .std_dev = 50 };
            harness.verify_latency = .{ .mean = 50, .std_dev = 40 };
            harness.certify_latency = struct {
                fn latency(_: usize) application_mod.Latency {
                    return .{ .mean = 50, .std_dev = 40 };
                }
            }.latency;
            for (0..10) |index| try harness.start_validator(index);
            try harness.wait_all(required);
            for (harness.validators) |*validator| {
                validator.reporter.assert_no_faults();
                validator.reporter.assert_no_invalid();
            }
            const blocked = try harness.oracle().blocked(E.gpa);
            defer E.gpa.free(blocked);
            try testing.expectEqual(0, blocked.len);
        }

        test "1k views finalize" {
            if (comptime !mocks or !build_options.slow_tests) return error.SkipZigTest;
            _ = try E.run_seeded(0, thousand_scenario, .{});
        }
    };
}

test {
    _ = Suite(MockFixture);
}
