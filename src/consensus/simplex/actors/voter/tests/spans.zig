//! commonware `simplex/actors/voter/mod.rs` trace-span test: per-view work is attributed to
//! view-scoped spans, and mailbox messages carry their enqueue span into voter processing.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");

pub fn Tests(comptime h: type) type {
    return struct {
        const Ctx = h.Ctx;
        const traces = runtime.telemetry.traces;
        const Event = traces.collector.RecordedEvent;
        const Metadata = traces.collector.EventMetadata;

        fn run(comptime body: fn (Ctx) anyerror!void) !void {
            try h.soak(10 * std.time.ns_per_s, body);
        }

        /// Whether `span` is a view span of epoch 333, view 2.
        fn at_view_2(span: Metadata) bool {
            span.expect_field_exact("epoch", "333") catch return false;
            span.expect_field_exact("view", "2") catch return false;
            return true;
        }

        /// Whether any of `event`'s spans is named `name` and passes `check`.
        fn has_span(event: Event, name: []const u8, comptime check: ?fn (Metadata) bool) bool {
            for (event.spans) |span| {
                if (!std.mem.eql(u8, span.content, name)) continue;
                if (check) |predicate| if (!predicate(span)) continue;
                return true;
            }
            return false;
        }

        /// Whether `event` is `message` with innermost span `name`.
        fn innermost(event: Event, message: []const u8, name: []const u8) bool {
            if (!std.mem.eql(u8, event.metadata.content, message)) return false;
            if (event.spans.len == 0) return false;
            return std.mem.eql(u8, event.spans[0].content, name);
        }

        const checks = struct {
            /// The propose request runs in the propose span (with epoch and view, so it reads
            /// standalone) under view 2's view span.
            fn propose(_: void, event: Event) bool {
                const message = "requested proposal from automaton";
                if (!innermost(event, message, "simplex.voter.propose")) return false;
                if (!at_view_2(event.spans[0])) return false;
                return has_span(event, "simplex.voter.view", at_view_2);
            }

            /// The notarize broadcast happens within notify under the view span.
            fn notify(_: void, event: Event) bool {
                if (!innermost(event, "broadcasting notarize", "simplex.voter.notify")) {
                    return false;
                }
                return has_span(event, "simplex.voter.view", null);
            }

            /// A recovered certificate is processed under the span it was enqueued with.
            fn recovered(_: void, event: Event) bool {
                const message = "received finalization";
                if (!innermost(event, message, "simplex.voter.process")) return false;
                return has_span(event, "simplex.voter.mailbox.recovered", null);
            }
        };

        // commonware test_view_spans_track_automaton_boundary: the automaton propose request
        // and the notarize broadcast nest under `simplex.voter.view`, and mailbox messages
        // carry their enqueue span into voter processing.
        test "voter view spans track automaton boundary" {
            try h.covers(.ed25519);
            try run(struct {
                fn body(ctx: Ctx) anyerror!void {
                    var collector = traces.Collector.init(ctx.gpa(), .{});
                    defer collector.deinit();
                    var subscriber = collector.subscriber();
                    subscriber.level = .trace;
                    var net: h.Network = undefined;
                    try net.start(ctx, 5, "consensus");
                    defer net.deinit();
                    var stack: h.VoterStack = undefined;
                    try stack.start(ctx, &net, .{
                        .leader_timeout_ms = 5_000,
                        .certification_timeout_ms = 5_000,
                        .timeout_retry_ms = 60 * 60 * 1_000,
                        .tracer = .init(subscriber, "commonware_consensus::simplex::voter"),
                    });
                    defer stack.stop();
                    // Round robin over epoch 333 and 5 validators makes us view 2's leader.
                    _ = try stack.next_update(ctx, 5_000);
                    _ = try h.advance_to_view(&stack, ctx, &net, 2);
                    try wait_own_notarize(ctx, &stack);
                    try collector.get_by_level(.debug).expect_event({}, checks.propose);
                    try collector.get_by_level(.debug).expect_event({}, checks.notify);
                    try collector.get_by_level(.trace).expect_event({}, checks.recovered);
                }
            }.body);
        }

        /// Waits up to 5 s per message for our notarize of view 2.
        fn wait_own_notarize(ctx: Ctx, stack: *h.VoterStack) !void {
            // Bounded by the per-message wait.
            while (true) {
                const next = try stack.next_batcher(ctx, 5_000);
                const message = next orelse return error.NoNotarize;
                if (message != .constructed or message.constructed != .notarize) continue;
                if (message.constructed.view().get() == 2) return;
            }
        }
    };
}
