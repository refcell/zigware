//! The p2p resolver's mailbox (commonware `resolver/src/p2p/ingress.rs`).
//!
//! Fetches carry their target peers as `ingress.Targets(P)` metadata: duplicate fetches for a
//! key coalesce their subscribers, merge their targets, and an unrestricted fetch clears them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const resolver = @import("../root.zig");
const ingress = @import("../ingress.zig");

const Feedback = actor.Feedback;

/// A key to fetch data for, optionally with target peers.
pub fn FetchKey(comptime K: type, comptime P: type, comptime S: type) type {
    return ingress.FetchKey(K, S, ingress.Targets(P));
}

/// Messages that can be sent to the peer actor.
pub fn Message(comptime K: type, comptime P: type, comptime S: type) type {
    return ingress.Message(K, S, ingress.Targets(P));
}

/// A way to send messages to the peer actor (`Resolver`, `TargetedResolver`).
pub fn Mailbox(comptime K: type, comptime P: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Key = K;
        pub const Subscriber = S;
        pub const PublicKey = P;
        pub const Msg = Message(K, P, S);
        const Fetch = resolver.Fetch(K, S);
        const Targets = ingress.Targets(P);

        gpa: Allocator,
        sender: actor.mailbox.Sender(Msg),

        /// Sends a fetch. A fetch already in progress for the key loses its targets (it may
        /// use any peer). A no-op once the engine has shut down.
        pub fn fetch(self: Self, item: Fetch) Allocator.Error!Feedback {
            return self.fetch_all(&.{item});
        }

        /// Sends fetches for a batch of keys, each clearing existing targets.
        pub fn fetch_all(self: Self, items: []const Fetch) Allocator.Error!Feedback {
            return self.send_batch(items.len, items, null);
        }

        /// Sends a retain request.
        pub fn retain(self: Self, predicate: resolver.Predicate(K, S)) Allocator.Error!Feedback {
            return self.sender.enqueue(.{ .retain = predicate });
        }

        /// Sends a targeted fetch. Targets may be any peers of the latest tracked peer set; a
        /// target outside it is skipped until a later set includes it, and a blocked target
        /// until the network unblocks it. For a fetch already in progress, targets add to its
        /// targets if it has any; an unrestricted fetch stays unrestricted. Targets clear when
        /// the fetch ends.
        pub fn fetch_targeted(
            self: Self,
            item: Fetch,
            targets: []const P,
        ) Allocator.Error!Feedback {
            assert(targets.len > 0);
            const targeted: resolver.Targeted(K, S, P) = .{ .fetch = item, .targets = targets };
            return self.fetch_all_targeted(&.{targeted});
        }

        /// Sends targeted fetches for a batch of keys.
        pub fn fetch_all_targeted(
            self: Self,
            items: []const resolver.Targeted(K, S, P),
        ) Allocator.Error!Feedback {
            return self.send_batch(items.len, null, items);
        }

        fn send_batch(
            self: Self,
            count: usize,
            plain: ?[]const Fetch,
            targeted: ?[]const resolver.Targeted(K, S, P),
        ) Allocator.Error!Feedback {
            assert((plain == null) != (targeted == null));
            var fetches: std.ArrayList(Msg.Fetch) = try .initCapacity(self.gpa, count);
            errdefer {
                for (fetches.items) |*item| item.deinit(self.gpa);
                fetches.deinit(self.gpa);
            }
            for (0..count) |index| {
                var item: Fetch = undefined;
                var targets: Targets = .unrestricted;
                if (plain) |items| {
                    item = items[index];
                } else {
                    item = targeted.?[index].fetch;
                    targets = try Targets.init(self.gpa, targeted.?[index].targets);
                }
                const created = Msg.Fetch.init(self.gpa, item.key, item.subscriber, targets);
                const fetch_key = created catch |err| {
                    targets.deinit(self.gpa);
                    return err;
                };
                fetches.appendAssumeCapacity(fetch_key);
            }
            assert(fetches.items.len == count);
            return self.sender.enqueue(.{ .fetch = .{ .gpa = self.gpa, .fetches = fetches } });
        }

        pub fn clone(self: Self) Self {
            return .{ .gpa = self.gpa, .sender = self.sender.clone() };
        }

        /// Releases this handle; the engine stops once every handle is gone.
        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }
    };
}

comptime {
    resolver.assert_targeted_resolver(Mailbox(u8, u8, u16));
}
