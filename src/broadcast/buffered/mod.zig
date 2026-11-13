//! Broadcast messages to and cache messages from untrusted peers (commonware
//! `broadcast/src/buffered`).
//!
//! The `Engine` accepts and caches messages from other participants, broadcasts messages to
//! peers, and serves cached messages on demand through its `Mailbox`.
//!
//! # Message sizes
//!
//! Each payload the engine sends is the encoding of one message broadcast through its
//! mailbox. The engine adds no framing, so a broadcast message must fit the network's
//! configured maximum message size.
//!
//! # Ingress
//!
//! An ingress task decodes inbound messages and blocks peers whose messages fail to decode
//! with `Config.blocker`. Decoded messages wait in a buffer sized to the network receiver's
//! `capacity()` and are dropped when it is full.
//!
//! # Message caching
//!
//! The cache is a bounded queue of digests per peer. When a peer's queue is full, its oldest
//! digest is removed to make room. Messages referenced by multiple senders stay cached until
//! the last per-sender queue containing them evicts them (each message is stored once).
//!
//! # Peer management
//!
//! Only primary peers of a tracked peer set (`all.primary`) may buffer messages. When a peer
//! is no longer a primary of any tracked set, its buffered messages are evicted unless
//! buffered by another primary peer. A peer that only leaves the latest set keeps its
//! messages through the overlap window.

pub const config = @import("config.zig");
pub const Config = config.Config;
pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;
pub const ingress = @import("ingress.zig");
pub const Mailbox = ingress.Mailbox;
pub const Message = ingress.Message;
pub const GetResult = ingress.GetResult;
pub const metrics = @import("metrics.zig");
pub const mocks = @import("mocks.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("policy_test.zig");
    _ = @import("engine_test.zig");
}
