//! Shard engine for erasure-coded block distribution and reconstruction (commonware
//! `marshal/coding/shards`).
//!
//! The shards subsystem distributes erasure-coded blocks, validates shard authenticity, and
//! reconstructs blocks on demand. Every validator contributes bandwidth proportional to a single
//! shard, while any node can recover the whole `CodedBlock` once enough shards are available.
//!
//! - `Engine` accepts commands over its `Mailbox` to disperse proposer shards, validate and
//!   reshare received shards, and serve reconstruction requests.
//! - It retains reconstruction state and reconstructed blocks in a bounded window of commitment
//!   records; records with the lowest rounds are evicted first.
//! - It tracks subscriptions for shard arrival and block reconstruction, notifying waiters when
//!   data becomes available.

const engine = @import("engine.zig");
const mailbox = @import("mailbox.zig");

pub const Config = engine.Config;
pub const Engine = engine.Engine;
pub const Mailbox = mailbox.Mailbox;
pub const Message = mailbox.Message;

test {
    _ = mailbox;
    _ = @import("metrics.zig");
    _ = @import("state.zig");
    _ = @import("engine_test.zig");
}
