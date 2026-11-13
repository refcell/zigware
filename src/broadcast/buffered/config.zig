//! Configuration for the engine (commonware `broadcast/src/buffered/config.rs`).

/// Configuration for the `Engine`. `P` is the public key, `MCfg` the message codec config,
/// `D` the peer-set provider (a p2p `Manager`), and `B` the blocker.
pub fn Config(comptime P: type, comptime MCfg: type, comptime D: type, comptime B: type) type {
    return struct {
        /// The public key of the participant.
        public_key: P,
        /// Capacity of the application inbox. Requests beyond it wait in order; while in
        /// overflow, broadcasts with the same digest combine recipients and are handled once
        /// at the first broadcast's position. Canceled overflow requests are discarded.
        mailbox_size: u32,
        /// The maximum number of cached items per sender.
        deque_size: usize,
        /// Whether messages are sent over the network as priority.
        priority: bool,
        /// The configuration for decoding messages.
        codec_config: MCfg,
        /// Provider for peer set changes (eviction follows the tracked primary sets).
        peer_provider: D,
        /// Blocks peers whose messages fail to decode.
        blocker: B,
    };
}
