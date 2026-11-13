//! Configuration of the p2p resolver engine (commonware `resolver/src/p2p/config.rs`).

const utils = @import("utils");

const Duration = utils.Duration;

/// Configuration for the peer actor over public keys `P`, peer provider `D`, blocker `B`,
/// consumer `C` (byte values), and producer `Pro`.
pub fn Config(
    comptime P: type,
    comptime D: type,
    comptime B: type,
    comptime C: type,
    comptime Pro: type,
) type {
    return struct {
        /// Manages the current set of peers. Peer selection for outbound fetches is
        /// documented in `fetcher.zig`.
        peer_provider: D,
        /// Blocks peers that send invalid responses and reports which peers are blocked.
        blocker: B,
        /// Notified when data is available.
        consumer: C,
        /// Serves data requests.
        producer: Pro,
        /// The maximum size of the mailbox backlog (non-zero).
        mailbox_size: u32,
        /// Local identity of the participant (if any).
        me: ?P,
        /// Maximum wait for a response (non-zero).
        fetch_timeout: Duration,
        /// Delay after an unresolved attempt before retrying its fetch. Zero permits
        /// immediate retries, subject to the sender's rate limit.
        fetch_retry_delay: Duration,
        /// Whether requests are sent with priority over other network messages.
        priority_requests: bool,
        /// Whether responses are sent with priority over other network messages.
        priority_responses: bool,
    };
}
