//! Configuration of a lookup network (commonware `lookup/config.rs`).
//!
//! Keep network and handshake settings the same across peers (except local credentials,
//! `listen`, `allow_private_ips`, `bypass_ip_check`, `max_peers_per_set`, `mailbox_size`,
//! `send_batch_size`, and `dial_timeout`); otherwise peers may drop connections, misparse
//! messages, or rate limit each other.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const rate_limit = @import("../../rate_limit.zig");
const Resolver = @import("runtime").resolver.Resolver;

const Duration = utils.Duration;
const Quota = rate_limit.Quota;

/// `U` is a stream upgrader (such as `stream.SakeCups(S, C)`).
pub fn Config(comptime U: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = U.PublicKey;

        /// Authenticates peers and establishes their streams.
        upgrader: U,
        /// Prefix of every signed message, against replay (borrowed).
        namespace: []const u8,
        /// Address to listen on.
        listen: std.Io.net.IpAddress,
        /// Whether peers with private IP addresses are allowed.
        allow_private_ips: bool,
        /// Whether DNS ingress addresses are allowed.
        allow_dns: bool,
        /// Whether an inbound connection may come from any IP rather than only a tracked
        /// peer's egress IP. The handshake still authenticates the peer.
        bypass_ip_check: bool,
        /// Largest application payload a sender takes.
        max_message_size: u32,
        /// Most distinct identities at one peer-set index, counting ourselves.
        max_peers_per_set: usize,
        /// Capacity of each connection's queues.
        mailbox_size: usize,
        /// Most queued frames passed to one `send_many` (1 disables batching).
        send_batch_size: usize,
        /// Longest a handshake may take, including admission.
        handshake_timeout: Duration,
        /// Longest an outbound dial attempt may take.
        dial_timeout: Duration,
        /// Minimum time between reservations of one peer.
        peer_connection_cooldown: Duration,
        /// Most handshakes in flight at once.
        max_concurrent_handshakes: u32,
        /// Handshake attempts allowed from one IP.
        allowed_handshake_rate_per_ip: Quota,
        /// Handshake attempts allowed from one subnet.
        allowed_handshake_rate_per_subnet: Quota,
        /// How often we ping each connected peer.
        ping_frequency: Duration,
        /// Average time between dial attempts across all peers.
        dial_frequency: Duration,
        /// Peer sets tracked at once.
        tracked_peer_sets: usize,
        /// How long a blocked peer stays blocked.
        block_duration: Duration,
        /// Resolves DNS ingress before dialing (commonware's runtime `Resolver`): the
        /// deterministic runner's `dns.resolver()` or the production runner's resolver. Without
        /// one, DNS ingress is never dialed.
        resolver: ?Resolver = null,

        /// The fields every constructor sets the same way.
        pub const Base = struct {
            upgrader: U,
            namespace: []const u8,
            listen: std.Io.net.IpAddress,
            max_peers_per_set: usize,
            max_message_size: u32,
            mailbox_size: usize,
        };

        /// Production defaults.
        pub fn recommended(base: Base) Self {
            assert(base.max_peers_per_set > 0 and base.mailbox_size > 0);
            return .{
                .upgrader = base.upgrader,
                .namespace = base.namespace,
                .listen = base.listen,
                .allow_private_ips = false,
                .allow_dns = true,
                .bypass_ip_check = false,
                .max_message_size = base.max_message_size,
                .max_peers_per_set = base.max_peers_per_set,
                .mailbox_size = base.mailbox_size,
                .send_batch_size = 8,
                .handshake_timeout = .from_secs(5),
                .dial_timeout = .from_secs(15),
                .peer_connection_cooldown = .from_secs(60),
                .max_concurrent_handshakes = 512,
                // One concurrent handshake per IP.
                .allowed_handshake_rate_per_ip = Quota.with_period(.from_secs(5)).?,
                .allowed_handshake_rate_per_subnet = .per_second(64),
                .ping_frequency = .from_secs(50),
                .dial_frequency = .from_secs(1),
                .tracked_peer_sets = 4,
                .block_duration = .from_secs(4 * 3600),
            };
        }

        /// Fast connections for local demos; not for production.
        pub fn local(base: Base) Self {
            var config = recommended(base);
            config.allow_private_ips = true;
            config.peer_connection_cooldown = .from_secs(1);
            config.max_concurrent_handshakes = 1_024;
            // 80 concurrent handshakes per IP.
            config.allowed_handshake_rate_per_ip = .per_second(16);
            config.allowed_handshake_rate_per_subnet = .per_second(128);
            config.ping_frequency = .from_secs(5);
            config.dial_frequency = .from_millis(500);
            config.block_duration = .from_secs(3600);
            assert(config.send_batch_size > 0);
            return config;
        }
    };
}
