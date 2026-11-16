//! Configuration of a discovery network (commonware `discovery/config.rs`).
//!
//! Keep network and handshake settings the same across peers (except local credentials,
//! `listen`, `bootstrappers`, `allow_private_ips`, `max_peers_per_set`, `mailbox_size`,
//! `send_batch_size`, and `dial_timeout`); otherwise peers may drop connections, misparse
//! messages, or rate limit each other.

const std = @import("std");
const assert = std.debug.assert;
const utils = @import("utils");
const traces = @import("runtime").telemetry.traces;
const p2p_types = @import("../../types.zig");
const rate_limit = @import("../../rate_limit.zig");
const types = @import("types.zig");
const directory = @import("directory.zig");

const Ingress = p2p_types.Ingress;
const Duration = utils.Duration;
const Quota = rate_limit.Quota;

/// A peer dialed at startup, at a known address.
pub fn Bootstrapper(comptime P: type) type {
    return directory.Directory(P).Bootstrapper;
}

/// `U` is a stream upgrader (such as `stream.SakeCups(S, C)`) whose `handshake.signer` also
/// signs our discovery records.
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
        /// Our dialable address, advertised to peers.
        dialable: Ingress,
        /// Peers dialed at startup (borrowed).
        bootstrappers: []const Bootstrapper(PublicKey),
        /// Whether DNS ingress addresses are allowed.
        allow_dns: bool,
        /// Whether peers with private IP addresses are allowed.
        allow_private_ips: bool,
        /// Largest application payload a sender takes; gossip frames may be larger.
        max_message_size: u32,
        /// Most distinct identities at one peer-set index, counting ourselves.
        max_peers_per_set: usize,
        /// Capacity of each connection's queues.
        mailbox_size: usize,
        /// Most queued frames passed to one `send_many` (1 disables batching).
        send_batch_size: usize,
        /// How far in the future a gossiped timestamp may be.
        synchrony_bound: Duration,
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
        /// Average time between dial attempts across all peers.
        dial_frequency: Duration,
        /// Failed dials before we ask peers for updated info about a peer.
        dial_fail_limit: usize,
        /// Peer sets tracked at once.
        tracked_peer_sets: usize,
        /// How often we gossip our bit vector (also the ping).
        gossip_bit_vec_frequency: Duration,
        /// Most peer records sent or accepted in one message.
        peer_gossip_max_count: usize,
        /// How long a blocked peer stays blocked.
        block_duration: Duration,
        /// Where the network's tracing events go (commonware's `tracing` subscriber); each part
        /// emits under its commonware module path. Set it from the runtime context's tracer.
        tracer: traces.Tracer = .none,

        /// The fields every constructor sets the same way.
        pub const Base = struct {
            upgrader: U,
            namespace: []const u8,
            listen: std.Io.net.IpAddress,
            dialable: Ingress,
            bootstrappers: []const Bootstrapper(PublicKey),
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
                .dialable = base.dialable,
                .bootstrappers = base.bootstrappers,
                .allow_dns = true,
                .allow_private_ips = false,
                .max_message_size = base.max_message_size,
                .max_peers_per_set = base.max_peers_per_set,
                .mailbox_size = base.mailbox_size,
                .send_batch_size = 8,
                .synchrony_bound = .from_secs(5),
                .handshake_timeout = .from_secs(5),
                .dial_timeout = .from_secs(15),
                .peer_connection_cooldown = .from_secs(60),
                .max_concurrent_handshakes = 512,
                // One concurrent handshake per IP.
                .allowed_handshake_rate_per_ip = Quota.with_period(.from_secs(5)).?,
                .allowed_handshake_rate_per_subnet = .per_second(64),
                .dial_frequency = .from_secs(1),
                .dial_fail_limit = 2,
                .tracked_peer_sets = 4,
                .gossip_bit_vec_frequency = .from_secs(50),
                .peer_gossip_max_count = 32,
                .block_duration = .from_secs(4 * 3600),
            };
        }

        /// Fast discovery for local demos; not for production.
        pub fn local(base: Base) Self {
            var config = recommended(base);
            config.allow_private_ips = true;
            config.peer_connection_cooldown = .from_secs(1);
            config.max_concurrent_handshakes = 1_024;
            // 80 concurrent handshakes per IP.
            config.allowed_handshake_rate_per_ip = .per_second(16);
            config.allowed_handshake_rate_per_subnet = .per_second(128);
            config.dial_frequency = .from_millis(500);
            config.dial_fail_limit = 1;
            config.gossip_bit_vec_frequency = .from_secs(5);
            config.block_duration = .from_secs(3600);
            return config;
        }

        /// An upper bound on any gossip message under this configuration.
        pub fn max_gossip_size(config: *const Self) usize {
            const max_bit_vec: u64 = config.max_peers_per_set;
            return types.max_gossip_size(PublicKey, max_bit_vec, config.peer_gossip_max_count);
        }
    };
}
