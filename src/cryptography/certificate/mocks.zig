//! Mocks for certificate signing schemes (commonware `certificate/mocks.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ed25519 = @import("../ed25519.zig");

/// Identities, identity private keys, per-participant signing schemes, and one verifier.
/// Every slice is owned and released by `deinit`.
pub fn Fixture(comptime S: type) type {
    return struct {
        const Self = @This();

        /// The participants' ed25519 identity keys, sorted.
        participants: []ed25519.PublicKey,
        /// The identity private keys, in the order of `participants`.
        private_keys: []ed25519.PrivateKey,
        /// One signing scheme per participant, in the order of `participants`.
        schemes: []S,
        /// A scheme that verifies but cannot sign.
        verifier: S,

        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(self.participants.len == self.private_keys.len);
            assert(self.participants.len == self.schemes.len);
            for (self.private_keys) |*key| key.zeroize();
            for (self.schemes) |*scheme| scheme.deinit(gpa);
            gpa.free(self.participants);
            gpa.free(self.private_keys);
            gpa.free(self.schemes);
            self.verifier.deinit(gpa);
            self.* = undefined;
        }
    };
}
