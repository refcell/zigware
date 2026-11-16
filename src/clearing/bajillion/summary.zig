//! Summaries of closes, certified by validators and posted to the ledger
//! (commonware `bajillion/summary.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const storage = @import("storage");
const mod = @import("mod.zig");
const matrix_module = @import("matrix.zig");
const validator = @import("validator.zig");
const arb = @import("arbitrary.zig");

const Epoch = mod.Epoch;
const Mmr = storage.mmr.Family;
const qmdb = storage.qmdb;

/// A ledger queue's requests that one close processes, as their count and the queue's running
/// hash (commonware `Processed<D>`).
///
/// `hash` extends the parent summary's hash by `H(hash || request)` for each request's encoding
/// in queue order, so it covers every request the queue has processed since genesis.
pub fn Processed(comptime D: type) type {
    return struct {
        const Self = @This();

        /// Number of queued requests the close processes.
        count: u64,
        /// Running hash of the queue after the close, over every request it has processed.
        hash: D,

        pub const start: Self = .{ .count = 0, .hash = .empty };

        pub fn eql(a: Self, b: Self) bool {
            return a.count == b.count and a.hash.eql(b.hash);
        }

        /// The record of a close that processes `requests` after the close `self` records. Its
        /// count is the number of requests, and its hash extends `self`'s over them.
        pub fn next(self: Self, comptime H: type, comptime R: type, requests: []const R) Self {
            comptime assert(H.Digest == D);
            var hash = self.hash;
            for (requests) |request| {
                const encoded = codec.encode_fixed(R, request);
                hash = H.hash(&.{ &hash.bytes, &encoded });
            }
            return .{ .count = requests.len, .hash = hash };
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.varint.write(u64, self.count, writer);
            self.hash.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return codec.varint.size(u64, self.count) + D.fixed_size;
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            const count = try codec.varint.read(u64, reader);
            return .{ .count = count, .hash = try codec.read(D, gpa, reader) };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            const count = u.int(u64);
            return .{ .count = count, .hash = try arb.value(D, gpa, u) };
        }
    };
}

/// Why the ledger refuses a post.
pub const SummaryError = error{
    /// The summary is for another epoch.
    WrongEpoch,
    /// The summary does not follow the last posted one.
    WrongParent,
    /// A count is outside the range given.
    InvalidCount,
    /// The certificate does not verify.
    InvalidCertificate,
};

/// An inclusive range of queued request counts, from a queue's required count to its length.
pub const CountRange = struct {
    min: u64,
    max: u64,

    pub fn contains(self: CountRange, count: u64) bool {
        return count >= self.min and count <= self.max;
    }
};

/// The effects of one close, as certified by validators and posted to the ledger (commonware
/// `Summary<H>`).
///
/// A summary's digest is what the next summary names as its parent, so the hasher `H` is part
/// of the type. It is a certificate subject: validators certify its encoding in
/// `Namespace.summary`, with a scheme such as
/// `cryptography.ed25519.certificate.Scheme(Summary(Sha256), utils.N3f1)`.
pub fn Summary(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const D = H.Digest;
        pub const Commitment = qmdb.chain.Commitment(Mmr, D);
        pub const Namespace = mod.Namespace;

        /// The largest encoding: fixed fields, a payouts size, and two counts as varints.
        pub const max_encode_size: usize = 8 + 3 * D.fixed_size +
            3 * (codec.varint.max_size(u64) + D.fixed_size);

        /// Epoch the close finalizes.
        epoch: Epoch,
        /// Digest of the summary of the previous close.
        parent: D,
        /// Root of the payment matrix the close settles.
        matrix: D,
        /// Root of the balances after the close.
        balances: D,
        /// The payout log after the close, as its size and root. Each posted close appends its
        /// payouts in account order, then a commit, and the size counts the initial commit, so
        /// the close's commit sits at `size - 1`.
        payouts: Commitment,
        /// The deposits the close processes, as their count and the queue's running hash.
        deposits: Processed(D),
        /// The forced withdrawals the close processes, as their count and running hash.
        forced_withdrawals: Processed(D),

        /// The summary of the state before the first close, with balances committed by
        /// `balances`, accounts of type `P`, and amounts of type `A`. Both running hashes start
        /// at all zeros, and the payout log holds only its initial commit.
        pub fn genesis(comptime P: type, comptime A: type, balances: D) Self {
            const Encoding = qmdb.value.Fixed(validator.Payout(P, A));
            return .{
                .epoch = 0,
                .parent = .empty,
                .matrix = matrix_module.root(H, P, &.{}, &.{}),
                .balances = balances,
                .payouts = .{ .size = 1, .root = qmdb.keyless.initial_root(Mmr, Encoding, H) },
                .deposits = .start,
                .forced_withdrawals = .start,
            };
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.epoch == b.epoch and a.parent.eql(b.parent) and a.matrix.eql(b.matrix) and
                a.balances.eql(b.balances) and a.payouts.eql(b.payouts) and
                a.deposits.eql(b.deposits) and a.forced_withdrawals.eql(b.forced_withdrawals);
        }

        /// The hash of the summary's encoding (commonware `Digestible`).
        pub fn digest(self: Self) D {
            var buffer: [max_encode_size]u8 = undefined;
            return H.hash(&.{codec.encode_to(Self, self, &buffer)});
        }

        /// `certificate::Subject::namespace`.
        pub fn namespace(_: Self, derived: *const Namespace) []const u8 {
            return derived.summary;
        }

        /// `certificate::Subject::message`: the summary's encoding; the caller frees it.
        pub fn message(self: Self, gpa: Allocator) Allocator.Error![]u8 {
            return codec.encode(Self, gpa, self);
        }

        /// Checks that a ledger expecting the close of `epoch` after the post with digest
        /// `parent` may post this summary under `certificate`. `deposits` and
        /// `forced_withdrawals` each range from the queue's required count to its length.
        ///
        /// The certificate is checked last, and it alone vouches for the matrix and balances
        /// roots, the payouts size and root, and the running hashes.
        pub fn verify(
            self: Self,
            gpa: Allocator,
            rng: anytype,
            verifier: anytype,
            certificate: anytype,
            epoch: Epoch,
            parent: D,
            deposits: CountRange,
            forced_withdrawals: CountRange,
            strategy: anytype,
        ) (SummaryError || Allocator.Error)!void {
            if (self.epoch != epoch) return error.WrongEpoch;
            if (!self.parent.eql(parent)) return error.WrongParent;
            if (!deposits.contains(self.deposits.count)) return error.InvalidCount;
            if (!forced_withdrawals.contains(self.forced_withdrawals.count)) {
                return error.InvalidCount;
            }
            const certified =
                try verifier.verify_certificate(gpa, rng, self, certificate, strategy);
            if (!certified) return error.InvalidCertificate;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(u64, self.epoch, writer);
            self.parent.write(writer);
            self.matrix.write(writer);
            self.balances.write(writer);
            self.payouts.write(writer);
            self.deposits.write(writer);
            self.forced_withdrawals.write(writer);
        }

        pub fn encode_size(self: Self) usize {
            return 8 + 3 * D.fixed_size + self.payouts.encode_size() +
                self.deposits.encode_size() + self.forced_withdrawals.encode_size();
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Self {
            return .{
                .epoch = try codec.read(u64, gpa, reader),
                .parent = try codec.read(D, gpa, reader),
                .matrix = try codec.read(D, gpa, reader),
                .balances = try codec.read(D, gpa, reader),
                .payouts = try Commitment.read(gpa, reader, {}),
                .deposits = try Processed(D).read(gpa, reader, {}),
                .forced_withdrawals = try Processed(D).read(gpa, reader, {}),
            };
        }

        pub fn arbitrary(gpa: Allocator, u: *arb.Unstructured) arb.Error!Self {
            return .{
                .epoch = u.int(u64),
                .parent = try arb.value(D, gpa, u),
                .matrix = try arb.value(D, gpa, u),
                .balances = try arb.value(D, gpa, u),
                .payouts = try Commitment.arbitrary(gpa, u),
                .deposits = try Processed(D).arbitrary(gpa, u),
                .forced_withdrawals = try Processed(D).arbitrary(gpa, u),
            };
        }
    };
}
