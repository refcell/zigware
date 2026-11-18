//! An operator, a committee of validators, and the ledger they settle on (commonware
//! `clearing/tests/bajillion/main.rs` `Deployment`).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const storage = @import("storage");
const utils = @import("utils");
const bajillion = @import("../../bajillion/mod.zig");
const m = @import("main.zig");

const gpa = m.gpa;
const Sha256 = m.Sha256;
const Digest = m.Digest;
const PublicKey = m.PublicKey;

pub const Summary = bajillion.Summary(Sha256);
/// Ed25519 certificates over summaries from at least `2f + 1` of `3f + 1` validators.
pub const Scheme = cryptography.ed25519.certificate.Scheme(Summary, utils.N3f1);
pub const Fixture = cryptography.certificate.mocks.Fixture(Scheme);
pub const Env = m.roles.validator.Env;
pub const TestValidator = m.roles.validator.Validator(
    PublicKey,
    PublicKey,
    Sha256,
    storage.translator.EightCap,
    u64,
);
pub const TestLedger = m.roles.ledger.Ledger(PublicKey, PublicKey, Scheme, Sha256, u64);
pub const Proposal = TestValidator.Proposal;
pub const Persisted = TestValidator.Persisted;

/// The configuration of a validator keeping its databases in partitions named after `name`.
pub fn config(ns: *const bajillion.Namespace, name: []const u8) TestValidator.Config {
    return .{
        .namespace = ns,
        .operator = m.operator_key().public_key(),
        .limits = m.limits,
        .name = name,
    };
}

/// Opens the validator named `name` on `env` from a copy of `persisted`.
pub fn open_validator(
    env: *Env,
    name: []const u8,
    persisted: *const Persisted,
    posted: ?*const Digest,
) !TestValidator {
    var ns = try m.namespace();
    defer ns.deinit(gpa);
    const copy = try persisted.clone(gpa);
    return TestValidator.init(gpa, env, config(&ns, name), copy, posted);
}

/// The signing schemes of `n` validators and the verifier of their certificates. Every call
/// returns the same keys.
pub fn committee(n: u32) !*Fixture {
    var rng = utils.rng.test_rng();
    const fixture = try gpa.create(Fixture);
    errdefer gpa.destroy(fixture);
    const make = cryptography.ed25519.certificate.fixture;
    fixture.* = try make(Scheme, gpa, &rng, m.namespace_bytes, n);
    return fixture;
}

/// Certifies `summary` with every scheme's signature, as validators that did not check it
/// would. The caller frees the certificate.
pub fn certify_all(schemes: []const Scheme, summary: *const Summary) !Scheme.Certificate {
    const attestations = try gpa.alloc(Scheme.Attestation, schemes.len);
    defer gpa.free(attestations);
    for (schemes, attestations) |*scheme, *attestation| {
        attestation.* = (try scheme.sign(gpa, summary.*)).?;
    }
    return schemes[0].assemble(gpa, attestations, parallel.sequential);
}

/// Whether two certificates encode the same.
pub fn certificates_equal(a: *const Scheme.Certificate, b: *const Scheme.Certificate) !bool {
    const x = try codec.encode(Scheme.Certificate, gpa, a.*);
    defer gpa.free(x);
    const y = try codec.encode(Scheme.Certificate, gpa, b.*);
    defer gpa.free(y);
    return std.mem.eql(u8, x, y);
}

/// Frees each proposal and the slice.
pub fn free_proposals(proposals: []Proposal) void {
    for (proposals) |*proposal| proposal.deinit(gpa);
    gpa.free(proposals);
}

/// An operator, a committee of validators certifying summaries, and the ledger they settle on.
/// Lives on the heap: the ledger borrows the committee's verifier.
pub const Deployment = struct {
    env: *Env,
    operator: m.TestOperator,
    validators: std.ArrayList(TestValidator),
    fixture: *Fixture,
    ledger: TestLedger,
    rng: utils.rng.TestRng,

    /// Starts a deployment with `n` validators keeping their databases on `env` in
    /// partitions named `{name}-{index}`.
    pub fn init(env: *Env, name: []const u8, n: u32) !*Deployment {
        const self = try gpa.create(Deployment);
        errdefer gpa.destroy(self);
        self.env = env;
        self.rng = utils.rng.test_rng();
        self.fixture = try committee(n);
        errdefer destroy_fixture(self.fixture);
        self.validators = .empty;
        errdefer self.deinit_validators();
        const empty: Persisted = .{};
        for (0..n) |index| {
            const partition = try std.fmt.allocPrint(gpa, "{s}-{d}", .{ name, index });
            defer gpa.free(partition);
            try self.validators.ensureUnusedCapacity(gpa, 1);
            self.validators.appendAssumeCapacity(try open_validator(env, partition, &empty, null));
        }
        self.operator = try m.operator();
        errdefer self.operator.deinit();
        var ns = try m.namespace();
        defer ns.deinit(gpa);
        const balances = self.validators.items[0].summary().balances;
        const operator_public = m.operator_key().public_key();
        const verifier = &self.fixture.verifier;
        self.ledger = try TestLedger.init(gpa, &ns, operator_public, verifier, balances);
        return self;
    }

    fn destroy_fixture(fixture: *Fixture) void {
        fixture.deinit(gpa);
        gpa.destroy(fixture);
    }

    fn deinit_validators(self: *Deployment) void {
        for (self.validators.items) |*validator| validator.deinit();
        self.validators.deinit(gpa);
    }

    pub fn deinit(self: *Deployment) void {
        self.ledger.deinit();
        self.operator.deinit();
        self.deinit_validators();
        destroy_fixture(self.fixture);
        gpa.destroy(self);
    }

    /// Checks that the operator and every validator hold each `{ index, balance }`, and that
    /// the ledger holds exactly those balances and the deposits no close processed. Every
    /// posted payout must already be withdrawn.
    pub fn check_balances(self: *Deployment, balances: []const [2]u64) !void {
        var held: u64 = 0;
        for (balances) |entry| {
            const account = m.account(entry[0]);
            try testing.expectEqual(entry[1], self.operator.balance(&account));
            for (self.validators.items) |*validator| {
                try testing.expectEqual(entry[1], try validator.balance(&account));
            }
            held += entry[1];
        }
        for (self.ledger.queue().deposits) |deposit| held += deposit.amount;
        try testing.expectEqual(held, self.ledger.custody());
    }

    /// Checks `close` with every validator against the ledger's queues. Each validator
    /// persists the close before its proposal is certified. The caller frees the proposals.
    pub fn verify(self: *Deployment, closed: *const m.TestClose) ![]Proposal {
        const queue = self.ledger.queue();
        const proposals = try gpa.alloc(Proposal, self.validators.items.len);
        var made: usize = 0;
        errdefer {
            for (proposals[0..made]) |*proposal| proposal.deinit(gpa);
            gpa.free(proposals);
        }
        for (self.validators.items, proposals) |*validator, *proposal| {
            proposal.* = try validator.verify(try closed.clone(gpa), &queue);
            made += 1;
        }
        return proposals;
    }

    /// Certifies the summary every proposal shares with every validator's signature.
    pub fn certify(self: *const Deployment, proposals: []const Proposal) !Scheme.Certificate {
        const summary = &proposals[0].summary;
        for (proposals) |*proposal| try testing.expect(proposal.summary.eql(summary.*));
        return certify_all(self.fixture.schemes, summary);
    }

    /// Posts the summary the proposals share and applies it at every validator. Frees the
    /// proposals. The payouts stay owed.
    pub fn post(self: *Deployment, proposals: []Proposal) !Summary {
        defer free_proposals(proposals);
        var certificate = try self.certify(proposals);
        defer certificate.deinit(gpa);
        const summary = proposals[0].summary;
        try self.ledger.post(&self.rng, &summary, &certificate);
        const posted = summary.digest();
        for (self.validators.items, proposals) |*validator, *proposal| {
            try validator.apply(proposal, &posted);
        }
        return summary;
    }

    /// Closes the operator's epoch, processing every queued request, posts the close, and
    /// withdraws each of its payouts with a proof from a validator. Returns the close; the
    /// caller frees it.
    pub fn close(self: *Deployment) !struct { m.TestClose, Summary } {
        const queue = self.ledger.queue();
        var closed = try m.close_epoch(
            &self.operator,
            &queue,
            queue.deposits.len,
            queue.forced_withdrawals.len,
        );
        errdefer closed.deinit(gpa);
        const proposals = try self.verify(&closed);
        var payouts = try proposals[0].payouts.clone(gpa);
        defer payouts.deinit(gpa);
        const summary = try self.post(proposals);
        try self.withdraw_payouts(summary.epoch, &payouts);
        return .{ closed, summary };
    }

    /// `close`, dropping the close.
    pub fn close_and_drop(self: *Deployment) !Summary {
        var closed, const summary = try self.close();
        closed.deinit(gpa);
        return summary;
    }

    /// Withdraws the `payouts` the posted close of `epoch` owes, each with a proof from a
    /// validator under the payouts root of the last close it applied.
    pub fn withdraw_payouts(self: *Deployment, epoch: m.Epoch, payouts: *const m.Amounts) !void {
        const validator = &self.validators.items[0];
        const applied = validator.summary().epoch;
        for (payouts.entries) |entry| {
            var proof = (try validator.prove_payout(epoch, &entry[0])) orelse
                return error.TestUnexpectedResult; // The close must owe the account a payout.
            defer proof.deinit(gpa);
            const account, const amount = try self.ledger.withdraw_payout(applied, &proof);
            try testing.expect(account.eql(entry[0]));
            try testing.expectEqual(entry[1], amount);
        }
    }
};
