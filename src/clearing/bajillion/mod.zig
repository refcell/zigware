//! Settle payments between accounts in epochs (commonware `clearing::bajillion`).
//!
//! An operator admits signed payment states from senders, closes each epoch into a payment
//! matrix, and signs the close. Validators check the close as the successor of the last post,
//! settle it on their balances and payout log, and certify its summary. A ledger posts certified
//! summaries, halts on a receiver's challenge, and pays out withdrawals and claims with proofs.
//! commonware's module documentation (clearing/src/bajillion/mod.rs) specifies every role's
//! obligations and the wire formats; this port keeps those formats byte for byte.
//!
//! Generic parameters follow commonware: `P` is an account key (`PublicKey`), `O` the
//! operator's key, `D` a digest, `H` a hasher, and `A` an amount, any unsigned integer type
//! (`u64`, `u128`, or a codec `uN` such as `u256`).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const cryptography = @import("cryptography");

pub const namespace = @import("namespace.zig");
pub const amounts = @import("amounts.zig");
pub const lookup = @import("lookup.zig");
pub const matrix = @import("matrix.zig");
pub const payment = @import("payment.zig");
pub const settlement = @import("settlement.zig");
pub const close = @import("close.zig");
pub const summary = @import("summary.zig");
pub const validator = @import("validator.zig");

pub const Namespace = namespace.Namespace;
pub const Amounts = amounts.Amounts;
pub const AmountsError = amounts.Error;
pub const Lookup = lookup.Lookup;
pub const InvalidOpening = lookup.InvalidOpening;
pub const Matrix = matrix.Matrix;
pub const Opening = matrix.Opening;
pub const State = payment.State;
pub const Signatures = payment.Signatures;
pub const Request = payment.Request;
pub const States = payment.States;
pub const Verified = payment.Verified;
pub const Admission = payment.Admission;
pub const Receipt = payment.Receipt;
pub const Challenge = payment.Challenge;
pub const RequestError = payment.RequestError;
pub const ChallengeError = payment.ChallengeError;
pub const Flow = settlement.Flow;
pub const FlowError = settlement.FlowError;
pub const Settled = settlement.Settled;
pub const Close = close.Close;
pub const Row = close.Row;
pub const Withdrawal = close.Withdrawal;
pub const Deposit = close.Deposit;
pub const ForcedWithdrawal = close.ForcedWithdrawal;
pub const Queue = close.Queue;
pub const Limits = close.Limits;
pub const AssemblyError = close.AssemblyError;
pub const Processed = summary.Processed;
pub const Summary = summary.Summary;
pub const SummaryError = summary.SummaryError;
pub const CountRange = summary.CountRange;
pub const Payout = validator.Payout;
pub const PayoutProof = validator.PayoutProof;
pub const Checkpoint = validator.Checkpoint;
pub const Checked = validator.Checked;
pub const CheckError = validator.CheckError;

/// An epoch number. Epochs start at one, and epoch zero names the state before the first close.
pub const Epoch = u64;

/// Asserts that `A` is an amount: an unsigned integer with a fixed big-endian encoding
/// (commonware's `Amount`, implemented by the primitive unsigned integers and `Uint`).
pub fn assert_amount(comptime A: type) void {
    comptime {
        const info = @typeInfo(A);
        if (info != .int or info.int.signedness != .unsigned or A == usize) {
            @compileError("clearing: an amount is an unsigned integer: " ++ @typeName(A));
        }
        assert(codec.fixed_size(A).? == (info.int.bits + 7) / 8);
    }
}

/// Asserts that `P` is an account key: a fixed-size, ordered public key.
pub fn assert_public_key(comptime P: type) void {
    comptime cryptography.signer.assert_public_key(P);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("amounts_test.zig");
    _ = @import("lookup_test.zig");
    _ = @import("matrix_test.zig");
    _ = @import("payment_test.zig");
    _ = @import("settlement_test.zig");
    _ = @import("close_test.zig");
    _ = @import("summary_test.zig");
    _ = @import("validator_test.zig");
    _ = @import("conformance_test.zig");
}
