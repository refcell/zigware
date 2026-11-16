//! Bulletproofs (commonware `cryptography/src/zk/bulletproofs`): the inner product argument,
//! and the circuit argument built on it (with the `zk.circuit` converter).

pub const ipa = @import("bulletproofs/ipa.zig");
pub const circuit = @import("bulletproofs/circuit.zig");
pub const zkc = @import("bulletproofs/zkc.zig");

test {
    _ = ipa;
    _ = circuit;
    _ = zkc;
    _ = @import("bulletproofs/ipa_test.zig");
    _ = @import("bulletproofs/circuit_test.zig");
}
