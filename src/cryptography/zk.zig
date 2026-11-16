//! Zero-knowledge building blocks (commonware `cryptography/src/zk`): arithmetic circuits
//! over the math lane's ring interfaces, Bulletproofs (the inner product argument and the
//! circuit argument), and the Pedersen-to-plain commitment equality proof.

pub const circuit = @import("zk/circuit.zig");
pub const bulletproofs = @import("zk/bulletproofs.zig");
pub const pedersen_to_plain = @import("zk/pedersen_to_plain.zig");

test {
    _ = circuit;
    _ = bulletproofs;
    _ = pedersen_to_plain;
    _ = @import("zk/pedersen_to_plain_test.zig");
    _ = @import("zk/fuzz_test.zig");
}
