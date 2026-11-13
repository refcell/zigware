//! Zero-knowledge building blocks (commonware `cryptography/src/zk`): arithmetic circuits
//! over the math lane's ring interfaces. Bulletproofs and `pedersen_to_plain` come next.

pub const circuit = @import("zk/circuit.zig");

test {
    _ = circuit;
}
