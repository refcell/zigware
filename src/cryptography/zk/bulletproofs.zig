//! Bulletproofs (commonware `cryptography/src/zk/bulletproofs`): the inner product argument.
//! The circuit argument comes next.

pub const ipa = @import("bulletproofs/ipa.zig");

test {
    _ = ipa;
    _ = @import("bulletproofs/ipa_test.zig");
}
