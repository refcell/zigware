//! zigware: the Commonware Library in Zig. Every package, re-exported under one module.

pub const formatting = @import("formatting");
pub const allocator = @import("allocator");
pub const bench = @import("bench");
pub const conformance = @import("conformance");
pub const invariants = @import("invariants");
pub const simd = @import("simd");
pub const codec = @import("codec");
pub const utils = @import("utils");
pub const parallel = @import("parallel");
pub const math = @import("math");
pub const cryptography = @import("cryptography");
pub const curve25519 = @import("curve25519");
pub const runtime = @import("runtime");
pub const actor = @import("actor");
pub const storage = @import("storage");
pub const stream = @import("stream");
pub const coding = @import("coding");
pub const clearing = @import("clearing");
pub const p2p = @import("p2p");
pub const broadcast = @import("broadcast");
pub const collector = @import("collector");
pub const resolver = @import("resolver");
pub const consensus = @import("consensus");
pub const glue = @import("glue");
pub const deployer = @import("deployer");

test {
    @import("std").testing.refAllDecls(@This());
}
