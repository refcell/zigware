//! deployer: Deploy infrastructure across cloud providers.
//!
//! Zig port of commonware's `commonware-deployer` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/deployer). See
//! docs/lanes/deployer.md for what is ported.

const std = @import("std");

pub const ip = @import("ip.zig");
pub const IpAddr = ip.IpAddr;
pub const yaml = @import("yaml.zig");
/// AWS EC2 deployer (commonware `deployer::aws`).
pub const aws = @import("aws/mod.zig");
/// The `deployer` command line (commonware `deployer/src/main.rs`).
pub const cli = @import("cli.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("yaml_test.zig");
}
