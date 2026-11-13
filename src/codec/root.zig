//! codec: Serialize structured data.
//!
//! Zig port of commonware's `commonware-codec` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/codec). Encodings are
//! byte-identical to commonware's.
//!
//! Quick reference (see `codec.zig` for the full type table and the custom type interface):
//!
//! ```zig
//! const bytes = try codec.encode(T, gpa, value);           // Encode::encode
//! defer gpa.free(bytes);
//! const value = try codec.decode_cfg(T, gpa, bytes, cfg);   // Decode::decode_cfg
//! defer codec.free(T, gpa, value);
//! const fixed = codec.encode_fixed(u64, 7);                 // EncodeFixed
//! var reader = codec.Reader.init(bytes);                    // Read::read_cfg
//! const header = try codec.read_cfg(Header, gpa, &reader, .{});
//! ```

const std = @import("std");

const codec_mod = @import("codec.zig");
const buf = @import("buf.zig");
const error_mod = @import("error.zig");

pub const varint = @import("varint.zig");
pub const util = @import("util.zig");
pub const config = @import("config.zig");

pub const Error = error_mod.Error;
pub const Diagnostic = error_mod.Diagnostic;
pub const Reader = buf.Reader;
pub const Writer = buf.Writer;
pub const RangeCfg = config.RangeCfg;
pub const UInt = varint.UInt;
pub const SInt = varint.SInt;
pub const Bytes = @import("types/bytes.zig").Bytes;
const map = @import("types/map.zig");
pub const Map = map.Map;
pub const HashMap = map.HashMap;
pub const Set = map.Set;
pub const HashSet = map.HashSet;
pub const OrderedMap = map.OrderedMap;
pub const OrderedSet = map.OrderedSet;
pub const MapCfg = map.MapCfg;
pub const net = @import("types/net.zig");
pub const Ipv4 = net.Ipv4;
pub const Ipv6 = net.Ipv6;
pub const IpAddr = net.IpAddr;
pub const SocketAddr = net.SocketAddr;
pub const SocketAddrV4 = net.SocketAddrV4;
pub const SocketAddrV6 = net.SocketAddrV6;
const mode_mod = @import("mode.zig");
pub const mode = mode_mod.mode;
pub const Modes = mode_mod.Modes;

pub const Cfg = codec_mod.Cfg;
pub const SliceCfg = codec_mod.SliceCfg;
pub const unit_cfg = codec_mod.unit_cfg;
pub const fixed_size = codec_mod.fixed_size;
pub const max_encode_size = codec_mod.max_encode_size;
pub const owns_memory = codec_mod.owns_memory;
pub const encode_size = codec_mod.encode_size;
pub const encode_size_items = codec_mod.encode_size_items;
pub const write = codec_mod.write;
pub const write_items = codec_mod.write_items;
pub const read_cfg = codec_mod.read_cfg;
pub const read = codec_mod.read;
pub const read_range = codec_mod.read_range;
pub const read_fixed = codec_mod.read_fixed;
pub const read_items = codec_mod.read_items;
pub const read_usize = codec_mod.read_usize;
pub const decode_cfg = codec_mod.decode_cfg;
pub const decode = codec_mod.decode;
pub const decode_range = codec_mod.decode_range;
pub const decode_fixed = codec_mod.decode_fixed;
pub const decode_reader = codec_mod.decode_reader;
pub const encode = codec_mod.encode;
pub const encode_to = codec_mod.encode_to;
pub const encode_fixed = codec_mod.encode_fixed;
pub const free = codec_mod.free;
pub const free_items = codec_mod.free_items;
pub const order = codec_mod.order;
pub const order_items = codec_mod.order_items;

test {
    std.testing.refAllDecls(@This());
    _ = @import("error.zig");
    _ = @import("config.zig");
    _ = @import("varint.zig");
    _ = @import("util.zig");
    _ = @import("buf.zig");
    _ = @import("types/bytes.zig");
    _ = @import("types/primitives.zig");
    _ = @import("types/vec.zig");
    _ = @import("types/tuple.zig");
    _ = @import("types/map_test.zig");
    _ = @import("types/net.zig");
    _ = @import("mode.zig");
    _ = @import("codec_test.zig");
    _ = @import("fuzz_test.zig");
}
