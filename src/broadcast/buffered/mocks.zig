//! Mock implementations for testing (commonware `broadcast/src/buffered/mocks.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const cryptography = @import("cryptography");

const Sha256 = cryptography.Sha256;

/// A simple test message: a commitment and a content, digested by the content alone.
pub const TestMessage = struct {
    /// The commitment of the message.
    commitment: []const u8,
    /// The content of the message.
    content: []const u8,

    pub const Digest = Sha256.Digest;
    pub const Cfg = codec.RangeCfg(usize);

    /// A message owning copies of `commitment` and `content`.
    pub fn init(gpa: Allocator, commitment: []const u8, content: []const u8) !TestMessage {
        const commitment_owned = try gpa.dupe(u8, commitment);
        errdefer gpa.free(commitment_owned);
        const content_owned = try gpa.dupe(u8, content);
        assert(content_owned.len == content.len);
        return .{ .commitment = commitment_owned, .content = content_owned };
    }

    /// A message whose commitment and content are both `message`.
    pub fn shared(gpa: Allocator, message: []const u8) !TestMessage {
        return init(gpa, message, message);
    }

    pub fn digest(message: *const TestMessage) Digest {
        return Sha256.hash(&.{message.content});
    }

    pub fn write(message: TestMessage, writer: *codec.Writer) void {
        codec.write([]const u8, message.commitment, writer);
        codec.write([]const u8, message.content, writer);
    }

    pub fn encode_size(message: TestMessage) usize {
        return codec.encode_size([]const u8, message.commitment) +
            codec.encode_size([]const u8, message.content);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, range: Cfg) codec.Error!TestMessage {
        const commitment = try codec.read_range([]const u8, gpa, reader, range);
        errdefer gpa.free(commitment);
        const content = try codec.read_range([]const u8, gpa, reader, range);
        assert(range.contains(content.len));
        return .{ .commitment = commitment, .content = content };
    }

    pub fn deinit(message: *TestMessage, gpa: Allocator) void {
        gpa.free(message.commitment);
        gpa.free(message.content);
        message.* = undefined;
    }
};

const testing = std.testing;

test "test message round-trips and digests its content" {
    var message = try TestMessage.init(testing.allocator, "commitment", "content");
    defer message.deinit(testing.allocator);
    const encoded = try codec.encode(TestMessage, testing.allocator, message);
    defer testing.allocator.free(encoded);
    var decoded = try codec.decode_cfg(TestMessage, testing.allocator, encoded, .full());
    defer decoded.deinit(testing.allocator);
    try testing.expectEqualStrings("commitment", decoded.commitment);
    try testing.expectEqualStrings("content", decoded.content);
    try testing.expect(decoded.digest().eql(Sha256.hash(&.{"content"})));
}
