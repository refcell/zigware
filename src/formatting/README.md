# formatting

Format and parse encoded data.

A Zig port of commonware's
[`commonware-formatting`](https://github.com/commonwarexyz/monorepo/tree/main/formatting).

## Status

**BETA** upstream: wire and storage formats are stable, and breaking changes come with a migration
path. See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every formatting item in the backlog of [docs/lanes/codec.md](../../docs/lanes/codec.md) is
checked, and its test audit lists no open formatting tests.

## Modules

- `hex`, `hex_encode` ([root.zig](root.zig)): bytes to lowercase hexadecimal. `hex` allocates
  and the caller frees; `hex_encode` writes into a caller buffer.
- `from_hex` ([root.zig](root.zig)): hexadecimal to bytes. It strips spaces, tabs, CR, and LF,
  then a leading `0X`, then one more `0x` or `0X`, as commonware does. It returns null on
  invalid input.
- `Hex`, `fmt_hex` ([root.zig](root.zig)): a `{f}` formatter that renders bytes as lowercase
  hex without allocating.
- `hex_literal` ([root.zig](root.zig)): comptime parsing of a hex literal into a `[N]u8`
  (commonware's `hex!` macro).

## Testing

```sh
zig build test-formatting                  # unit tests and the hex fuzz targets
zig build bench -Dbench-filter=formatting  # encode, decode, and display benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs. The `std.testing.fuzz`
targets cover the hex round trip and `from_hex`; for long runs use
`zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

- Functions that allocate take an explicit allocator, and the caller frees the result. See the
  [codec lane's formatting API](../../docs/lanes/codec.md#formatting).
- `Hex` has only a `format` method. Commonware's `Debug` and `From<T> for Hex<T>` impls have no
  counterpart. See the [formatting test audit](../../docs/lanes/codec.md#formatting-1).
