# codec

Serialize structured data.

A Zig port of commonware's
[`commonware-codec`](https://github.com/commonwarexyz/monorepo/tree/main/codec).

## Status

Stability upstream varies by primitive. lib.rs puts `buf`, `codec`, `config`, `error`,
`extensions`, `mode`, `types`, `util`, and `varint` in the **BETA** scope. `uint`,
`conformance`, and `fuzz` are ALPHA, and so are a few items inside `varint` and `types/lazy`.
See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every backlog item in [docs/lanes/codec.md](../../docs/lanes/codec.md) is done, and every
commonware test is ported or not portable. Vectored writes (`write_bufs`) are not ported yet.

## Modules

- `encode`, `decode_cfg`, `read_cfg`, `write`, `encode_size`, ... ([codec.zig](codec.zig)):
  the core operations. commonware's `Write`, `Read`, and `EncodeSize` traits become comptime
  dispatch on the value's type. Covers integers, floats, bools, arrays, optionals, slices, and
  tuples.
- `Reader`, `Writer` ([buf.zig](buf.zig)): read from one contiguous slice and write into one
  caller-provided slice.
- `Error`, `Diagnostic` ([error.zig](error.zig)): the error set, and the values commonware
  attaches to an error, recorded in the reader.
- `RangeCfg` ([config.zig](config.zig)): a read configuration that limits a value, most often
  a decoded length.
- `varint`, `UInt`, `SInt` ([varint.zig](varint.zig)): protobuf-style varints. Every value
  has exactly one valid encoding.
- `util` ([util.zig](util.zig)): helpers for reading, validating, and sizing encoded values.
- `Bytes` ([types/bytes.zig](types/bytes.zig)): a byte string that borrows the input instead
  of copying it.
- `Map`, `HashMap`, `Set`, `HashSet` ([types/map.zig](types/map.zig)): canonical maps and
  sets. Decoding rejects unsorted and duplicate keys.
- `net` ([types/net.zig](types/net.zig)): `Ipv4`, `Ipv6`, `IpAddr`, and the socket address
  types.
- `mode`, `Modes` ([mode.zig](mode.zig)): a compact encoding for ordered, extensible mode
  values.
- `Lazy(T)` ([types/lazy.zig](types/lazy.zig)): a value decoded on first use. Re-encoding a
  deferred value copies its bytes unchanged.
- `NonZero(T)` ([types/nonzero.zig](types/nonzero.zig)): non-zero unsigned integers.
- `arbitrary` ([arbitrary.zig](arbitrary.zig)): deterministic value generation that matches
  commonware's conformance hashes.
- `fuzz` ([fuzz.zig](fuzz.zig)): the seeded fuzz driver, and `Draws`, which seeded fuzz
  bodies in other packages use too.

## Testing

```sh
zig build test-codec                        # unit, conformance, and seeded fuzz tests
zig build bench -Dbench-filter=codec::lazy  # Lazy benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs. For long, coverage-guided
fuzz runs, use `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the [codec lane decisions](../../docs/lanes/codec.md#decisions).

- Zig errors carry no payload. The payload lives in `Reader.diagnostic` instead.
- Readers take one contiguous slice, with no `Chain` or `Take` buffers. `Bytes` borrows like
  `Viewing`, and `[]const u8` copies like `Vec<u8>`. The wire format is the same.
- Decoding takes an explicit allocator. Types that do not allocate ignore it. `read_fixed`
  and `decode_fixed` use `Allocator.failing`.
- Vectored writes (`write_bufs`, `BufsMut`) are not ported yet. Writes go to one buffer.
- One map and one set implementation serve both the BTree and Hash flavors, with the same wire
  format. The flavor only picks the context of an `Invalid` error.
