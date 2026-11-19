# conformance

Automatically assert the stability of encoding and mechanisms over time.

A Zig port of commonware's
[`commonware-conformance`](https://github.com/commonwarexyz/monorepo/tree/main/conformance).

## Status

Upstream, stability varies by primitive, and the crate's source marks no module with a level.
See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every conformance item in the backlog of [docs/lanes/codec.md](../../docs/lanes/codec.md) is
checked.

## Modules

- `compute_hash` ([root.zig](root.zig)): commits seeds `0..n_cases` with a type's `commit`
  and returns the hex SHA-256 of every commitment, each prefixed by its length.
- `find`, `Entry` ([root.zig](root.zig)): look up a type's `n_cases` and hash in the text of a
  conformance TOML file.
- `verify` ([root.zig](root.zig)): checks that a type still produces its recorded hash, and
  fails with `ConformanceMismatch` or `ConformanceMissing`.
- `default_cases` ([root.zig](root.zig)): 65536 cases, used when a test does not pick a count.

## Testing

```sh
zig build test-conformance  # unit tests
```

## Differences from commonware

- conformance does no file I/O. TOML text comes in through `@embedFile`, and a missing entry
  fails and prints the entry to add; commonware writes the file instead. See the
  [codec lane decisions](../../docs/lanes/codec.md#decisions).
- The `conformance_tests!` macro is not ported: call `conformance.verify` in a test instead.
  See the [codec lane backlog](../../docs/lanes/codec.md#backlog).
- The conformance/macros `fixtures` tool for stale TOML entries is not ported, since a missing
  entry already fails `verify`. See the [codec lane backlog](../../docs/lanes/codec.md#backlog).
