# Architecture

zigware mirrors the commonware monorepo crate for crate. Each crate is one Zig package with
the same name, the same public concepts, and the same dependency edges.

| commonware | zigware |
| --- | --- |
| `<crate>/src/lib.rs` | `src/<crate>/root.zig` |
| `<crate>/src/<module>` | `src/<crate>/<module>/` (or `<module>.zig`) |
| `<crate>/fuzz/` | `std.testing.fuzz` tests next to the code, plus seeded fuzz in `zig build test` |
| `<crate>/src/**/conformance.rs` | the same conformance hashes, checked by `zig build test` |
| `examples/<name>` | `examples/<name>/main.zig`, a `run-<name>` build step |
| `macros`, `*/macros` | comptime code in the package that uses it (no separate package) |
| `docs`, `mcp`, `sol`, `docker`, `pipeline` | not ported |

## Packages and dependency order

`build.zig` declares one module per package and lets a package import only the packages
its Rust crate depends on. The order below is a valid build order: each line depends only
on lines above it.

| Package | Imports | commonware size (Rust lines) |
| --- | --- | ---: |
| formatting | | 0.6k |
| allocator | | 2.2k |
| bench | | 1.8k |
| conformance | formatting | 0.8k |
| invariants | formatting | 0.6k |
| simd | invariants | 9k |
| codec | conformance, formatting | 9k |
| utils | codec, formatting, conformance, invariants | 35k |
| parallel | utils | 26k |
| math | codec, invariants, parallel, utils, simd | 4.6k |
| cryptography | codec, formatting, math, parallel, utils, invariants, simd, conformance | 87k |
| runtime | codec, cryptography, formatting, parallel, utils, conformance | 99k |
| actor | runtime, utils | 2.8k |
| storage | codec, cryptography, formatting, parallel, runtime, utils, math, conformance | 220k |
| stream | codec, cryptography, formatting, math, runtime, utils | 4.3k |
| coding | codec, cryptography, parallel, storage, utils, runtime, invariants | 4.3k |
| clearing | codec, cryptography, formatting, parallel, storage, utils, runtime | 16k |
| p2p | actor, codec, cryptography, math, parallel, runtime, stream, utils | 42k |
| broadcast | actor, codec, cryptography, p2p, parallel, runtime, utils | 3.3k |
| collector | actor, codec, cryptography, p2p, runtime, utils | 2.4k |
| resolver | actor, codec, cryptography, p2p, runtime, stream, utils | 14k |
| consensus | actor, broadcast, codec, coding, cryptography, formatting, math, parallel, p2p, resolver, runtime, storage, utils | 139k |
| glue | everything above except clearing, collector, deployer | 68k |
| deployer | cryptography, utils | 8.8k |

Rust line counts include tests, which are a large share of every crate.

## Principles

- **Same wire formats.** Codec encodings, storage layouts, network messages, hashes, and
  signatures are byte-identical to commonware's. Commonware's conformance hashes and test
  vectors are ported with the code and must pass.
- **The runtime is the only door to the OS.** Commonware passes a `Context` that implements
  `Spawner`, `Clock`, `Network`, `Storage`, `Metrics`, and an RNG. zigware does the same
  with `runtime.Context`: library code never reads the clock, opens a socket or file, or
  draws randomness except through it. There are two runtimes behind one interface:
  - **deterministic**: single-threaded, seeded scheduler on stackful tasks, simulated time,
    in-memory storage with fault injection, and an auditor hash of every event, so any run
    replays exactly from its seed and two runs can be compared;
  - **production**: io_uring on Linux (kqueue on macOS) through `std.Io`, real clock and
    sockets, files on disk.
  The runtime lane owns the exact interface and documents it in `src/runtime/root.zig`.
- **Actors and bounded mailboxes.** Long-lived components are actors that own their state
  and talk through bounded mailboxes (`actor`), as in commonware.
- **Simulated networks for protocols.** p2p ships `simulated` (in the deterministic
  runtime: links with latency, jitter, drops, partitions) and `authenticated` (real TCP with
  the `stream` encrypted handshake). Broadcast, resolver, and consensus are tested on the
  simulated network with many nodes and Byzantine actors, like commonware's tests.
- **Generics are comptime.** Rust traits become comptime interfaces (a type parameter
  checked with `comptime` assertions) or small vtables where dynamic dispatch is needed.
  Proc macros become comptime functions.
