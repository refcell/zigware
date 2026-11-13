# zigware

[![Zig](https://img.shields.io/badge/Zig-0.17.1-F7A41D?style=for-the-badge&logo=zig&logoColor=white)](#installation)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](#installation)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=for-the-badge)](#design)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange?style=for-the-badge)](#packages)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

zigware is the [Commonware Library](https://github.com/commonwarexyz/monorepo) rewritten from
scratch in Zig: codec, cryptography, a deterministic runtime, storage, authenticated p2p,
broadcast, and BFT consensus, with zero dependencies.

It is a ground-up port of the public commonware monorepo and keeps its layout: every crate
there is a package here with the same name and the same dependency graph, and wire formats
are byte-identical so the two can interoperate.

> [!WARNING]
> zigware is pre-alpha and being ported now. Do not use it in production.

## Packages

| Package | What it does | Status |
| --- | --- | --- |
| [codec](src/codec) | Serialize structured data | porting |
| [cryptography](src/cryptography) | Keys, signatures, hashes, BLS12-381 threshold crypto | porting |
| [math](src/math) | Fields, polynomials, NTT | porting |
| [runtime](src/runtime) | Async tasks with a deterministic scheduler or io_uring | porting |
| [storage](src/storage) | Journals, archives, MMRs, authenticated databases | porting |
| [utils](src/utils) | Shared functionality across primitives | porting |
| [parallel](src/parallel) | Parallel folds with pluggable strategies | porting |
| [actor](src/actor) | Coordinate concurrent components | planned |
| [stream](src/stream) | Encrypted messages over any transport | planned |
| [p2p](src/p2p) | Communicate with authenticated peers | planned |
| [broadcast](src/broadcast) | Disseminate data over a wide-area network | planned |
| [resolver](src/resolver) | Resolve data by a fixed-length key | planned |
| [collector](src/collector) | Collect responses to committable requests | planned |
| [coding](src/coding) | Erasure-code data for recovery from fragments | planned |
| [clearing](src/clearing) | Settle actions at scale | planned |
| [consensus](src/consensus) | Order messages in a Byzantine environment (simplex, marshal) | planned |
| [glue](src/glue) | Default constructions spanning several primitives | planned |
| [deployer](src/deployer) | Deploy infrastructure across cloud providers | planned |

Support packages: [formatting](src/formatting), [conformance](src/conformance),
[invariants](src/invariants), [simd](src/simd), [allocator](src/allocator),
[bench](src/bench). [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) maps every commonware crate
to its package and lists the dependency order.

## Design

- **Zero dependencies.** Only the Zig standard library: no C libraries, no vendored code,
  `build.zig.zon` has an empty `.dependencies`. BLS12-381, ed25519, secp256r1, the hashes,
  Reed-Solomon, the runtime, and the storage engines are all implemented here.
- **Same wire formats.** Encodings, storage layouts, and network messages match
  commonware's byte for byte, checked against commonware's own test vectors and
  conformance hashes.
- **Deterministic simulation testing.** All time, randomness, tasks, network, and storage go
  through the runtime. The deterministic runtime runs real protocol code on a simulated
  network with fault injection, and any run replays exactly from its seed.
- **TigerStyle.** Assertions on every precondition, postcondition, and invariant; every
  loop, queue, and mailbox bounded; no recursion; functions ≤ 70 lines. See
  [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md).
- **Fuzzed.** Every decoder, parser, and state machine has a coverage-guided fuzz target
  and a seeded fuzz run that executes with the normal test suite.
- **io_uring.** The production runtime is completion-based IO on Linux, kqueue on macOS.

## Installation

```sh
git clone https://github.com/refcell/zigware && cd zigware
just release
```

`just release` needs [`just`](https://github.com/casey/just) and `curl`. It uses Zig 0.17.1
from `PATH`, or downloads it into `.cache/zig`, and writes optimized binaries to
`zig-out/bin`. zigware has no other build dependency. There are no tagged releases; build
from `main`.

Use a package from your own `build.zig` through the `zigware` module, or one package by
name (`b.dependency("zigware", .{}).module("codec")`).

## Contributing

`just` lists every development recipe. `zig build test` runs every package's tests and
`zig build test-<package>` runs one. Contributor rules are in [AGENTS.md](AGENTS.md); the
port's work split is in [docs/lanes](docs/lanes/README.md) and
[docs/ROADMAP.md](docs/ROADMAP.md).

## License

[MIT](LICENSE). zigware is a port of the Commonware Library, which is dual-licensed under
MIT and Apache 2.0.
