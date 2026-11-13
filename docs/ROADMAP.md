# Roadmap

zigware ports the whole Commonware Library. Lanes run in parallel, each in its own clone,
and start when what they build on has landed (or can be stubbed behind an interface).

| Wave | Lane | Owns | Starts when |
| --- | --- | --- | --- |
| 1 | codec | formatting, conformance, invariants, codec | done |
| 1 | utils | utils | now |
| 2 | parallel | parallel, allocator, bench | now (started) |
| 1 | crypto | cryptography (hashes, ed25519, secp256r1, certificate, handshake, zk, ...) | now |
| 1 | bls-math | math, simd, cryptography/bls12381 (primitives, dkg, tle, certificate) | now |
| 1 | runtime | runtime: interface, deterministic runtime, iobuf, storage, network, io_uring | now |
| 1 | storage-merkle | storage: merkle (mmr, mmb), bmt, bitmap, index, rmap, translator | now |
| 2 | actor-stream | actor, stream | done |
| 2 | storage-journal | storage: journal, metadata, queue | runtime storage (started) |
| 2 | storage-archive | storage: archive, freezer, ordinal, cache | segmented journal (started) |
| 2 | p2p | p2p: simulated first, then authenticated | deterministic runtime (started) |
| 2 | coding | coding, storage/bmt, cryptography/reed_solomon | done |
| 3 | broadcast-resolver | resolver | p2p simulated (started) |
| 3 | broadcast-collector | broadcast, collector | p2p simulated (started) |
| 3 | runtime-telemetry | runtime telemetry (metrics registry, traces) | now (started) |
| 3 | examples-estimator | the estimator example, the first README demo | DSL now (started); simulation after p2p simulated |
| 3 | clearing | clearing | qmdb |
| 3 | storage-qmdb | storage: qmdb shared modules, keyless, immutable, any (started) | journal, merkle |
| 3 | storage-qmdb-sync | storage: qmdb current, sync, compact | qmdb any |
| 3 | consensus-simplex | consensus: types, simplex | types now (started); actors after p2p, broadcast, resolver |
| 3 | consensus-marshal | consensus: aggregation, marshal | aggregation now (started); marshal actors after broadcast, resolver, archive |
| 4 | glue-examples | glue, deployer, examples (log, chat, dkg, bridge, estimator, flood) | consensus |

Demo recordings for the README come from the examples as they become runnable.
