# Roadmap

zigware ports the whole Commonware Library. Lanes run in parallel, each in its own clone,
and start when what they build on has landed (or can be stubbed behind an interface).

| Wave | Lane | Owns | Starts when |
| --- | --- | --- | --- |
| 1 | codec | formatting, conformance, invariants, codec | now |
| 1 | utils | utils, parallel, allocator, bench | now |
| 1 | crypto | cryptography (hashes, ed25519, secp256r1, certificate, handshake, reed_solomon, zk, ...) | now |
| 1 | bls-math | math, simd, cryptography/bls12381 (primitives, dkg, tle, certificate) | now |
| 1 | runtime | runtime: interface, deterministic runtime, iobuf, storage, network, io_uring | now |
| 1 | storage-merkle | storage: merkle (mmr, mmb), bmt, bitmap, index, rmap, translator | now |
| 2 | actor-stream | actor, stream | runtime interface |
| 2 | storage-journal | storage: journal, metadata, archive, freezer, ordinal, queue, cache | runtime storage |
| 2 | p2p | p2p: simulated, authenticated, utils | actor, stream |
| 2 | coding-clearing | coding, clearing | crypto reed_solomon, storage |
| 3 | broadcast-resolver | broadcast, collector, resolver | p2p simulated |
| 3 | storage-qmdb | storage: qmdb (any, current, immutable, keyless, compact, sync, store) | journal, merkle |
| 3 | consensus-simplex | consensus: types, simplex, aggregation | p2p, broadcast, resolver |
| 3 | consensus-marshal | consensus: marshal | simplex, storage archive |
| 4 | glue-examples | glue, deployer, examples (log, chat, dkg, bridge, estimator, flood) | consensus |

Demo recordings for the README come from the examples as they become runnable.
