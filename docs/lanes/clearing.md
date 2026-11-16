# Lane: clearing

Owns `src/clearing`.

Reference: `~/.cache/zigware/commonware-ref/clearing` (about 16k Rust lines: lib.rs and
`bajillion`: amounts, close, lookup, matrix, namespace, payment, settlement, summary,
validator, tests). Its dependencies are all on main: codec, cryptography (incl. bls12381 and
the certificate mocks), parallel, utils, storage `bmt` and `merkle` (mmr, mmb), conformance,
formatting, and the deterministic runtime for tests. qmdb is only mentioned in comments.

## Public API (on main)
- `clearing.bajillion`: `Epoch` (`u64`), `assert_amount(A)` (any unsigned integer type,
  commonware's `Amount`), `assert_public_key(P)`.
- `Namespace` (`init(gpa, base)`/`derive`, `clone`, `deinit`, `eql`; fields `state`,
  `acknowledgement`, `withdrawal`, `close`, `summary`).
- `Amounts(P, A)`: `init(gpa, entries)` (any order), `from_sorted(gpa, owned)`, `empty`,
  `deinit`, `clone`, `eql`, `is_empty`, `len`, `get`, `total`, `combine(gpa, other)`,
  `position`, `root(H)` (allocation-free), `tree(H, gpa)`, `lookup(D, gpa, tree, account)`,
  codec (cfg `RangeCfg(usize)`), `arbitrary`, `arbitrary_nonempty`; `amounts.leaf(H, P, A, ...)`,
  `amounts.RootBuilder(H)`; errors `ZeroAmount`, `Duplicate`, `TooManyEntries`, `Overflow`.
- `Lookup(K, V, D)`: union `member`/`non_member`, `init(gpa, entries, tree, key)`,
  `verify(H, root, key, leaf) error{InvalidOpening}!?V`, codec, `clone`, `eql`, `deinit`.

## Decisions
- Errors carry no payload (`WrongEpoch`'s expected/found are dropped), as in other lanes.
- `Amounts` owns its entry slice (Rust `Vec`); `Lookup` owns its proof. Values are freed with
  `deinit`; decoded values the same way.
- `Amounts.root` folds the bmt with a per-level counter instead of building a `Tree`, so
  computing a payment map's root never allocates; a test checks it against `storage.bmt` for
  0..69 leaves. Openings still build the real tree.
- Lookup's non-member verification runs the bmt multi-proof on a stack `FixedBufferAllocator`.
- `arbitrary.zig` ports the crate's `Arbitrary` impls (ed25519 keys/signatures, SHA-256
  digests, and every protocol type) on top of `codec.arbitrary`; conformance types that draw
  ed25519 keys skip in Debug unless `-Dslow-tests` (CI's ReleaseSafe run checks them).
- build.zig: clearing also imports `conformance` and `invariants` (commonware dev-deps).

## Backlog
- [x] lib.rs types and traits (`Epoch`, `Amount`), namespace.
- [x] amounts and lookup, with their tests and conformance hashes.
- [ ] matrix (Matrix, Opening) with tests and conformance hash.
- [ ] payment (State, Signatures, Request, States, Verified, Admission, Receipt, Challenge).
- [ ] settlement (Total, Flow, Settled, Flows), close (Withdrawal, Deposit, ForcedWithdrawal,
  Queue, Row, Limits, Close, assembly).
- [ ] summary (Processed, Summary, genesis, verify with the ed25519 certificate scheme).
- [ ] validator (Payout, BalanceProof, PayoutProof codecs and verify; Checkpoint, check).
  `settle`/`apply` need qmdb `current` (balances) and keyless `Db` (payout log), not yet on
  main; build behind a minimal interface until they land.
- [ ] tests.rs ledger vector, and the integration tests (clearing/tests/bajillion).
- [ ] Fuzz targets (clearing/fuzz: decode, verify) and benches (`src/clearing/benches.zig`).

## Log
- 2026-11-16: namespace, amounts, lookup with their tests; Amounts and Lookup conformance
  hashes match commonware.
