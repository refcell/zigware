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
- `Matrix(P, H, A)`: `empty(gpa)`, `from_sorted(gpa, rows)` (takes the payment maps),
  reference-counted `clone`/`deinit`, `root`, `len`, `is_empty`, `rows`, `payment_maps`,
  `payments(sender)`, `payments_root(sender)`, `open(gpa, sender, receiver)`;
  `matrix.root(H, P, senders, roots)` (allocation-free), `matrix.leaf`.
- `Opening(P, D, A)`: `row`, `entry`, `verify_row(H, root, sender)`,
  `verify(H, root, sender, receiver)`, codec, `clone`, `eql`, `deinit`.

- `payment`: `State(P, D)` (`message`, `sign`, `verify`, `acknowledge`,
  `verify_acknowledgement`), `Signatures(P)`, `Latest(P, D, A)` (`state`, `payments` pointers),
  `Request(P, D, A)` (`states(H, gpa, epoch, account, batch, latest, previous)` takes the
  batch, `verify(H, ns, epoch)`; codec cfg = max receivers), `States` (`request`, `sign`),
  `Verified.admit(H, gpa, latest, previous)`, `Admission` (`retry`/`new`),
  `Receipt(P, O, D, A)` (`issue(H, gpa, ...) ?[]Receipt`, `verify(H, ns, operator)`),
  `Challenge(P, O, D, A)` (`verify(H, ns, operator, epoch, matrix_root)`), `RequestError`,
  `ChallengeError`. Signers and operators are passed by pointer (`anytype`).
- `settlement`: `Total(A)`, `Flow(A)` (`settle(previous) FlowError!Settled`), `Settled(A)`,
  `Flows(P, A)` (`init(gpa, epoch, rows, withdrawals, deposits, forced)`, `len`, `account(i)`,
  `settle(gpa, previous) -> Settlement`), `FlowError`.
- `close`: `Withdrawal(P, A)` (`sign`, `message`, `verify`, `order_request`), `Deposit(P, A)`,
  `ForcedWithdrawal(P, A)`, `Queue(P, A)` (borrows its slices; `prefix`), `Row(P, A)`,
  `Limits`, `Close(P, O, A)` (`sign`/`assemble` take ownership of the row and withdrawal
  slices; `assemble` returns `Assembled{ close, flows }`; `message`, `matrix_root`,
  `matrix(H, gpa, strategy)`, codec with cfg `Limits`), `AssemblyError`.

## Decisions
- Errors carry no payload (`WrongEpoch`'s expected/found are dropped), as in other lanes.
- `Amounts` owns its entry slice (Rust `Vec`); `Lookup` owns its proof. Values are freed with
  `deinit`; decoded values the same way.
- `Amounts.root` folds the bmt with a per-level counter instead of building a `Tree`, so
  computing a payment map's root never allocates; a test checks it against `storage.bmt` for
  0..69 leaves. Openings still build the real tree.
- Lookup's non-member verification runs the bmt multi-proof on a stack `FixedBufferAllocator`.
- `Matrix` shares its rows like commonware's `Arc` (atomic reference count); the per-row
  payment trees are built on first `open` under a spin lock (commonware's `OnceLock`).
- `arbitrary.zig` ports the crate's `Arbitrary` impls (ed25519 keys/signatures, SHA-256
  digests, and every protocol type) on top of `codec.arbitrary`; conformance types that draw
  ed25519 keys skip in Debug unless `-Dslow-tests` (CI's ReleaseSafe run checks them).
- `Flows` collects one part per payment, deposit, and withdrawal, stable-sorts by account, and
  merges, instead of commonware's `HashMap` then sort; sums are exact, so the flows match.
- `Close::check` is `Checked(P, H, A).check(O, ...)`: Zig cannot add the method from
  validator.zig, and the check borrows the close instead of consuming it (it clones the
  payment maps into the matrix).
- The fuzz targets read their choices from bytes (as storage's do) and draw values from
  `codec.arbitrary` seeds. The decode target also decodes each drawn value's encoding with two
  bytes flipped, which commonware's does not. The verify target runs 8 seeded cases in Debug
  (signatures dominate) and 256 otherwise; each input runs in an arena.
- build.zig: clearing also imports `conformance` and `invariants` (commonware dev-deps).

## Backlog
- [x] lib.rs types and traits (`Epoch`, `Amount`), namespace.
- [x] amounts and lookup, with their tests and conformance hashes.
- [x] matrix (Matrix, Opening) with tests and conformance hash.
- [x] payment (State, Signatures, Request, States, Verified, Admission, Receipt, Challenge)
  with every test and its five conformance hashes.
- [x] settlement (Total, Flow, Settled, Flows), close (Withdrawal, Deposit, ForcedWithdrawal,
  Queue, Row, Limits, Close, assembly) with their tests and six conformance hashes.
- [x] summary (Processed, Summary, genesis, verify) with its tests and two conformance hashes;
  the ledger vector's genesis digest, initial payout-log root, and first running hash match.
- [x] validator: Payout, PayoutProof (codec, verify), Checkpoint, `Checked.check` with the
  check tests; Payout and PayoutProof conformance hashes match.
- [x] validator: `Payouts` (keyless `Db` over the MMR), `Payout.stage`, and the payout-log tests.
- [ ] validator: BalanceProof, `settle`, `apply`, and the database tests need qmdb `current`
  (after `any` unordered fixed in storage-qmdb). The check tests build parents without
  settling until then.
- [ ] tests.rs ledger vector, and the integration tests (clearing/tests/bajillion).
- [x] Fuzz targets `src/clearing/fuzz/{decode,verify}.zig` (commonware clearing/fuzz), seeded
  in `zig build test` and under `std.testing.fuzz`; BalanceProof joins them with qmdb `current`.
- [ ] Benches (`src/clearing/benches.zig`).

## Log
- 2026-11-16: namespace, amounts, lookup with their tests; Amounts and Lookup conformance
  hashes match commonware.
- 2026-11-16: matrix (Matrix, Opening) with its tests; the Opening conformance hash matches.
- 2026-11-16: payment (states, requests, admission, receipts, challenges) with every test;
  its five conformance hashes match.
- 2026-11-16: settlement and close with their tests; the Flow, Deposit, ForcedWithdrawal,
  Withdrawal, Row, and Close conformance hashes match.
- 2026-11-16: summary and the database-free validator (payouts, payout proofs, checkpoints,
  close checks); 18 of the 19 conformance hashes match (BalanceProof waits on qmdb `current`).
- 2026-11-16: the payout log on storage's keyless `Db`: `Payouts`, `Payout.stage`, and the
  stage and payout-proof tests.
- 2026-11-16: the decode and verify fuzz targets; 25,600 decode and 5,120 verify cases clean
  in ReleaseSafe soaks.
