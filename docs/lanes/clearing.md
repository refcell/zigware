# Lane: clearing

Owns `src/clearing`.

Reference: `~/.cache/zigware/commonware-ref/clearing` (about 16k Rust lines: lib.rs and
`bajillion`: amounts, close, lookup, matrix, namespace, payment, settlement, summary,
validator, tests). Its dependencies are all on main: codec, cryptography (incl. bls12381 and
the certificate mocks), parallel, utils, storage `bmt` and `merkle` (mmr, mmb), conformance,
formatting, and the deterministic runtime for tests. The validator databases are storage's
qmdb `current` (balances, over the MMB) and `keyless` (payout log, over the MMR).

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
- `summary`: `Processed(D)` (`start`, `next(H, R, requests)`, codec), `Summary(H)` (`genesis(P,
  A, balances)`, `digest`, `verify(gpa, rng, verifier, certificate, epoch, parent, deposits,
  forced_withdrawals, strategy)`, codec; a certificate subject: certify it with
  `cryptography.ed25519.certificate.Scheme(Summary(H), utils.N3f1)`), `CountRange`,
  `SummaryError`.
- `validator`: `Payout(P, A)` (`stage(log, payouts)` returns the log's merkleized batch),
  `Payouts(P, H, A)` (the payout log: `storage.qmdb.keyless.Db` over the MMR on a fixed
  journal), `PayoutOperation(P, A)`, `PayoutProof(P, D, A)` (`verify(H, root)`, codec, owns
  its proof), `Balances(P, H, I, A)` (the balances database: `storage.qmdb.current.Db` over
  the MMB on a fixed journal with index `I`, chunk `balances_chunk_size` = 32),
  `BalanceUpdate(P, A)`, `BalanceProof(D, A)` (`verify(H, P, root, account)`, codec,
  arbitrary), `Checkpoint(P, H, A)` (`clone`, `deinit`), `Checked(P, H, A)` (`check(O, gpa,
  close, namespace, operator, parent, queue, strategy)`, commonware's `Close::check`; the
  close stays the caller's; `settle(gpa, *balances, *log) -> Proposal`), `Proposal(P, H, A,
  B)` (`summary`, `parent`, `matrix`, `payouts`, `batch`, `appends`; `apply(*balances, *log,
  posted) -> Checkpoint`; `deinit`), `CheckError`, `SettleError`, `ApplyError`.
- `src/clearing/fuzz/{decode,verify}.zig`: the fuzz targets; `src/clearing/benches.zig`.

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
- `settle` and `apply` borrow the databases instead of consuming and returning them, and
  `apply` borrows the proposal (cloning its matrix into the checkpoint), so the caller deinits
  a proposal whether or not it applied. After a database error the caller reopens both
  databases, as commonware's dropped handles require. Settle and apply errors are inferred:
  `InvalidCheckpoint`, a `FlowError`, or the databases' own errors.
- The integration roles keep each role's persisted state as plain owned values with
  `clone`/`eql`, and maps as sorted arrays (`roles/map.zig`) in place of `BTreeMap`. Validators
  share one `Env` per test, each in its own partitions: `runtime.storage.faulty` over
  `runtime.storage.memory` with a seeded RNG, which maps onto commonware's `FaultConfig`
  (`env.faults.config.sync_rate` and the other rates) more exactly than the buffer mock's
  `crash()` and `allow_mutations`. `start_and_recover` is `env.crash()` (replay the retention
  journal, retire open handles, reset the fault config) and then `deinit` of the dropped
  validator; a seed varies only the fault draws, not the whole runtime. Commonware's tests
  that open the payout log's partitions directly use `Validator.reopen_log(size)` instead.
- `testing.zig` holds commonware's `tests.rs` helpers: `Harness` (in-memory storage; each
  database registers its metrics afresh on open) and `Store(I)` with `settle`, `apply`,
  `commit`, `roots`, `post`. The database tests are in `validator_db_test.zig`, the ledger
  vector in `ledger_test.zig`.
- model.rs's checker (`tests/bajillion/checker.zig`) is depth first, as commonware's `check`
  (`spawn_dfs`, `finish_when(HasDiscoveries::Any)`, no target state count or depth). Every
  property is an invariant, so the search order changes neither the verdict nor the unique
  state count, and depth first keeps only the stack in memory. No BFS mode. It runs on one
  thread where Stateright uses all cores.
- model.rs's six workloads are in `tests/bajillion/model/` (`workload.zig` the predictors,
  `actions.zig`, `steps.zig`, `properties.zig` the seven invariants, `model_test.zig`). The
  first ("admits one payment", 232 states) runs in every `zig build test`; the other five run
  only with `-Dslow-tests`, best under `-Doptimize=ReleaseSafe`, and print their counts. The
  checker is bounded at 1 << 23 states (commonware has no bound). ReleaseSafe counts: replays a
  dropped request 3,151 (depth 14); halts and claims 74,116 (17); rebuilds on the posted row
  257,586 (21); retries payments 196,690 (17); recovers funds after a halt 3,099,281 (19, about
  9 minutes). The fingerprint hashes the same fields as commonware's derived `Hash` on `World`,
  with its sets kept as sorted maps like the BTreeSets.

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
- [x] validator: BalanceProof codec and arbitrary on storage's `current` KeyValueProof; its
  conformance hash matches, so all 19 do.
- [x] validator: `BalanceProof.verify`, `Balances`, `settle`, `apply`, `Proposal`, and all 15
  validator tests on the databases.
- [x] tests.rs ledger vector in full: every pinned root, digest, and encoding matches.
- [x] Integration test reference roles in `src/clearing/tests/bajillion/roles` (sender,
  receiver, operator, ledger, validator, with a sorted-array `map`), the `Deployment`
  harness, and operator.rs's three tests.
- [x] Integration tests: validator.rs (all 12 tests).
- [x] Integration tests: payments.rs (all 21 tests).
- [x] Integration tests: ledger.rs (all 13 tests, with the reorg module).
- [x] Integration tests: lifecycle.rs (all 6 tests; `schemes` runs secp256r1 users, a
  BLS12-381 operator, secp256r1 certificates, and `u256` amounts on its own small harness).
- [x] `tests/bajillion/checker.zig`: an explicit-state model checker in place of Stateright
  (depth first on an explicit stack, a 64-bit fingerprint visited set as Stateright's, the
  first failing property with its action path, bounded by `max_states`), tested on a planted
  bug.
- [x] model.rs groundwork: `model/world.zig` (World with a deep `clone` and a structural
  fingerprint, and the roles' `clone`) and `model/replay.zig` (the committee replay, memoized
  by the last post and the candidate).
- [x] Integration tests: model.rs's workload, properties, and six workloads on the checker.
- [x] Fuzz targets `src/clearing/fuzz/{decode,verify}.zig` (commonware clearing/fuzz), seeded
  in `zig build test` and under `std.testing.fuzz`; the verify target includes BalanceProof.
- [x] Benches `src/clearing/benches.zig` (zigware's own; commonware's clearing has none):
  `clearing::amounts_root`, `clearing::matrix_open`, `clearing::close_check`.
- Storage benches (assigned after clearing closed), one `benches.zig` per module, each run
  once on smoke inputs under `zig build test`:
  - [x] index (`index::*` 8 criterion benches and `index_scale`; `index_scale` is opt-in in
    commonware, so standard inputs skip it, full inputs run its 20M/100M tier once per variant,
    and smoke inputs run 10,000 keys).
  - [x] merkle (all 12, both families, 160 cases). Zigware's batches hash sequentially, so
    commonware's `workers=8` and `strategy=BatchedParallel` cases keep their names but measure
    the sequential path. The proof benches share one tree per family and size.
  - [x] archive (get, put, restart; prunable and immutable, compression off and 3).
  - [x] freezer (get, put, restart).
  - Per-push smoke runs are trimmed (`bench_support.quick`: smoke inputs without
    `-Dslow-tests`): one or two cases per bench on the smallest input, MMR only, compression
    off, serial reads, and archive fills of 100 items instead of commonware's 1,000 (64 KiB
    values, about 0.9 s per fill in Debug). Index, merkle, archive, and freezer went from about
    55 s to about 3 s together. `-Dslow-tests` (nightly) runs the full smoke list (61, 160, 24,
    and 6 cases). Archive and freezer fill their data on first use, so filtered and listed runs
    skip the fills.
  - `src/storage/bench_support.zig` opens production disk storage under `.zig-cache/tmp` for
    measured runs (as commonware's tokio benches use the disk) and in-memory storage on smoke
    inputs. The archive and freezer `mode=concurrent` reads run one after another, since
    zigware's stores are not shared between tasks.
- Storage test audit (assigned after the benches): tally commonware's tests for archive,
  freezer, ordinal, cache, index, rmap, bitmap, translator, utils, and bmt against zigware,
  written into the owning lane files (storage-archive, storage-merkle, coding), then port the
  open ones in batches with a planted bug each.
  - [x] Tally: 495 tests, 375 ported, 17 partial, 30 open, 73 not portable.
  - [x] Freezer's 9 open tests; archive's slow tests at commonware's sizes; a sync count in
    `runtime.storage.mocks.Recordings`.
  - [x] Archive's open tests: 11 of 14 (markers, sync counts, below-floor syncs, destroys).
  - [x] Archive's marker-damage, floor-rejection, and torn-index-tail tests.
  - [x] Partitioned index `new_range`/`install_range` and its 5 dependent tests.
  - [x] Partials and index's last 2 open tests: 15 partials completed, each with a planted
    bug. Left partial: archive immutable interrupted destroy (its `crash()` drops unsynced
    data, so no recovery runs over uncommitted bytes on disk).

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
- 2026-11-16: benches. ReleaseFast, 256 rows: payment-map root 47 µs, matrix opening and
  verify 1.4 µs, close check 17 ms (about 66 µs per row, mostly the row signature).
- 2026-11-16: BalanceProof codec on storage's `current` proof codecs; all 19 clearing
  conformance hashes match commonware.
- 2026-11-16: settle and apply on storage's `current` balances database: `Balances`,
  `BalanceProof.verify`, `Checked.settle`, `Proposal.apply`, the 15 validator tests, and the
  full ledger vector (balances, summary, balance-proof, and payout-proof encodings match).
  Storage fixes: `current`'s bounded reopen now checks its bitmap floor before the journal
  discards history, and `key_value_proof` compares keys by value.
- 2026-11-18: integration roles (sender, receiver, operator, ledger, validator), the
  deployment harness, operator.rs's tests, and validator.rs's agreement test.
- 2026-11-18: the rest of validator.rs (withdrawals, overdraft, gross flows, settling once,
  resuming, the empty close, interrupted apply over 8 fault seeds, durability, re-attesting,
  and the payout log behind or ahead of the balances), on `runtime.storage.faulty`.
- 2026-11-18: payments.rs, all 21 tests (operator admission, sender and receiver rules, posts
  resolving requests, replays, limits, restarts).
- 2026-11-18: ledger.rs, all 13 tests (queues, posting, halts, challenges, claims, custody,
  payout withdrawals under every posted root, compact ranges, and the reorg case).
- 2026-11-18: lifecycle.rs, all 6 tests, including the mixed-schemes `u256` deployment.
- 2026-11-18: the model checker for model.rs (`tests/bajillion/checker.zig`).
- 2026-11-18: model.rs groundwork: World, its fingerprint, and the memoized committee replay.
- 2026-11-19: model.rs: the workload, its seven properties, and all six workloads (five slow).
- 2026-11-19: storage index benches (`src/storage/index/benches.zig`).
- 2026-11-19: conformance payment and close (about 96 s and 63 s in ReleaseSafe) run only with
  `-Dslow-tests`, in every mode; nightly covers them.
- 2026-11-19: storage merkle, archive, and freezer benches; the storage bench backlog is done.
- 2026-11-19: trimmed the storage benches' per-push smoke runs to about 3 s; the full list
  runs under `-Dslow-tests`.
- 2026-11-19: storage test audit: tallies in storage-archive.md, storage-merkle.md, coding.md.
- 2026-11-19: freezer's 9 open tests, archive slow sizes, and the mock sync count.
- 2026-11-19: partitioned index ranges and their 5 tests.
- 2026-11-19: 11 prunable archive tests (marker publication, below-floor syncs, destroys).
- 2026-11-19: archive's marker-damage, floor-rejection, and torn-tail tests.
- 2026-11-19: storage audit partials and the last index tests; audit backlog done.
