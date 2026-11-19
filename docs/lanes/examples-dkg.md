# Lane: examples-dkg

Owner: the examples lane (thread T-01a1d5b9-c891-7699-81af-37a9c87adafc) for the application,
bootstrap, validator, CLI, and demo; the broadcast-resolver thread ported config, types, and
setup. Owns `examples/dkg` (commonware `examples/dkg`).

## Backlog

- [x] `config.zig`: `node.json` and `network.json`, written exactly as `serde_json::to_string_pretty`
      writes them; Rust `SocketAddr` text form.
- [x] `types.zig`: constants, `Block` (codec, digest, `ReshareBlock`), committee rotation
      (`Participants`, a glue `ParticipantsProvider`), `Secrets` (a glue `SecretStore` over
      `storage.metadata`), and `genesis.json`.
- [x] `setup.zig` and the `setup` subcommand.
- [x] `cli.zig`: the clap `Cli` (`--log-level`, `--worker-threads`, `bootstrap`, `setup`,
      `validator`, `help`), byte-identical to `commonware-dkg` over 176 recorded cases.
- [x] `application.zig`: the height-writing QMDB application over `glue.stateful.db.any`,
      checked against commonware's state roots and ranges.
- [x] `bootstrap.zig`: the genesis hand-off (`write_genesis_to_sibling_validators`) with
      commonware's test.
- [x] `validator.zig`: the probe's configuration over the persisted `SyncPlan`
      (`probe_config`, commonware's `probe_resumes_persisted_floor`).
- [x] `provider.zig`: `DynamicProvider`, `Registrar`, and `scheme` (commonware `types.rs`).
- [x] `validator` run: p2p, broadcast, marshal, probe, QMDB resolver, reshare, orchestrator,
      and the stateful application. A 4-peer, committee-3 cluster reshares every epoch
      (`completed reshare ceremony ... success=true` through epoch 3) and recovers on restart.
- [ ] `validator --state-sync` and startup from a persisted state-sync floor: needs glue's
      bootstrap `Node` to take a floor start, plus `Stateful`'s resolvers and sync config.
- [x] `bootstrap.complete`: await the ceremony, hand epoch zero's share to the validator
      store, and write the genesis to sibling validators (singleton ceremony test).
- [x] `bootstrap` run on discovery p2p and the production runner (`network.zig` holds the
      discovery setup the validator shares); runs end to end on a one-node network.
- [ ] Demo recording (`just` recipe `dkg`, etc/scripts/record-demo.sh).

## Decisions

- Vectors in `testdata/` come from a scratch Rust test run against commonware's own types
  (block and genesis encodings and digests, `node.json`, `network.json`, `genesis.json`).
- `setup`'s printed commands run `zig build run-dkg -- ...` where commonware's run
  `cargo run --bin commonware-dkg -- ...`.
- Test names start with `dkg: ` so `-Dtest-filter="dkg: "` runs exactly this example.
- `Secrets` is shared by pointer (commonware clones an `Arc`); a failed write drops the store
  and later calls fail with `error.SecretsFailed` (commonware panics on next use).

- The CLI's help screens are fixed text from `commonware-dkg`; the parser models clap 4.6's
  order of checks (see `cli.zig`). `--worker-threads` is parsed and ignored: the production
  runner runs on `std.Io.Threaded`, not Tokio.
- `validator` builds marshal from glue's bootstrap `Node`, so marshal's own partition is
  `validator-marshal` (commonware: `validator`) and it always starts from genesis; a state-sync
  startup fails with `error.StateSyncUnsupported`. The QMDB resolver and `Stateful` run as
  plain futures (their awaits are not cancelable) and stop at shutdown rather than in
  `select`. zigware's `Stateful` attaches its databases to the resolver only after state sync,
  so the validator attaches them once `Stateful` opens them (commonware's recovery path).
- `Reporter` fans each finalized block out to the stateful, orchestrator, and reshare
  mailboxes with a clone of the block and acknowledgement each, then logs it
  (`commonware_dkg::types: finalized block`, commonware's `LogReporter`).
- zigware's probe takes the persisted floor's epoch (`floor_epoch`), not the floor, so
  `probe_resumes_persisted_floor` checks the epoch; its manager and blocker come from the
  simulated network instead of a discovery network, since the config only carries them.

- `application.zig`'s `App` meets glue.stateful's `Processor` contract (`propose`/`process`
  over the ancestry stream, empty `capture`/`finalized`); `build` and `execute` are their
  cores. Its root vectors come from a scratch Rust test over commonware's `Database` and
  `db_config` (heights 1-4, forked batches, height 2 applied and finalized).
- `App.Input` is glue's `reshare.application.InputOf(Payload)` (`{ gpa, payload }`), the type
  the `reshare.Application` wrapper hands the stateful mailbox.

## Log

- 2026-11-18: config, types, and setup with commonware's tests and vectors.
- 2026-11-18: the clap CLI with commonware-dkg's recorded cases (examples lane).
- 2026-11-18: the application with commonware's state-root vectors (examples lane).
- 2026-11-19: bootstrap's genesis hand-off with commonware's test (examples lane).
- 2026-11-19: the validator's probe config over the sync plan (examples lane).
- 2026-11-19: bootstrap's completion and genesis hand-off on the bootstrap engine (examples lane).
- 2026-11-19: the application on glue.stateful's Processor contract (examples lane).
- 2026-11-19: the `bootstrap` subcommand on the production runtime (examples lane).
- 2026-11-19: the validator composition, resharing across epochs on 4 nodes (examples lane).
