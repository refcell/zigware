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
- [ ] `validator` run: p2p, broadcast, marshal, probe, QMDB resolver, reshare, orchestrator,
      and the stateful application. Waits on glue.stateful's `Stateful` actor (utils lane) and
      the QMDB resolver actor (deployer lane); the reshare actor, orchestrator, and probe are on
      main.
- [ ] `bootstrap` run: waits on glue.dkg's bootstrap `Engine` (bls-math lane).
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
- Until glue.dkg's actor `run` lands, `bootstrap` and `validator` parse and exit 1.
- zigware's probe takes the persisted floor's epoch (`floor_epoch`), not the floor, so
  `probe_resumes_persisted_floor` checks the epoch; its manager and blocker come from the
  simulated network instead of a discovery network, since the config only carries them.

- `application.zig`'s hooks take the parent block (propose) or the block height (process)
  directly until glue's stateful `Application` contract lands; its root vectors come from a
  scratch Rust test over commonware's `Database` and `db_config` (heights 1-4, forked batches,
  height 2 applied and finalized).

## Log

- 2026-11-18: config, types, and setup with commonware's tests and vectors.
- 2026-11-18: the clap CLI with commonware-dkg's recorded cases (examples lane).
- 2026-11-18: the application with commonware's state-root vectors (examples lane).
- 2026-11-19: bootstrap's genesis hand-off with commonware's test (examples lane).
- 2026-11-19: the validator's probe config over the sync plan (examples lane).
