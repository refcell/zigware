# deployer

Deploy infrastructure across cloud providers.

A Zig port of commonware's
[`commonware-deployer`](https://github.com/commonwarexyz/monorepo/tree/main/deployer).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is complete. [docs/lanes/deployer.md](../../docs/lanes/deployer.md) tracks
it: every item in its backlog is done, and all 55 of commonware's deployer tests have
counterparts.

## Modules

- `aws` ([aws/mod.zig](aws/mod.zig)): the AWS EC2 deployer: configuration, hosts, and metadata
  files, the generated service files, the S3 and EC2 calls, and the `create`, `update`,
  `destroy`, `list`, `attach`, `profile`, `authorize`, and `clean` commands.
- `cli` ([cli.zig](cli.zig)): parses `deployer [-v] aws <command> [options]` with clap's rules
  for the options commonware declares.
- `yaml` ([yaml.zig](yaml.zig)): the subset of YAML serde_yaml 0.9 writes for the deployer's
  types, read and written byte for byte.
- `IpAddr` ([ip.zig](ip.zig)): IP addresses parsed and displayed as Rust's `IpAddr` does.
- The `deployer` binary ([main.zig](main.zig)): parses the command line and runs
  the `aws` command over HTTPS, `ssh`/`scp`, and local processes.

## Testing

```sh
zig build test-deployer             # unit tests
zig build run-deployer -- aws list  # run the deployer CLI
```

Tests never call AWS and never hold credentials. AWS calls in tests go through scripted
responses. `list` and `attach` need no credentials.

## Differences from commonware

All of these are recorded in the
[deployer lane decisions](../../docs/lanes/deployer.md#decisions).

- AWS calls go through a small client over `std.http` with zigware's own SigV4 signer, not the
  AWS SDK. EC2 failures print the code, status, and message rather than the SDK's error text.
- Credentials come from the environment or the shared credentials file only. Instance
  metadata, SSO, and credential processes are not supported.
- serde_yaml is replaced by `deployer.yaml`. Written files are byte-identical, but multi-line
  strings are rejected.
- The CLI returns a `Failure` instead of printing clap's messages, and `usage` is a short
  summary rather than clap's text.
- `list` prints creation times in UTC, because zigware has no time zone database.
- `create` uploads to S3 and waits for instances one at a time, where commonware overlaps
  them. In `destroy`, a failed region does not cancel the others.
