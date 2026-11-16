# Lane: deployer

Owns `src/deployer` (commonware `deployer`, about 8.8k Rust lines). Its packages: cryptography
and utils.

Reference: `~/.cache/zigware/commonware-ref/deployer`. Everything in `deployer::aws` that
does not call a cloud API is ported with commonware's tests: the configuration types and their
YAML, validation, availability-zone and subnet planning, the generated service files and S3
key layout, the deployment directory and metadata, and the CLI. AWS calls go through a small
client interface over `std.http` with a SigV4 signer checked against the AWS documentation's
test vectors. Tests never call AWS and never hold credentials.

## Public API (on main)
- (none yet)

## Decisions
- serde_yaml 0.9 is replaced by `deployer.yaml`: the subset of YAML serde_yaml writes for the
  deployer's types (block mappings and sequences of scalars and mappings, `[]`/`{}`, plain,
  single-quoted, and double-quoted scalars). Scalar styles follow libyaml's
  `analyze_scalar`/`select_scalar_style` with serde_yaml's settings (unlimited width, unicode)
  and serde_yaml's style inference (strings that would read back as null, bool, int, or float
  are single-quoted), so written files are byte-identical. Multi-line strings (serde_yaml's
  literal blocks) are rejected.
- `IpAddr` is the deployer's own: Rust's `IpAddr` parsing and display (RFC 5952 compression,
  `::ffff:a.b.c.d` for IPv4-mapped addresses), since `std.Io.net.IpAddress` formats ports.

## Backlog
- [ ] Config types and YAML: `Config`, `InstanceConfig`, `MonitoringConfig`, `PortConfig`,
  `BandwidthWeighting`, `Host`, `Hosts`, `Ips`, `Metadata`, `Architecture`, constants
  (`mod.rs` test). Unblocks flood's `setup`.
- [ ] `utils.rs` pure helpers (SSH/SCP targets, attach exit codes, CIDR) with their tests.
- [ ] `services.rs`: generated service files, install scripts, and S3 keys (10 tests).
- [ ] `attach.rs` host lookup (4 tests); `create.rs` validation and AZ-group planning (24
  tests); `ec2.rs` pure logic (12 tests).
- [ ] SigV4 signer with the AWS documentation's test vectors; S3 presigned URLs.
- [ ] Deployment directory, metadata, and status files; `list`.
- [ ] CLI (`deployer aws <command>`) with argument parsing tests.
- [ ] AWS client interface (EC2 and S3 query/REST calls over `std.http`), never exercised
  against AWS in tests.
- [ ] Fuzz: YAML parse/write round trips, config validation, SigV4 canonicalization.

## Log
- 2026-11-16: lane started.
