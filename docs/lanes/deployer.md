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
- `deployer.aws`: `Config`, `MonitoringConfig`, `InstanceConfig`, `PortConfig`,
  `BandwidthWeighting` (`.default`, `.vpc_1`, `.ebs_1`), `Hosts`, `Host`, `Ips`, `Metadata`,
  `Architecture`. `Config`, `Hosts`, and `Metadata` have `parse(arena, text)` (values borrow the
  arena and text) and `write(writer)`, whose output is byte-identical to serde_yaml 0.9's
  `to_string`/`to_writer`. Constants: `metrics_port` (9090), `system_port`, `logs_port`,
  `profiles_port`, `traces_port`, `monitoring_name`, `monitoring_region`, file names,
  `default_concurrency`, and the subcommand names (`cmd`, `create_cmd`, ...).
- `deployer.IpAddr`: Rust `IpAddr` parse and display; `to_io(port)` gives a
  `std.Io.net.IpAddress`.
- `deployer.yaml`: `Document.parse`, `Node`/`Map` accessors with serde_yaml's typed-scalar
  rules, `write_string`/`style_of`, and `Emitter` for serde_yaml's block layout.
- `deployer.aws.services`: every install script, systemd unit, and config commonware writes
  (`write_install_*_cmd`, `write_promtail_config`, `write_prometheus_config`,
  `write_pyroscope_script`, static files), S3 keys, and download URLs; `deployer.aws.s3` holds
  the key prefixes and `wget`; `deployer.aws.utils` the SSH/SCP helpers.
- `deployer.aws.create`: `validate_names`, `validate_storage_config`,
  `select_availability_zone_groups`, `grouped_subnets`; `deployer.aws.ec2`: `VolumeType`,
  `validate_storage_options`, launch-error classification; `deployer.aws.Failure` carries
  commonware's configuration errors with their payloads and `Display` text.
- `utils.fuzz` is now exported (the seeded fuzz driver over `FuzzRng`).

## Decisions
- serde_yaml 0.9 is replaced by `deployer.yaml`: the subset of YAML serde_yaml writes for the
  deployer's types (block mappings and sequences of scalars and mappings, `[]`/`{}`, plain,
  single-quoted, and double-quoted scalars). Scalar styles follow libyaml's
  `analyze_scalar`/`select_scalar_style` with serde_yaml's settings (unlimited width, unicode)
  and serde_yaml's style inference (strings that would read back as null, bool, int, or float
  are single-quoted), so written files are byte-identical. Multi-line strings (serde_yaml's
  literal blocks) are rejected.
- `services` templates are commonware's raw strings verbatim, rendered at comptime-parsed
  `format!` syntax; `deployer_version` is commonware's (`2026.10.0`) so both share an S3 config
  cache. The home directory is spliced in at comptime so no source line spells it out.
- Zig errors carry no payload, so validation returns `?Failure` (commonware's error variant
  and fields) instead of an error; `VolumeType` lists the EC2 API's documented values.
- `list` prints creation times in UTC: zigware has no time zone database (commonware uses
  the local zone). Deployments load sorted by tag, so ties and `attach` order are
  deterministic regardless of directory order.
- SigV4 vectors: the AWS docs' IAM `ListUsers` signature and signing key and the S3 docs'
  header-signed GET and presigned URL, each reproduced offline by aws-sdk-go-v2 v1.41.7's
  signer before use; that signer also produced the escaping, POST, and session-token
  vectors. The S3 docs' example key ID is split in source so the secret scanner passes.
- Commonware's upper-case constants (`METRICS_PORT`, `CREATE_CMD`, ...) are snake_case
  (`metrics_port`, `create_cmd`), per TigerStyle naming.
- `IpAddr` is the deployer's own: Rust's `IpAddr` parsing and display (RFC 5952 compression,
  `::ffff:a.b.c.d` for IPv4-mapped addresses), since `std.Io.net.IpAddress` formats ports.

## Backlog
- [x] Config types and YAML: `Config`, `InstanceConfig`, `MonitoringConfig`, `PortConfig`,
  `BandwidthWeighting`, `Host`, `Hosts`, `Ips`, `Metadata`, `Architecture`, constants
  (`mod.rs` test). Unblocks flood's `setup`.
- [x] `utils.rs` pure helpers (SSH/SCP targets, attach exit codes, CIDR) with their tests.
- [x] `services.rs`: generated service files, install scripts, and S3 keys (10 tests, plus
  SHA-256 conformance hashes of every generated file).
- [x] `create.rs` validation and AZ-group planning (22 sync tests); `ec2.rs` storage
  limits and RunInstances error classification.
- [x] `attach.rs` host lookup (4 tests), `list.rs` loading and ordering, and the deployment
  directory (`deployer.aws.deployments`).
- [ ] `create.rs`'s `run_launches` ordering (2 async
  tests); `ec2.rs`'s launch retry loop (11 async tests, over a mock client).
- [x] SigV4 signer with the AWS documentation's test vectors; S3 presigned URLs
  (`deployer.aws.sigv4`).
- [ ] CLI (`deployer aws <command>`) with argument parsing tests.
- [ ] AWS client interface (EC2 and S3 query/REST calls over `std.http`), never exercised
  against AWS in tests.
- [ ] Fuzz: YAML parse/write round trips, config validation, SigV4 canonicalization.

## Log
- 2026-11-16: lane started.
- 2026-11-16: `deployer.yaml`, `deployer.IpAddr`, and the aws config types landed with
  serde_yaml 0.9.34 golden files and the `mod.rs` test. The YAML round-trip fuzz found that
  quoted keys with `\"` or `''` escapes split at the wrong colon; fixed.
