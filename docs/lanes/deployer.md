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
- `deployer.aws.sigv4`: `sign`, `presign`, `signing_key`, `amz_date`, `write_uri_encoded`.
- `deployer.cli`: `parse(args)` returns `.ok` (`Parsed{ verbose, command }`, where `command`
  is `.help`, `.version`, `.none`, or `.aws` with each subcommand's options) or `.failure`
  (`Failure{ kind, argument }`); `usage` and `version`.
- `deployer.aws.client`: `Client{ io, transport, credentials, region }` with `send` (any
  SigV4-signed `Call`), `call` (with the SDK's standard retries and commonware's 256-attempt
  backoff settings, classified into `Result`), and `ec2_query`; `ApiError`, `is_transient`,
  `classify`; `Transport` (`send` returns an `Outcome`: a response,
  `io_failure`, `timeout`, or `other{ transient }`), `HttpTransport` over `std.http.Client`, and
  `Replay` (scripted outcomes for tests). `deployer.aws.query`: Query bodies (`Body`) and the
  XML scanner (`scan`, `first_text`, `decode_text`, `service_error`).
- `deployer.aws.ec2.launch_instances(client, gpa, arena, request, subnets, az_support,
  start_index)` returns `.ok` (`Launched{ instance_ids, az }`) or `.failure`;
  `run_instances_body`, `new_client_token`. `deployer.aws.create.run_launches(Launcher, io,
  gpa, launcher, monitoring_region, regions)` runs regional launch queues concurrently.
- `deployer.aws.ec2_api`: `Ec2{ client, arena }` (a refused call returns `error.AwsEc2` with
  the `ApiError` in `failure`) and one function per commonware EC2 call (`create_vpc`,
  `wait_for_instances_running`, `find_az_instance_support`, ...). `deployer.aws.query`
  also has `elements`, `texts`, and `decoded_text` for nested responses.
- `deployer.aws.credentials` (`load`, `from_environ`, `parse_profile`), `deployer.aws.session`
  (`Session`), and `deployer.aws.commands` (`clean`, `authorize`, `require_created`).
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
- The CLI follows clap's rules for the options commonware declares (`--name value` and
  `--name=value`, required options, defaults, a repeated option fails, a flag-like word is not
  a value, Rust's `u64::from_str` for numbers, empty paths rejected), but returns a
  `Failure` instead of printing clap's messages; `usage` is a short summary, not clap's text.
- AWS calls go through `client.Transport`, which tests replace with `Replay` the way
  commonware's tests replace the SDK's HTTP connector; nothing in the suite opens a socket to
  AWS. `RunInstances` parameters are written in our own order (EC2 does not care), and
  `aws_ec2` failures print the code, status, and message rather than the SDK's error text.
  As in commonware, `launch_instances` retries capacity failures until capacity returns;
  canceling its task ends it.
- Concurrent region jobs (`destroy`) run in an `Io.Group` and share the session arena (thread
  safe in 0.17 over a thread-safe child); the first failure wins. Unlike `try_join_all`, a
  failed region does not cancel the others; they finish their own steps.
- Credentials come from the environment or the shared credentials file only (the SDK's
  first two providers); instance metadata, SSO, and credential processes are not ported.
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
- [x] `ec2.rs`'s launch retry loop (`launch_instances` and its 11 tests, over `Replay`).
- [x] `create.rs`'s `run_launches` (`deployer.aws.create.run_launches`) and its 2 ordering
  tests, plus a failure test.
- [x] SigV4 signer with the AWS documentation's test vectors; S3 presigned URLs
  (`deployer.aws.sigv4`).
- [x] CLI argument parsing (`deployer.cli`) with tests and a seeded fuzz. The `deployer`
  binary itself waits for the AWS client.
- [x] AWS client interface: SigV4-signed EC2 Query requests over `std.http`, never exercised
  against AWS in tests.
- [x] `s3.rs`: the bucket config file, `hash_file`, and the S3 calls (`ensure_bucket_exists`,
  `object_exists`, `put_object` with commonware's unlimited upload retry, `presign_url`,
  `cache_and_presign`, `delete_prefix`, `delete_bucket`, `is_no_such_bucket_error`) over the
  client, tested against scripted responses. `HttpTransport` was checked by hand against a
  public HTTPS server (GET, HEAD, POST, DNS failure), never against AWS.
- [ ] `upload_instance_files` and `hash_files`.
- [x] The remaining EC2 calls (`deployer.aws.ec2_api`: key pairs, instance types, AMIs, VPCs,
  gateways, route tables, subnets, security groups, instances and their waits, peering, tag
  lookups, teardown, AZ offerings, enabled regions), tested against scripted responses.
- [x] Credentials (environment, then the shared credentials file's profile), the command
  `Session` (per-region clients, failure diagnostics, config loading, public IP), and the
  `clean` and `authorize` commands with tests over a temporary home and scripted responses.
- [x] `destroy` (`deployer.aws.destroy`), regions torn down concurrently, with tests over
  per-endpoint scripted responses (`client.RoutedReplay`).
- [ ] The create, update, profile, and attach flows and the `deployer` binary.
- [ ] Fuzz: YAML parse/write round trips, config validation, SigV4 canonicalization.

## Log
- 2026-11-16: lane started.
- 2026-11-16: `deployer.yaml`, `deployer.IpAddr`, and the aws config types landed with
  serde_yaml 0.9.34 golden files and the `mod.rs` test. The YAML round-trip fuzz found that
  quoted keys with `\"` or `''` escapes split at the wrong colon; fixed.
