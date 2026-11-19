# bridge

Send succinct consensus certificates between two networks.

A Zig port of commonware's
[`commonware-bridge`](https://github.com/commonwarexyz/monorepo/tree/main/examples/bridge).

![Two networks finalize each other's certificates](../../docs/assets/bridge-demo.gif)

([video](../../docs/assets/bridge-demo.mp4); `etc/scripts/record-demo.sh bridge` records it
again.)

## Status

Every example is ALPHA upstream
([stability](https://github.com/commonwarexyz/monorepo#stability)). The port is complete:
`bridge-dealer`, `bridge-indexer`, and `bridge-validator`, which interoperate with commonware's
binaries. See [docs/lanes/examples-estimator.md](../../docs/lanes/examples-estimator.md).

## Usage

Build the three binaries once:

```sh
zig build -Doptimize=ReleaseFast
```

`examples/bridge/local.sh /tmp/zigware-bridge` runs everything below in one command, with each
process's log in that directory. The steps it takes follow.

## Generate Shared Secrets

### Network 1

```sh
mkdir -p /tmp/zigware-bridge
zig-out/bin/bridge-dealer --seed 1 --participants 1,2,3,4 | tee /tmp/zigware-bridge/network-1.txt
```

```txt
polynomial: 00000000040385bcdb782d3c7c11e637d6cc2609... (588 hex digits)
public: 85bcdb782d3c7c11e637d6cc2609ecf1caba021c... (192 hex digits)
share (index=0 validator=4): 003521e062da79bd64dc8c5e0d07f07d64c805a137153ef2e6fa5485d28026990e
share (index=1 validator=1): 016b63f2c22039b703a52e4903a00986d2ea63361d3a6ef33b00330a52d4dce155
share (index=2 validator=2): 023fa89505734c5ab4d8727e5011e17fd0fee654d1f05496f0a9660025432adc38
share (index=3 validator=3): 0325dd6e7ffd4f25c0a992d5fa671a4064594ca15836ee3a06f5ed6748cb1089b8
```

### Network 2

```sh
zig-out/bin/bridge-dealer --seed 2 --participants 5,6,7,8 | tee /tmp/zigware-bridge/network-2.txt
```

```txt
polynomial: 000000000403a505888a5ef6fdd0f1f8b8c840f3... (588 hex digits)
public: a505888a5ef6fdd0f1f8b8c840f3bc20a648300b... (192 hex digits)
share (index=0 validator=7): 004dba2ad66b0bb0760cdfc1b1e51fb96fb3b6bdd8cdd451beca1fb0247b2071c0
share (index=1 validator=8): 014342ca6e1877c338e416dc67bb836c996ca78e5c99dc12e937008e810c59ba44
share (index=2 validator=5): 0255ccd5a1f8962ce3e665d75f504d27e33db466838eb38476a162a32e4e73341a
share (index=3 validator=6): 03116aa51ee1c9702ee092da9099db1347d31fa24aac5c4a680945ee2d416cdf41
```

The polynomial and public key run to hundreds of hex digits, so the commands below read them
from the saved output. Define these two helpers in every terminal first:

```sh
field() { awk -v key="$2" '$1 == key { print $NF }' /tmp/zigware-bridge/network-$1.txt; }
share() { awk -v v="validator=$2)" 'index($0,v) { print $NF }' /tmp/zigware-bridge/network-$1.txt; }
```

## Start Indexer

```sh
zig-out/bin/bridge-indexer --me 0@3000 --participants 1,2,3,4,5,6,7,8 \
    --networks "$(field 1 public:),$(field 2 public:)"
```

## Start Validators

### Network 1 (Run at Least 3 to Make Progress)

#### Participant 1 (Bootstrapper)

```sh
zig-out/bin/bridge-validator --me 1@3001 --participants 1,2,3,4 \
    --storage-dir /tmp/zigware-bridge/1 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 1 polynomial:)" --share "$(share 1 1)" \
    --other-public "$(field 2 public:)"
```

#### Participant 2

```sh
zig-out/bin/bridge-validator --me 2@3002 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 \
    --storage-dir /tmp/zigware-bridge/2 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 1 polynomial:)" --share "$(share 1 2)" \
    --other-public "$(field 2 public:)"
```

#### Participant 3

```sh
zig-out/bin/bridge-validator --me 3@3003 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 \
    --storage-dir /tmp/zigware-bridge/3 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 1 polynomial:)" --share "$(share 1 3)" \
    --other-public "$(field 2 public:)"
```

#### Participant 4

```sh
zig-out/bin/bridge-validator --me 4@3004 --bootstrappers 1@127.0.0.1:3001 --participants 1,2,3,4 \
    --storage-dir /tmp/zigware-bridge/4 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 1 polynomial:)" --share "$(share 1 4)" \
    --other-public "$(field 2 public:)"
```

### Network 2 (Run at Least 3 to Make Progress)

#### Participant 5 (Bootstrapper)

```sh
zig-out/bin/bridge-validator --me 5@3005 --participants 5,6,7,8 \
    --storage-dir /tmp/zigware-bridge/5 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 2 polynomial:)" --share "$(share 2 5)" \
    --other-public "$(field 1 public:)"
```

#### Participant 6

```sh
zig-out/bin/bridge-validator --me 6@3006 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 \
    --storage-dir /tmp/zigware-bridge/6 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 2 polynomial:)" --share "$(share 2 6)" \
    --other-public "$(field 1 public:)"
```

#### Participant 7

```sh
zig-out/bin/bridge-validator --me 7@3007 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 \
    --storage-dir /tmp/zigware-bridge/7 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 2 polynomial:)" --share "$(share 2 7)" \
    --other-public "$(field 1 public:)"
```

#### Participant 8

```sh
zig-out/bin/bridge-validator --me 8@3008 --bootstrappers 5@127.0.0.1:3005 --participants 5,6,7,8 \
    --storage-dir /tmp/zigware-bridge/8 --indexer 0@127.0.0.1:3000 \
    --identity "$(field 2 polynomial:)" --share "$(share 2 8)" \
    --other-public "$(field 1 public:)"
```

The indexer stores both networks' blocks and finalizations:

```txt
2026-11-19T11:30:56.564734Z  INFO indexer: stored block network=85bcdb782d3c7c11...
2026-11-19T11:30:56.594469Z  INFO indexer: stored finalization network=85bcdb782d3c7c11...
```

Each validator proposes either random data or the other network's latest finalization, which
it verifies against the other network's public key before voting:

```txt
INFO commonware_bridge::application::actor: proposed block=Random(1222903288640180275...)
INFO commonware_bridge::application::actor: finalized view=1 payload=bad0598e9a68fc72...
INFO commonware_bridge::application::actor: proposed block=Bridge(Finalization { proposal: ...
```

### Stalls at 10 messages per second

As in commonware's validator, each consensus channel is rate-limited to 10 messages per second
per peer (commonware: "To support more views per second, increase the rate"). When views run
faster, as in the first seconds of a run, the limiter drops a validator's votes and
certificates, the network can split across two views, and no nullification forms until
`timeout_retry` (10 s) sends the votes again. In one 90 s run of `local.sh` on one machine,
commonware's binaries stalled this way once in each network (views 1 and 49) and this port's
once in one network (view 12, where the limiter dropped every view-11 notarize, notarization,
and finalize broadcast of two validators to all three peers).

## Testing

```sh
zig build test-example-bridge             # this example's tests
zig build run-bridge-dealer -- --help     # the dealer's CLI
zig build run-bridge-indexer -- --help    # the indexer's CLI
zig build run-bridge-validator -- --help  # the validator's CLI
```

## Differences from commonware

- commonware's README shows an older polynomial encoding, without the 6-byte header that its
  dealer binary writes; `bridge-dealer` matches the binary byte for byte
  ([backlog](../../docs/lanes/examples-estimator.md#bridge-commonware-examplesbridge)).
- Field values over 128 bytes print shortened in logs, so the indexer's `network=` field shows
  a prefix ([backlog](../../docs/lanes/examples-estimator.md#bridge-commonware-examplesbridge)).
- Propose and verify share the indexer connection under a mutex instead of commonware's single
  actor ([backlog](../../docs/lanes/examples-estimator.md#bridge-commonware-examplesbridge)).
