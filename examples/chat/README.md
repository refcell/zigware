# chat

Send encrypted messages to a group of friends using `cryptography.ed25519` and
`p2p.authenticated`.

A Zig port of commonware's
[`commonware-chat`](https://github.com/commonwarexyz/monorepo/tree/main/examples/chat).

![Three chat peers exchange encrypted messages](../../docs/assets/chat-demo.gif)

([video](../../docs/assets/chat-demo.mp4); `etc/scripts/record-demo.sh chat` records it again.)

## Status

Every example is ALPHA upstream
([stability](https://github.com/commonwarexyz/monorepo#stability)). The port is complete: the
terminal UI, the CLI, and chatting over `p2p.authenticated.discovery` on the production
runtime. See [docs/lanes/examples-estimator.md](../../docs/lanes/examples-estimator.md).

## Offline Friends

`chat` only sends messages to connected friends. If a friend is offline at the time a message
is sent, `p2p.authenticated` drops the message. You can confirm you are connected to all your
friends in the Metrics pane on the right: `network_tracker_directory_connected` has one sample
per connected friend, which should equal the number of distinct `--friends` entries, excluding
yourself. TAB moves focus between panes and the arrow keys scroll the focused one.

## Synchronized Friends

`p2p.authenticated` requires all friends to have the same set of friends for friend discovery
to work correctly. If you do not synchronize friends, you may be able to form connections
between specific friends but may not be able to form connections with all friends. You can
learn more about why in commonware's
[discovery documentation][discovery].

[discovery]: https://docs.rs/commonware-p2p/latest/commonware_p2p/authenticated/index.html#discovery

## Usage (4 Friends)

Run each friend in its own terminal. ENTER sends the typed message and ESC quits.

### Friend 1 (Bootstrapper)

```sh
zig build run-chat -Doptimize=ReleaseFast -- --me=1@3001 --friends=1,2,3,4
```

### Friend 2

```sh
zig build run-chat -Doptimize=ReleaseFast -- --me=2@3002 --friends=1,2,3,4 \
    --bootstrappers=1@127.0.0.1:3001
```

### Friend 3

```sh
zig build run-chat -Doptimize=ReleaseFast -- --me=3@3003 --friends=1,2,3,4 \
    --bootstrappers=1@127.0.0.1:3001
```

### Friend 4 (Different Friend as Bootstrapper)

```sh
zig build run-chat -Doptimize=ReleaseFast -- --me=4@3004 --friends=1,2,3,4 \
    --bootstrappers=3@127.0.0.1:3003
```

A message sent by friend 1 and one sent by friend 4 reach every friend's Messages pane:

```txt
[11/19 06:13:05] 478b**5266: hello from friend 1
[11/19 06:13:07] 1c0c**f880: friend 4 here
```

### Not Friend (Blocked)

```sh
zig build run-chat -Doptimize=ReleaseFast -- --me=5@3005 --friends=1,2,3,4,5 \
    --bootstrappers=1@127.0.0.1:3001
```

Friends 1 to 4 do not list 5, so none of them connects to it. Its messages reach no one, and
its Logs pane says so:

```txt
[11/19 11:13:09|WARN] commonware_chat::handler => dropped message (input="can anyone hear me")
```

## Testing

```sh
zig build test                  # every package and example, these tests included
zig build run-chat -- --help    # the CLI
```

## Differences from commonware

- commonware's README points at a `p2p_connections` gauge that commonware removed; the Metrics
  pane shows `network_tracker_directory_connected` instead
  ([decisions](../../docs/lanes/examples-estimator.md#decisions)).
- The terminal UI reimplements the slice of ratatui and crossterm that chat draws with, checked
  cell by cell against ratatui's test backend
  ([decisions](../../docs/lanes/examples-estimator.md#decisions)).
