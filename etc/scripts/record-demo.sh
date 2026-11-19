#!/usr/bin/env bash
# Records a README demo: docs/assets/<name>-demo.{cast,gif,mp4}.
#   etc/scripts/record-demo.sh estimator
# Needs asciinema 3, agg, and ffmpeg on PATH. The session itself is scripted below, so a
# re-recording types the same commands.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

name=${1:?usage: record-demo.sh <name>}
out=docs/assets/$name-demo
mkdir -p docs/assets

if [ "${DEMO_SESSION:-}" = "1" ]; then
  # Inside the recording: type each command, then run it.
  type_cmd() {
    printf '\033[1;32m$\033[0m '
    local text=$1 i
    for ((i = 0; i < ${#text}; i++)); do printf '%s' "${text:i:1}"; sleep 0.025; done
    printf '\n'
    sleep 0.4
    eval "$text"
    sleep "${2:-2}"
  }
  case $name in
    estimator)
      zig build -Doptimize=ReleaseFast >/dev/null
      printf '\033[H\033[2J'
      type_cmd 'cat examples/estimator/simplex.lazy' 3
      printf '\n'
      type_cmd 'zig build run-estimator -Doptimize=ReleaseFast -- examples/estimator/simplex.lazy \
--distribution us-east-1:3,eu-west-1:2,ap-northeast-1:2' 6
      ;;
    flood)
      # Build outside the recording when possible: skip it while the binary is fresh.
      if [ -n "$(find src examples/flood build.zig -newer zig-out/bin/flood -print -quit \
        2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/flood ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      rm -rf /tmp/zigware-flood
      printf '\033[H\033[2J'
      type_cmd 'examples/flood/local.sh 4 /tmp/zigware-flood' 1
      printf '\n'
      type_cmd 'examples/flood/demo.sh /tmp/zigware-flood 6' 1
      ;;
    chat)
      if [ -n "$(find src examples/chat build.zig -newer zig-out/bin/chat -print -quit \
        2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/chat ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      # Three friends in one tmux window (its own server, no user config), typed by a driver.
      chat=$(realpath zig-out/bin/chat)
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s chat -x 200 -y 50 "$chat --me=1@3001 --friends=1,2,3"
      t set-option -g status off
      t split-window -h -t chat \
        "$chat --me=2@3002 --friends=1,2,3 --bootstrappers=1@127.0.0.1:3001"
      t split-window -v -t chat \
        "$chat --me=3@3003 --friends=1,2,3 --bootstrappers=1@127.0.0.1:3001"
      mapfile -t panes < <(t list-panes -t chat -F '#{pane_id}')
      say() {
        local pane=$1 text=$2 i
        for ((i = 0; i < ${#text}; i++)); do t send-keys -t "$pane" -l "${text:i:1}"; sleep 0.05; done
        t send-keys -t "$pane" Enter
      }
      (
        sleep 4
        say "${panes[0]}" 'gm frens'
        sleep 1.5
        say "${panes[1]}" 'gm from friend 2'
        sleep 1.5
        say "${panes[2]}" 'zero deps, all zig'
        sleep 3
        # Ends the session on the chat frame (ESC would close each pane first).
        t kill-server
      ) &
      t attach -t chat || true
      wait
      ;;
    log)
      if [ -n "$(find src examples/log examples/ui build.zig -newer zig-out/bin/log -print \
        -quit 2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/log ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      # Four validators in a 2x2 tmux grid (its own server, no user config), from empty storage.
      log=$(realpath zig-out/bin/log)
      rm -rf /tmp/zigware-log-demo
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      validator() {
        local id=$1 flags=${2:-}
        echo "$log $flags --me $id@300$id --participants 0,1,2,3 \
          --storage-dir /tmp/zigware-log-demo/$id"
      }
      boot='--bootstrappers 0@127.0.0.1:3000'
      t kill-server 2>/dev/null || true
      t new-session -d -s log -x 200 -y 44 "$(validator 0)"
      t set-option -g status off
      t split-window -h -t log "$(validator 1 "$boot")"
      t split-window -v -t log "$(validator 3 "$boot")"
      t select-pane -t log -L
      t split-window -v -t log "$(validator 2 "$boot")"
      (
        sleep 7
        # Detach first, so the recording ends on the validators' frames: killing the server
        # closes the panes one by one and tmux redraws before it leaves the screen.
        t detach-client -s log
      ) &
      t attach -t log || true
      wait
      t kill-server
      ;;
    bridge)
      if [ -n "$(find src examples/bridge examples/ui build.zig -newer \
        zig-out/bin/bridge-validator -print -quit 2>/dev/null || echo stale)" ] ||
        [ ! -x zig-out/bin/bridge-validator ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      # An indexer and two networks of 4 (examples/bridge/local.sh) in the background. Once
      # both networks finalize, tmux shows the indexer's stores and each network's first
      # validator: time, message, and fields, with long hex cut short.
      dir=/tmp/zigware-bridge-demo
      rm -rf "$dir"
      NO_COLOR=1 examples/bridge/local.sh "$dir" &
      network=$!
      printf '\033[H\033[2J\033[1mstarting an indexer and two networks of 4 validators\033[0m\n'
      for _ in $(seq 120); do
        grep -qs ' finalized' "$dir/validator-1.log" &&
          grep -qs ' finalized' "$dir/validator-5.log" && break
        sleep 0.5
      done
      line='s/^[0-9-]+T([0-9:]+)\.[0-9]+Z +[A-Z]+ [a-z_:]+: /\1 /'
      line+='; s/([0-9a-f]{8})[0-9a-f]{16,}/\1../g; s/signature=.*//; s/Finalization \{.*/../'
      green='s/(finalized|stored finalization)/\x1b[32m&\x1b[0m/'
      yellow='s/(proposed|stored block)/\x1b[33m&\x1b[0m/'
      follow() {
        local title=$1 file=$2 pattern=$3 width=$4
        printf '%s' "printf '\\033[1m%s\\033[0m\\n' '$title'; tail -n0 -F $dir/$file 2>/dev/null | \
grep --line-buffered -E '$pattern' | sed -u -E '$line; s/^(.{$width}).*/\\1/; $green; $yellow'"
      }
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s bridge -x 160 -y 40 \
        "$(follow 'indexer (both networks)' indexer.log 'stored' 156)"
      t set-option -g status off
      t split-window -v -t bridge \
        "$(follow 'network 1: validator 1' validator-1.log 'actor: (proposed|finalized)' 77)"
      t split-window -h -t bridge \
        "$(follow 'network 2: validator 5' validator-5.log 'actor: (proposed|finalized)' 77)"
      (
        sleep 10
        t detach-client -s bridge
      ) &
      t attach -t bridge || true
      wait %2 2>/dev/null || true
      t kill-server
      kill "$network" 2>/dev/null || true
      wait "$network" 2>/dev/null || true
      ;;
    dkg)
      if [ -n "$(find src examples/dkg examples/ui build.zig -newer zig-out/bin/dkg -print \
        -quit 2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/dkg ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      # commonware's README flow: setup, the epoch-0 bootstrap, then four validators running
      # DKG and resharing over epochs in a 2x2 tmux grid of their trace events. A fifth peer
      # joins mid-run with --state-sync in the bottom pane: it starts from the probe's floor
      # (its first block is the floor's, not genesis) and catches up into the next reshare.
      dir=/tmp/zigware-dkg-demo
      rm -rf "$dir"
      mkdir -p "$dir"
      export PATH="$PWD/zig-out/bin:$PATH" NO_COLOR=1
      trim='s/^[0-9-]+T([0-9:]+)\.[0-9]+Z +/\1 /; s/commonware_glue::dkg::/dkg::/'
      trim+='; s/commonware_//; s/([0-9a-f]{8})[0-9a-f]{16,}/\1../g'
      cat >"$dir/follow.sh" <<EOF
#!/usr/bin/env bash
# Validator \$1's events: every DKG event, its first finalized block, and one in eight.
tail -n +1 -F $dir/validator-\$1.log 2>/dev/null |
  awk '!/finalized block/ || !seen++ || (match(\$0, /height=[0-9]+/) &&
    substr(\$0, RSTART + 7, RLENGTH - 7) % 8 == 0) { print; fflush() }' |
  sed -u -E '$trim; s/^(.{108}).*/\1/;
    s/(completed reshare ceremony.*)/\x1b[32m\1\x1b[0m/; s/(entered epoch)/\x1b[33m\1\x1b[0m/'
EOF
      cat >"$dir/join.sh" <<EOF
#!/usr/bin/env bash
# The late joiner: once every validator completed epoch 1's reshare, type its command, start
# it, and follow its events.
until [ "\$(cat $dir/validator-[0-3].log | grep -c 'completed reshare ceremony epoch=1')" \
  -ge 4 ]; do sleep 0.5; done
command='dkg validator --node-dir $dir/data/validator-4 --state-sync'
printf '\033[1;32m\$\033[0m '
for ((i = 0; i < \${#command}; i++)); do printf '%s' "\${command:i:1}"; sleep 0.025; done
printf '\n'
\$command >$dir/validator-4.log 2>&1 &
echo \$! >$dir/joiner.pid
exec $dir/follow.sh 4
EOF
      chmod +x "$dir/follow.sh" "$dir/join.sh"
      printf '\033[H\033[2J'
      type_cmd "dkg setup --node-dir $dir/data --peers 5 --committee-size 4 --base-port 3500" 3
      printf '\n'
      type_cmd "for i in 0 1 2 3; do dkg bootstrap --node-dir $dir/data/validator-\$i \
>$dir/bootstrap-\$i.log 2>&1 & done" 0
      until [ "$(cat "$dir"/bootstrap-*.log 2>/dev/null | grep -c 'bootstrap complete')" = 4 ]; do
        sleep 0.5
      done
      grep -h 'bootstrap complete' "$dir"/bootstrap-*.log | sed -E "$trim"
      sleep 3
      # Stop the bootstraps and let their ports close before the validators bind them.
      jobs -p >"$dir/bootstrap.pids"
      while read -r pid; do kill "$pid" 2>/dev/null || true; done <"$dir/bootstrap.pids"
      wait 2>/dev/null || true
      while ss -ltn | grep -qE ':350[0-4] '; do sleep 0.2; done
      for i in 0 1 2 3; do
        dkg validator --node-dir "$dir/data/validator-$i" >"$dir/validator-$i.log" 2>&1 &
      done
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s dkg -x 220 -y 50 "$dir/follow.sh 0"
      t set-option -g status off
      t set-option -g pane-border-status top
      t set-option -g pane-border-format ' #[bold]#{pane_title}#[default] '
      t select-pane -t dkg -T 'validator 0'
      t split-window -v -l 14 -t dkg "$dir/join.sh"
      t select-pane -t dkg -T 'validator 4 (joins with --state-sync)'
      t select-pane -t dkg -U
      t split-window -h -t dkg "$dir/follow.sh 1"
      t select-pane -t dkg -T 'validator 1'
      t split-window -v -t dkg "$dir/follow.sh 3"
      t select-pane -t dkg -T 'validator 3'
      t select-pane -t dkg -L
      t split-window -v -t dkg "$dir/follow.sh 2"
      t select-pane -t dkg -T 'validator 2'
      (
        # End just after the joiner completed its first reshare ceremony, while its pane still
        # shows the floor start.
        for _ in $(seq 480); do
          grep -q 'completed reshare ceremony' "$dir/validator-4.log" 2>/dev/null && break
          sleep 0.5
        done
        sleep 2
        t detach-client -s dkg
      ) &
      t attach -t dkg || true
      wait %%
      t kill-server
      if [ -f "$dir/joiner.pid" ]; then kill "$(cat "$dir/joiner.pid")" 2>/dev/null || true; fi
      kill $(jobs -p) 2>/dev/null || true
      wait 2>/dev/null || true
      ;;
    interop)
      # commonware's chat (left) and zigware's (right) as two friends over authenticated
      # discovery: commonware's is built from the reference clone (etc/scripts/interop.sh).
      reference=${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}
      target=${INTEROP_TARGET:-${TMPDIR:-/tmp}/zigware-interop-target}
      (cd "$reference" && CARGO_TARGET_DIR="$target" cargo build --release --offline -q \
        -p commonware-chat)
      if [ -n "$(find src examples/chat build.zig -newer zig-out/bin/chat -print -quit \
        2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/chat ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      rust_chat=$target/release/commonware-chat
      zig_chat=$(realpath zig-out/bin/chat)
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s interop -x 220 -y 50 "$rust_chat --me=1@3201 --friends=1,2"
      t set-option -g status off
      t set-option -g pane-border-status top
      t set-option -g pane-border-format ' #[bold]#{pane_title}#[default] '
      t select-pane -t interop -T 'commonware (Rust): friend 1'
      t split-window -h -t interop \
        "$zig_chat --me=2@3202 --friends=1,2 --bootstrappers=1@127.0.0.1:3201"
      t select-pane -t interop -T 'zigware (Zig): friend 2'
      mapfile -t panes < <(t list-panes -t interop -F '#{pane_id}')
      say() {
        local pane=$1 text=$2 i
        for ((i = 0; i < ${#text}; i++)); do
          t send-keys -t "$pane" -l "${text:i:1}"
          sleep 0.05
        done
        t send-keys -t "$pane" Enter
      }
      (
        # Type once the friends are connected, so no line is dropped.
        for _ in $(seq 120); do
          ss -Htn state established '( sport = :3201 or dport = :3201 )' | grep -q . && break
          sleep 0.5
        done
        sleep 2
        say "${panes[0]}" 'hello from Rust'
        sleep 2
        say "${panes[1]}" 'hello from Zig'
        sleep 4
        t detach-client -s interop
      ) &
      t attach -t interop || true
      wait %%
      t kill-server
      ;;
    interop-log)
      # Two commonware validators (top rows) and two zigware validators (bottom rows) in one
      # simplex network, from empty storage; their Activity panes show the same finalized digests at
      # the same views (etc/scripts/interop_log.py checks it).
      reference=${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}
      target=${INTEROP_TARGET:-${TMPDIR:-/tmp}/zigware-interop-target}
      (cd "$reference" && CARGO_TARGET_DIR="$target" cargo build --release --offline -q \
        -p commonware-log)
      if [ -n "$(find src examples/log examples/ui build.zig -newer zig-out/bin/log -print \
        -quit 2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/log ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      rust_log=$target/release/commonware-log
      zig_log=$(realpath zig-out/bin/log)
      dir=/tmp/zigware-interop-log-demo
      rm -rf "$dir"
      validator() {
        local binary=$1 id=$2 boot=
        [ "$id" = 0 ] || boot='--bootstrappers 0@127.0.0.1:3600'
        echo "$binary $boot --me $id@360$id --participants 0,1,2,3 --storage-dir $dir/$id"
      }
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s ilog -x 220 -y 50 "$(validator "$rust_log" 0)"
      t set-option -g status off
      t set-option -g pane-border-status top
      t set-option -g pane-border-format ' #[bold]#{pane_title}#[default] '
      t select-pane -t ilog -T 'commonware (Rust): validator 0'
      # Full-width rows, so each finalized line shows its digest and view.
      t split-window -v -t ilog "$(validator "$rust_log" 1)"
      t select-pane -t ilog -T 'commonware (Rust): validator 1'
      t split-window -v -t ilog "$(validator "$zig_log" 2)"
      t select-pane -t ilog -T 'zigware (Zig): validator 2'
      t split-window -v -t ilog "$(validator "$zig_log" 3)"
      t select-pane -t ilog -T 'zigware (Zig): validator 3'
      t select-layout -t ilog even-vertical
      (
        sleep 12
        t detach-client -s ilog
      ) &
      t attach -t ilog || true
      wait %%
      t kill-server
      ;;
    interop-dkg)
      # commonware's and zigware's dkg validators in one network (etc/scripts/interop_dkg.py
      # checks it): a mixed epoch-0 DKG, validators rrzzr finalizing the same heights through
      # each epoch's reshare, and zigware's validator 5 joining late with --state-sync.
      reference=${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}
      target=${INTEROP_TARGET:-${TMPDIR:-/tmp}/zigware-interop-target}
      (cd "$reference" && CARGO_TARGET_DIR="$target" cargo build --release --offline -q \
        -p commonware-dkg)
      if [ -n "$(find src examples/dkg build.zig -newer zig-out/bin/dkg -print -quit \
        2>/dev/null || echo stale)" ] || [ ! -x zig-out/bin/dkg ]; then
        zig build -Doptimize=ReleaseFast >/dev/null
      fi
      dir=/tmp/zigware-interop-dkg-demo
      rm -rf "$dir"
      mkdir -p "$dir"
      export PATH="$target/release:$PWD/zig-out/bin:$PATH" NO_COLOR=1
      # One line format for both: drop commonware's colors, thread ids, and source locations.
      trim='s/\x1b\[[0-9;]*m//g; s/ ThreadId\([0-9]+\)//; s/ [a-z_/]+\.rs:[0-9]+://'
      trim+='; s/^[0-9-]+T([0-9:]+)\.[0-9]+Z +/\1 /; s/commonware_glue::dkg::/dkg::/'
      trim+='; s/commonware_//; s/Epoch\(([0-9]+)\)/\1/g; s/([0-9a-f]{8})[0-9a-f]{16,}/\1../g'
      trim+='; s/ dealers=.*//'
      cat >"$dir/follow.sh" <<FOLLOW
#!/usr/bin/env bash
# Validator \$1's events: every DKG event, its first finalized block, and every eighth height,
# so the same heights line up across panes.
tail -n +1 -F $dir/validator-\$1.log 2>/dev/null | sed -u -E '$trim' |
  awk '/reshare ceremony|entered epoch/ || (/finalized block/ && (!seen++ ||
    (match(\$0, /height=[0-9]+/) && substr(\$0, RSTART + 7, RLENGTH - 7) % 8 == 0))) {
    print; fflush() }' |
  sed -u -E 's/ (INFO|WARN) / /; s/^(.{106}).*/\1/;
    s/(completed reshare ceremony.*)/\x1b[32m\1\x1b[0m/; s/(entered epoch)/\x1b[33m\1\x1b[0m/'
FOLLOW
      cat >"$dir/join.sh" <<JOIN
#!/usr/bin/env bash
# The late joiner: once validators 0-4 completed epoch 1's reshare, type its command, start
# it, and follow its events.
until [ "\$(sed -E '$trim' $dir/validator-[0-4].log |
  grep -c 'completed reshare ceremony epoch=1 ')" -ge 5 ]; do sleep 0.5; done
command='dkg validator --node-dir $dir/data/validator-5 --state-sync'
printf '\033[1;32m\$\033[0m '
for ((i = 0; i < \${#command}; i++)); do printf '%s' "\${command:i:1}"; sleep 0.025; done
printf '\n'
\$command >$dir/validator-5.log 2>&1 &
echo \$! >$dir/joiner.pid
exec $dir/follow.sh 5
JOIN
      chmod +x "$dir/follow.sh" "$dir/join.sh"
      printf '\033[H\033[2J'
      type_cmd "commonware-dkg setup --node-dir $dir/data --peers 6 --committee-size 4 \
--base-port 3500 >/dev/null" 1
      type_cmd "for i in 0 1; do commonware-dkg bootstrap --node-dir $dir/data/validator-\$i \
>$dir/bootstrap-\$i.log 2>&1 & done; for i in 2 3; do dkg bootstrap --node-dir \
$dir/data/validator-\$i >$dir/bootstrap-\$i.log 2>&1 & done" 0
      until [ "$(cat "$dir"/bootstrap-*.log 2>/dev/null | grep -c 'bootstrap complete')" = 4 ]; do
        sleep 0.5
      done
      for i in 0 1 2 3; do
        impl=commonware; [ "$i" -ge 2 ] && impl=zigware
        printf '%-10s ' "$impl"
        grep -h 'bootstrap complete' "$dir/bootstrap-$i.log" | sed -E "$trim" | cut -c1-150
      done
      type_cmd "md5sum $dir/data/validator-*/genesis.json | cut -c1-32 | uniq -c" 3
      # Stop the bootstraps and let their ports close before the validators bind them.
      jobs -p >"$dir/bootstrap.pids"
      while read -r pid; do kill "$pid" 2>/dev/null || true; done <"$dir/bootstrap.pids"
      wait 2>/dev/null || true
      while ss -ltn | grep -qE ':350[0-5] '; do sleep 0.2; done
      kinds=(commonware-dkg commonware-dkg dkg dkg commonware-dkg)
      for i in 0 1 2 3 4; do
        "${kinds[$i]}" validator --node-dir "$dir/data/validator-$i" \
          >"$dir/validator-$i.log" 2>&1 &
      done
      t() { tmux -L zigware-demo -f /dev/null "$@"; }
      t kill-server 2>/dev/null || true
      t new-session -d -s idkg -x 220 -y 50 "$dir/follow.sh 0"
      t set-option -g status off
      t set-option -g pane-border-status top
      t set-option -g pane-border-format ' #[bold]#{pane_title}#[default] '
      t select-pane -t idkg -T 'commonware (Rust): validator 0'
      titles=('commonware (Rust): validator 1' 'zigware (Zig): validator 2'
        'zigware (Zig): validator 3' 'commonware (Rust): validator 4')
      for i in 1 2 3 4; do
        t split-window -t idkg "$dir/follow.sh $i"
        t select-pane -t idkg -T "${titles[$((i - 1))]}"
        t select-layout -t idkg tiled
      done
      t split-window -t idkg "$dir/join.sh"
      t select-pane -t idkg -T 'zigware (Zig): validator 5, joins with --state-sync'
      t select-layout -t idkg tiled
      (
        # End just after the joiner completed its first reshare ceremony.
        for _ in $(seq 480); do
          grep -q 'completed reshare ceremony' "$dir/validator-5.log" 2>/dev/null && break
          sleep 0.5
        done
        sleep 3
        t detach-client -s idkg
      ) &
      t attach -t idkg || true
      wait %%
      t kill-server
      if [ -f "$dir/joiner.pid" ]; then kill "$(cat "$dir/joiner.pid")" 2>/dev/null || true; fi
      kill $(jobs -p) 2>/dev/null || true
      wait 2>/dev/null || true
      ;;
    *) echo "unknown demo: $name" >&2; exit 1 ;;
  esac
  exit 0
fi

case $name in
  flood) size=150x40 ;;
  chat) size=200x50 ;;
  log) size=200x44 ;;
  bridge) size=160x40 ;;
  dkg) size=220x50 ;;
  interop) size=220x50 ;;
  interop-log) size=200x64 ;;
  interop-dkg) size=220x50 ;;
  *) size=104x40 ;;
esac
DEMO_SESSION=1 TERM=xterm-256color asciinema rec --overwrite --quiet --output-format asciicast-v2 --window-size "$size" \
  --command "$0 $name" "$out.cast"
if [ "$name" = chat ] || [ "$name" = log ] || [ "$name" = bridge ] || [ "$name" = dkg ] ||
  [ "$name" = interop ] || [ "$name" = interop-log ] || [ "$name" = interop-dkg ]; then
  # End on the panes, not tmux's exit screen: cut where tmux leaves the alternate screen, and
  # drop the screen clear tmux sometimes writes as a separate event just before it.
  awk 'index($0, "\\u001b[?1049l") { if (held && !index(held, "\\u001b[2J")) print held; exit }
    { if (held) print held; held = $0 }' "$out.cast" >"$out.cast.cut"
  mv "$out.cast.cut" "$out.cast"
fi
# log redraws four wide, busy panes: a smaller font and frame rate keep its gif near 1 MB.
font=16 fps=30
[ "$name" = log ] && font=12 fps=6
[ "$name" = bridge ] && font=14 fps=8
[ "$name" = dkg ] && font=12 fps=6
[ "$name" = interop ] && font=14 fps=12
[ "$name" = interop-log ] && font=12 fps=8
[ "$name" = interop-dkg ] && font=12 fps=8
# x264's default quality (crf 23) puts dkg's five busy panes near 4 MB; 30 keeps it under 3.
crf=23
[ "$name" = dkg ] && crf=30
[ "$name" = interop-dkg ] && crf=28
agg --theme monokai --font-size "$font" --idle-time-limit 3 --last-frame-duration 6 \
  --fps-cap "$fps" "$out.cast" "$out.gif"
ffmpeg -y -loglevel error -i "$out.gif" -movflags faststart -pix_fmt yuv420p -crf "$crf" \
  -vf 'fps=30,scale=trunc(iw/2)*2:trunc(ih/2)*2' "$out.mp4"
rm "$out.cast"
ls -lh "$out.gif" "$out.mp4"
