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
    *) echo "unknown demo: $name" >&2; exit 1 ;;
  esac
  exit 0
fi

case $name in
  flood) size=150x40 ;;
  chat) size=200x50 ;;
  *) size=104x40 ;;
esac
DEMO_SESSION=1 TERM=xterm-256color asciinema rec --overwrite --quiet --output-format asciicast-v2 --window-size "$size" \
  --command "$0 $name" "$out.cast"
if [ "$name" = chat ]; then
  # End on the chat, not tmux's exit screen: cut where tmux leaves the alternate screen.
  awk 'index($0, "\\u001b[?1049l") { exit } { print }' "$out.cast" >"$out.cast.cut"
  mv "$out.cast.cut" "$out.cast"
fi
agg --theme monokai --font-size 16 --idle-time-limit 3 --last-frame-duration 6 \
  "$out.cast" "$out.gif"
ffmpeg -y -loglevel error -i "$out.gif" -movflags faststart -pix_fmt yuv420p \
  -vf 'fps=30,scale=trunc(iw/2)*2:trunc(ih/2)*2' "$out.mp4"
rm "$out.cast"
ls -lh "$out.gif" "$out.mp4"
