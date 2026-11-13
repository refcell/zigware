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
    *) echo "unknown demo: $name" >&2; exit 1 ;;
  esac
  exit 0
fi

DEMO_SESSION=1 TERM=xterm-256color asciinema rec --overwrite --quiet --output-format asciicast-v2 --window-size 104x40 \
  --command "$0 $name" "$out.cast"
agg --theme monokai --font-size 16 --idle-time-limit 3 --last-frame-duration 6 \
  "$out.cast" "$out.gif"
ffmpeg -y -loglevel error -i "$out.gif" -movflags faststart -pix_fmt yuv420p \
  -vf 'fps=30,scale=trunc(iw/2)*2:trunc(ih/2)*2' "$out.mp4"
rm "$out.cast"
ls -lh "$out.gif" "$out.mp4"
