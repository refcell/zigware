#!/usr/bin/env bash
# Live interop between zigware and commonware over authenticated p2p.
#
# Builds commonware's `examples/chat` from the reference clone (offline, from the local cargo
# cache) into a target directory outside this repository, builds zigware's chat, and runs
# them as two friends on 127.0.0.1: commonware is friend 1 and the bootstrapper, zigware is
# friend 2. Each side sends a chat line until the other side shows it, which needs the SAKE
# handshake, the CUPS encrypted stream, and discovery's greeting, bit vector, and peer
# exchange to agree byte for byte. A control run with a dead bootstrapper must fail.
#
# Skips (exit 0) when cargo or the reference clone is missing.
#
# Environment: COMMONWARE_REF (default ~/.cache/zigware/commonware-ref), INTEROP_TARGET
# (cargo target directory, default ${TMPDIR:-/tmp}/zigware-interop-target), INTEROP_PORT
# (base port, default 23500), INTEROP_TIMEOUT (seconds, default 60).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
reference="${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}"
target="${INTEROP_TARGET:-${TMPDIR:-/tmp}/zigware-interop-target}"
port="${INTEROP_PORT:-23500}"
timeout_s="${INTEROP_TIMEOUT:-60}"

if ! command -v cargo > /dev/null 2>&1; then
    echo "interop: skipped (cargo not found)"
    exit 0
fi
if [ ! -f "$reference/examples/chat/Cargo.toml" ]; then
    echo "interop: skipped (no commonware reference at $reference)"
    exit 0
fi
if ! command -v python3 > /dev/null 2>&1; then
    echo "interop: skipped (python3 not found)"
    exit 0
fi

echo "interop: building commonware-chat at $(git -C "$reference" rev-parse --short HEAD)"
(cd "$reference" && CARGO_TARGET_DIR="$target" cargo build --release --offline -q \
    -p commonware-chat)
echo "interop: building zigware chat"
(cd "$root" && zig build install -Doptimize=ReleaseSafe)

rust_chat="$target/release/commonware-chat"
zig_chat="$root/zig-out/bin/chat"
driver="$root/etc/scripts/interop_chat.py"

echo "interop: discovery chat, commonware (friend 1) <-> zigware (friend 2)"
python3 -I "$driver" "$rust_chat" "$zig_chat" "$port" "$timeout_s"

echo "interop: control run, zigware bootstraps from a dead port (must fail)"
if python3 -I "$driver" "$rust_chat" "$zig_chat" "$((port + 20))" 10 --control > /dev/null; then
    echo "interop: control run passed, so the check cannot tell a connection apart"
    exit 1
fi
echo "interop: ok"
