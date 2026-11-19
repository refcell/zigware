#!/usr/bin/env python3
"""Drive two chat peers over authenticated discovery and check messages cross both ways.

Usage: interop_chat.py <rust-chat> <zig-chat> <base-port> [timeout-seconds]

Runs commonware's `commonware-chat` as friend 1 (the bootstrapper) and zigware's `chat` as
friend 2, each in its own pseudo-terminal (both are terminal UIs). Each side types a marker
and presses ENTER every second until the other side's screen shows it, which can only happen
after the handshake, the encrypted stream, and discovery's peer exchange succeed. Then both
sides are asked to quit with ESC. Exits 0 when both directions arrive, 1 otherwise.
"""

import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

ANSI = re.compile(rb"\x1b(\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*\x07|[()][0-9A-Za-z]|[=>78])")


class Peer:
    def __init__(self, name, argv):
        self.name = name
        self.output = bytearray()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(argv[0], argv)
        # A wide screen so whole chat lines render on one row.
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 220, 0, 0))
        os.kill(self.pid, signal.SIGWINCH)

    def pump(self):
        while True:
            ready, _, _ = select.select([self.fd], [], [], 0)
            if not ready:
                return
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output.extend(chunk)

    def screen_text(self):
        return ANSI.sub(b"", bytes(self.output))

    def type_line(self, text):
        os.write(self.fd, text.encode() + b"\r")

    def stop(self):
        try:
            os.write(self.fd, b"\x1b")
        except OSError:
            pass
        deadline = time.time() + 3
        while time.time() < deadline:
            self.pump()
            done, _ = os.waitpid(self.pid, os.WNOHANG)
            if done:
                return
            time.sleep(0.1)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)


def received(screen, marker):
    """Whether `screen` shows `marker` as a received chat line: `abcd**wxyz: marker`."""
    return re.search(rb"[0-9a-f]{4}\*\*[0-9a-f]{4}: " + re.escape(marker), screen) is not None


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    rust_bin, zig_bin, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 60.0
    # `--control` points zigware at a dead bootstrapper, so the run must fail (a check that a
    # pass cannot come from local echo).
    control = "--control" in sys.argv[5:]
    rust_port, zig_port = base, base + 1
    bootstrap_port = base + 7 if control else rust_port
    rust = Peer("commonware", [rust_bin, f"--me=1@{rust_port}", "--friends=1,2"])
    time.sleep(1)
    zig = Peer("zigware", [
        zig_bin, f"--me=2@{zig_port}", "--friends=1,2",
        f"--bootstrappers=1@127.0.0.1:{bootstrap_port}",
    ])
    to_zig, to_rust = b"rust-to-zig-marker", b"zig-to-rust-marker"
    got = {"zigware": None, "commonware": None}
    start = time.time()
    attempt = 0
    try:
        while time.time() - start < timeout_s and None in got.values():
            attempt += 1
            if got["zigware"] is None:
                rust.type_line(to_zig.decode())
            if got["commonware"] is None:
                zig.type_line(to_rust.decode())
            time.sleep(1)
            rust.pump()
            zig.pump()
            if got["zigware"] is None and received(zig.screen_text(), to_zig):
                got["zigware"] = time.time() - start
            if got["commonware"] is None and received(rust.screen_text(), to_rust):
                got["commonware"] = time.time() - start
    finally:
        rust.stop()
        zig.stop()
    for side, seconds in got.items():
        if seconds is None:
            print(f"interop: {side} never showed the other side's message")
        else:
            print(f"interop: {side} received the other side's message after {seconds:.1f}s")
    if None in got.values():
        for peer in (rust, zig):
            path = f"/tmp/interop-{peer.name}.screen"
            with open(path, "wb") as out:
                out.write(peer.screen_text())
            print(f"interop: {peer.name} screen text saved to {path}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
