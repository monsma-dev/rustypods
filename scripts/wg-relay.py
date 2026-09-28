#!/usr/bin/env python3
"""UDP relay for WireGuard between two hosts that cannot handshake
directly (provider DPI). Bind one listen port and forward only from
an allowlist of source IPs — an open relay is a reflector.

Usage:
  wg-relay.py <listen-port> <dst-host> <dst-port> <allow-ip> [<allow-ip>...]
"""
import selectors
import socket
import sys

MAX_SESSIONS = 64
MAX_DATAGRAM = 65535


def relay(lport: int, dst: tuple[str, int], allow: set[str]) -> None:
    ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ls.bind(("0.0.0.0", lport))
    ls.setblocking(False)
    sel = selectors.DefaultSelector()
    ups: dict[tuple, socket.socket] = {}
    sel.register(ls, selectors.EVENT_READ, "l")
    while True:
        for key, _ in sel.select(0.5):
            if key.data == "l":
                data, cli = ls.recvfrom(MAX_DATAGRAM)
                if cli[0] not in allow:
                    continue
                us = ups.get(cli)
                if us is None:
                    if len(ups) >= MAX_SESSIONS:
                        continue
                    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    us.setblocking(False)
                    sel.register(us, selectors.EVENT_READ, ("u", cli))
                    ups[cli] = us
                us.sendto(data, dst)
            else:
                _, cli = key.data
                data, _ = key.fileobj.recvfrom(MAX_DATAGRAM)
                ls.sendto(data, cli)


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.stderr.write(
            "usage: wg-relay.py <lport> <dst-host> <dst-port> <allow-ip> [...]\n"
        )
        sys.exit(2)
    relay(
        int(sys.argv[1]),
        (sys.argv[2], int(sys.argv[3])),
        set(sys.argv[4:]),
    )
