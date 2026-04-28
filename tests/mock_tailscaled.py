#!/usr/bin/env python3
"""
Mock tailscaled local-API server.

Listens on a unix socket and answers /localapi/v0/status with a fixed peer
list. Used by CI's getent integration test, and handy for manual local
testing of the NSS plugin without joining a real tailnet.

Usage
-----
    sudo python3 tests/mock_tailscaled.py \\
        --socket /var/run/tailscale/tailscaled.sock \\
        --peers alice@dialo.ai,bob@dialo.ai,stranger@other.com

The socket path defaults to tailscaled's canonical
`/var/run/tailscale/tailscaled.sock`. Peers default to a small set that
covers the happy path plus the cross-domain filtering case the plugin
must reject.

Wire format
-----------
We mirror tailscaled's actual response shape, sufficient for the plugin's
needs:

    { "User": { "<id>": { "LoginName": "<email>" }, ... } }

The plugin only reads `User[*].LoginName`. We don't bother filling in
the dozens of other fields a real tailscaled emits; serde_json's
`#[serde(default)]` on the unused fields tolerates absence.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
from typing import Iterable


def build_payload(emails: Iterable[str]) -> bytes:
    """Build the JSON body of a /localapi/v0/status response."""
    users = {str(i): {"LoginName": email} for i, email in enumerate(emails, start=1)}
    return json.dumps({"User": users}).encode()


def serve(socket_path: str, payload: bytes) -> None:
    """Listen forever, answering each connection with `payload`."""
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    # 0o666 so the NSS plugin (running as whatever uid did `getent`) can
    # connect. tailscaled itself uses 0o666 for its local API socket; we
    # match that to keep the surface identical.
    os.chmod(socket_path, 0o666)
    srv.listen(8)

    response = (
        b"HTTP/1.0 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
        + payload
    )

    def handle(conn: socket.socket) -> None:
        try:
            # Drain the request so the client doesn't see a connection
            # reset before its read of the response. We don't actually
            # parse the request — every path gets the same answer.
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            conn.sendall(response)
        finally:
            conn.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket",
        default="/var/run/tailscale/tailscaled.sock",
        help="unix socket path to listen on (default: tailscaled's canonical path)",
    )
    parser.add_argument(
        "--peers",
        default="alice@dialo.ai,bob@dialo.ai,stranger@other.com",
        help="comma-separated list of peer emails to advertise",
    )
    args = parser.parse_args()

    emails = [p.strip() for p in args.peers.split(",") if p.strip()]
    payload = build_payload(emails)

    print(f"mock-tailscaled: serving {len(emails)} peers on {args.socket}", file=sys.stderr)
    serve(args.socket, payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
