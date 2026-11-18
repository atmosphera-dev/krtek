#!/usr/bin/env python3
"""Controlled, numeric dual-family full UDP echo peer. Run inside the device guest.

The JSONL ledger contains synthetic bytes only. Each row is flushed to disk before
echo, then an echo row records the actual send. No ACK, truncation or retry path.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import time


def bind_peer(address, port):
    address = ipaddress.ip_address(address)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if address.version == 6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, 8, 1)  # Linux IP_PKTINFO.
        sock.bind((str(address), port))
        return sock
    except BaseException:
        sock.close()
        raise


def append(ledger, row):
    ledger.write(json.dumps(row, sort_keys=True) + "\n")
    ledger.flush()
    os.fsync(ledger.fileno())


def serve(ipv4, ipv6, port, ledger_path, ready_path, duration, max_requests=0):
    """Bounded owner; zero max_requests means duration alone determines the end."""
    if ipaddress.ip_address(ipv4).version != 4 or ipaddress.ip_address(ipv6).version != 6:
        raise ValueError("One numeric address per family required")
    sockets = []
    try:
        sockets.append(bind_peer(ipv4, port))
        sockets.append(bind_peer(ipv6, port))
        with selectors.DefaultSelector() as selector, Path(ledger_path).open("x") as ledger:
            for sock in sockets:
                selector.register(sock, selectors.EVENT_READ)
            ready = {"schema": 1, "pid": os.getpid(), "port": port,
                     "addresses": [str(ipaddress.ip_address(ipv4)), str(ipaddress.ip_address(ipv6))]}
            with Path(ready_path).open("x") as output:
                json.dump(ready, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            deadline = time.monotonic() + duration
            count = 0
            while time.monotonic() < deadline and (not max_requests or count < max_requests):
                for key, _ in selector.select(max(0, deadline - time.monotonic())):
                    sock = key.fileobj
                    data, ancillary, flags, source = sock.recvmsg(65535, 256)
                    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                        raise RuntimeError("Truncated peer request or packet metadata")
                    family = 4 if sock.family == socket.AF_INET else 6
                    info = [(level, kind, raw) for level, kind, raw in ancillary
                            if (level, kind) == ((socket.IPPROTO_IP, 8) if family == 4
                                                  else (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO))]
                    if len(info) != 1:
                        raise RuntimeError("Missing or ambiguous receive interface")
                    raw = info[0][2]
                    if family == 4:
                        ifindex = struct.unpack_from("=I", raw)[0]
                        destination = socket.inet_ntop(socket.AF_INET, raw[8:12])
                    else:
                        ifindex = struct.unpack_from("=I", raw, 16)[0]
                        destination = socket.inet_ntop(socket.AF_INET6, raw[:16])
                    count += 1
                    row = {"schema": 1, "event": "request", "index": count,
                           "family": family, "source": source[0], "source_port": source[1],
                           "destination": destination, "destination_port": sock.getsockname()[1],
                           "ifindex": ifindex, "interface": socket.if_indextoname(ifindex),
                           "size": len(data), "payload_hex": data.hex(),
                           "received_monotonic_ns": time.monotonic_ns()}
                    append(ledger, row)
                    sent = sock.sendto(data, source)
                    if sent != len(data):
                        raise RuntimeError("Short peer echo")
                    append(ledger, {"schema": 1, "event": "echo", "index": count,
                                    "size": sent, "sent_monotonic_ns": time.monotonic_ns()})
                    if max_requests and count >= max_requests:
                        break
            append(ledger, {"schema": 1, "event": "stopped", "requests": count})
    finally:
        for sock in sockets:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=600)
    parser.add_argument("--max-requests", type=int, default=0)
    args = parser.parse_args()
    if not 0 < args.port <= 65535 or args.duration <= 0 or args.max_requests < 0:
        parser.error("Positive port/duration and nonnegative request count required")
    serve(args.ipv4, args.ipv6, args.port, args.ledger, args.ready, args.duration, args.max_requests)


if __name__ == "__main__":
    main()
