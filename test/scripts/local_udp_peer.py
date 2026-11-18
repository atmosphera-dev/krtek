#!/usr/bin/env python3
"""Controlled, numeric dual-family full UDP echo peer. Run inside the device guest.

The JSONL ledger contains synthetic bytes only. Each row is flushed to disk before
echo, then an echo row records the actual send. No ACK, truncation or retry path.
"""

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import time

from local_udp_vectors import payload


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


def bind_dual(ipv4, ipv6, port):
    """Allocate and retain both families before publishing the selected port."""
    while True:
        first = bind_peer(ipv4, port)
        try:
            return [first, bind_peer(ipv6, first.getsockname()[1])]
        except OSError as error:
            first.close()
            if port != 0 or error.errno != errno.EADDRINUSE:
                raise


def serve(ipv4, ipv6, port, ledger_path, ready_path, duration, max_requests=0, reply_size=None,
          tcp_port=None):
    """Bounded owner; zero max_requests means duration alone determines the end."""
    if ipaddress.ip_address(ipv4).version != 4 or ipaddress.ip_address(ipv6).version != 6:
        raise ValueError("One numeric address per family required")
    sockets = []
    clients = set()
    try:
        sockets = bind_dual(ipv4, ipv6, port)
        port = sockets[0].getsockname()[1]
        with selectors.DefaultSelector() as selector, Path(ledger_path).open("x") as ledger:
            for sock in sockets:
                selector.register(sock, selectors.EVENT_READ, "udp")
            if tcp_port is not None:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(tcp)
                tcp.bind((ipv4, tcp_port))
                tcp.listen()
                selector.register(tcp, selectors.EVENT_READ, "listen")
            ready = {"schema": 1, "pid": os.getpid(), "port": port,
                     "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                     "listening_monotonic_ns": time.monotonic_ns(),
                     "addresses": [str(ipaddress.ip_address(ipv4)), str(ipaddress.ip_address(ipv6))]}
            if tcp_port is not None:
                ready["tcp_port"] = tcp.getsockname()[1]
            append(ledger, dict(ready, event="listening"))
            pending = Path(str(ready_path) + ".pending")
            with pending.open("x") as output:
                json.dump(ready, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.link(pending, ready_path)  # atomic publication without replacing an old receipt
            pending.unlink()
            deadline = time.monotonic() + duration
            count = 0
            while time.monotonic() < deadline and (not max_requests or count < max_requests):
                for key, _ in selector.select(max(0, deadline - time.monotonic())):
                    sock = key.fileobj
                    if key.data == "listen":
                        client, source = sock.accept()
                        client.settimeout(5)
                        clients.add(client)
                        selector.register(client, selectors.EVENT_READ, "tcp")
                        append(ledger, {"event": "tcp_accept", "fd": client.fileno(),
                                        "source": source[0], "source_port": source[1]})
                        continue
                    if key.data == "tcp":
                        data = sock.recv(65535)
                        append(ledger, {"event": "tcp_request", "fd": sock.fileno(),
                                        "payload_hex": data.hex(), "size": len(data)})
                        if not data:
                            selector.unregister(sock); clients.remove(sock); sock.close()
                        else:
                            sock.sendall(data)
                            append(ledger, {"event": "tcp_echo", "fd": sock.fileno(),
                                            "payload_hex": data.hex(), "size": len(data)})
                        continue
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
                    response = data if reply_size is None else payload(reply_size, data)
                    if reply_size is not None:
                        if len(data) != 32 or reply_size != (65508 if family == 4 else 65488):
                            raise ValueError("Reply-limit operation requires one nonce and exact family limit+1")
                        append(ledger, {"schema": 1, "event": "reply_attempt", "index": count,
                                        "size": len(response), "payload_hex": response.hex()})
                    try:
                        sent = sock.sendto(response, source)
                    except OSError as error:
                        if not (reply_size == 65508 and family == 4 and error.errno == 90):
                            raise
                        append(ledger, {"schema": 1, "event": "reply_refused", "index": count,
                                        "size": len(response), "errno": error.errno,
                                        "stage": "kernel-send"})
                        if max_requests and count >= max_requests:
                            break
                        continue
                    if sent != len(response):
                        raise RuntimeError("Short peer echo")
                    append(ledger, {"schema": 1, "event": "echo" if reply_size is None else "reply_sent", "index": count,
                                    "size": sent, "sent_monotonic_ns": time.monotonic_ns()})
                    if max_requests and count >= max_requests:
                        break
            append(ledger, {"schema": 1, "event": "stopped", "requests": count,
                            "pid": ready["pid"], "boot_id": ready["boot_id"],
                            "stopped_monotonic_ns": time.monotonic_ns()})
    finally:
        for client in clients:
            client.close()
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
    parser.add_argument("--reply-size", type=int, choices=(65488, 65508),
                        help="Reply-limit control only: receive 32-byte nonce, attempt family maximum+1")
    parser.add_argument("--tcp-port", type=int, help="Continuity fixture: explicit IPv4 TCP stream echo")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or args.duration <= 0 or args.max_requests < 0:
        parser.error("Positive port/duration and nonnegative request count required")
    if args.tcp_port is not None and (not 0 <= args.tcp_port <= 65535 or args.reply_size is not None):
        parser.error("TCP requires a valid port and the exact-echo mode")
    serve(args.ipv4, args.ipv6, args.port, args.ledger, args.ready, args.duration, args.max_requests,
          args.reply_size, args.tcp_port)


if __name__ == "__main__":
    main()
