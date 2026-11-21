#!/usr/bin/env python3
"""Controlled, numeric dual-family full UDP echo peer. Run inside the device guest.

The JSONL ledger contains synthetic bytes only. Each row is flushed to disk before
echo, then an echo row records the actual send. No ACK, truncation or retry path.
"""

import argparse
from contextlib import ExitStack
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
from local_tcp_peer import TcpPeer


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


class TcpLedger:
    """Commit every TCP service's complete observations with one durable flush.

    Per-nonce fsync inside TcpPeer's frame loop delays the next echo by the
    number of frames in a burst. UDP keeps its existing per-event append path.
    A failed commit is terminal: replaying a possibly written batch duplicates
    evidence and cannot establish a receive watermark.
    """
    def __init__(self, ledger):
        self.ledger = ledger
        self.pending = []
        self.failure = None

    def append(self, row):
        if self.failure is not None:
            raise self.failure
        self.pending.append(row)

    def flush(self):
        if self.failure is not None:
            raise self.failure
        if not self.pending:
            return
        try:
            self.ledger.write("".join(json.dumps(row, sort_keys=True) + "\n" for row in self.pending))
            self.ledger.flush()
            os.fsync(self.ledger.fileno())
        except OSError as error:
            self.failure = error
            raise
        self.pending.clear()


def bind_dual(ipv4, ipv6, port):
    """Allocate and retain both families before publishing the selected port."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        first = bind_peer(ipv4, port)
        try:
            return [first, bind_peer(ipv6, first.getsockname()[1])]
        except OSError as error:
            first.close()
            if port != 0 or error.errno != errno.EADDRINUSE:
                raise
    raise OSError(errno.EADDRINUSE, "No common UDP port available before startup deadline")


def serve(ipv4, ipv6, port, ledger_path, ready_path, duration, max_requests=0, reply_size=None,
          tcp_port=None, finish_path=None):
    """A finish receipt plus a drained receive set proves coverage; deadlines do not."""
    if ipaddress.ip_address(ipv4).version != 4 or ipaddress.ip_address(ipv6).version != 6:
        raise ValueError("One numeric address per family required")
    sockets = []
    try:
        sockets = bind_dual(ipv4, ipv6, port)
        port = sockets[0].getsockname()[1]
        with selectors.DefaultSelector() as selector, Path(ledger_path).open("x") as ledger, ExitStack() as cleanup:
            for sock in sockets:
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ, "udp")
            tcp_ledger = TcpLedger(ledger)
            tcp = TcpPeer(selector, tcp_ledger.append)
            def finish_tcp():
                try:
                    return tcp.finish()
                finally:
                    tcp_ledger.flush()
            cleanup.callback(finish_tcp)
            if tcp_port is not None:
                tcp_port = tcp.listen(ipv4, ipv6, tcp_port)
            ready = {"schema": 1, "pid": os.getpid(), "port": port,
                     "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                     "listening_monotonic_ns": time.monotonic_ns(),
                     "addresses": [str(ipaddress.ip_address(ipv4)), str(ipaddress.ip_address(ipv6))]}
            if tcp_port is not None:
                ready["tcp_port"] = tcp_port
                ready["tcp_addresses"] = ready["addresses"]
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
            finish = None
            coverage_complete = False
            coverage_ns = 0
            while time.monotonic() < deadline and (finish_path or not max_requests or count < max_requests):
                if finish_path and finish is None and Path(finish_path).exists():
                    finish = json.loads(Path(finish_path).read_text())
                    if ((finish.get("peer_pid"), finish.get("boot_id")) != (ready["pid"], ready["boot_id"])
                            or not finish.get("token") or not finish.get("nonce")
                            or not isinstance(finish.get("finish_seen_monotonic_ns"), int)
                            or not ready["listening_monotonic_ns"] <= finish["finish_seen_monotonic_ns"] <= time.monotonic_ns()):
                        raise ValueError("Finish receipt does not identify this peer lifetime")
                poll_ns = time.monotonic_ns()
                wait = 0 if finish and not tcp.clients else max(0, deadline - time.monotonic())
                if finish_path:
                    wait = min(wait, .05)
                events = selector.select(wait)
                if finish and not events and not tcp.clients:
                    # Every registered source (both UDP sockets, TCP listeners,
                    # and clients) was serviced before this empty poll. This is
                    # a receive watermark, not proof against future arrivals.
                    coverage_complete, coverage_ns = True, poll_ns
                    break
                for key, mask in events:
                    sock = key.fileobj
                    if key.data != "udp":
                        try:
                            tcp.service(sock, key.data[1], mask)
                        finally:
                            tcp_ledger.flush()
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
                        if not finish_path and max_requests and count >= max_requests:
                            break
                        continue
                    if sent != len(response):
                        raise RuntimeError("Short peer echo")
                    append(ledger, {"schema": 1, "event": "echo" if reply_size is None else "reply_sent", "index": count,
                                    "size": sent, "sent_monotonic_ns": time.monotonic_ns()})
                    if not finish_path and max_requests and count >= max_requests:
                        break
            tcp_summary = finish_tcp()
            append(ledger, {"schema": 1, "event": "stopped", "requests": count,
                             "pid": ready["pid"], "boot_id": ready["boot_id"],
                             "coverage_complete": coverage_complete and not tcp_summary["tcp_errors"],
                             "coverage_monotonic_ns": coverage_ns, "finish": finish,
                             "stopped_monotonic_ns": time.monotonic_ns(), **tcp_summary})
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
    parser.add_argument("--reply-size", type=int, choices=(65488, 65508),
                        help="Reply-limit control only: receive 32-byte nonce, attempt family maximum+1")
    parser.add_argument("--tcp-port", type=int, help="Continuity fixture: dual-family TCP stream echo")
    parser.add_argument("--finish", type=Path,
                        help="Runner atomically publishes the peer-clock finish receipt here; required for audit coverage")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or args.duration <= 0 or args.max_requests < 0:
        parser.error("Positive port/duration and nonnegative request count required")
    if args.tcp_port is not None and (not 0 <= args.tcp_port <= 65535 or args.reply_size is not None):
        parser.error("TCP requires a valid port and the exact-echo mode")
    serve(args.ipv4, args.ipv6, args.port, args.ledger, args.ready, args.duration, args.max_requests,
          args.reply_size, args.tcp_port, args.finish)


if __name__ == "__main__":
    main()
