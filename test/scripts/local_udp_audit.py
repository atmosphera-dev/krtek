#!/usr/bin/env python3
"""Independent test-only minimal-IP UDP wire and full-consumer oracle.

Does not import Krtek, lwIP, smoltcp or the fixture packet generator. Output
acceptance is deliberately stricter than stock receive overlap semantics: a
generated reply must have exactly-once coverage, one ID, legal offsets and a
correct complete checksum. This is not a replacement production reassembler.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import struct


class AuditError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise AuditError(reason)


def checksum(data):
    words = [int.from_bytes(data[i:i + 2].ljust(2, b"\0"), "big")
             for i in range(0, len(data), 2)]
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


@dataclass(frozen=True)
class Piece:
    family: int
    source: str
    destination: str
    identifier: int | None
    offset: int
    more: bool
    data: bytes


def decode(packet, mtu):
    require(0 < len(packet) <= mtu, "empty or over-MTU packet")
    family = packet[0] >> 4
    if family == 4:
        require(len(packet) >= 20 and packet[0] == 0x45, "noncanonical IPv4 header")
        require(int.from_bytes(packet[2:4], "big") == len(packet), "IPv4 total length")
        require(checksum(packet[:20]) == 0, "IPv4 header checksum")
        require(packet[9] == 17, "IPv4 is not UDP")
        flags = int.from_bytes(packet[6:8], "big")
        require(not flags & 0x8000, "IPv4 reserved flag")
        offset, more = (flags & 8191) * 8, bool(flags & 8192)
        require(not (flags & 0x4000 and (offset or more)), "IPv4 DF fragment")
        identifier = int.from_bytes(packet[4:6], "big") if offset or more else None
        source, destination = packet[12:16], packet[16:20]
        data = packet[20:]
    elif family == 6:
        require(len(packet) >= 40, "short IPv6 header")
        require(int.from_bytes(packet[4:6], "big") + 40 == len(packet), "IPv6 payload length")
        source, destination = packet[8:24], packet[24:40]
        offset, more, identifier = 0, False, None
        if packet[6] == 44:
            require(len(packet) >= 48 and packet[40] == 17, "noncanonical IPv6 Fragment header")
            field = int.from_bytes(packet[42:44], "big")
            require(packet[41] == 0 and field & 6 == 0, "IPv6 reserved fields")
            offset, more = field & 0xfff8, bool(field & 1)
            identifier = int.from_bytes(packet[44:48], "big")
            data = packet[48:]
        else:
            require(packet[6] == 17, "noncanonical IPv6 UDP header chain")
            data = packet[40:]
    else:
        raise AuditError("unknown IP version")
    require(len(data) > 0, "empty fragment/transport")
    require(not more or len(data) % 8 == 0, "unaligned nonfinal fragment")
    require(offset + len(data) <= (65515 if family == 4 else 65495), "Local complete size limit")
    return Piece(family, str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination)),
                 identifier, offset, more, data)


def audit_packets(packets, *, mtu, source, destination, source_port, destination_port, payload):
    pieces = [decode(packet, mtu) for packet in packets]
    require(bool(pieces), "no packets")
    source, destination = str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination))
    first = pieces[0]
    for piece in pieces:
        require((piece.family, piece.source, piece.destination, piece.identifier) ==
                (first.family, source, destination, first.identifier), "mixed tuple/family/ID")
    require(first.identifier is not None or len(pieces) == 1, "multiple unfragmented packets")
    ordered = sorted(pieces, key=lambda piece: piece.offset)
    end = 0
    parts = []
    for index, piece in enumerate(ordered):
        require(piece.offset == end, "hole, duplicate or overlap")
        require(piece.more == (index < len(ordered) - 1), "missing or conflicting terminal")
        end += len(piece.data)
        parts.append(piece.data)
    segment = b"".join(parts)
    require(len(segment) >= 8, "short UDP header")
    sport, dport, length, check = struct.unpack("!HHHH", segment[:8])
    require((sport, dport) == (source_port, destination_port), "UDP ports")
    require(length == len(segment), "UDP complete length")
    require(segment[8:] == payload, "UDP full payload mismatch")
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    pseudo = (src + dst + (struct.pack("!BBH", 0, 17, length) if first.family == 4
                          else struct.pack("!I3xB", length, 17)))
    require(check != 0, "generated UDP checksum is zero")
    require(checksum(pseudo + segment) == 0, "UDP complete checksum")
    return {"family": first.family, "packets": len(pieces), "payload_size": len(payload),
            "identifier": first.identifier, "largest_packet": max(map(len, packets))}


def consumer_payload(report):
    """Reconstruct the synthetic request independently, not from a Binder payload."""
    require("payload_hex" not in report and "reply_hex" not in report, "payload in Binder report")
    size = report["payload_size"]
    require(isinstance(size, int) and 0 <= size <= 65508, "request payload size")
    nonce = bytes.fromhex(report["nonce"])
    require(len(nonce) == 32, "consumer nonce size")
    payload = bytes(nonce[i] if i < 32 else nonce[i % 32] ^ ((i * 31 + i // 32) & 255)
                    for i in range(size))
    require(report["payload_sha256"] == hashlib.sha256(payload).hexdigest(), "consumer nonce/pattern digest")
    return payload


def invocation_requests(report, peer_rows, observation):
    """Scope by exclusive capture barriers on the peer guest's monotonic clock.

    The runner records start_ack immediately before acknowledging Android's start
    barrier, and finish_seen after observing its finish barrier. Neither Android's
    clock nor a payload prefix can identify this interval.
    """
    require(isinstance(observation, dict), "missing invocation observation receipt")
    require(observation.get("nonce") == report["nonce"] and observation.get("exclusive") is True,
            "observation must identify this nonce and exclusive peer window")
    require(bool(observation.get("token")), "missing capture barrier token")
    start, finish = observation["start_ack_monotonic_ns"], observation["finish_seen_monotonic_ns"]
    require(isinstance(start, int) and isinstance(finish, int) and 0 < start < finish,
            "invalid capture barrier interval")
    listening = [row for row in peer_rows if row.get("event") == "listening"]
    stopped = [row for row in peer_rows if row.get("event") == "stopped"]
    require(len(listening) == len(stopped) == 1, "one complete peer lifetime required")
    opened, closed = listening[0], stopped[0]
    require((opened["pid"], opened["boot_id"]) == (closed["pid"], closed["boot_id"]) ==
            (observation["peer_pid"], observation["boot_id"]), "peer/clock identity mismatch")
    require(closed.get("coverage_complete") is True, "peer receive coverage incomplete")
    coverage = closed["coverage_monotonic_ns"]
    require(opened["listening_monotonic_ns"] <= start < finish <= coverage <= closed["stopped_monotonic_ns"],
            "peer did not cover full invocation window")
    terminal = closed.get("finish")
    require(isinstance(terminal, dict) and all(terminal.get(key) == observation[key] for key in
            ("peer_pid", "boot_id", "token", "nonce", "finish_seen_monotonic_ns")),
            "peer did not drain this invocation finish barrier")
    require(opened["port"] == report["remote_port"] and
            ipaddress.ip_address(report["remote_address"]) in
            [ipaddress.ip_address(address) for address in opened["addresses"]], "observation peer endpoint")
    requests = []
    for row in peer_rows:
        if row.get("event") != "request" or row.get("family") != report["family"]:
            continue
        require(isinstance(row.get("received_monotonic_ns"), int), "missing peer receive timestamp")
        require(opened["listening_monotonic_ns"] <= row["received_monotonic_ns"] <= closed["stopped_monotonic_ns"],
                "request outside peer lifetime")
        # A receive may be serviced after Android's finish barrier. Keep queued
        # evidence through shutdown rather than hiding it as late traffic.
        if row["received_monotonic_ns"] < start:
            continue
        if (ipaddress.ip_address(row["destination"]) == ipaddress.ip_address(report["remote_address"]) and
                row["destination_port"] == report["remote_port"]):
            requests.append(row)
    return requests


def audit_consumer(report, peer_rows, *, expect, expected_uid=None, expected_peer_source=None,
                   observation=None):
    """Require in-process full comparison AND independent peer/wire bytes, never a digest alone."""
    payload = consumer_payload(report)
    require(report["family"] in (4, 6), "consumer family")
    require(ipaddress.ip_address(report["remote_address"]).version == report["family"], "peer family")
    require(report["remote_port"] == 18081, "peer port")
    if expected_uid is not None:
        require(report["uid"] == expected_uid, "consumer UID")
    require(report["option_set"] and report["option_value"] == 0, "fragment-permitting socket option")
    # ALL requests in this exclusive endpoint/window belong to the invocation,
    # including empty and corrupted datagrams. Never identify them by payload.
    hits = invocation_requests(report, peer_rows, observation)
    if expect == "echo":
        require(report.get("validated") is True and "error_stage" not in report, "consumer did not validate")
        require(report["sent"] == report["received"] == len(payload), "consumer datagram length")
        require(report.get("bytes_equal") is True, "consumer full byte comparison")
        require(report.get("source_matches") is True, "consumer source comparison")
        require(report["reply_sha256"] == hashlib.sha256(payload).hexdigest(), "consumer full reply digest")
        require(ipaddress.ip_address(report["reply_source"]) == ipaddress.ip_address(report["remote_address"])
                and report["reply_port"] == 18081, "consumer source tuple")
        require(len(hits) == 1, "expected exactly one full peer request")
        hit = hits[0]
        require(hit["payload_hex"] == payload.hex() and hit["size"] == len(payload)
                and hit["destination_port"] == 18081, "peer full bytes/length/port")
        require(ipaddress.ip_address(hit["destination"]) == ipaddress.ip_address(report["remote_address"]),
                "peer destination")
        require(hit["ifindex"] > 0 and bool(hit["interface"]), "physical receive interface")
        if expected_peer_source is not None:
            require(ipaddress.ip_address(hit["source"]) == ipaddress.ip_address(expected_peer_source),
                    "protected physical source")
        echoes = [row for row in peer_rows if row.get("event") == "echo" and row.get("index") == hit["index"]]
        require(len(echoes) == 1 and echoes[0]["size"] == len(payload), "peer exact echo send")
    elif expect == "oversized-reply":
        maximum = 65507 if report["family"] == 4 else 65487
        nonce = bytes.fromhex(report["nonce"])
        require(report.get("requested_reply_size") == maximum + 1 and payload == nonce,
                "reply limit must use one short nonce request")
        require(report.get("sent") == 32 and not report.get("validated") and "received" not in report,
                "reply limit received a shortened or unexpected datagram")
        require(report.get("error_stage") == "receive" and report.get("errno") in (11, 110),
                "reply limit is not a receive timeout")
        require(len(hits) == 1, "reply limit needs one complete peer request")
        hit = hits[0]
        require(hit["payload_hex"] == nonce.hex() and hit["size"] == 32 and
                hit["destination_port"] == 18081 and hit["ifindex"] > 0 and bool(hit["interface"]),
                "reply limit request/physical interface")
        require(ipaddress.ip_address(hit["destination"]) == ipaddress.ip_address(report["remote_address"]),
                "reply limit destination")
        if expected_peer_source is not None:
            require(ipaddress.ip_address(hit["source"]) == ipaddress.ip_address(expected_peer_source),
                    "reply limit protected physical source")
        related = [row for row in peer_rows if row.get("index") == hit["index"] and
                   row.get("event") in ("reply_attempt", "reply_sent", "reply_refused", "echo")]
        require(len(related) == 2 and related[0]["event"] == "reply_attempt", "one reply attempt only")
        attempted = related[0]
        response = bytes(nonce[i] if i < 32 else nonce[i % 32] ^ ((i * 31 + i // 32) & 255)
                         for i in range(maximum + 1))
        require(attempted["size"] == len(response) and attempted["payload_hex"] == response.hex(),
                "peer did not attempt the exact oversized full pattern")
        terminal = related[1]
        require(terminal["size"] == len(response), "peer attempted a shortened reply")
        if report["family"] == 4:
            require((terminal["event"], terminal.get("errno"), terminal.get("stage")) ==
                    ("reply_refused", 90, "kernel-send"), "IPv4 peer kernel EMSGSIZE required")
        else:
            require(terminal["event"] == "reply_sent", "IPv6 full oversized reply was not sent")
    else:
        require(expect in ("denied", "oversized"), "unknown expectation")
        if expect == "oversized":
            require(len(payload) == (65508 if report["family"] == 4 else 65488),
                    "oversized request must be exact family maximum+1")
        require(not report.get("validated") and "received" not in report, "negative received a datagram")
        require(not hits, "negative reached peer")
        if expect == "oversized" and report["family"] == 4:
            require((report.get("error_stage"), report.get("errno")) == ("send", 90), "IPv4 EMSGSIZE")
        else:
            require(report.get("sent") == len(payload), "negative was not fully sent")
            require(report.get("error_stage") == "receive" and report.get("errno") in (11, 110),
                    "negative is not a receive timeout")
    return {"expect": expect, "family": report["family"], "payload_size": len(payload), "peer_hits": len(hits)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--peer-ledger", type=Path, required=True)
    parser.add_argument("--expect", choices=("echo", "denied", "oversized", "oversized-reply"), required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--physical-source", required=True)
    parser.add_argument("--observation", type=Path, required=True,
                        help="exclusive invocation barriers on the peer guest monotonic clock")
    parser.add_argument("--request-packets", type=Path,
                        help="JSON array of exact request IP packet hex strings from TUN capture")
    parser.add_argument("--reply-packets", type=Path,
                        help="JSON array of exact reply IP packet hex strings from TUN capture")
    parser.add_argument("--mtu", type=int, help="Observed capture MTU, required for wire auditing")
    args = parser.parse_args()
    report = json.loads(args.consumer.read_text())
    rows = [json.loads(line) for line in args.peer_ledger.read_text().splitlines()]
    result = audit_consumer(report, rows, expect=args.expect, expected_uid=args.uid,
                            expected_peer_source=args.physical_source,
                            observation=json.loads(args.observation.read_text()))
    if args.expect in ("echo", "oversized-reply"):
        require(args.request_packets and args.reply_packets and args.mtu,
                "echo CLI requires both TUN packet arrays and observed MTU")
        family = report["family"]
        fixed_source = "172.27.1.1" if family == 4 else "fdf0:ce4a:801d::172:27:1:1"
        require(ipaddress.ip_address(report["local_address"]) == ipaddress.ip_address(fixed_source),
                "consumer fixed capture source")
        payload = consumer_payload(report)
        directions = (
            ("request", args.request_packets, fixed_source, report["remote_address"], report["local_port"], 18081),
            ("reply", args.reply_packets, report["remote_address"], fixed_source, 18081, report["local_port"]),
        )
        for direction, path, source, destination, sport, dport in directions:
            packets = [bytes.fromhex(value) for value in json.loads(path.read_text())]
            if args.expect == "oversized-reply" and direction == "reply":
                require(not packets, "oversized reply emitted app-facing packets")
                result[direction] = {"packets": 0}
                continue
            result[direction] = audit_packets(packets, mtu=args.mtu, source=source, destination=destination,
                                              source_port=sport, destination_port=dport, payload=payload)
        if len(payload) == 4096:
            require(result["request"]["packets"] > 1 and result["reply"]["packets"] > 1,
                    "4096-byte device proof requires genuine fragments both ways")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
