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


def audit_consumer(report, peer_rows, *, expect, expected_uid=None, expected_peer_source=None):
    """Require in-process full comparison AND independent peer/wire bytes, never a digest alone."""
    payload = consumer_payload(report)
    require(report["family"] in (4, 6), "consumer family")
    require(ipaddress.ip_address(report["remote_address"]).version == report["family"], "peer family")
    require(report["remote_port"] == 18081, "peer port")
    if expected_uid is not None:
        require(report["uid"] == expected_uid, "consumer UID")
    require(report["option_set"] and report["option_value"] == 0, "fragment-permitting socket option")
    requests = [row for row in peer_rows if row.get("event") == "request" and
                row.get("family") == report["family"]]
    # A nonce-bearing prefix at the peer is a failed negative too. Matching only
    # exact payloads would hide the very truncation this harness must detect.
    hits = []
    for row in requests:
        data = bytes.fromhex(row["payload_hex"])
        prefix = min(32, len(data), len(payload))
        if (prefix > 0 and data[:prefix] == payload[:prefix]) or data == payload:
            hits.append(row)
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
    else:
        require(expect in ("denied", "oversized"), "unknown expectation")
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
    parser.add_argument("--expect", choices=("echo", "denied", "oversized"), required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--physical-source", required=True)
    parser.add_argument("--request-packets", type=Path,
                        help="JSON array of exact request IP packet hex strings from TUN capture")
    parser.add_argument("--reply-packets", type=Path,
                        help="JSON array of exact reply IP packet hex strings from TUN capture")
    parser.add_argument("--mtu", type=int, help="Observed capture MTU, required for wire auditing")
    args = parser.parse_args()
    report = json.loads(args.consumer.read_text())
    rows = [json.loads(line) for line in args.peer_ledger.read_text().splitlines()]
    require(any(row.get("event") == "stopped" for row in rows), "peer ledger is not terminal")
    result = audit_consumer(report, rows, expect=args.expect, expected_uid=args.uid,
                            expected_peer_source=args.physical_source)
    if args.expect == "echo":
        require(args.request_packets and args.reply_packets and args.mtu,
                "echo CLI requires both TUN packet arrays and observed MTU")
        family = report["family"]
        fixed_source = "172.27.1.1" if family == 4 else "fdf0:ce4a:801d::172:27:1:1"
        require(ipaddress.ip_address(report["local_address"]) == ipaddress.ip_address(fixed_source),
                "consumer fixed capture source")
        payload = consumer_payload(report)
        for direction, path, source, destination, sport, dport in (
            ("request", args.request_packets, fixed_source, report["remote_address"], report["local_port"], 18081),
            ("reply", args.reply_packets, report["remote_address"], fixed_source, 18081, report["local_port"]),
        ):
            packets = [bytes.fromhex(value) for value in json.loads(path.read_text())]
            result[direction] = audit_packets(packets, mtu=args.mtu, source=source, destination=destination,
                                              source_port=sport, destination_port=dport, payload=payload)
        if len(payload) == 4096:
            require(result["request"]["packets"] > 1 and result["reply"]["packets"] > 1,
                    "4096-byte device proof requires genuine fragments both ways")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
