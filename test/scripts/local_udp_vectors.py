#!/usr/bin/env python3
"""Test-only canonical wire inputs, independent of production packet encoders.

Emit binary IP pieces plus a JSON manifest for native/Rust driver consumption.
Splitting here is fixture generation only, never shipped in the app.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import struct


def payload(size, nonce=bytes(range(32))):
    if not 0 <= size <= 65527 or len(nonce) != 32:
        raise ValueError("payload size or nonce")
    return bytes(nonce[i] if i < 32 else nonce[i % 32] ^ ((i * 31 + i // 32) & 255)
                 for i in range(size))


def wire_checksum(data):
    padded = data + (b"\0" if len(data) % 2 else b"")
    value = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return value ^ 65535


def udp_segment(source, destination, source_port, destination_port, body):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if src.version != dst.version or len(body) + 8 > 65535:
        raise ValueError("UDP endpoints or length")
    length = len(body) + 8
    segment = bytearray(struct.pack("!HHHH", source_port, destination_port, length, 0) + body)
    trailer = struct.pack("!BBH", 0, 17, length) if src.version == 4 else struct.pack("!I3xB", length, 17)
    check = wire_checksum(src.packed + dst.packed + trailer + segment) or 65535
    segment[6:8] = check.to_bytes(2, "big")
    return bytes(segment)


def ip_piece(source, destination, identifier, offset, more, segment, *, fragment=True, protocol=17):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if src.version != dst.version or offset % 8 or not 0 <= offset <= 65528:
        raise ValueError("IP endpoints or offset")
    if src.version == 4:
        field = offset // 8 | (8192 if more else 0)
        header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(segment) + 20,
                                       identifier, field, 64, protocol, 0, src.packed, dst.packed))
        header[10:12] = wire_checksum(header).to_bytes(2, "big")
    else:
        fragment_header = struct.pack("!BBHI", protocol, 0, offset | int(more), identifier) if fragment else b""
        header = struct.pack("!IHBB16s16s", 6 << 28, len(segment) + len(fragment_header),
                             44 if fragment else protocol, 64, src.packed, dst.packed) + fragment_header
    return bytes(header) + segment


def datagram(source, destination, source_port, destination_port, body, mtu=1280, identifier=0x1234):
    segment = udp_segment(source, destination, source_port, destination_port, body)
    family = ipaddress.ip_address(source).version
    base = 20 if family == 4 else 40
    if len(segment) + base <= mtu:
        return [ip_piece(source, destination, identifier, 0, False, segment, fragment=False)]
    overhead = 20 if family == 4 else 48
    capacity = (mtu - overhead) // 8 * 8
    if capacity < 8:
        raise ValueError("MTU too small")
    return [ip_piece(source, destination, identifier, offset, offset + capacity < len(segment),
                     segment[offset:offset + capacity]) for offset in range(0, len(segment), capacity)]


def write_vectors(directory):
    directory.mkdir(parents=True, exist_ok=False)
    cases = []
    for family in (4, 6):
        source = "172.27.1.1" if family == 4 else "fdf0:ce4a:801d::172:27:1:1"
        destination = "192.0.2.81" if family == 4 else "fd00:10::81"
        maximum = 65507 if family == 4 else 65487
        for mtu in ((68, 1280, 65535) if family == 4 else (1280, 65535)):
            fit = mtu - (28 if family == 4 else 48)
            sizes = sorted({0, 1, 31, fit, min(fit + 1, maximum), 4096, 4097, maximum, maximum + 1})
            for size in sizes:
                if size > maximum + 1:
                    continue
                name = f"v{family}-mtu{mtu}-size{size}"
                packets = datagram(source, destination, 30001, 18081, payload(size), mtu)
                paths = []
                for index, packet in enumerate(packets):
                    path = f"{name}-{index:04}.bin"
                    (directory / path).write_bytes(packet)
                    paths.append(path)
                cases.append({"name": name, "family": family, "mtu": mtu, "payload_size": size,
                              "source": source, "destination": destination,
                              "source_port": 30001, "destination_port": 18081,
                              "packets": paths, "expected": "oversized" if size > maximum else "complete"})
    (directory / "manifest.json").write_text(json.dumps({"schema": 1, "cases": cases}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    write_vectors(parser.parse_args().directory)


if __name__ == "__main__":
    main()
