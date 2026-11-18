#!/usr/bin/env python3
"""Harness/oracle tests only: no claim of Local forwarding before C3."""

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import local_udp_audit as audit
import local_udp_vectors as vectors


class LocalUdpHarnessTest(unittest.TestCase):
    def test_stock_lwip_bounded_consumer_report_at_both_maxima(self):
        for family, size in ((4, 65507), (6, 65487)):
            body = vectors.payload(size)
            peer = "192.0.2.81" if family == 4 else "fd00::81"
            report = dict(family=family, payload_size=size, nonce=bytes(range(32)).hex(),
                          payload_sha256=hashlib.sha256(body).hexdigest(),
                          reply_sha256=hashlib.sha256(body).hexdigest(), bytes_equal=True,
                          source_matches=True, validated=True, remote_address=peer,
                          remote_port=18081, reply_source=peer, reply_port=18081,
                          sent=size, received=size, option_set=True, option_value=0)
            request = dict(event="request", index=1, family=family, size=size,
                           payload_hex=body.hex(), source=peer, destination=peer,
                           destination_port=18081, ifindex=2, interface="eth0")
            rows = [request, dict(event="echo", index=1, size=size)]
            self.assertLess(len(json.dumps(report)), 2048)
            self.assertEqual(1, audit.audit_consumer(report, rows, expect="echo")["peer_hits"])
            for key, value in (("bytes_equal", False), ("source_matches", False),
                               ("payload_sha256", "0" * 64), ("reply_sha256", "0" * 64),
                               ("reply_sha256", hashlib.sha256(body[:32]).hexdigest()),
                               ("payload_hex", body.hex()), ("reply_hex", body.hex())):
                with self.assertRaises(audit.AuditError):
                    audit.audit_consumer(dict(report, **{key: value}), rows, expect="echo")
            with self.assertRaises(audit.AuditError):
                audit.audit_consumer(report, [dict(request, payload_hex=body[:32].hex()), rows[1]], expect="echo")

    def test_stock_lwip_independent_checksum_known_answer(self):
        # RFC 1071's example, unrelated to either implementation's packet builder.
        self.assertEqual(0x220d, audit.checksum(bytes.fromhex("0001f203f4f5f6f7")))
        self.assertEqual(0x220d, vectors.wire_checksum(bytes.fromhex("0001f203f4f5f6f7")))

    def test_stock_lwip_oracle_exact_sizes_and_mtu(self):
        for family, source, destination, maximum in (
            (4, "192.0.2.81", "172.27.1.1", 65507),
            (6, "fd00:10::81", "fdf0:ce4a:801d::172:27:1:1", 65487),
        ):
            for mtu in ((68, 1280, 65535) if family == 4 else (1280, 65535)):
                fit = mtu - (28 if family == 4 else 48)
                for size in {0, 1, 31, fit, min(fit + 1, maximum), 4096, 4097, maximum}:
                    with self.subTest(family=family, mtu=mtu, size=size):
                        body = vectors.payload(size)
                        packets = vectors.datagram(source, destination, 18081, 30001, body, mtu)
                        result = audit.audit_packets(list(reversed(packets)), mtu=mtu,
                            source=source, destination=destination, source_port=18081,
                            destination_port=30001, payload=body)
                        self.assertEqual(size, result["payload_size"])
                        if family == 4 and mtu == 68 and size == maximum:
                            self.assertEqual(1365, result["packets"])

    def test_stock_lwip_oracle_rejects_missing_duplicate_overlap_and_mixed_id(self):
        body = vectors.payload(4097)
        for source, destination in (("192.0.2.81", "172.27.1.1"), ("fd00:10::81", "fd00::1")):
            packets = vectors.datagram(source, destination, 18081, 30001, body)
            segment = vectors.udp_segment(source, destination, 18081, 30001, body)
            corrupt_id = vectors.ip_piece(source, destination, 0x1235, 0, True, segment[:1232])
            overlap = vectors.ip_piece(source, destination, 0x1234, 8, True, segment[8:24])
            for broken in (packets[1:], packets[:-1], packets[:1] + packets[2:],
                           packets + packets[:1], packets + [overlap], [corrupt_id] + packets[1:]):
                with self.assertRaises(audit.AuditError):
                    audit.audit_packets(broken, mtu=1280, source=source, destination=destination,
                                        source_port=18081, destination_port=30001, payload=body)

    def test_stock_lwip_oracle_checks_complete_checksum_and_tuple(self):
        for source, destination in (("192.0.2.81", "172.27.1.1"), ("fd00:10::81", "fd00::1")):
            body = vectors.payload(4097)
            packets = vectors.datagram(source, destination, 18081, 30001, body)
            tail = bytearray(packets[-1])
            tail[-1] ^= 1
            changed_body = body[:-1] + bytes([body[-1] ^ 1])
            with self.assertRaisesRegex(audit.AuditError, "checksum"):
                audit.audit_packets(packets[:-1] + [bytes(tail)], mtu=1280, source=source,
                    destination=destination, source_port=18081, destination_port=30001, payload=changed_body)
            with self.assertRaisesRegex(audit.AuditError, "ports"):
                audit.audit_packets(packets, mtu=1280, source=source, destination=destination,
                                    source_port=18082, destination_port=30001, payload=body)

    def test_stock_lwip_oracle_checks_header_and_size_refusal(self):
        for source, destination, maximum in (("192.0.2.81", "172.27.1.1", 65507),
                                             ("fd00:10::81", "fd00::1", 65487)):
            body = vectors.payload(maximum + 1)
            packets = vectors.datagram(source, destination, 18081, 30001, body)
            with self.assertRaisesRegex(audit.AuditError, "size limit"):
                audit.audit_packets(packets, mtu=1280, source=source, destination=destination,
                                    source_port=18081, destination_port=30001, payload=body)
        packet = bytearray(vectors.datagram("192.0.2.81", "172.27.1.1", 18081, 30001, b"x")[0])
        packet[10] ^= 1
        with self.assertRaisesRegex(audit.AuditError, "header checksum"):
            audit.decode(packet, 1280)

    def test_stock_lwip_consumer_audit_rejects_prefix_wrong_tuple_and_duplicate(self):
        body = vectors.payload(4096)
        report = {"family": 4, "uid": 12345, "payload_size": len(body), "payload_sha256": hashlib.sha256(body).hexdigest(),
                  "nonce": bytes(range(32)).hex(),
                  "remote_address": "192.0.2.81", "remote_port": 18081, "option_set": True,
                  "option_value": 0, "sent": len(body), "received": len(body),
                  "reply_sha256": hashlib.sha256(body).hexdigest(), "reply_source": "192.0.2.81", "reply_port": 18081,
                  "bytes_equal": True, "source_matches": True, "validated": True}
        request = {"event": "request", "index": 1, "family": 4, "size": len(body),
                   "payload_hex": body.hex(), "source": "10.0.2.15", "destination": "192.0.2.81",
                   "destination_port": 18081, "ifindex": 2, "interface": "eth0"}
        rows = [request, {"event": "echo", "index": 1, "size": len(body)}]
        self.assertEqual(1, audit.audit_consumer(report, rows, expect="echo", expected_uid=12345,
                                               expected_peer_source="10.0.2.15")["peer_hits"])
        for key, value in (("reply_sha256", hashlib.sha256(body[:32]).hexdigest()), ("received", 32), ("reply_port", 18082),
                           ("validated", False), ("uid", 0)):
            changed = dict(report, **{key: value})
            with self.assertRaises(audit.AuditError):
                audit.audit_consumer(changed, rows, expect="echo", expected_uid=12345)
        with self.assertRaises(audit.AuditError):
            audit.audit_consumer(report, rows + [request], expect="echo")

    def test_stock_lwip_denial_audit_requires_timeout_and_peer_silence(self):
        report = {"family": 6, "uid": 12345, "payload_size": 4096, "nonce": bytes(range(32)).hex(),
                  "payload_sha256": hashlib.sha256(vectors.payload(4096)).hexdigest(), "remote_address": "fd00::81",
                  "remote_port": 18081, "option_set": True, "option_value": 0,
                  "sent": 4096, "error_stage": "receive", "errno": 11}
        self.assertEqual(0, audit.audit_consumer(report, [], expect="denied")["peer_hits"])
        for key, value in (("error_stage", "create"), ("errno", 13), ("sent", 32), ("received", 0)):
            with self.assertRaises(audit.AuditError):
                audit.audit_consumer(dict(report, **{key: value}), [], expect="denied")
        hit = {"event": "request", "family": 6, "payload_hex": vectors.payload(4096).hex()}
        with self.assertRaises(audit.AuditError):
            audit.audit_consumer(report, [hit], expect="denied")
        with self.assertRaises(audit.AuditError):
            audit.audit_consumer(report, [dict(hit, payload_hex=hit["payload_hex"][:64])], expect="denied")

    def test_stock_lwip_peer_real_full_dual_family_echo(self):
        # These are isolated guest loopback harness checks, NOT device Local proof.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            command = [sys.executable, str(Path(__file__).with_name("local_udp_peer.py")),
                       "--ipv4", "127.0.0.1", "--ipv6", "::1", "--port", str(port),
                       "--ledger", str(root / "ledger.jsonl"), "--ready", str(root / "ready.json"),
                       "--duration", "15", "--max-requests", "8"]
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                try:
                    deadline = time.monotonic() + 5
                    while not (root / "ready.json").exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("Peer failed before ready: " + process.communicate(timeout=1)[1].decode())
                        time.sleep(0.01)
                    for family, address, maximum in ((socket.AF_INET, "127.0.0.1", 65507),
                                                      (socket.AF_INET6, "::1", 65487)):
                        with socket.socket(family, socket.SOCK_DGRAM) as consumer:
                            consumer.settimeout(3)
                            for size in (0, 31, 4096, maximum):
                                body = vectors.payload(size, os.urandom(32))
                                self.assertEqual(size, consumer.sendto(body, (address, port)))
                                reply, _, flags, source = consumer.recvmsg(65535)
                                self.assertFalse(flags & socket.MSG_TRUNC)
                                self.assertEqual(body, reply)
                                self.assertEqual(ipaddress.ip_address(address), ipaddress.ip_address(source[0]))
                                self.assertEqual(port, source[1])
                    _, error = process.communicate(timeout=5)
                    self.assertEqual(0, process.returncode, error.decode())
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.communicate(timeout=2)
            rows = [json.loads(line) for line in (root / "ledger.jsonl").read_text().splitlines()]
            requests = [row for row in rows if row["event"] == "request"]
            self.assertEqual(8, len(requests))
            self.assertEqual([0, 31, 4096, 65507, 0, 31, 4096, 65487], [row["size"] for row in requests])
            for row in requests:
                self.assertEqual(row["size"] * 2, len(row["payload_hex"]))
                self.assertGreater(row["ifindex"], 0)
                self.assertEqual("lo", row["interface"])

    def test_stock_lwip_vector_manifest_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "vectors"
            vectors.write_vectors(root)
            manifest = json.loads((root / "manifest.json").read_text())
            self.assertEqual(1, manifest["schema"])
            self.assertGreaterEqual(len(manifest["cases"]), 35)
            for case in manifest["cases"]:
                packets = [(root / name).read_bytes() for name in case["packets"]]
                arguments = {key: case[key] for key in ("mtu", "source", "destination", "source_port", "destination_port")}
                if case["expected"] == "oversized":
                    with self.assertRaises(audit.AuditError):
                        audit.audit_packets(packets, payload=vectors.payload(case["payload_size"]), **arguments)
                else:
                    audit.audit_packets(packets, payload=vectors.payload(case["payload_size"]), **arguments)

    def test_stock_lwip_full_cli_requires_consumer_peer_and_both_wire_directions(self):
        body = vectors.payload(4096)
        app, peer, port = "172.27.1.1", "192.0.2.81", 30001
        report = {"family": 4, "uid": 12345, "nonce": bytes(range(32)).hex(),
                  "payload_size": len(body), "payload_sha256": hashlib.sha256(body).hexdigest(),
                  "remote_address": peer, "remote_port": 18081, "option_set": True,
                  "option_value": 0, "sent": len(body), "received": len(body),
                  "reply_sha256": hashlib.sha256(body).hexdigest(), "reply_source": peer, "reply_port": 18081,
                  "bytes_equal": True, "source_matches": True,
                  "local_address": app, "local_port": port, "validated": True}
        rows = [{"event": "request", "index": 1, "family": 4, "size": len(body),
                 "payload_hex": body.hex(), "source": "10.0.2.15", "destination": peer,
                 "destination_port": 18081, "ifindex": 2, "interface": "eth0"},
                {"event": "echo", "index": 1, "size": len(body)}, {"event": "stopped", "requests": 1}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "consumer.json").write_text(json.dumps(report))
            (root / "ledger.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            request = vectors.datagram(app, peer, port, 18081, body)
            reply = vectors.datagram(peer, app, 18081, port, body)
            (root / "request.json").write_text(json.dumps([packet.hex() for packet in request]))
            (root / "reply.json").write_text(json.dumps([packet.hex() for packet in reply]))
            command = [sys.executable, str(Path(__file__).with_name("local_udp_audit.py")),
                       "--consumer", str(root / "consumer.json"), "--peer-ledger", str(root / "ledger.jsonl"),
                       "--expect", "echo", "--uid", "12345", "--physical-source", "10.0.2.15"]
            missing = subprocess.run(command, capture_output=True, timeout=5)
            self.assertNotEqual(0, missing.returncode)
            command += ["--mtu", "1280", "--request-packets", str(root / "request.json"),
                        "--reply-packets", str(root / "reply.json")]
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr.decode())
            self.assertEqual(4, json.loads(result.stdout)["reply"]["packets"])
            (root / "reply.json").write_text(json.dumps([packet.hex() for packet in reply[:-1]]))
            broken = subprocess.run(command, capture_output=True, timeout=5)
            self.assertNotEqual(0, broken.returncode)


if __name__ == "__main__":
    unittest.main()
