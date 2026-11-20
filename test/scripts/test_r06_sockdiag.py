#!/usr/bin/env python3
"""Live Linux UAPI helper checks, not Android tracing-capability proof."""

import json
import os
from pathlib import Path
import socket
import subprocess
import unittest


class R06SockdiagTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ["R06_SOCKDIAG"]).resolve(strict=True)

    def sample(self, protocol, address, port, pid=None):
        result = subprocess.run([str(self.binary), protocol, address, str(port),
                                 str(os.getpid() if pid is None else pid), "2", "1"],
                                capture_output=True, timeout=12)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([1, 2], [row["sequence"] for row in rows if row["event"] == "snapshot_begin"])
        self.assertEqual([1, 2], [row["sequence"] for row in rows if row["event"] == "snapshot_end"])
        for row in rows:
            self.assertGreater(row["boottime_ns"], 0)
            if row["event"] == "snapshot_end":
                self.assertIs(row["complete"], True)
        self.assertEqual(sorted(row["boottime_ns"] for row in rows), [row["boottime_ns"] for row in rows])
        return rows

    def check_socket(self, rows, consumer, family, protocol):
        records = [row for row in rows if row["event"] == "socket" and row["source_port"] == consumer.getsockname()[1]]
        self.assertEqual(2, len(records))
        self.assertEqual(1, len({tuple(row["cookie"]) for row in records}))
        self.assertEqual(1, len({row["inode"] for row in records}))
        for row in records:
            self.assertEqual(family, row["family"])
            self.assertEqual(protocol, row["protocol"])
            self.assertEqual(os.getuid(), row["uid"])
            self.assertEqual(consumer.getsockname()[0], row["source"])
            self.assertEqual(consumer.getpeername()[0], row["destination"])
            self.assertEqual(consumer.getpeername()[1], row["destination_port"])
            self.assertTrue(row["fd_scan_available"])
            self.assertGreater(row["fd_matches"], 0)
            self.assertTrue(any(fd["event"] == "fd" and fd["sequence"] == row["sequence"]
                                and fd["inode"] == row["inode"] and fd["fd"] == consumer.fileno()
                                and fd["pid"] == os.getpid() for fd in rows))
        return records

    def test_existing_tcp_socket_tuple_fd_inode_and_cookie_in_both_families(self):
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with self.subTest(family=family), socket.socket(family, socket.SOCK_STREAM) as listener:
                listener.bind((address, 0))
                listener.listen()
                with socket.create_connection((address, listener.getsockname()[1]), timeout=2) as consumer:
                    with listener.accept()[0]:
                        rows = self.sample("tcp", address, listener.getsockname()[1])
                        records = self.check_socket(rows, consumer, 4 if family == socket.AF_INET else 6, socket.IPPROTO_TCP)
                        self.assertEqual([1, 1], [row["state"] for row in records])  # TCP_ESTABLISHED

    def test_existing_udp_socket_is_observed_without_sending_or_consuming_data(self):
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with self.subTest(family=family), socket.socket(family, socket.SOCK_DGRAM) as consumer:
                consumer.connect((address, 18081))
                rows = self.sample("udp", address, 18081)
                self.check_socket(rows, consumer, 4 if family == socket.AF_INET else 6, socket.IPPROTO_UDP)

    def test_unavailable_fd_scan_is_distinct_from_no_socket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as consumer:
            consumer.connect(("127.0.0.1", 18081))
            rows = self.sample("udp", "127.0.0.1", 18081, pid=2147483647)
            records = [row for row in rows if row["event"] == "socket" and row["source_port"] == consumer.getsockname()[1]]
            self.assertEqual(2, len(records))
            self.assertTrue(all(not row["fd_scan_available"] and row["fd_matches"] == -1 for row in records))
            self.assertFalse(any(row["event"] == "fd" for row in rows))

    def test_wrong_endpoint_does_not_match_existing_socket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as consumer:
            consumer.connect(("127.0.0.1", 18081))
            rows = self.sample("udp", "127.0.0.2", 18081)
            self.assertFalse(any(row["event"] == "socket" for row in rows))

    def test_invalid_arguments_fail_before_observation(self):
        for arguments in ([], ["tcp", "host.example", "18080", "1", "1", "0"],
                          ["tcp", "127.0.0.1", "65536", "1", "1", "0"],
                          ["icmp", "127.0.0.1", "18080", "1", "1", "0"],
                          ["tcp", "127.0.0.1", "18080", "1", "0", "0"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([str(self.binary), *arguments], capture_output=True, timeout=2)
                self.assertEqual(2, result.returncode)
                self.assertEqual(b"", result.stdout)


if __name__ == "__main__":
    unittest.main()
