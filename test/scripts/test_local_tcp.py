#!/usr/bin/env python3
"""TCP observation helper regressions. Execute only inside the assigned guest."""

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from local_tcp_peer import Connection, TcpPeer


@contextmanager
def running_peer(duration="5"):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        command = [sys.executable, str(Path(__file__).with_name("local_udp_peer.py")),
                   "--ipv4", "127.0.0.1", "--ipv6", "::1", "--port", "0", "--tcp-port", "0",
                   "--ledger", str(root / "ledger"), "--ready", str(root / "ready"),
                   "--duration", duration, "--finish", str(root / "finish")]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 3
                while not (root / "ready").exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("Peer did not publish readiness")
                    time.sleep(.005)
                yield process, root, json.loads((root / "ready").read_text())
            finally:
                if process.poll() is None:
                    os.kill(process.pid, signal.SIGCONT)
                    process.terminate()
                process.communicate(timeout=3)


def finish(root, ready):
    receipt = dict(peer_pid=ready["pid"], boot_id=ready["boot_id"], token="tcp-fixture",
                   nonce="00" * 32, finish_seen_monotonic_ns=time.monotonic_ns())
    (root / "pending").write_text(json.dumps(receipt))
    (root / "pending").rename(root / "finish")
    return receipt


def read_all(consumer):
    data = bytearray()
    while True:
        chunk = consumer.recv(65535)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def read_exact(consumer, size):
    data = bytearray()
    while len(data) < size:
        chunk = consumer.recv(size - len(data))
        if not chunk:
            raise AssertionError("Peer closed before complete TCP echo")
        data.extend(chunk)
    return bytes(data)


class LocalTcpPeerTest(unittest.TestCase):
    def rows(self, root):
        return [json.loads(line) for line in (root / "ledger").read_text().splitlines()]

    def terminal(self, process, root):
        _, error = process.communicate(timeout=3)
        self.assertEqual(0, process.returncode, error.decode())
        return self.rows(root)

    def test_finish_services_tcp_only_queued_accepts_and_bytes_in_both_families(self):
        for family, address in ((4, "127.0.0.1"), (6, "::1")):
            with self.subTest(family=family), running_peer() as (process, root, ready):
                os.kill(process.pid, signal.SIGSTOP)
                consumers = []
                try:
                    # Multiple completed kernel handshakes are queued BEFORE
                    # finish; no UDP socket is ready to keep the owner alive.
                    for _ in range(2):
                        consumer = socket.create_connection((address, ready["tcp_port"]), timeout=2)
                        consumers.append(consumer)
                        consumer.sendall(b"nonce-split-" + address.encode())
                        consumer.shutdown(socket.SHUT_WR)
                    receipt = finish(root, ready)
                    os.kill(process.pid, signal.SIGCONT)
                    for consumer in consumers:
                        self.assertEqual(b"nonce-split-" + address.encode(), read_all(consumer))
                    rows = self.terminal(process, root)
                finally:
                    for consumer in consumers:
                        consumer.close()
                self.assertEqual([family, family], [row["family"] for row in rows if row["event"] == "tcp_accept"])
                closed = rows[-1]
                self.assertTrue(closed["coverage_complete"])
                self.assertEqual(receipt, closed["finish"])
                self.assertEqual(2, closed["tcp_connections"])
                self.assertEqual(2, closed["tcp_closed"])
                self.assertEqual(0, closed["tcp_incomplete"])
                self.assertEqual(0, closed["tcp_pending_bytes"])
                self.assertGreaterEqual(closed["coverage_monotonic_ns"], receipt["finish_seen_monotonic_ns"])

    def test_stream_offsets_and_stable_identity_survive_fd_reuse(self):
        with running_peer() as (process, root, ready):
            bodies = [b"a" * 131073, b"second-connection"]
            for body in bodies:
                with socket.create_connection(("127.0.0.1", ready["tcp_port"]), timeout=2) as consumer:
                    consumer.sendall(body)
                    consumer.shutdown(socket.SHUT_WR)
                    self.assertEqual(body, read_all(consumer))
            finish(root, ready)
            rows = self.terminal(process, root)
            self.assertTrue(rows[-1]["coverage_complete"])
            accepts = [row for row in rows if row["event"] == "tcp_accept"]
            self.assertEqual([1, 2], [row["connection_id"] for row in accepts])
            for identity, body in enumerate(bodies, 1):
                selected = [row for row in rows if row.get("connection_id") == identity]
                times = [row["monotonic_ns"] for row in selected]
                self.assertEqual(sorted(times), times)
                self.assertEqual("tcp_accept", selected[0]["event"])
                self.assertEqual("tcp_close", selected[-1]["event"])
                self.assertTrue(selected[-1]["complete"])
                for event in ("tcp_request", "tcp_echo"):
                    position = 0
                    for row in selected:
                        if row["event"] == event:
                            self.assertEqual(position, row["offset"])
                            data = bytes.fromhex(row["payload_hex"])
                            self.assertEqual(body[position:position + len(data)], data)
                            position += len(data)
                    self.assertEqual(len(body), position)

    def test_finish_with_open_client_is_incomplete_even_after_empty_poll(self):
        with running_peer(".5") as (process, root, ready):
            with socket.create_connection(("127.0.0.1", ready["tcp_port"]), timeout=2) as consumer:
                consumer.sendall(b"still-open")
                self.assertEqual(b"still-open", read_exact(consumer, len(b"still-open")))
                finish(root, ready)
                rows = self.terminal(process, root)
            self.assertFalse(rows[-1]["coverage_complete"])
            self.assertEqual(0, rows[-1]["coverage_monotonic_ns"])
            self.assertEqual(1, rows[-1]["tcp_incomplete"])
            self.assertFalse([row for row in rows if row["event"] == "tcp_close"][0]["complete"])

    def test_deadline_without_finish_never_proves_coverage(self):
        with running_peer(".2") as (process, root, _):
            rows = self.terminal(process, root)
            self.assertFalse(rows[-1]["coverage_complete"])
            self.assertEqual(0, rows[-1]["coverage_monotonic_ns"])

    def test_nonce_frames_join_stream_chunks_in_receive_and_actual_write_ledgers(self):
        fresh = b"krtek-m3-01234567-89ab-cdef-0123-456789abcdef"
        session = b"krtek-m3-0123456789abcdef0123456789abc-t-0001"
        with running_peer() as (process, root, ready):
            with socket.create_connection(("127.0.0.1", ready["tcp_port"]), timeout=2) as consumer:
                consumer.sendall(fresh[:13])
                self.assertEqual(fresh[:13], read_exact(consumer, 13))
                consumer.sendall(fresh[13:] + session)
                consumer.shutdown(socket.SHUT_WR)
                self.assertEqual(fresh[13:] + session, read_all(consumer))
            finish(root, ready)
            rows = self.terminal(process, root)
            for event in ("tcp_frame_request", "tcp_frame_echo"):
                self.assertEqual([(0, fresh.hex()), (45, session.hex())],
                                 [(row["offset"], row["payload_hex"]) for row in rows if row["event"] == event])
            self.assertTrue([row for row in rows if row["event"] == "tcp_close"][0]["nonce_frames_complete"])

    def fixture(self, pending=b"abcdef", eof=True):
        selector = mock.Mock()
        sock = mock.Mock(family=socket.AF_INET)
        sock.fileno.return_value = 42
        connection = Connection(sock, 7, ("127.0.0.2", 10000), ("127.0.0.1", 18080),
                                pending=bytearray(pending), received=len(pending), eof=eof)
        rows = []
        peer = TcpPeer(selector, rows.append)
        peer.clients[7] = connection
        return peer, connection, rows

    def test_short_write_and_eagain_retain_exact_pending_bytes(self):
        peer, connection, rows = self.fixture()
        connection.socket.send.side_effect = [2, BlockingIOError(), 4]
        for remaining in (b"cdef", b"cdef", b""):
            peer.service(connection.socket, connection, selectors.EVENT_WRITE)
            self.assertEqual(remaining, connection.pending)
        self.assertFalse(peer.clients)
        self.assertEqual([0, 2], [row["offset"] for row in rows if row["event"] == "tcp_echo"])
        self.assertEqual(b"abcdef", b"".join(bytes.fromhex(row["payload_hex"]) for row in rows
                                            if row["event"] == "tcp_echo"))
        self.assertEqual("eof-drained", rows[-1]["reason"])

    def test_pending_write_at_owner_deadline_is_explicitly_incomplete(self):
        peer, connection, rows = self.fixture()
        result = peer.finish()
        self.assertEqual(6, result["tcp_pending_bytes"])
        self.assertEqual(1, result["tcp_incomplete"])
        self.assertFalse(rows[-1]["complete"])
        self.assertEqual(6, rows[-1]["pending_bytes"])

    def test_socket_errno_is_recorded_without_a_successful_close_claim(self):
        peer, connection, rows = self.fixture()
        connection.socket.send.side_effect = OSError(errno.EPIPE, "closed")
        peer.service(connection.socket, connection, selectors.EVENT_WRITE)
        self.assertEqual("tcp_error", rows[-2]["event"])
        self.assertEqual(errno.EPIPE, rows[-2]["errno"])
        self.assertEqual("write", rows[-2]["operation"])
        self.assertFalse(rows[-1]["complete"])
        self.assertEqual(1, peer.errors)


if __name__ == "__main__":
    unittest.main()
