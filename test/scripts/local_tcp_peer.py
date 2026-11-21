"""Nonblocking TCP echo observation for the guest-only Local test peer.

Connection identity never depends on a reusable fd. Byte offsets, not recv
boundaries, join a nonce to the captured stream. No framing is invented for the
existing raw echo protocol. A caller must service listeners as well as clients
before publishing a receive watermark.
"""

from dataclasses import dataclass, field
import errno
import selectors
import socket
import time

from local_tcp_frames import NonceFrames


@dataclass
class Connection:
    socket: socket.socket
    identity: int
    source: tuple
    destination: tuple
    pending: bytearray = field(default_factory=bytearray)
    received: int = 0
    sent: int = 0
    eof: bool = False
    received_frames: NonceFrames = field(default_factory=NonceFrames)
    sent_frames: NonceFrames = field(default_factory=NonceFrames)


class TcpPeer:
    def __init__(self, selector, emit):
        self.selector = selector
        self.emit = emit
        self.listeners = []
        self.clients = {}
        self.next_identity = 1
        self.closed = 0
        self.errors = 0

    def listen(self, ipv4, ipv6, port):
        # Retain both binds before publishing a port, as with the UDP peer.
        deadline = time.monotonic() + 5
        while True:
            try:
                for family, address in ((socket.AF_INET, ipv4), (socket.AF_INET6, ipv6)):
                    listener = socket.socket(family, socket.SOCK_STREAM)
                    self.listeners.append(listener)
                    if family == socket.AF_INET6:
                        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    listener.bind((address, port if family == socket.AF_INET else selected))
                    selected = listener.getsockname()[1]
                break
            except OSError as error:
                for listener in self.listeners:
                    listener.close()
                self.listeners.clear()
                if port or error.errno != errno.EADDRINUSE or time.monotonic() >= deadline:
                    raise
        for listener in self.listeners:
            listener.listen()
            listener.setblocking(False)
            self.selector.register(listener, selectors.EVENT_READ, (self, None))
        return selected

    def record(self, event, connection, **fields):
        sock = connection.socket
        self.emit(dict(schema=1, event=event, connection_id=connection.identity,
                       fd=sock.fileno(), family=4 if sock.family == socket.AF_INET else 6,
                       source=connection.source[0], source_port=connection.source[1],
                       destination=connection.destination[0], destination_port=connection.destination[1],
                       monotonic_ns=time.monotonic_ns(), received_total=connection.received,
                       sent_total=connection.sent, pending_bytes=len(connection.pending), **fields))

    def close(self, connection, reason, complete):
        frame_complete = True
        for direction, decoder in (("request", connection.received_frames), ("echo", connection.sent_frames)):
            partial = decoder.incomplete()
            if partial is not None:
                frame_complete = False
                offset, data = partial
                self.record("tcp_frame_incomplete", connection, direction=direction,
                            offset=offset, payload_hex=data.hex(), size=len(data))
        self.record("tcp_close", connection, reason=reason, complete=complete,
                    nonce_frames_complete=frame_complete)
        self.selector.unregister(connection.socket)
        del self.clients[connection.identity]
        connection.socket.close()
        self.closed += 1

    def service(self, sock, connection, mask):
        if connection is None:
            while True:
                try:
                    client, source = sock.accept()
                except BlockingIOError:
                    return
                client.setblocking(False)
                connection = Connection(client, self.next_identity, source, client.getsockname())
                self.next_identity += 1
                self.clients[connection.identity] = connection
                self.selector.register(client, selectors.EVENT_READ, (self, connection))
                self.record("tcp_accept", connection)
            return
        operation = "read"
        try:
            if mask & selectors.EVENT_READ and not connection.eof:
                try:
                    data = sock.recv(65535)
                except BlockingIOError:
                    data = None
                if data == b"":
                    connection.eof = True
                    self.record("tcp_eof", connection)
                elif data is not None:
                    offset = connection.received
                    connection.received += len(data)
                    connection.pending.extend(data)
                    self.record("tcp_request", connection, offset=offset,
                                payload_hex=data.hex(), size=len(data))
                    for frame_offset, frame in connection.received_frames.feed(data):
                        self.record("tcp_frame_request", connection, offset=frame_offset,
                                    payload_hex=frame.hex(), size=len(frame))
            if mask & selectors.EVENT_WRITE and connection.pending:
                operation = "write"
                try:
                    sent = sock.send(connection.pending)
                except BlockingIOError:
                    sent = None
                if sent == 0:
                    raise OSError(errno.EIO, "Zero-byte TCP write")
                if sent is not None:
                    data = bytes(connection.pending[:sent])
                    del connection.pending[:sent]
                    offset = connection.sent
                    connection.sent += sent
                    self.record("tcp_echo", connection, offset=offset,
                                payload_hex=data.hex(), size=sent)
                    for frame_offset, frame in connection.sent_frames.feed(data):
                        self.record("tcp_frame_echo", connection, offset=frame_offset,
                                    payload_hex=frame.hex(), size=len(frame))
            if connection.eof and not connection.pending:
                self.close(connection, "eof-drained", True)
                return
            # One read-sized pending buffer per client. Do not read more bytes
            # while the echo is backpressured, or block unrelated UDP/clients.
            events = selectors.EVENT_WRITE if connection.pending else selectors.EVENT_READ
            self.selector.modify(sock, events, (self, connection))
        except OSError as error:
            self.errors += 1
            self.record("tcp_error", connection, operation=operation, errno=error.errno)
            self.close(connection, "socket-error", False)

    def finish(self):
        incomplete = len(self.clients)
        pending = sum(len(connection.pending) for connection in self.clients.values())
        for connection in list(self.clients.values()):
            self.close(connection, "owner-stopped-before-eof-drain", False)
        for listener in self.listeners:
            self.selector.unregister(listener)
            listener.close()
        self.listeners.clear()
        return dict(tcp_connections=self.next_identity - 1, tcp_closed=self.closed,
                    tcp_incomplete=incomplete, tcp_pending_bytes=pending, tcp_errors=self.errors)
