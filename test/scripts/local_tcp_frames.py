"""Observation-only decoder for the consumer's two canonical 45-byte nonce forms.

Fresh probes use a UUID; continuity uses a 29-hex session ID and stream/sequence.
Other bytes are still echoed/recorded by the peer, never rejected as networking
failure. This decoder is not a transport or admission parser.
"""
import re

PREFIX = b'krtek-m3-'
FRESH = re.compile(rb'krtek-m3-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
SESSION = re.compile(rb'krtek-m3-[0-9a-f]{29}-[tu]-[0-9a-f]{4}')
FRAME_BYTES = 45  # Both existing Java consumer forms, independent of recv chunks.


class NonceFrames:
    def __init__(self):
        self.pending = bytearray()
        self.offset = 0

    def feed(self, data):
        self.pending.extend(data)
        frames = []
        while self.pending:
            start = self.pending.find(PREFIX)
            if start < 0:
                keep = min(len(PREFIX) - 1, len(self.pending))
                self.offset += len(self.pending) - keep
                del self.pending[:len(self.pending) - keep]
                break
            if start:
                self.offset += start
                del self.pending[:start]
            if len(self.pending) < FRAME_BYTES:
                break
            candidate = bytes(self.pending[:FRAME_BYTES])
            if FRESH.fullmatch(candidate) or SESSION.fullmatch(candidate):
                frames.append((self.offset, candidate))
                self.offset += FRAME_BYTES
                del self.pending[:FRAME_BYTES]
            else:
                self.offset += 1
                del self.pending[:1]
        return frames

    def incomplete(self):
        data = bytes(self.pending)
        if data and (data.startswith(PREFIX) or PREFIX.startswith(data)):
            return self.offset, data
        return None
