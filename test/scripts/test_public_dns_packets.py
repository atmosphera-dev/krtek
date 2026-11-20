#!/usr/bin/env python3
"""Independent ordinary packet audit controls; guest-only."""
import struct
import unittest

from local_udp_vectors import datagram
from public_dns_audit import AuditError
import public_dns_packets as packets


class PublicDnsPacketsTest(unittest.TestCase):
    def family(self, family, size=4096):
        source = '172.27.1.1' if family == 4 else 'fdf0:ce4a:801d::172:27:1:1'
        destination = '1.1.1.1' if family == 4 else '2606:4700:4700::1111'
        body = bytes(index % 251 for index in range(size))
        wire = datagram(source, destination, 30001, 53, body, 1280, 1234)
        return source, destination, body, wire

    def test_both_families_small_and_fragmented(self):
        for family in (4, 6):
            for size in (76, 4096):
                with self.subTest(family=family, size=size):
                    source, destination, body, wire = self.family(family, size)
                    result = packets.audit_datagram(list(reversed(wire)), source, destination, 30001, 53, body)
                    self.assertEqual(len(wire), result['fragments'])
                    self.assertEqual(size, result['payload_size'])
                    self.assertTrue(result['udp_checksum_valid'])

    def test_ordinary_ipv6_protocol_size_not_local_ceiling(self):
        source, destination, body, wire = self.family(6, 65527)
        result = packets.audit_datagram(wire, source, destination, 30001, 53, body)
        self.assertEqual(65527, result['payload_size'])

    def test_rejects_holes_duplicates_and_terminal_conflicts(self):
        for family in (4, 6):
            source, destination, body, wire = self.family(family)
            for malformed in (wire[1:], wire[:-1], wire + wire[:1]):
                with self.subTest(family=family, count=len(malformed)):
                    with self.assertRaises(AuditError):
                        packets.audit_datagram(malformed, source, destination, 30001, 53, body)

    def test_rejects_mixed_fragment_ids(self):
        for family in (4, 6):
            source, destination, body, wire = self.family(family)
            other = datagram(source, destination, 30001, 53, body, 1280, 9876)
            with self.assertRaisesRegex(AuditError, 'Mixed packet'):
                packets.audit_datagram([wire[0], *other[1:]], source, destination, 30001, 53, body)

    def test_rejects_bad_checksum_and_changed_saved_bytes(self):
        for family in (4, 6):
            source, destination, body, wire = self.family(family)
            changed = bytearray(wire[-1])
            changed[-1] ^= 1
            with self.assertRaises(AuditError):
                packets.audit_datagram([*wire[:-1], bytes(changed)], source, destination, 30001, 53, body)
            with self.assertRaisesRegex(AuditError, 'saved app bytes'):
                packets.audit_datagram(wire, source, destination, 30001, 53, b'wrong')

    def test_rejects_wrong_ports(self):
        source, destination, body, wire = self.family(4)
        with self.assertRaisesRegex(AuditError, 'UDP tuple'):
            packets.audit_datagram(wire, source, destination, 30002, 53, body)

    def test_capture_record_round_trip_and_empty_refusal(self):
        _, _, _, wire = self.family(6)
        encoded = b'KRTEK08\n' + b''.join(struct.pack('!QIII', 100 + index, 12, 4, len(packet)) + packet
                                            for index, packet in enumerate(wire))
        self.assertEqual(wire, [row['packet'] for row in packets.capture_records(encoded)])
        for invalid in (b'KRTEK08\n', encoded[:-1], b'bad'):
            with self.assertRaises(AuditError):
                packets.capture_records(invalid)


if __name__ == '__main__':
    unittest.main()
