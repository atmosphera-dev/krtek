#!/usr/bin/env python3
"""Independent ordinary packet audit controls; guest-only."""
import struct
import unittest

from local_udp_vectors import datagram, ip_piece, udp_segment
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

    def tun(self, family, body, wire, incoming=(), response=None):
        source, destination, _, _ = self.family(family)
        records = [dict(timestamp_ns=100 + index, ifindex=12, packet=packet)
                   for index, packet in enumerate([*wire, *incoming])]
        probe = dict(uid=10001, pid=123, family=family, local_address=source,
                     remote_address=destination, local_port=30001,
                     send_started_ns=90, completed_ns=190)
        observer = dict(uid=0, pid=456, packet_drops=0, readback_verified=True,
                        writer_flushed=True, ifindex=12, started_ns=50, finished_ns=200)
        return packets.audit_tun(records, probe, body, response, observer)

    def test_ipv4_udp_header_only_first_fragment(self):
        source, destination, body, _ = self.family(4, 76)
        segment = udp_segment(source, destination, 30001, 53, body)
        wire = [ip_piece(source, destination, 1234, 0, True, segment[:8]),
                ip_piece(source, destination, 1234, 8, False, segment[8:])]
        self.assertEqual(2, self.tun(4, body, wire)['request']['fragments'])
        with self.assertRaisesRegex(AuditError, 'duplicate DNS first'):
            self.tun(4, body, [*wire, *wire])

    def test_ipv6_fragmentable_destination_options_before_udp(self):
        source, destination, body, _ = self.family(6)
        fragmentable = bytes([17, 0]) + bytes(6) + udp_segment(source, destination, 30001, 53, body)
        wire = [ip_piece(source, destination, 1234, offset, offset + 1232 < len(fragmentable),
                         fragmentable[offset:offset + 1232], protocol=60)
                for offset in range(0, len(fragmentable), 1232)]
        result = packets.audit_datagram(wire[::-1], source, destination, 30001, 53, body)
        self.assertEqual(len(wire), result['fragments'])
        self.assertEqual(len(wire), self.tun(6, body, wire)['request']['fragments'])
        self.assertEqual(fragmentable[1232:2464], packets.decode(wire[1])['payload'])

    def test_ipv6_first_fragment_must_contain_complete_headers(self):
        source, destination, body, _ = self.family(6, 76)
        for extension in (bytes([17, 1]) + bytes(14), bytes([17, 0]) + bytes(6)):
            fragmentable = extension + udp_segment(source, destination, 30001, 53, body)
            wire = [ip_piece(source, destination, 1234, 0, True, fragmentable[:8], protocol=60),
                    ip_piece(source, destination, 1234, 8, False, fragmentable[8:], protocol=60)]
            with self.subTest(extension_bytes=len(extension)):
                with self.assertRaises(AuditError):
                    packets.audit_datagram(wire, source, destination, 30001, 53, body)

    def test_ipv6_udp_header_only_first_fragment(self):
        source, destination, body, _ = self.family(6, 76)
        segment = udp_segment(source, destination, 30001, 53, body)
        wire = [ip_piece(source, destination, 1234, 0, True, segment[:8]),
                ip_piece(source, destination, 1234, 8, False, segment[8:])]
        self.assertEqual(2, self.tun(6, body, wire)['request']['fragments'])

    def test_ipv6_tail_next_header_does_not_select_protocol(self):
        source, destination, body, wire = self.family(6)
        wire = [wire[0], *[packet[:40] + bytes([59]) + packet[41:] for packet in wire[1:]]]
        self.assertEqual(len(wire), packets.audit_datagram(
            wire[::-1], source, destination, 30001, 53, body)['fragments'])
        self.assertEqual(len(wire), self.tun(6, body, wire)['request']['fragments'])

    def test_ipv6_atomic_datagrams_with_reused_id_are_independent(self):
        source, destination, body, _ = self.family(6, 76)
        atomic = ip_piece(source, destination, 1234, 0, False,
                          udp_segment(source, destination, 30001, 53, body))
        unrelated = ip_piece(source, destination, 1234, 0, False,
                             udp_segment(source, destination, 30002, 53, body))
        self.assertEqual(1, self.tun(6, body, [unrelated, atomic])['request']['fragments'])
        with self.assertRaisesRegex(AuditError, 'independent datagrams'):
            packets.audit_datagram([atomic, unrelated], source, destination, 30001, 53, body)

    def test_ipv6_atomic_packet_does_not_join_fragmented_datagram(self):
        source, destination, body, wire = self.family(6)
        unrelated = ip_piece(source, destination, 1234, 0, False,
                             udp_segment(source, destination, 30002, 53, b'other'))
        self.assertEqual(len(wire), self.tun(6, body, [unrelated, *wire])['request']['fragments'])

    def test_reassembled_ipv4_options_count_toward_length(self):
        source, destination, body, wire = self.family(4, 65504)
        first = bytearray(wire[0][:20] + bytes([1, 1, 1, 0]) + wire[0][20:])
        first[0] = 0x46
        first[2:4] = len(first).to_bytes(2, 'big')
        first[10:12] = bytes(2)
        first[10:12] = packets.checksum(first[:24]).to_bytes(2, 'big')
        with self.assertRaisesRegex(AuditError, 'complete protocol extent'):
            packets.audit_datagram([bytes(first), *wire[1:]], source, destination, 30001, 53, body)

    def test_reassembled_ipv6_pre_fragment_extensions_count_toward_length(self):
        source, destination, body, wire = self.family(6, 65527)
        extended = []
        for packet in wire:
            new = bytearray(packet[:40] + bytes([44, 0]) + bytes(6) + packet[40:])
            new[6] = 60
            new[4:6] = (len(new) - 40).to_bytes(2, 'big')
            extended.append(bytes(new))
        with self.assertRaisesRegex(AuditError, 'complete protocol extent'):
            packets.audit_datagram(extended, source, destination, 30001, 53, body)

    def test_timeout_separates_other_udp_and_unattributed_tails(self):
        for family in (4, 6):
            source, destination, body, wire = self.family(family, 76)
            unrelated = datagram(destination, source, 54, 30002, body, 1280, 2222)
            orphan = datagram(destination, source, 53, 30001, bytes(4096), 1280, 3333)[1:]
            result = self.tun(family, body, wire, [*unrelated, *orphan])
            self.assertEqual(0, result['matching_return_packet_count'])
            self.assertEqual(len(orphan), result['unattributed_return_packet_count'])
            self.assertEqual(len(unrelated), result['unrelated_return_packet_count'])
            self.assertEqual(len(unrelated) + len(orphan), result['reverse_address_packet_count'])

    def test_matching_return_requires_ports_and_dns_identity(self):
        for family in (4, 6):
            source, destination, body, wire = self.family(family, 76)
            good = datagram(destination, source, 53, 30001, body, 1280, 2222)
            wrong = datagram(destination, source, 53, 30001, b'XX' + body[2:], 1280, 3333)
            result = self.tun(family, body, wire, [*good, *wrong], body)
            self.assertEqual(len(good), result['matching_return_packet_count'])
            self.assertEqual(len(wrong), result['unrelated_return_packet_count'])

    def test_udp_header_only_return_reassembled_for_identity(self):
        source, destination, body, wire = self.family(4, 76)
        segment = udp_segment(destination, source, 53, 30001, body)
        incoming = [ip_piece(destination, source, 2222, 0, True, segment[:8]),
                    ip_piece(destination, source, 2222, 8, False, segment[8:])]
        self.assertEqual(2, self.tun(4, body, wire, incoming, body)['matching_return_packet_count'])


if __name__ == '__main__':
    unittest.main()
