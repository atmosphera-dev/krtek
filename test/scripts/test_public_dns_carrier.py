#!/usr/bin/env python3
"""Carrier byte custody controls; guest-only, no packet transmission."""
import copy
import unittest

from public_dns_audit import AuditError
from public_dns_carrier import audit_call_owner, read_carrier


class PublicDnsCarrierTest(unittest.TestCase):
    def setUp(self):
        self.receipt = dict(pid=123, observer=2, session=3, target=4, request=5,
                            started_ns=50, finished_ns=200, feature='public-dns-diagnostics',
                            readback_verified=True, writer_flushed=True, packet_drops=0)
        self.prefix = 'KRTEK_PUBLIC_DNS schema=1 boot_ns=100 pid=123 observer=2 session=3 target=4 request=5 '

    def lines(self, size=4096, boundary='handoff-input', completed=True):
        data = bytes(index % 251 for index in range(size))
        count = (size + 127) // 128
        rows = [self.prefix + 'event=marker boundary=observer-open packet=0']
        for index in range(count):
            chunk = data[index * 128:(index + 1) * 128]
            rows.append(self.prefix + f'event=chunk packet=1 boundary={boundary} outbound={str(boundary == "handoff-input").lower()} family=4 bytes={size} index={index} chunks={count} hex={chunk.hex()}')
        if completed:
            marker = {'handoff-input': 'handoff-return', 'decrypted-return': 'decrypted-return-queued',
                      'translated-return': 'return-queued'}[boundary]
            rows.append(self.prefix + f'event=marker boundary={marker} packet=1')
        rows.append(self.prefix + f'event=marker boundary=observer-close packet=0 packets=1 chunks={count} completions={int(completed)}')
        return data, rows

    def test_exact_complete_packets_at_every_boundary(self):
        for boundary in ('handoff-input', 'decrypted-return', 'translated-return'):
            for size in (76, 1280, 4096, 65535):
                data, lines = self.lines(size, boundary)
                rows = read_carrier('\n'.join(lines), self.receipt)
                self.assertEqual(data, rows[0]['packet'])
                self.assertTrue(rows[0]['completed'])

    def test_input_without_success_marker_is_not_handoff(self):
        _, lines = self.lines(completed=False)
        self.assertFalse(read_carrier('\n'.join(lines), self.receipt)[0]['completed'])

    def test_rejects_missing_whole_packet_using_terminal_counters(self):
        _, lines = self.lines()
        with self.assertRaisesRegex(AuditError, 'terminal counters'):
            read_carrier('\n'.join(lines).replace('packets=1 chunks=', 'packets=2 chunks='), self.receipt)

    def test_rejects_missing_duplicate_and_short_chunks(self):
        _, lines = self.lines()
        for bad in (lines[:1] + lines[2:], lines + lines[1:2],
                    [line[:-2] if 'index=0 ' in line else line for line in lines]):
            with self.assertRaises(AuditError):
                read_carrier('\n'.join(bad), self.receipt)

    def test_rejects_orphan_and_duplicate_success_markers(self):
        _, lines = self.lines()
        with self.assertRaisesRegex(AuditError, 'Duplicate carrier success marker'):
            read_carrier('\n'.join([*lines, lines[-2]]), self.receipt)
        orphan = [line.replace('completions=1', 'completions=2') for line in lines]
        orphan.append(lines[-2].replace('packet=1', 'packet=999'))
        with self.assertRaisesRegex(AuditError, 'Orphan carrier success marker'):
            read_carrier('\n'.join(orphan), self.receipt)

    def test_rejects_wrong_epoch_clock_and_unsealed_lifetime(self):
        _, lines = self.lines()
        for bad in (lines[1:], lines[:-1], [line.replace('request=5', 'request=6') for line in lines]):
            with self.assertRaises(AuditError):
                read_carrier('\n'.join(bad), self.receipt)
        with self.assertRaises(ValueError):
            read_carrier('\n'.join(lines).replace('boot_ns=100', 'boot_ns=unavailable'), self.receipt)

    def test_rejects_incomplete_collector_and_empty_data(self):
        _, lines = self.lines()
        for key, value in (('packet_drops', 1), ('readback_verified', False), ('writer_flushed', False)):
            receipt = copy.deepcopy(self.receipt)
            receipt[key] = value
            with self.assertRaises(AuditError):
                read_carrier('\n'.join(lines), receipt)
        with self.assertRaises(AuditError):
            read_carrier('', self.receipt)

    def durable(self):
        data, lines = self.lines()
        lines = [line.replace('schema=1', 'schema=2 epoch=25') for line in lines]
        lines[0] = lines[0].replace('boot_ns=100', 'boot_ns=75')
        lines[-1] = lines[-1].replace('boot_ns=100', 'boot_ns=150')
        receipt = dict(self.receipt, epoch=25, call_started_ns=90, call_finished_ns=125)
        return data, lines, receipt

    def test_durable_owner_seal_reconstructs_original_bytes(self):
        data, lines, receipt = self.durable()
        self.assertEqual(data, read_carrier('\n'.join(lines), receipt)[0]['packet'])

    def test_rejects_pid_or_epoch_replacement_even_with_original_seal(self):
        _, lines, receipt = self.durable()
        for old, new in (('pid=123', 'pid=124'), ('epoch=25', 'epoch=26'),
                         ('observer=2', 'observer=3'), ('request=5', 'request=6')):
            replacement = lines[1].replace(old, new)
            with self.assertRaisesRegex(AuditError, 'owner changed'):
                read_carrier('\n'.join(lines + [replacement]), receipt)

    def test_rejects_replacement_only_and_abrupt_exit_without_final_counters(self):
        _, lines, receipt = self.durable()
        for bad in (lines[:-1], [line.replace('pid=123', 'pid=124') for line in lines]):
            with self.assertRaises(AuditError):
                read_carrier('\n'.join(bad), receipt)

    def test_rejects_owner_started_late_or_sealed_before_call_end(self):
        _, lines, receipt = self.durable()
        for key, value in (('call_started_ns', 60), ('call_finished_ns', 170)):
            with self.assertRaisesRegex(AuditError, 'complete call'):
                audit_call_owner('\n'.join(lines), dict(receipt, **{key: value}))

    def test_ignores_successors_only_outside_the_sealed_call_window(self):
        _, lines, receipt = self.durable()
        replacement = lines[0].replace('pid=123', 'pid=124').replace('boot_ns=75', 'boot_ns=180')
        audit_call_owner('\n'.join(lines + [replacement]), receipt)

    def test_rejects_foreign_lifetime_enclosing_call_without_packets(self):
        _, lines, receipt = self.durable()
        foreign = [lines[0].replace('pid=123', 'pid=124').replace('boot_ns=75', 'boot_ns=80'),
                   lines[-1].replace('pid=123', 'pid=124').replace('boot_ns=150', 'boot_ns=140')]
        with self.assertRaisesRegex(AuditError, 'foreign owner changed'):
            read_carrier('\n'.join([*lines, *foreign]), receipt)

    def test_foreign_open_lifetime_and_missing_open_are_not_silence(self):
        _, lines, receipt = self.durable()
        for foreign in (lines[0].replace('pid=123', 'pid=124'),
                        lines[-1].replace('pid=123', 'pid=124')):
            with self.assertRaisesRegex(AuditError, 'foreign owner changed'):
                read_carrier('\n'.join([*lines, foreign]), receipt)
        prior = [lines[0].replace('pid=123', 'pid=124').replace('boot_ns=75', 'boot_ns=60'),
                 lines[-1].replace('pid=123', 'pid=124').replace('boot_ns=150', 'boot_ns=80')]
        audit_call_owner('\n'.join([*lines, *prior]), receipt)


if __name__ == '__main__':
    unittest.main()
