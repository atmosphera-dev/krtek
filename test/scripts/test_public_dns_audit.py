#!/usr/bin/env python3
"""Saved-byte audit contracts. Run only inside the assigned run-11 guest."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import public_dns_audit as audit


SMALL = bytes.fromhex(
    '123401000001000000000001076578616d706c6503636f6d0000010001'
    '0000291000000000000024000c0020'
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
GOOD = bytes.fromhex(
    '123481800001000100000000076578616d706c6503636f6d0000010001'
    'c00c000100010000012c0004c0000201')


class PublicDnsAuditTest(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix='public-dns-audit-')
        self.addCleanup(self.owner.cleanup)
        self.directory = Path(self.owner.name)
        self.receipt = dict(schema=1, family=4, dns_id=0x1234, request_bytes=76,
                            remote_address='1.1.1.1', remote_port=53,
                            send_calls=1, receive_calls=1, received=len(GOOD),
                            reply_source='1.1.1.1', reply_port=53,
                            classification='usable-a', semantic_usable_a=True)
        self.save('query', 'query.bin', SMALL)
        self.save('response', 'response-000.bin', GOOD)

    def save(self, field, name, data):
        (self.directory / name).write_bytes(data)
        self.receipt[field] = dict(
            path=f'/data/user/0/consumer/files/public-dns/{self.directory.name}/{name}',
            size=len(data), sha256=audit.sha(data))
        if field == 'response':
            self.receipt['received'] = len(data)

    def result(self):
        return audit.audit(self.directory, json.dumps(self.receipt).encode())

    def test_small_and_large_golden(self):
        self.assertEqual(76, len(SMALL))
        audit.query_audit(SMALL)
        large = bytearray(SMALL + bytes(4020))
        large[38:40] = bytes.fromhex('0fd8')
        large[42:44] = bytes.fromhex('0fd4')
        audit.query_audit(bytes(large))

    def test_complete_usable_a(self):
        result = self.result()
        self.assertEqual('PASS', result['custody_status'])
        self.assertEqual('usable-a', result['classification'])
        self.assertTrue(result['usable_a'])

    def test_timeout_is_not_delivery(self):
        del self.receipt['response']
        (self.directory / 'response-000.bin').unlink()
        self.receipt.update(received=0, classification='receive-timeout', semantic_usable_a=False)
        result = self.result()
        self.assertFalse(result['response_observed'])
        self.assertFalse(result['usable_a'])
        self.assertEqual('receive-timeout', result['classification'])

    def test_rejected_response_stays_available(self):
        self.save('response', 'response-000.bin', b'bad')
        self.receipt.update(classification='malformed', semantic_usable_a=False)
        result = self.result()
        self.assertEqual('malformed', result['classification'])
        self.assertEqual(b'bad', (self.directory / 'response-000.bin').read_bytes())

    def test_rejects_unreported_first_response_on_timeout(self):
        del self.receipt['response']
        self.receipt.update(received=0, classification='receive-timeout', semantic_usable_a=False)
        with self.assertRaisesRegex(audit.AuditError, 'Unreported first response'):
            self.result()

    def test_rejects_any_unreported_response_artifact(self):
        (self.directory / 'response-002.bin').write_bytes(GOOD)
        with self.assertRaisesRegex(audit.AuditError, 'Unreported extra response'):
            self.result()

    def test_wrong_source_and_port(self):
        self.receipt.update(reply_source='1.0.0.1', semantic_usable_a=False)
        self.assertEqual('wrong-source', self.result()['classification'])
        self.receipt.update(reply_source='1.1.1.1', reply_port=54)
        self.assertEqual('wrong-source', self.result()['classification'])

    def test_protocol_outcomes_remain_distinct(self):
        for low_flags, expected in ((0x80, 'usable-a'), (0x83, 'rcode'), (0x85, 'rcode')):
            with self.subTest(flags=low_flags):
                reply = bytearray(GOOD)
                reply[3] = low_flags
                self.save('response', 'response-000.bin', bytes(reply))
                self.receipt['semantic_usable_a'] = expected == 'usable-a'
                self.assertEqual(expected, self.result()['classification'])
        reply = bytearray(GOOD)
        reply[2] = 0x83
        self.save('response', 'response-000.bin', bytes(reply))
        self.receipt['semantic_usable_a'] = False
        self.assertEqual('tc', self.result()['classification'])

    def test_no_answer_and_unrelated_answer(self):
        no_answer = bytes.fromhex('123481800001000000000000') + SMALL[12:29]
        self.save('response', 'response-000.bin', no_answer)
        self.receipt['semantic_usable_a'] = False
        self.assertEqual('no-answer', self.result()['classification'])
        unrelated = GOOD[:29] + bytes.fromhex('056f7468657203636f6d00000100010000012c0004c0000201')
        self.save('response', 'response-000.bin', unrelated)
        self.assertEqual('unusable-answer', self.result()['classification'])

    def test_rejects_byte_and_digest_custody_mismatch(self):
        (self.directory / 'response-000.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(audit.AuditError, 'custody mismatch'):
            self.result()

    def test_rejects_wrong_private_attempt(self):
        self.receipt['response']['path'] = '/data/user/0/consumer/files/public-dns/other/response-000.bin'
        with self.assertRaisesRegex(audit.AuditError, 'attempt identity'):
            self.result()

    def test_rejects_success_without_saved_bytes(self):
        del self.receipt['response']
        with self.assertRaisesRegex(audit.AuditError, 'without a saved response'):
            self.result()

    def test_rejects_resend_and_unscheduled_peer(self):
        original = copy.deepcopy(self.receipt)
        self.receipt['send_calls'] = 2
        with self.assertRaisesRegex(audit.AuditError, 'resent/retried'):
            self.result()
        self.receipt = original
        self.receipt['remote_address'] = '8.8.8.8'
        with self.assertRaisesRegex(audit.AuditError, 'pinned Cloudflare'):
            self.result()

    def test_rejects_false_java_semantic_success(self):
        self.save('response', 'response-000.bin', b'bad')
        with self.assertRaisesRegex(audit.AuditError, 'claimed usable A'):
            self.result()


if __name__ == '__main__':
    unittest.main()
