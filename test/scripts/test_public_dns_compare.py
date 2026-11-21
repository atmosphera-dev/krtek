#!/usr/bin/env python3
"""Comparison-control tests, run only in a named project guest."""
import copy
import unittest

from public_dns_audit import AuditError, sha
from public_dns_compare import compare_pair, padding_only, STOCK_SOURCE
from test_public_dns_audit import SMALL


class PublicDnsCompareTest(unittest.TestCase):
    def setUp(self):
        common = dict(family=4, request_bytes=76, peer='1.1.1.1', remote_port=53,
                      consumer_apk_sha256='a' * 64, consumer_test_apk_sha256='b' * 64,
                      consumer_included_uid_verified=True, emulator_serial='emulator-5554',
                      relay_endpoint='192.0.2.1:51820', transport='udp', tunnel_mtu=1280,
                      ipv6_enabled=True, android_image_sha256='c' * 64, emulator_build='test-build',
                      topology='tap', outer_mtu=1500, os_lockdown=True, private_dns='off',
                      signer_sha256='d' * 64, source_unmodified=True,
                      dns_audit=dict(custody_status='PASS', query_sha256=sha(SMALL),
                                     usable_a=True, classification='usable-a'))
        self.krtek = copy.deepcopy(common)
        self.krtek.update(app='krtek', instance='krtek-d-krtek', source_commit='7c610b', version_name='krtek-test')
        self.stock = copy.deepcopy(common)
        self.stock.update(app='stock', instance='krtek-d-stock', source_commit=STOCK_SOURCE, version_name='stock-test')
        self.krtek_receipt, self.stock_receipt = b'krtek attempt', b'stock attempt'
        self.krtek['dns_audit']['receipt_sha256'] = sha(self.krtek_receipt)
        self.stock['dns_audit']['receipt_sha256'] = sha(self.stock_receipt)

    def result(self):
        return compare_pair(self.krtek, self.stock, SMALL, SMALL,
                            self.krtek_receipt, self.stock_receipt)

    def test_matched_inputs_are_not_a_cause_claim(self):
        result = self.result()
        self.assertTrue(result['network_inputs_matched'])
        self.assertEqual('both-usable', result['observation'])
        self.assertFalse(result['cause_located'])
        self.assertNotEqual(result['build_differences']['krtek_source'], result['build_differences']['stock_source'])

    def test_silence_and_asymmetry_remain_observations(self):
        for left, right, expected in ((False, False, 'neither-usable'),
                                     (False, True, 'krtek-no-usable-answer'),
                                     (True, False, 'stock-no-usable-answer')):
            self.krtek['dns_audit'].update(usable_a=left, classification='usable-a' if left else 'receive-timeout')
            self.stock['dns_audit'].update(usable_a=right, classification='usable-a' if right else 'tc')
            result = self.result()
            self.assertEqual(expected, result['observation'])
            self.assertFalse(result['cause_located'])

    def test_missing_or_different_relay_is_not_equivalent(self):
        self.stock['relay_endpoint'] = '192.0.2.2:51820'
        result = self.result()
        self.assertFalse(result['network_inputs_matched'])
        self.assertEqual('different', result['mismatches'][0]['reason'])
        self.stock['relay_endpoint'] = None
        self.assertEqual('unobserved', self.result()['mismatches'][0]['reason'])

    def test_rejects_nonindependent_instances_and_consumer_bytes(self):
        self.stock['instance'] = 'krtek-d-krtek'
        with self.assertRaisesRegex(AuditError, 'Separate complete Android'):
            self.result()
        self.stock['instance'] = 'krtek-d-stock'
        self.stock['consumer_apk_sha256'] = 'e' * 64
        with self.assertRaisesRegex(AuditError, 'consumer APK bytes differ'):
            self.result()

    def test_rejects_wrong_stock_source_or_unverified_uid(self):
        self.stock['source_commit'] = 'other'
        with self.assertRaisesRegex(AuditError, 'pinned unmodified'):
            self.result()
        self.stock['source_commit'] = STOCK_SOURCE
        self.krtek['consumer_included_uid_verified'] = False
        with self.assertRaisesRegex(AuditError, 'UID coverage unverified'):
            self.result()

    def test_rejects_wrong_dns_peer_or_query_bytes(self):
        self.stock['peer'] = '8.8.8.8'
        with self.assertRaisesRegex(AuditError, 'peer differs'):
            self.result()
        self.stock['peer'] = '1.1.1.1'
        with self.assertRaisesRegex(AuditError, 'query bytes differ'):
            compare_pair(self.krtek, self.stock, SMALL, b'wrong',
                         self.krtek_receipt, self.stock_receipt)

    def test_rejects_same_query_audit_from_another_attempt(self):
        for call in (self.krtek, self.stock):
            original = call['dns_audit']['receipt_sha256']
            call['dns_audit']['receipt_sha256'] = sha(b'earlier usable attempt')
            with self.assertRaisesRegex(AuditError, 'selected receipt binding'):
                self.result()
            call['dns_audit']['receipt_sha256'] = original

    def test_rejects_false_byte_custody_or_query_binding(self):
        self.stock['dns_audit']['custody_status'] = 'FAIL'
        with self.assertRaisesRegex(AuditError, 'byte custody'):
            self.result()
        self.stock['dns_audit'].update(custody_status='PASS', query_sha256='0' * 64)
        with self.assertRaisesRegex(AuditError, 'query binding differs'):
            self.result()

    def test_padding_is_the_only_small_large_variable(self):
        large = bytearray(SMALL + bytes(4020))
        large[38:40] = bytes.fromhex('0fd8')
        large[42:44] = bytes.fromhex('0fd4')
        self.assertTrue(padding_only(SMALL, bytes(large))['padding_is_only_variable'])
        large[44] ^= 1
        with self.assertRaisesRegex(AuditError, 'more than EDNS padding'):
            padding_only(SMALL, bytes(large))


if __name__ == '__main__':
    unittest.main()
