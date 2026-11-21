#!/usr/bin/env python3
"""Matched-input comparison, not an attribution oracle. No device/network I/O."""
import ipaddress

from public_dns_audit import need, query_audit, sha


NETWORK_INPUTS = ('relay_endpoint', 'transport', 'tunnel_mtu', 'ipv6_enabled',
                  'android_image_sha256', 'emulator_build', 'topology', 'outer_mtu',
                  'os_lockdown', 'private_dns')
STOCK_SOURCE = '8fcbcd553ebf514f854fd835fe1bd37c8551b56a'


def padding_only(small, large):
    need(len(small) == 76 and len(large) == 4096, 'Small/original-large pair required')
    query_audit(small)
    query_audit(large)
    normalized = bytearray(large[:76])
    normalized[38:40] = small[38:40]
    normalized[42:44] = small[42:44]
    need(bytes(normalized) == small and large[76:] == bytes(4020),
         'Comparison changed more than EDNS padding length')
    return dict(padding_is_only_variable=True, small_sha256=sha(small), large_sha256=sha(large))


def compare_pair(krtek, stock, krtek_query, stock_query, krtek_receipt, stock_receipt):
    need(krtek['app'] == 'krtek' and stock['app'] == 'stock', 'Independent app labels required')
    need(stock['source_commit'] == STOCK_SOURCE and stock['source_unmodified'] is True,
         'Stock source must be the pinned unmodified commit')
    need(krtek['instance'] == 'krtek-d-krtek' and stock['instance'] == 'krtek-d-stock',
         'Separate complete Android data sets required')
    need(krtek['consumer_apk_sha256'] == stock['consumer_apk_sha256']
         and krtek['consumer_test_apk_sha256'] == stock['consumer_test_apk_sha256'],
         'Standalone consumer APK bytes differ')
    for call in (krtek, stock):
        need(call['family'] in (4, 6) and call['request_bytes'] in (76, 4096), 'Unscheduled query vector')
        need(call['consumer_included_uid_verified'] is True, 'Ordinary included-UID coverage unverified')
        need(call['emulator_serial'] == 'emulator-5554', 'Wrong nested emulator serial')
        need(call['remote_port'] == 53, 'Comparison DNS port differs')
        peer = '1.1.1.1' if call['family'] == 4 else '2606:4700:4700::1111'
        need(ipaddress.ip_address(call['peer']) == ipaddress.ip_address(peer), 'Comparison peer differs')
    need(krtek['family'] == stock['family'] and krtek['request_bytes'] == stock['request_bytes'],
         'Unmatched family/request size')
    need(len(krtek_query) == krtek['request_bytes'] and krtek_query == stock_query,
         'Krtek/stock query bytes differ')
    query_audit(krtek_query)
    mismatches = []
    for field in NETWORK_INPUTS:
        left, right = krtek.get(field), stock.get(field)
        if left is None or right is None:
            mismatches.append(dict(field=field, reason='unobserved', krtek=left, stock=right))
        elif left != right:
            mismatches.append(dict(field=field, reason='different', krtek=left, stock=right))
    left = krtek['dns_audit']
    right = stock['dns_audit']
    need(left['custody_status'] == right['custody_status'] == 'PASS', 'Unverified private byte custody')
    need(left['query_sha256'] == right['query_sha256'] == sha(krtek_query), 'Audit query binding differs')
    for audit, receipt in ((left, krtek_receipt), (right, stock_receipt)):
        need(audit['receipt_sha256'] == sha(receipt), 'Audit selected receipt binding differs')
    usable = (left['usable_a'], right['usable_a'])
    observation = {(True, True): 'both-usable', (True, False): 'stock-no-usable-answer',
                   (False, True): 'krtek-no-usable-answer', (False, False): 'neither-usable'}[usable]
    return dict(schema=1, family=krtek['family'], request_bytes=krtek['request_bytes'],
                query_sha256=sha(krtek_query), consumer_bytes_identical=True,
                network_inputs_matched=not mismatches, mismatches=mismatches,
                observation=observation, krtek_outcome=left['classification'],
                stock_outcome=right['classification'], cause_located=False,
                scope='Independently source-built stock, not an official release-signature claim',
                build_differences=dict(krtek_source=krtek['source_commit'],
                    stock_source=stock['source_commit'], krtek_version=krtek['version_name'],
                    stock_version=stock['version_name'], krtek_signer=krtek['signer_sha256'],
                    stock_signer=stock['signer_sha256']))
