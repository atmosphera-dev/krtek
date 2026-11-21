import json
from pathlib import Path
import tempfile
import unittest

from r06_receive_boundary import COMMANDS, preconnect, snapshot, summarize

TRAFFIC = '''TrafficController
  sUidOwnerMap:
    10182 IIF_MATCH LOCKDOWN_VPN_MATCH 66
    99999 PRIVATE_UID
  sIngressDiscardMap:
    [/172.27.1.1]: 65(null), 65(null)
    [/fdf0:ce4a:801d:0:172:27:1:1]: 66(tun1), 66(tun1)
    [/192.0.2.99]: 1(private), 1(private)
  sLocalNetAccessMap:
    PRIVATE_STATE
'''


class Android:
    def __init__(self, missing=None, traffic=TRAFFIC):
        self.missing, self.traffic, self.acks = missing, traffic, []

    def boottime_ns(self):
        return {'android_boottime_s': '2.00'}

    def su(self, command, **kwargs):
        if self.missing == command:
            raise RuntimeError('PRIVATE_ERROR')
        if command == COMMANDS['trafficcontroller']:
            return self.traffic.encode()
        if command == COMMANDS['links']:
            return b'66: tun1: <UP> mtu 1280\n'
        return b'PRIVATE_RAW_KERNEL_STATE\n'

    def run_as(self, command, data):
        self.acks.append((command, json.loads(data)))


class ReceiveBoundaryTests(unittest.TestCase):
    def request(self):
        return dict(token='fixture-token', index=7, nonce='krtek-m3-fixture', consumer_uid=10182)

    def spec(self):
        return dict(token='fixture-token', arguments={'krtek_r06_receive_boundary': 'true'})

    def test_fixed_addresses_and_exact_uid_only(self):
        value = summarize({'trafficcontroller': TRAFFIC, 'links': '66: tun1: <UP>\n'}, 10182)
        self.assertTrue(value['ingress_map_observed'])
        self.assertFalse(value['ingress_map_malformed'])
        self.assertEqual(len(value['fixed_address_entries']), 2)
        self.assertEqual(value['fixed_address_entries'][0]['ifindexes'], [65, 65])
        self.assertEqual(value['consumer_uid_rules'], ['10182 IIF_MATCH LOCKDOWN_VPN_MATCH 66'])
        self.assertEqual(value['tun_links'], {'tun1': 66})
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_absent_map_is_not_empty_map(self):
        self.assertFalse(summarize({}, 10182)['ingress_map_observed'])
        self.assertTrue(summarize({'trafficcontroller': '  sIngressDiscardMap:\n  Next:\n'}, 10182)['ingress_map_observed'])

    def test_malformed_map_is_explicit(self):
        self.assertTrue(summarize({'trafficcontroller': '  sIngressDiscardMap:\n    broken\n'}, 1)['ingress_map_malformed'])

    def test_empty_uid_entry_not_guessed(self):
        self.assertEqual(summarize({'trafficcontroller': TRAFFIC}, 1)['consumer_uid_rules'], [])

    def test_private_raw_and_public_hashes(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            value = snapshot(Android(), p/'private/token', p/'collected/call/snapshot', self.request())
            self.assertEqual(len(value['private_files']), len(COMMANDS))
            self.assertIn('PRIVATE', (p/'private/token/connectivity.txt').read_text())
            self.assertNotIn('PRIVATE', (p/'collected/call/snapshot/receive-boundary.json').read_text())

    def test_private_path_inside_collection_refused(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            with self.assertRaises(RuntimeError):
                snapshot(Android(), p/'collected/private', p/'collected/snapshot', self.request())

    def test_duplicate_snapshot_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            snapshot(Android(), p/'private/token', p/'collected/call/snapshot', self.request())
            with self.assertRaises(FileExistsError):
                snapshot(Android(), p/'private/token', p/'collected/call/snapshot', self.request())

    def test_ack_binds_original_request_and_is_atomic(self):
        with tempfile.TemporaryDirectory() as root:
            p, android = Path(root), Android()
            preconnect(android, p/'private', p/'collected/call', self.spec(), self.request())
            command, ack = android.acks[0]
            self.assertEqual(ack, dict(token='fixture-token', index=7, nonce='krtek-m3-fixture', snapshot_sealed=True))
            self.assertIn('mv files/krtek-r06/fixture-token/receive-7.ack.next files/krtek-r06/fixture-token/receive-7.ack', command)

    def test_invalid_request_refused_before_android_io(self):
        for key, wrong in [('token', 'other'), ('index', -1), ('index', True), ('nonce', '../bad'),
                           ('consumer_uid', '10182'), ('consumer_uid', -1)]:
            with self.subTest(key=key, wrong=wrong), tempfile.TemporaryDirectory() as root:
                p, android, request = Path(root), Android(), self.request()
                request[key] = wrong
                with self.assertRaises(RuntimeError):
                    preconnect(android, p/'private', p/'collected/call', self.spec(), request)
                self.assertEqual(android.acks, [])
                self.assertFalse((p/'private').exists())

    def test_default_off_refuses_snapshot_and_ack(self):
        with tempfile.TemporaryDirectory() as root:
            p, android = Path(root), Android()
            with self.assertRaises(RuntimeError):
                preconnect(android, p/'private', p/'collected/call', {'token': 'fixture-token'}, self.request())
            self.assertEqual(android.acks, [])

    def test_unavailable_boundary_withholds_ack_and_retains_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            p, android = Path(root), Android(missing=COMMANDS['netd'])
            with self.assertRaises(RuntimeError):
                preconnect(android, p/'private', p/'collected/call', self.spec(), self.request())
            value = json.loads((p/'collected/call/receive-7/receive-boundary.json').read_text())
            self.assertEqual(value['unavailable'], {'netd': 'RuntimeError'})
            self.assertEqual(android.acks, [])
            self.assertNotIn('PRIVATE_ERROR', json.dumps(value))

    def test_missing_map_withholds_ack(self):
        with tempfile.TemporaryDirectory() as root:
            p, android = Path(root), Android(traffic='unavailable')
            with self.assertRaises(RuntimeError):
                preconnect(android, p/'private', p/'collected/call', self.spec(), self.request())
            self.assertEqual(android.acks, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
