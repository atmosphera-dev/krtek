"""Guest-only parser and lifecycle refusal controls; no Android/account needed."""
import copy
import errno
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import r06_async_sampler as s


def message(kind, payload=b'', seq=1, flags=0):
    size = 16 + len(payload)
    return struct.pack('=IHHII', size, kind, flags, seq, 0) + payload + b'\0' * (-size % 4)


def attribute(kind, payload):
    size = 4 + len(payload)
    return struct.pack('=HH', size, kind) + payload + b'\0' * (-size % 4)


def source(kind, data=b'', seq=1, error=0):
    return dict(event='source', sequence=seq, kind=kind, begin_ns=101, end_ns=102, errno=error, hex=data.hex())


def fixture():
    rows = [dict(event='map', kind=k, id=i, key_size=n, value_size=8)
            for i, (k, n) in enumerate((('ingress', 16), ('uid_owner', 4)), 1)]
    rows += [dict(event='start', uid=10182, interval_ms=25, boottime_ns=90, pid=123)]
    for kind in sorted(s.KINDS):
        data = struct.pack('=II', 66, 66) if kind.startswith('ingress') else \
            struct.pack('=II', 0, 128) if kind == 'uid_owner' else \
            b'Ip: InReceives InDiscards\nIp: 10 1\n' if kind in {'snmp', 'netstat'} else message(3)
        rows.append(source(kind, data))
    rows += [dict(event='sample', sequence=1, begin_ns=100, end_ns=110, wall_ns=1000100, wall_boot_end_ns=101, missed_periods=0),
             dict(event='end', boottime_ns=120, samples=1, signalled=True, failed=False)]
    return rows


class SamplerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def analyze(self, rows):
        raw, public = self.root / 'raw', self.root / 'public'
        raw.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return s.summarize(raw, public, 10182)

    def reject(self, rows):
        with self.assertRaises((ValueError, KeyError, struct.error)):
            self.analyze(rows)

    def test_complete(self):
        result = self.analyze(fixture())
        self.assertEqual(result['samples'], 1)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['raw_sha256'], s.file_sha(self.root / 'raw'))

    def test_missing_source(self):
        rows = fixture(); del rows[4]; self.reject(rows)

    def test_missing_terminal(self):
        self.reject(fixture()[:-1])

    def test_failed_terminal(self):
        rows = fixture(); rows[-1]['failed'] = True; self.reject(rows)

    def test_duplicate_source(self):
        rows = fixture(); rows.insert(4, copy.deepcopy(rows[3])); self.reject(rows)

    def test_wrong_uid(self):
        rows = fixture(); rows[2]['uid'] = 10183; self.reject(rows)

    def test_stale_sequence(self):
        rows = fixture(); rows[3]['sequence'] = 2; self.reject(rows)

    def test_missing_maps(self):
        rows = fixture(); del rows[0]; self.reject(rows)

    def test_wrong_map_identity_schema(self):
        rows = fixture(); rows[0]['value_size'] = 16; self.reject(rows)

    def test_terminal_clock(self):
        rows = fixture(); rows[-1]['boottime_ns'] = 99; self.reject(rows)

    def test_counter_permission_error(self):
        rows = fixture()
        next(r for r in rows if r.get('kind') == 'snmp')['errno'] = errno.EACCES
        self.reject(rows)

    def test_counter_format_error(self):
        with self.assertRaises(ValueError):
            s.decode_source(source('snmp', b'Ip: A B\nIp: 2\n'), 10182)

    def test_absent_map_is_distinct_from_unreadable(self):
        self.assertEqual(s.decode_source(source('ingress4', error=errno.ENOENT), 10182), {'absent': True})
        with self.assertRaises(ValueError):
            s.decode_source(source('ingress4', error=errno.EPERM), 10182)

    def test_current_and_wildcard_iif(self):
        for iif in (0, 66):
            result = s.decode_source(source('uid_owner', struct.pack('=II', iif, 128)), 10182)
            self.assertEqual(result['wildcard_iif'], iif == 0)
            self.assertEqual(result['iif'], iif)

    def test_wrong_uid_map_schema(self):
        with self.assertRaises(struct.error):
            s.decode_source(source('uid_owner', bytes(16)), 10182)

    def test_rule_consumer_range(self):
        rule = struct.pack('=BBBBBBBBI', 2, 0, 0, 0, 100, 0, 0, 1, 0)
        data = rule + attribute(20, struct.pack('=II', 10000, 11000)) + attribute(6, struct.pack('=I', 12000))
        parsed = s.decode_source(source('rules4', message(32, data) + message(3)), 10182)
        self.assertEqual(parsed[0]['uid_range'], [10000, 11000])
        self.assertEqual(parsed[0]['table'], 100)
        self.assertEqual(s.decode_source(source('rules4', message(32, data) + message(3)), 12000), [])

    def test_tun_counters(self):
        body = struct.pack('=BBHiII', 0, 0, 65534, 66, 1, 0)
        body += attribute(3, b'tun1\0') + attribute(23, struct.pack('=8Q', *range(8)))
        parsed = s.decode_source(source('links', message(16, body) + message(3)), 10182)
        self.assertEqual(parsed[0]['rx_dropped'], 6)
        self.assertEqual(parsed[0]['ifindex'], 66)

    def test_missing_tun_counters(self):
        body = struct.pack('=BBHiII', 0, 0, 65534, 66, 1, 0) + attribute(3, b'tun1\0')
        with self.assertRaises(ValueError):
            s.decode_source(source('links', message(16, body) + message(3)), 10182)

    def test_addresses_only_fixed(self):
        body = struct.pack('=BBBBI', 2, 32, 0, 0, 66) + attribute(2, bytes((172, 27, 1, 1)))
        parsed = s.decode_source(source('addresses', message(20, body) + message(3)), 10182)
        self.assertEqual(parsed, [dict(address='172.27.1.1', ifindex=66)])

    def test_fixed_ipv6_address_uses_canonical_identity(self):
        body = struct.pack('=BBBBI', 10, 128, 0, 0, 66)
        body += attribute(1, bytes.fromhex('fdf0ce4a801d00000172002700010001'))
        parsed = s.decode_source(source('addresses', message(20, body) + message(3)), 10182)
        self.assertEqual(parsed, [dict(address='fdf0:ce4a:801d:0:172:27:1:1', ifindex=66)])

    def test_netlink_missing_done(self):
        with self.assertRaises(ValueError):
            s.messages(message(16, bytes(16)), 1)

    def test_netlink_stale(self):
        with self.assertRaises(ValueError):
            s.messages(message(3, seq=2), 1)

    def test_netlink_interrupted(self):
        with self.assertRaises(ValueError):
            s.messages(message(3, flags=16), 1)

    def test_netlink_truncated(self):
        with self.assertRaises(ValueError):
            s.messages(message(3)[:-1], 1)

    def test_source_clock(self):
        rows = fixture(); rows[3]['end_ns'] = 99; self.reject(rows)

    def test_source_outside_sample(self):
        rows = fixture(); rows[3]['end_ns'] = 111; self.reject(rows)

    def test_realtime_bracket_outside_sample(self):
        rows = fixture(); rows[-2]['wall_boot_end_ns'] = 111; self.reject(rows)

    def test_counter_deltas_and_reset(self):
        rows = fixture(); first = copy.deepcopy(rows[3:-1]); rows.pop()
        def link_bytes(seq, counters):
            body = struct.pack('=BBHiII', 0, 0, 65534, 66, 1, 0)
            body += attribute(3, b'tun1\0') + attribute(23, struct.pack('=8Q', *counters))
            return (message(16, body, seq=seq) + message(3, seq=seq)).hex()
        next(r for r in rows if r.get('kind') == 'links')['hex'] = link_bytes(1, [1]*8)
        for row in first:
            row['sequence'] = 2
            row['begin_ns'] += 25000000; row['end_ns'] += 25000000
            if row['event'] == 'sample':
                row['wall_ns'] += 25000000; row['wall_boot_end_ns'] += 25000000
            if row.get('kind') in ('rules4', 'rules6', 'links', 'addresses'):
                row['hex'] = message(3, seq=2).hex()
            if row.get('kind') == 'snmp':
                row['hex'] = b'Ip: InReceives InDiscards\nIp: 15 0\n'.hex()
            if row.get('kind') == 'links':
                row['hex'] = link_bytes(2, [2]*8)
        rows += first + [dict(event='end', boottime_ns=25000200, samples=2, signalled=True, failed=False)]
        result = self.analyze(rows)
        output = json.loads((self.root / 'public').read_text().splitlines()[-1])
        self.assertEqual(output['counter_deltas']['snmp']['Ip:InReceives'], 5)
        self.assertEqual(output['counter_resets'], ['snmp:Ip:InDiscards'])
        self.assertEqual(result['interval_ns']['mean'], 25000000)
        self.assertEqual(output['link_deltas'][0]['deltas']['rx_dropped'], 1)

    def test_framework_bounded_projection(self):
        raw = b'100\nNetworkAgentInfo{network{115} InterfaceName: tun1 Transports: VPN Uids: <{0-10181,10183-99999}> private-data}\n120\n'
        value = s.framework_summary(raw)
        self.assertEqual(value['vpns'][0]['net_id'], 115)
        self.assertTrue(value['vpns'][0]['complete'])
        self.assertNotIn('private-data', json.dumps(value))

    def test_framework_unavailable_not_empty_success(self):
        with self.assertRaises(ValueError):
            s.framework_summary(b'100\nPermission denied\n120\n')

    def test_framework_timeout_marker_rejects_partial_network_heading(self):
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            s.framework_summary(b"100\nNetwork partial\n*** SERVICE 'connectivity' DUMP TIMEOUT (10000ms) EXPIRED ***\n120\n")

    def test_framework_shell_preserves_failing_command_status(self):
        sampler = object.__new__(s.AsyncSampler)
        sampler.private, sampler.remote = self.root, '/unused'
        sampler.stop_event, sampler.errors, sampler.framework = Mock(), [], []
        sampler.stop_event.is_set.return_value = False
        sampler.android = Mock()
        observed = []
        def fail_mid_sequence(command, **_kwargs):
            # Replace only executable names; execute the actual shell structure.
            command = command.replace('/unused/sampler --boottime', 'printf "100\\n"')
            command = command.replace('dumpsys connectivity', 'false')
            result = subprocess.run(['sh', '-c', command], capture_output=True)
            observed.append(result)
            raise RuntimeError('remote exit')
        sampler.android.su.side_effect = fail_mid_sequence
        sampler._framework()
        self.assertNotEqual(observed[0].returncode, 0)
        self.assertEqual(observed[0].stdout, b'100\n')
        self.assertEqual(len(sampler.errors), 1)
        self.assertEqual(sampler.framework, [])

    def stop_fixture(self):
        sampler = object.__new__(s.AsyncSampler)
        sampler.stop_event, sampler.android = Mock(), Mock()
        sampler.remote, sampler.errors, sampler.framework = '/remote', [], [dict()]
        sampler.proc, sampler.thread = Mock(), Mock()
        sampler.proc.poll.return_value = None
        sampler.proc.returncode = 0
        sampler.thread.is_alive.return_value = False
        sampler.raw, sampler.error_log = Mock(), Mock()
        return sampler

    def test_stop_remote_failure_still_waits_joins_and_closes(self):
        sampler = self.stop_fixture()
        error = RuntimeError('remote TERM failed')
        sampler.android.su.side_effect = error
        with patch.object(s, 'summarize') as summarize:
            with self.assertRaises(RuntimeError) as caught:
                sampler.stop()
            self.assertIs(caught.exception, error)
            summarize.assert_not_called()
        sampler.proc.wait.assert_called_once_with(timeout=20)
        sampler.thread.join.assert_called_once_with(timeout=20)
        sampler.raw.close.assert_called_once()
        sampler.error_log.close.assert_called_once()
        self.assertTrue(sampler.errors)

    def test_stop_wait_failure_still_reaps_joins_and_closes(self):
        sampler = self.stop_fixture()
        error = subprocess.TimeoutExpired('adb', 20)
        sampler.proc.wait.side_effect = [error, 0]
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            sampler.stop()
        self.assertIs(caught.exception, error)
        sampler.proc.terminate.assert_called_once()
        sampler.thread.join.assert_called_once_with(timeout=20)
        sampler.raw.close.assert_called_once()
        sampler.error_log.close.assert_called_once()

    def test_all_local_cleanup_is_attempted_and_first_failure_remains_primary(self):
        sampler = self.stop_fixture()
        error = RuntimeError('remote TERM failed')
        sampler.android.su.side_effect = error
        sampler.thread.join.side_effect = RuntimeError('join failed')
        sampler.raw.close.side_effect = OSError('close failed')
        with self.assertRaises(RuntimeError) as caught:
            sampler.stop()
        self.assertIs(caught.exception, error)
        sampler.error_log.close.assert_called_once()
        self.assertEqual(len(sampler.errors), 3)

    def test_framework_vpn_combined_with_underlying_transport(self):
        for transports in ('WIFI|VPN', 'CELLULAR|VPN', 'VPN|WIFI'):
            raw = ('100\nNetworkAgentInfo{network{115} InterfaceName: tun1 Transports: ' + transports +
                   ' Capabilities: INTERNET Uids: <{0-99999}>}\n120\n').encode()
            value = s.framework_summary(raw)
            self.assertEqual(len(value['vpns']), 1)
            self.assertTrue(value['vpns'][0]['complete'])

    def test_framework_not_vpn_capability_is_not_transport(self):
        raw = b'100\nNetworkAgentInfo{network{101} InterfaceName: wlan0 Transports: WIFI Capabilities: NOT_VPN}\n120\n'
        self.assertEqual(s.framework_summary(raw)['vpns'], [])

    def test_default_off_lifecycle(self):
        with self.assertRaisesRegex(ValueError, 'default-off'):
            s.AsyncSampler(None, '/unused', self.root / 'private', self.root / 'public', {'token': 'c1-' + 'a'*24}, 10182, 'boot')

    def test_public_raw_path_refused(self):
        with self.assertRaisesRegex(ValueError, 'guest-private'):
            s.AsyncSampler(None, '/unused', self.root / 'public/private', self.root / 'public',
                           dict(token='c1-' + 'a'*24, observer_flags=dict(async_receive=True)), 10182, 'boot')


class NativeSamplerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tmp.name) / 'sampler'
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(Path(__file__).with_name('r06_async_sampler.c')), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_native(self, args):
        return subprocess.run([str(self.binary), *args], capture_output=True, timeout=5)

    def test_default_off(self):
        self.assertEqual(self.run_native([]).returncode, 2)

    def test_clock_boottime(self):
        values = [int(self.run_native(['--boottime']).stdout) for _ in range(2)]
        self.assertLess(values[0], values[1])

    def test_boot_refusal(self):
        cp = self.run_native(['--enable-r06-observer', '10182', '25', '1000', 'stale', '/unavailable'])
        self.assertEqual(cp.returncode, 1)
        self.assertIn(b'boot differs', cp.stderr)

    def test_missing_map_refusal(self):
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.assertEqual(self.run_native(['--enable-r06-observer', '10182', '25', '1000', boot, '/unavailable']).returncode, 1)


if __name__ == '__main__':
    unittest.main()
