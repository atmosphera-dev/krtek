import copy
import unittest

from r06_tcp_trace import correlate, parse_traces


class R06TcpTraceTest(unittest.TestCase):
    def trace(self, tail=''):
        return parse_traces({13: '\n'.join([
            '1000.000000 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 5<TCPv6:[410]> <0.000001>',
            '1000.002000 connect(5<TCPv6:[410]>, {sa_family=AF_INET6, sin6_port=htons(18080), inet_pton(AF_INET6, "::ffff:10.0.2.2", &sin6_addr)}, 28) = -1 EINPROGRESS (Operation now in progress) <0.000100>',
            '1000.003000 poll([{fd=5<TCPv6:[::ffff:172.27.1.1:4444->::ffff:10.0.2.2:18080]>, events=POLLOUT}], 1, 4999) = 0 (Timeout) <4.999000>',
            '1005.002100 close(5<TCPv6:[::ffff:172.27.1.1:4444->::ffff:10.0.2.2:18080]>) = 0 <0.000010>',
            tail,
        ])}, 12)

    def report(self):
        return dict(pid=12, request_id='request-1', nonce='krtek-m3-test', requested_destination='10.0.2.2',
                    requested_port=18080, requested_connect_deadline_elapsed_ns=15_001_000_000,
                    clock_uncertainty_ns=2_000_000, events=[
                        dict(operation='connect', phase='begin', pid=12, tid=13, wall_ms=1_000_001, elapsed_ns=10_001_000_000),
                        dict(operation='connect', phase='failed', pid=12, tid=13, wall_ms=1_005_003, elapsed_ns=15_003_000_000),
                    ])

    epochs = [dict(epoch=8, ready_elapsed_ns=9_000_000_000, retired_elapsed_ns=16_000_000_000)]

    def test_original_userspace_timeout_never_becomes_invented_etimedout(self):
        result = correlate(self.report(), self.trace(), self.epochs)
        self.assertEqual(['EINPROGRESS'], result['observed_errno'])
        self.assertIsNone(result['inferred_timeout_errno'])
        self.assertEqual(8, result['epoch']['epoch'])
        self.assertEqual(5, result['fd'])
        self.assertIn('4444->', result['socket_records'][-1]['fd_annotation'])
        self.assertEqual(1, len([r for r in result['socket_records'] if r['syscall'] == 'poll' and r['result'] == 0]))
        self.assertEqual([], result['observation_gaps'])

    def test_so_error_and_syscall_errno_are_distinct_observations(self):
        trace = self.trace('1000.004000 getsockopt(5<TCP:[410]>, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0 <0.000001>')
        result = correlate(self.report(), trace, self.epochs)
        self.assertEqual(['EINPROGRESS'], result['observed_errno'])
        self.assertEqual(['ECONNREFUSED'], result['observed_socket_errors'])

    def test_fd_reuse_is_not_joined_to_the_old_socket(self):
        trace = self.trace('1005.003000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5<TCP:[411]> <0.000001>\n'
                           '1005.004000 connect(5<TCP:[411]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH (Network unreachable) <0.000001>')
        result = correlate(self.report(), trace, self.epochs)
        self.assertEqual(['EINPROGRESS'], result['observed_errno'])
        self.assertNotIn('ENETUNREACH', str(result))

    def test_unfinished_resumed_call_retains_entry_time_and_both_raw_lines(self):
        trace = parse_traces({13: '1000.001000 connect(5, {sa_family=AF_INET, sin_port=htons(18080), sin_addr=inet_addr("10.0.2.2")}, 16 <unfinished ...>\n'
                                '1000.002000 <... connect resumed>) = -1 EINPROGRESS (Operation now in progress) <0.001000>'}, 12)
        row = trace['records'][0]
        self.assertEqual(1_000_001_000_000, row['wall_ns'])
        self.assertEqual(2, len(row['raw']))
        self.assertEqual('EINPROGRESS', row['errno'])
        self.assertEqual([], trace['gaps'])

    def test_truncated_or_unknown_trace_is_explicitly_incomplete(self):
        trace = parse_traces({13: 'strace: attach: ptrace(PTRACE_SEIZE, 13): Operation not permitted\n'
                                '1000.000000 mystery output\n'
                                '1000.001000 poll( <unfinished ...>'}, 12)
        self.assertEqual(['tracer-message', 'unparsed-call', 'unfinished-at-end'], [r['reason'] for r in trace['gaps']])

    def test_missing_socket_birth_cannot_be_called_exact_fd_linkage(self):
        trace = self.trace()
        trace['records'] = trace['records'][1:]
        for row in trace['records']:
            row['socket_incarnation'] = None
        with self.assertRaisesRegex(ValueError, 'fd birth'):
            correlate(self.report(), trace, self.epochs)

    def test_process_thread_destination_and_epoch_mismatches_are_rejected(self):
        for field, value in [('pid', 99), ('requested_destination', '10.0.2.3'), ('requested_port', 18081)]:
            with self.subTest(field=field):
                report = self.report()
                report[field] = value
                with self.assertRaises(ValueError):
                    correlate(report, self.trace(), self.epochs)
        report = self.report()
        report['events'][1]['tid'] = 99
        with self.assertRaises(ValueError):
            correlate(report, self.trace(), self.epochs)
        for epochs in ([], self.epochs * 2, [dict(epoch=8, ready_elapsed_ns=11_000_000_000)]):
            with self.subTest(epochs=epochs), self.assertRaises(ValueError):
                correlate(self.report(), self.trace(), epochs)

    def test_clock_step_is_not_silently_joined_to_the_wrong_epoch(self):
        report = self.report()
        report['events'][1]['wall_ms'] += 1000
        with self.assertRaisesRegex(ValueError, 'Clock step'):
            correlate(report, self.trace(), self.epochs)

    def test_cross_thread_fd_table_uses_socket_completion_and_close_entry(self):
        trace = parse_traces({13: '1000.000000 socket(AF_INET, SOCK_STREAM, 0) = 5<TCP:[410]> <0.000001>\n'
                                '1001.000000 close(5<TCP:[410]>) = 0 <0.100000>',
                              14: '1001.001000 socket(AF_INET, SOCK_STREAM, 0) = 5<TCP:[411]> <0.000001>\n'
                                  '1001.002000 write(5<TCP:[411]>, "x", 1) = 1 <0.000001>'}, 12)
        self.assertEqual([1, 1, 2, 2], [r['socket_incarnation'] for r in trace['records']])

    def test_aliases_and_unmatched_resume_are_not_silently_complete(self):
        trace = parse_traces({13: '1000.001000 dup(5) = 6 <0.000001>\n'
                                '1000.002000 <... connect resumed>) = 0 <0.000001>'}, 12)
        self.assertEqual(['fd-alias-or-transfer-requires-review', 'unmatched-resume'], [r['reason'] for r in trace['gaps']])

    def test_multiple_candidate_sockets_are_not_arbitrarily_selected(self):
        trace = self.trace()
        second = copy.deepcopy(next(r for r in trace['records'] if r['syscall'] == 'connect'))
        second.update(fd=6, socket_incarnation=2)
        trace['records'].append(second)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            correlate(self.report(), trace, self.epochs)


if __name__ == '__main__':
    unittest.main()
