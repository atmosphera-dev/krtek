#!/usr/bin/env python3
"""Read-only original-socket strace evidence, never a replacement connect path.

Input is per-TID `strace -ff -ttt -T -yy` output with the original process's
socket/connect/poll/getsockopt/getsockname/read/write/close calls selected.
Raw lines and unsupported/incomplete records survive. An unobserved errno,
tuple or fd birth is missing evidence, not ETIMEDOUT or a negative window.
The caller must independently bind PID/TIDs and files to one Android boot.
"""
import argparse
from decimal import Decimal
import ipaddress
import json
from pathlib import Path
import re

STAMP = re.compile(r'^(\d+\.\d+)\s+(.*)$')
CALL = re.compile(r'^(\w+)\((.*)\)\s+=\s+(.+?)(?:\s+<(\d+\.\d+)>)?$')
FD = re.compile(r'^(\d+)(?:<(.+)>)?(?:,|$)')
RESULT = re.compile(r'^(-?\d+|\?)(?:<(.+)>)?(?:\s+(E[A-Z0-9_]+)\b)?')
RESUMED = re.compile(r'^<\.\.\. (\w+) resumed>(.*)$')


def ns(seconds):
    return int(Decimal(seconds) * 1_000_000_000)


def address(value):
    parsed = ipaddress.ip_address(value.split('%', 1)[0])
    return str(parsed.ipv4_mapped or parsed) if parsed.version == 6 else str(parsed)


def destination(arguments):
    port = re.search(r'sin6?_port=htons\((\d+)\)', arguments)
    ipv4 = re.search(r'inet_addr\("([^"]+)"\)', arguments)
    ipv6 = re.search(r'inet_pton\(AF_INET6, "([^"]+)"', arguments)
    if not port or not (ipv4 or ipv6):
        return None
    return dict(address=address((ipv4 or ipv6).group(1)), port=int(port.group(1)))


def parse_traces(traces, pid):
    """TIDs must be verified members of this PID; FD table is process-wide.

    Aliases/SCM_RIGHTS/forked process FD tables are not guessed. Unsupported
    fd creation is explicit and prevents an exact fd-incarnation claim.
    """
    records, gaps = [], []
    for tid, text in traces.items():
        pending = None
        for line_number, raw in enumerate(text.splitlines(), 1):
            match = STAMP.match(raw)
            if not match:
                if raw and not raw.startswith('strace:'):
                    gaps.append(dict(tid=tid, line=line_number, reason='unparsed-line', raw=raw))
                elif raw:
                    gaps.append(dict(tid=tid, line=line_number, reason='tracer-message', raw=raw))
                continue
            at, body = match.groups()
            if body.startswith(('--- ', '+++ ')):
                continue
            if body.endswith('<unfinished ...>'):
                if pending is not None:
                    gaps.append(dict(tid=tid, reason='overlapping-unfinished-call', raw=pending[2]))
                pending = (at, body.removesuffix('<unfinished ...>'), raw, line_number)
                continue
            resumed = RESUMED.match(body)
            raw_lines = [raw]
            if resumed:
                if pending is None or not pending[1].startswith(resumed.group(1) + '('):
                    gaps.append(dict(tid=tid, line=line_number, reason='unmatched-resume', raw=raw))
                    continue
                at, beginning, first_raw, line_number = pending
                body = beginning + resumed.group(2)
                raw_lines = [first_raw, raw]
                pending = None
            call = CALL.match(body)
            if not call:
                gaps.append(dict(tid=tid, line=line_number, reason='unparsed-call', raw=raw_lines))
                continue
            name, arguments, result, duration = call.groups()
            returned = RESULT.match(result)
            fd = FD.match(arguments)
            row = dict(pid=pid, tid=tid, line=line_number, wall_ns=ns(at), syscall=name,
                       arguments=arguments, raw=raw_lines, result_raw=result,
                       duration_ns=ns(duration) if duration is not None else None,
                       result=int(returned.group(1)) if returned and returned.group(1) != '?' else None,
                       errno=returned.group(3) if returned else None,
                       fd=int(fd.group(1)) if fd else None,
                       fd_annotation=fd.group(2) if fd else None)
            if name in ('poll', 'ppoll'):
                row['fd_references'] = [int(value) for value in re.findall(r'\bfd=(\d+)', arguments)]
            elif name in ('select', 'pselect6'):
                row['fd'] = None  # First argument is nfds, not a descriptor.
                row['fd_references'] = []
                gaps.append(dict(tid=tid, line=line_number, reason='select-fdsets-require-review', raw=raw_lines))
            else:
                row['fd_references'] = [row['fd']] if row['fd'] is not None else []
            if name == 'connect':
                row['destination'] = destination(arguments)
            if name == 'getsockopt' and 'SO_ERROR,' in arguments and row['result'] == 0:
                error = re.search(r'SO_ERROR, \[([A-Z0-9_]+)\]', arguments)
                row['socket_error'] = error.group(1) if error else None
            if name in ('dup', 'dup2', 'dup3', 'recvmsg') or (name == 'fcntl' and 'F_DUPFD' in arguments):
                gaps.append(dict(tid=tid, line=line_number, reason='fd-alias-or-transfer-requires-review', raw=raw_lines))
            records.append(row)
        if pending is not None:
            gaps.append(dict(tid=tid, reason='unfinished-at-end', raw=pending[2]))
    # socket births are known only at return. Other calls refer to their fd at
    # entry. A slow close cannot erase a new socket reusing that numeric fd.
    timeline = []
    for index, row in enumerate(records):
        birth = row['syscall'] == 'socket' and row['result'] is not None and row['result'] >= 0
        when = row['wall_ns'] + (row['duration_ns'] or 0) if birth else row['wall_ns']
        timeline.append((when, index, birth))
    fds, incarnation = {}, 0
    for _, index, birth in sorted(timeline):
        row = records[index]
        if birth:
            incarnation += 1
            fds[row['result']] = incarnation
            row['socket_incarnation'] = incarnation
            row['socket_incarnations'] = [incarnation]
            continue
        row['socket_incarnation'] = fds.get(row['fd'])
        row['socket_incarnations'] = sorted({fds[fd] for fd in row['fd_references'] if fd in fds})
        if row['syscall'] == 'close':
            fds.pop(row['fd'], None)
    return dict(pid=pid, records=sorted(records, key=lambda row: (row['wall_ns'], row['tid'], row['line'])), gaps=gaps)


def correlate(report, trace, epochs):
    """Join one Java attempt using its own wall/boottime samples, not VM time.

    Millisecond wall samples are approximate; the caller supplies a measured
    uncertainty. A clock-step/ambiguous fd or epoch is refused, not defaulted.
    Epochs are independently observed half-open Android boottime intervals.
    """
    begin = [e for e in report['events'] if e['operation'] == 'connect' and e['phase'] == 'begin']
    end = [e for e in report['events'] if e['operation'] == 'connect' and e['phase'] in ('ok', 'failed')]
    if len(begin) != 1 or len(end) != 1:
        raise ValueError('One original Java connect interval required')
    begin, end = begin[0], end[0]
    uncertainty = report['clock_uncertainty_ns']
    if uncertainty < 1_000_000:
        raise ValueError('Millisecond Java clock samples require measured uncertainty of at least 1 ms')
    offsets = [e['elapsed_ns'] - e['wall_ms'] * 1_000_000 for e in (begin, end)]
    if abs(offsets[1] - offsets[0]) > 2 * uncertainty:
        raise ValueError('Clock step or uncertainty mismatch')
    if report['pid'] != trace['pid'] or begin['pid'] != report['pid'] or end['tid'] != begin['tid']:
        raise ValueError('Java/trace process or thread mismatch')
    first = begin['wall_ms'] * 1_000_000 - uncertainty
    last = end['wall_ms'] * 1_000_000 + uncertainty
    expected = dict(address=address(report['requested_destination']), port=report['requested_port'])
    calls = [r for r in trace['records'] if r['tid'] == begin['tid'] and first <= r['wall_ns'] <= last
             and r['syscall'] == 'connect' and r.get('destination') == expected]
    identities = {(r['fd'], r['socket_incarnation']) for r in calls}
    if len(identities) != 1 or next(iter(identities))[1] is None:
        raise ValueError('Missing or ambiguous original connect/fd birth')
    fd, identity = identities.pop()
    related = [r for r in trace['records'] if identity in r['socket_incarnations']]
    matching_epochs = [e for e in epochs if e['ready_elapsed_ns'] <= begin['elapsed_ns']
                       and (e.get('retired_elapsed_ns') is None or end['elapsed_ns'] < e['retired_elapsed_ns'])]
    if len(matching_epochs) != 1:
        raise ValueError('Missing or ambiguous live capture epoch')
    return dict(request_id=report['request_id'], nonce=report['nonce'], pid=report['pid'], tid=begin['tid'],
                fd=fd, socket_incarnation=identity, epoch=matching_epochs[0], java_connect=end,
                requested_deadline_elapsed_ns=report['requested_connect_deadline_elapsed_ns'],
                connect_syscalls=calls, socket_records=related, observation_gaps=trace['gaps'],
                observed_errno=[r['errno'] for r in related if r['errno']],
                observed_socket_errors=[r['socket_error'] for r in related if r.get('socket_error')],
                inferred_timeout_errno=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--trace', action='append', required=True, help='TID=per-TID-trace-path')
    parser.add_argument('--attempt', type=Path, required=True)
    parser.add_argument('--epochs', type=Path, required=True)
    args = parser.parse_args()
    traces = {}
    for value in args.trace:
        tid, name = value.split('=', 1)
        if int(tid) in traces:
            raise ValueError('Duplicate TID input')
        traces[int(tid)] = Path(name).read_text()
    result = correlate(json.loads(args.attempt.read_text()), parse_traces(traces, args.pid),
                       json.loads(args.epochs.read_text()))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
