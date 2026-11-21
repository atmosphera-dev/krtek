"""Read-only async r06 observer. Raw dumps stay private; no connect-path hook.

The native process samples map entries, kernel UID rules, addresses, link stats
and proc counters. Framework dumpsys runs in another independent worker, with
its actual cadence reported separately. Neither is an atomic kernel history.
"""
import errno
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import threading
import time

KINDS = {'ingress4', 'ingress6', 'uid_owner', 'rules4', 'rules6', 'links', 'addresses', 'snmp', 'netstat'}
FIXED = {ipaddress.ip_address(address) for address in ('172.27.1.1', 'fdf0:ce4a:801d::172:27:1:1')}


def attrs(data):
    result = {}
    while data:
        if len(data) < 4:
            raise ValueError('Truncated attribute')
        size, kind = struct.unpack_from('=HH', data)
        if size < 4 or size > len(data) or kind in result:
            raise ValueError('Malformed/duplicate attribute')
        result[kind] = data[4:size]
        data = data[(size + 3) & ~3:]
    return result


def messages(data, sequence):
    result, done = [], False
    while data:
        if len(data) < 16:
            raise ValueError('Truncated netlink header')
        size, kind, flags, seq, _ = struct.unpack_from('=IHHII', data)
        if size < 16 or size > len(data) or seq != sequence or flags & 16 or done:
            raise ValueError('Incomplete/stale netlink dump')
        payload = data[16:size]
        if kind == 3:
            if payload and (len(payload) < 4 or struct.unpack_from('=i', payload)[0]):
                raise ValueError('Netlink completion error')
            done = True
        elif kind == 2:
            raise ValueError('Netlink error')
        else:
            result.append((kind, payload))
        data = data[(size + 3) & ~3:]
    if not done:
        raise ValueError('Missing netlink completion')
    return result


def uint(data):
    if len(data) != 4:
        raise ValueError('Expected u32')
    return struct.unpack('=I', data)[0]


def decode_source(row, uid):
    if row['errno']:
        if row['kind'] in {'ingress4', 'ingress6', 'uid_owner'} and row['errno'] == errno.ENOENT and not row['hex']:
            return {'absent': True}
        raise ValueError('Unreadable source: ' + row['kind'] + ' errno=' + str(row['errno']))
    data, kind = bytes.fromhex(row['hex']), row['kind']
    if kind.startswith('ingress'):
        return {'ifindexes': list(struct.unpack('=II', data))}
    if kind == 'uid_owner':
        # Connectivity tag 2026100200 bpf/netd.h: two u32s, verified map schema.
        iif, rule = struct.unpack('=II', data)
        return {'iif': iif, 'rule': rule, 'wildcard_iif': iif == 0}
    if kind in {'snmp', 'netstat'}:
        lines = data.decode('ascii').splitlines()
        if not lines or len(lines) % 2:
            raise ValueError('Missing/unpaired proc counters')
        counters = {}
        for header, values in zip(lines[::2], lines[1::2]):
            names, numbers = header.split(), values.split()
            if not names or names[0] != numbers[0] or len(names) != len(numbers):
                raise ValueError('Mismatched proc counter fields')
            for name, value in zip(names[1:], numbers[1:]):
                key = names[0] + name
                if key in counters:
                    raise ValueError('Duplicate proc counter')
                counters[key] = int(value)
        return counters
    result = []
    for msg, body in messages(data, row['sequence']):
        if kind.startswith('rules'):
            if msg != 32 or len(body) < 12:
                raise ValueError('Unexpected rule')
            family, _, _, _, table, _, _, action, flags = struct.unpack_from('=BBBBBBBBI', body)
            a = attrs(body[12:])
            ranges = list(struct.unpack('=II', a[20])) if 20 in a else None
            if ranges is not None and not ranges[0] <= uid <= ranges[1]:
                continue
            result.append(dict(family=family, uid_range=ranges, table=uint(a[15]) if 15 in a else table,
                               priority=uint(a[6]) if 6 in a else None, action=action, flags=flags,
                               fwmark=uint(a[10]) if 10 in a else None, fwmask=uint(a[16]) if 16 in a else None,
                               iif=a.get(3, b'').rstrip(b'\0').decode('ascii'),
                               oif=a.get(17, b'').rstrip(b'\0').decode('ascii')))
        elif kind == 'links':
            if msg != 16 or len(body) < 16:
                raise ValueError('Unexpected link')
            _, _, _, index, flags, _ = struct.unpack_from('=BBHiII', body)
            a = attrs(body[16:])
            name = a.get(3, b'').rstrip(b'\0').decode('ascii')
            if re.fullmatch(r'tun\d+', name):
                if 23 not in a or len(a[23]) < 8 * 8:
                    raise ValueError('TUN 64-bit counters unavailable')
                values = struct.unpack_from('=8Q', a[23])
                result.append(dict(ifindex=index, interface=name, flags=flags,
                                   **dict(zip(('rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
                                               'rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped'), values))))
        elif kind == 'addresses':
            if msg != 20 or len(body) < 8:
                raise ValueError('Unexpected address')
            family, _, _, _, index = struct.unpack_from('=BBBBI', body)
            a = attrs(body[8:])
            raw = a.get(2, a.get(1))
            if family in (2, 10) and raw:
                address = ipaddress.ip_address(raw)
                if address in FIXED:
                    result.append(dict(address=str(address), ifindex=index))
    return result


def summarize(raw, public, uid):
    """Stream raw file once. Reject missing/error/stale sources, preserve failures."""
    pending, previous, starts, spans, missed, count = {}, {}, [], [], 0, 0
    identity, terminal, maps = None, None, []
    with Path(raw).open() as source, Path(public).open('x') as dest:
        for line in source:
            row = json.loads(line)
            event = row['event']
            if terminal:
                raise ValueError('Data after terminal')
            if event == 'map':
                if identity is not None:
                    raise ValueError('Late map identity')
                maps.append(row)
            elif event == 'start':
                if identity is not None or row['uid'] != uid:
                    raise ValueError('Sampler identity differs')
                identity = row
            elif event == 'source':
                if identity is None or row['sequence'] != count + 1 or row['kind'] not in KINDS or row['kind'] in pending:
                    raise ValueError('Duplicate/stale source')
                if row['begin_ns'] > row['end_ns']:
                    raise ValueError('Reversed source clock')
                pending[row['kind']] = row
            elif event == 'sample':
                if identity is None or row['sequence'] != count + 1 or set(pending) != KINDS:
                    raise ValueError('Incomplete sample')
                if row['begin_ns'] > row['end_ns'] or starts and row['begin_ns'] <= starts[-1]:
                    raise ValueError('Sampler clock not monotone')
                if not row['begin_ns'] <= row['wall_boot_end_ns'] <= row['end_ns'] or row['wall_ns'] <= 0:
                    raise ValueError('Realtime/BOOTTIME bracket invalid')
                decoded = {k: decode_source(v, uid) for k, v in pending.items()}
                for v in pending.values():
                    if not row['begin_ns'] <= v['begin_ns'] <= v['end_ns'] <= row['end_ns']:
                        raise ValueError('Source outside sample')
                deltas, resets = {}, []
                for kind in ('snmp', 'netstat'):
                    deltas[kind] = {}
                    for key, value in decoded[kind].items():
                        if kind in previous and key in previous[kind]:
                            delta = value - previous[kind][key]
                            if delta < 0:
                                resets.append(kind + ':' + key)
                            else:
                                deltas[kind][key] = delta
                link_deltas = []
                old_links = {v['ifindex']: v for v in previous.get('links', [])}
                for link in decoded['links']:
                    old = old_links.get(link['ifindex'])
                    if old is not None and old['interface'] == link['interface']:
                        fields = {k: value-old[k] for k, value in link.items()
                                  if k.startswith(('rx_', 'tx_')) and value >= old[k]}
                        reset = [k for k, value in link.items() if k.startswith(('rx_', 'tx_')) and value < old[k]]
                        link_deltas.append(dict(ifindex=link['ifindex'], interface=link['interface'], deltas=fields, resets=reset))
                dest.write(json.dumps(dict(row, sources=decoded, source_clocks={k: [v['begin_ns'], v['end_ns']] for k, v in pending.items()},
                                           wall_minus_boot_interval_ns=[row['wall_ns']-row['wall_boot_end_ns'], row['wall_ns']-row['begin_ns']],
                                           counter_deltas=deltas, counter_resets=resets, link_deltas=link_deltas)) + '\n')
                starts.append(row['begin_ns'])
                spans.append(row['end_ns'] - row['begin_ns'])
                missed += row['missed_periods']
                previous, pending = decoded, {}
                count += 1
            elif event == 'end':
                terminal = row
            else:
                raise ValueError('Unknown sampler event')
    if not identity or not terminal or pending or terminal['failed'] or terminal['samples'] != count or not count:
        raise ValueError('Sampler not complete')
    if {m['kind'] for m in maps} != {'ingress', 'uid_owner'} or len(maps) != 2:
        raise ValueError('Missing map identities')
    if any(m['key_size'] != (16 if m['kind'] == 'ingress' else 4) or m['value_size'] != 8 for m in maps):
        raise ValueError('Map schema differs')
    if terminal['boottime_ns'] < starts[-1] + spans[-1]:
        raise ValueError('Terminal clock precedes samples')
    intervals = [b-a for a, b in zip(starts, starts[1:])]
    return dict(status='PASS', samples=count, identity=identity, terminal=terminal, maps=maps,
                raw_sha256=file_sha(raw), samples_sha256=file_sha(public), missed_periods=missed,
                interval_ns=dict(min=min(intervals) if intervals else None, max=max(intervals) if intervals else None,
                                 mean=sum(intervals)/len(intervals) if intervals else None),
                max_sample_span_ns=max(spans),
                limitation='Sequential sampled state, not per-packet drops; aggregate counters are not tuple attribution')


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def framework_summary(data):
    lines = data.decode().splitlines()
    if len(lines) < 3 or not lines[0].isdigit() or not lines[-1].isdigit():
        raise ValueError('Framework BOOTTIME brackets unavailable')
    begin, end = int(lines[0]), int(lines[-1])
    if end < begin or not any('Network' in line for line in lines[1:-1]):
        raise ValueError('Framework dump incomplete')
    vpns = []
    for line in lines[1:-1]:
        transports = re.search(r'Transports:\s*([A-Z_|]+)', line)
        if 'NetworkAgentInfo{' not in line or not transports or 'VPN' not in transports[1].split('|'):
            continue
        net = re.search(r'network\{(\d+)\}', line)
        interface = re.search(r'InterfaceName:\s*(tun\d+)', line)
        ranges = re.search(r'Uids:\s*<\{([0-9, -]*)\}>', line)
        vpns.append(dict(net_id=int(net[1]) if net else None, interface=interface[1] if interface else None,
                         uid_ranges=ranges[1] if ranges else None, complete=bool(net and interface and ranges)))
    return dict(begin_ns=begin, end_ns=end, vpns=vpns)


class AsyncSampler:
    """One explicit owner, no synchronous callback from a consumer request."""
    def __init__(self, android, binary, private, public, spec, uid, android_boot):
        if spec.get('observer_flags', {}).get('async_receive') is not True:
            raise ValueError('Async observer is default-off')
        if not re.fullmatch(r'c\d+-[a-f0-9]{24}', spec['token']) or type(uid) is not int or uid <= 0:
            raise ValueError('Async observer identity differs')
        private, public = Path(private), Path(public)
        if private.resolve() != private or public.resolve() != public or private.is_relative_to(public.parent):
            raise ValueError('Raw sampler state must stay guest-private')
        self.android, self.binary, self.private, self.public = android, Path(binary), private, public
        self.spec, self.uid, self.boot = spec, uid, android_boot
        self.remote = '/data/local/tmp/krtek-r06-async-' + spec['token']
        self.proc, self.thread, self.raw = None, None, None
        self.stop_event = threading.Event()
        self.framework, self.errors = [], []

    def _framework(self):
        try:
            with (self.private / 'framework.jsonl').open('x') as raw:
                while not self.stop_event.is_set():
                    command = '{0}/sampler --boottime; dumpsys connectivity; {0}/sampler --boottime'.format(self.remote)
                    data = self.android.su(command, timeout=15)
                    raw.write(json.dumps(dict(raw=data.decode())) + '\n')
                    raw.flush()
                    self.framework.append(framework_summary(data))
                    # Independent measured cadence, never a wait in the test thread.
                    self.stop_event.wait(.025)
        except BaseException as error:
            self.errors.append(type(error).__name__ + ': ' + str(error))

    def start(self):
        if self.android.su('cat /proc/sys/kernel/random/boot_id').decode().strip() != self.boot:
            raise ValueError('Android boot changed')
        self.private.mkdir(mode=0o700, parents=True)
        self.public.mkdir(mode=0o700, parents=True)
        self.android.su('mkdir -m 700 {0} && cat > {0}/sampler && chmod 700 {0}/sampler'.format(self.remote),
                        data=self.binary.read_bytes())
        if self.android.su('sha256sum ' + self.remote + '/sampler').decode().split()[0] != file_sha(self.binary):
            raise ValueError('Sampler binary differs')
        self.raw = (self.private / 'native.jsonl').open('xb')
        self.error_log = (self.private / 'native.stderr').open('xb')
        argv = [self.remote + '/sampler', '--enable-r06-observer', str(self.uid), '25', '1800000', self.boot,
                '/sys/fs/bpf/netd_shared']
        command = 'echo $$ > {0}/pid; exec '.format(self.remote) + shlex.join(argv)
        self.proc = subprocess.Popen([self.android.adb_path, '-s', 'emulator-5554', 'shell', '-T', 'su', '0',
                                      'sh', '-c', shlex.quote(command)], stdout=self.raw, stderr=self.error_log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise ValueError('Sampler exited before instrumentation; inspect private stderr')
            with (self.private / 'native.jsonl').open('rb') as f:
                if b'"event":"sample"' in f.read(262144):
                    break
            time.sleep(.025)
        else:
            raise ValueError('Sampler produced no complete initial sample')
        self.thread = threading.Thread(target=self._framework, name='r06-framework-sampler')
        self.thread.start()

    def stop(self):
        if hasattr(self, 'result'):
            return self.result
        self.stop_event.set()
        if self.proc is not None and self.proc.poll() is None:
            command = ('p=$(cat {0}/pid); test "$(readlink /proc/$p/exe)" = {0}/sampler && kill -TERM "$p"').format(self.remote)
            self.android.su(command)
        if self.proc is not None:
            self.proc.wait(timeout=20)
        if self.thread is not None:
            self.thread.join(timeout=20)
            if self.thread.is_alive():
                raise ValueError('Framework worker did not join')
        for stream in (self.raw, getattr(self, 'error_log', None)):
            if stream:
                stream.close()
        if self.proc is None or self.proc.returncode != 0 or self.errors or not self.framework:
            raise ValueError('Async observer incomplete: ' + repr(self.errors))
        result = summarize(self.private / 'native.jsonl', self.public / 'samples.jsonl', self.uid)
        result.update(binary_sha256=file_sha(self.binary), android_boot=self.boot, token=self.spec['token'],
                      framework=self.framework, framework_private_sha256=file_sha(self.private / 'framework.jsonl'))
        (self.public / 'observer.json').write_text(json.dumps(result, indent=2) + '\n')
        self.result = result
        return result
