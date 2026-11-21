"""Test-only, read-only Android VPN receive snapshots; raw state stays guest-private."""
import hashlib
import ipaddress
import json
import os
import re
import time
from decimal import Decimal

FIXED = {ipaddress.ip_address(x) for x in ('172.27.1.1', 'fdf0:ce4a:801d::172:27:1:1')}
COMMANDS = {
    'trafficcontroller': 'dumpsys connectivity trafficcontroller',
    'connectivity': 'dumpsys connectivity',
    'netd': 'dumpsys netd',
    'links': 'ip -s link show',
    'rules4': 'ip -4 rule show',
    'rules6': 'ip -6 rule show',
    'routes4': 'ip -4 route show table all',
    'routes6': 'ip -6 route show table all',
    'counters': 'cat /proc/net/snmp /proc/net/netstat /proc/net/snmp6',
    'rp_filter': 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do printf "%s " "$f"; cat "$f"; done',
}


def section(text, name):
    match = re.search(r'(?m)^  ' + re.escape(name) + r':\s*\n', text)
    if not match:
        return None
    return re.split(r'(?m)^  \S', text[match.end():], maxsplit=1)[0]


def summarize(texts, uid):
    traffic = texts.get('trafficcontroller', '')
    block = section(traffic, 'sIngressDiscardMap')
    entries, malformed = [], False
    if block is not None:
        for line in block.splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r'\s*\[/([^]]+)\]: (\d+)\(([^)]*)\), (\d+)\(([^)]*)\)\s*', line)
            try:
                address = ipaddress.ip_address(match[1]) if match else None
            except ValueError:
                address = None
            if address is None:
                malformed = True
            elif address in FIXED:
                entries.append(dict(address=str(address), ifindexes=[int(match[2]), int(match[4])],
                                    interfaces=[match[3], match[5]]))
    owner = section(traffic, 'sUidOwnerMap')
    uid_lines = [line.strip() for line in (owner or '').splitlines()
                 if re.match(r'\s*' + str(uid) + r'\s', line)] if uid is not None else []
    links = texts.get('links', '')
    tun_links = {m[2]: int(m[1]) for m in re.finditer(r'(?m)^(\d+): (tun\d+):', links)}
    return dict(ingress_map_observed=block is not None, ingress_map_malformed=malformed,
                fixed_address_entries=entries, uid_owner_map_observed=owner is not None,
                consumer_uid=uid, consumer_uid_rules=uid_lines, tun_links=tun_links)


def dumpsys_timed_out(data):
    return re.search(rb'\bDUMP\s+TIMEOUT\b', data, re.IGNORECASE) is not None


class Deadline:
    """One budget for transport, collection, durable writes and ACK publication."""
    def __init__(self):
        self.end = time.monotonic() + 30

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Receive-boundary deadline')
        return remaining

    def clock(self, android):
        before = time.monotonic()
        uptime = android.su('cat /proc/uptime', timeout=min(8, self.remaining())).split()[0]
        self.remaining()
        return dict(android_boottime_s=uptime.decode(), guest_monotonic_before_ns=int(before * 1e9),
                    guest_monotonic_after_ns=int(time.monotonic() * 1e9))


def snapshot(android, private, public, identity, deadline=None):
    deadline = deadline or Deadline()
    if private.resolve() != private or private.is_relative_to(public.parent):
        raise RuntimeError('Receive snapshot must stay outside collected evidence')
    private.mkdir(mode=0o700, parents=True)
    public.mkdir(mode=0o700, parents=True)
    saved, texts, unavailable, clocks = {}, {}, {}, {}
    begin = None
    try:
        begin = deadline.clock(android)
    except Exception as error:
        unavailable['clock'] = type(error).__name__
    for name, command in COMMANDS.items():
        clocks[name] = dict(guest_monotonic_begin_ns=time.monotonic_ns())
        try:
            clocks[name]['begin'] = deadline.clock(android)
            data = android.su(command, timeout=min(8, deadline.remaining()))
            with (private / (name + '.txt')).open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if (private / (name + '.txt')).read_bytes() != data:
                raise RuntimeError('Private snapshot readback differs')
            saved[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            deadline.remaining()
            if command.startswith('dumpsys ') and dumpsys_timed_out(data):
                raise TimeoutError('Partial dumpsys output')
            texts[name] = data.decode(errors='replace')
        except Exception as error:
            unavailable[name] = type(error).__name__
        try:
            clocks[name]['end'] = deadline.clock(android)
        except Exception as error:
            unavailable[name + '-clock'] = type(error).__name__
        clocks[name]['guest_monotonic_end_ns'] = time.monotonic_ns()
    end = None
    try:
        end = deadline.clock(android)
    except Exception as error:
        unavailable['deadline'] = type(error).__name__
    value = dict(identity=identity, begin=begin, end=end, commands=COMMANDS,
                 clocks=clocks, private_root=str(private), private_files=saved, unavailable=unavailable,
                 summary=summarize(texts, identity.get('consumer_uid')),
                 timing='Sequential read-only snapshots, not atomic or proof of per-packet drop')
    with (public / 'receive-boundary.json').open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        deadline.remaining()
    except TimeoutError:
        # Retain the incomplete receipt even if writing it exhausted the budget.
        value['unavailable']['deadline'] = 'TimeoutError'
        (public / 'receive-boundary.json').write_text(json.dumps(value, indent=2) + '\n')
    return value


def preconnect(android, private, public, spec, request):
    if (not re.fullmatch(r'[a-zA-Z0-9-]+', spec['token']) or
            request.get('token') != spec['token'] or type(request.get('index')) is not int or
            request['index'] < 0 or not re.fullmatch(r'krtek-m3-[a-zA-Z0-9-]+', request.get('nonce', '')) or
            type(request.get('consumer_uid')) is not int or request['consumer_uid'] < 0 or
            type(request.get('elapsed_ns')) is not int or request['elapsed_ns'] <= 0 or
            spec.get('arguments', {}).get('krtek_r06_receive_boundary') != 'true'):
        raise RuntimeError('Pre-connect request identity differs or observer is disabled')
    index = request['index']
    deadline = Deadline()
    anchor = deadline.clock(android)
    android_deadline = request['elapsed_ns'] + 30_000_000_000
    # /proc/uptime is truncated to centiseconds. Use its upper bound and the
    # pre-query guest clock, so transfer/dispatch delay cannot extend the wait.
    upper = Decimal(anchor['android_boottime_s']) + Decimal('.01')
    deadline.end = min(deadline.end, anchor['guest_monotonic_before_ns'] / 1e9 +
                       float(Decimal(android_deadline) / Decimal(1_000_000_000) - upper))
    value = snapshot(android, private / ('receive-%d' % index), public / ('receive-%d' % index), request, deadline)
    # An incomplete observation is a tooling failure, never an empty-map claim.
    if value['unavailable'] or not value['summary']['ingress_map_observed'] or value['summary']['ingress_map_malformed']:
        raise RuntimeError('Receive-boundary observation incomplete; ACK withheld')
    ack = json.dumps(dict(token=spec['token'], index=index, nonce=request['nonce'], snapshot_sealed=True)).encode()
    root = 'files/krtek-r06/' + spec['token']
    temp, final = '%s/receive-%d.ack.next' % (root, index), '%s/receive-%d.ack' % (root, index)
    # The device checks time again immediately before publication. Whole-second
    # ceiling is conservative; no delayed shell can publish an expired ACK.
    android.run_as('set -eu; umask 077; test ! -e %s; test ! -e %s; cat > %s; test "$(wc -c < %s)" -eq %d; '
                   'read -r uptime rest < /proc/uptime; test "$(( (${uptime%%%%.*} + 1) * 1000000000 ))" -lt %d; mv %s %s'
                   % (final, temp, temp, temp, len(ack), android_deadline, temp, final),
                   data=ack, timeout=deadline.remaining())
    deadline.remaining()
    return value
