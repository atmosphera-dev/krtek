"""Test-only, read-only Android VPN receive snapshots; raw state stays guest-private."""
import hashlib
import ipaddress
import json
import os
import re

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


def snapshot(android, private, public, identity):
    if private.resolve() != private or private.is_relative_to(public.parent):
        raise RuntimeError('Receive snapshot must stay outside collected evidence')
    private.mkdir(mode=0o700, parents=True)
    public.mkdir(mode=0o700, parents=True)
    begin = android.boottime_ns()
    saved, texts, unavailable, clocks = {}, {}, {}, {}
    for name, command in COMMANDS.items():
        clocks[name] = dict(begin=android.boottime_ns())
        try:
            data = android.su(command, timeout=8)
            with (private / (name + '.txt')).open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if (private / (name + '.txt')).read_bytes() != data:
                raise RuntimeError('Private snapshot readback differs')
            saved[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            texts[name] = data.decode(errors='replace')
        except Exception as error:
            unavailable[name] = type(error).__name__
        clocks[name]['end'] = android.boottime_ns()
    value = dict(identity=identity, begin=begin, end=android.boottime_ns(), commands=COMMANDS,
                 clocks=clocks, private_root=str(private), private_files=saved, unavailable=unavailable,
                 summary=summarize(texts, identity.get('consumer_uid')),
                 timing='Sequential read-only snapshots, not atomic or proof of per-packet drop')
    with (public / 'receive-boundary.json').open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    return value


def preconnect(android, private, public, spec, request):
    if (request.get('token') != spec['token'] or type(request.get('index')) is not int or
            request['index'] < 0 or not re.fullmatch(r'krtek-m3-[a-zA-Z0-9-]+', request.get('nonce', '')) or
            type(request.get('consumer_uid')) is not int or request['consumer_uid'] < 0 or
            spec.get('arguments', {}).get('krtek_r06_receive_boundary') != 'true'):
        raise RuntimeError('Pre-connect request identity differs or observer is disabled')
    index = request['index']
    value = snapshot(android, private / ('receive-%d' % index), public / ('receive-%d' % index), request)
    # An incomplete observation is a tooling failure, never an empty-map claim.
    if value['unavailable'] or not value['summary']['ingress_map_observed'] or value['summary']['ingress_map_malformed']:
        raise RuntimeError('Receive-boundary observation incomplete; ACK withheld')
    ack = json.dumps(dict(token=spec['token'], index=index, nonce=request['nonce'], snapshot_sealed=True)).encode()
    root = 'files/krtek-r06/' + spec['token']
    temp, final = '%s/receive-%d.ack.next' % (root, index), '%s/receive-%d.ack' % (root, index)
    android.run_as('set -eu; umask 077; test ! -e %s; test ! -e %s; cat > %s; test "$(wc -c < %s)" -eq %d; mv %s %s'
                   % (final, temp, temp, temp, len(ack), temp, final), data=ack)
    return value
