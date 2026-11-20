#!/usr/bin/env python3
"""Reconstruct feature-only carrier bytes; incomplete logs are not negative evidence."""
from public_dns_audit import need, sha


SUCCESS = {'handoff-input': 'handoff-return', 'decrypted-return': 'decrypted-return-queued',
           'translated-return': 'return-queued'}


def read_carrier(text, receipt):
    need(receipt['readback_verified'] is True and receipt['writer_flushed'] is True
         and receipt['packet_drops'] == 0, 'Incomplete carrier log custody/drop accounting')
    need(receipt['feature'] == 'public-dns-diagnostics', 'Wrong carrier build feature')
    expected = {name: int(receipt[name]) for name in ('pid', 'observer', 'session', 'target', 'request')}
    need(all(value > 0 for value in expected.values()), 'Invalid carrier observer identity')
    groups, markers = {}, {}
    opened, closed, totals = None, None, None
    for line in text.splitlines():
        if 'KRTEK_PUBLIC_DNS ' not in line:
            continue
        words = line.split('KRTEK_PUBLIC_DNS ', 1)[1].split()
        need(all(word.count('=') == 1 for word in words), 'Malformed carrier record')
        fields = dict(word.split('=', 1) for word in words)
        need(len(fields) == len(words), 'Duplicate carrier record field')
        need(fields.get('schema') == '1', 'Unsupported carrier log schema')
        try:
            identity = {name: int(fields[name]) for name in expected}
            stamp = int(fields['boot_ns'])
            packet_id = int(fields['packet'])
        except (KeyError, ValueError) as error:
            raise ValueError('Missing/invalid carrier identity or clock') from error
        if identity != expected:
            continue
        need(stamp > 0 and receipt['started_ns'] <= stamp <= receipt['finished_ns'],
             'Carrier record outside verified capture window')
        boundary, event = fields.get('boundary'), fields.get('event')
        if event == 'marker':
            if boundary == 'observer-open':
                need(opened is None and packet_id == 0, 'Duplicate/invalid observer open')
                opened = stamp
            elif boundary == 'observer-close':
                need(closed is None and packet_id == 0, 'Duplicate/invalid observer close')
                closed = stamp
                totals = tuple(int(fields[name]) for name in ('packets', 'chunks', 'completions'))
            else:
                need(boundary in SUCCESS.values() and packet_id > 0, 'Unknown carrier success marker')
                need((packet_id, boundary) not in markers, 'Duplicate carrier success marker')
                markers[packet_id, boundary] = stamp
            continue
        need(event == 'chunk' and boundary in SUCCESS and packet_id > 0, 'Unknown carrier byte boundary')
        try:
            size, count, index = (int(fields[name]) for name in ('bytes', 'chunks', 'index'))
            family = int(fields['family'])
            data = bytes.fromhex(fields['hex'])
        except (KeyError, ValueError) as error:
            raise ValueError('Malformed carrier chunk data') from error
        need(fields['hex'] == data.hex() and family in (4, 6) and 20 <= size <= 65575
             and count == (size + 127) // 128 and 0 <= index < count,
             'Invalid carrier chunk extent/family')
        need(fields.get('outbound') == ('true' if boundary == 'handoff-input' else 'false'),
             'Carrier direction differs from boundary')
        need(len(data) == min(128, size - index * 128), 'Short/oversized carrier chunk')
        meta = dict(boundary=boundary, size=size, count=count, family=family, stamp=stamp)
        group = groups.setdefault(packet_id, dict(meta=meta, chunks={}))
        need(group['meta'] == meta, 'Mixed carrier packet metadata')
        need(index not in group['chunks'], 'Duplicate carrier byte chunk')
        group['chunks'][index] = data
    need(opened is not None and closed is not None and opened <= closed,
         'Carrier observer lifetime not sealed')
    need(groups, 'Empty carrier log is not negative evidence')
    need(totals == (len(groups), sum(len(group['chunks']) for group in groups.values()), len(markers)),
         'Carrier terminal counters expose missing whole packets/chunks/markers')
    packets = []
    used_markers = set()
    for packet_id, group in groups.items():
        meta, chunks = group['meta'], group['chunks']
        need(len(chunks) == meta['count'], 'Missing carrier byte chunks')
        need(opened <= meta['stamp'] <= closed, 'Packet outside carrier observer lifetime')
        data = b''.join(chunks[index] for index in range(meta['count']))
        marker = (packet_id, SUCCESS[meta['boundary']])
        success = markers.get(marker)
        if success is not None:
            need(meta['stamp'] <= success <= closed, 'Carrier success marker clock/epoch differs')
            used_markers.add(marker)
        packets.append(dict(packet_id=packet_id, boundary=meta['boundary'], family=meta['family'],
                            timestamp_ns=meta['stamp'], completed_ns=success,
                            completed=success is not None, packet=data, size=len(data), sha256=sha(data)))
    need(used_markers == set(markers), 'Orphan carrier success marker')
    return packets
