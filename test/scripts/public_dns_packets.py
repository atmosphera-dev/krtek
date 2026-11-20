#!/usr/bin/env python3
"""Independent ordinary-transit fragment audit from saved DNS files.

No production imports and no Local size limits. This test receiver checks
exact fragment coverage/checksums but does not change product forwarding.
"""
import ipaddress
import struct

from public_dns_audit import AuditError, need, sha


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def capture_records(data):
    need(data.startswith(b'KRTEK08\n'), 'TUN observer magic differs')
    cursor = 8
    records = []
    while cursor < len(data):
        need(cursor + 20 <= len(data), 'Truncated capture record')
        stamp, index, kind, size = struct.unpack_from('!QIII', data, cursor)
        cursor += 20
        need(index > 0 and kind <= 7 and 20 <= size <= 65575
             and cursor + size <= len(data), 'Invalid capture packet extent')
        records.append(dict(timestamp_ns=stamp, ifindex=index, kind=kind,
                            packet=data[cursor:cursor + size]))
        cursor += size
    need(records, 'Empty capture is not negative evidence')
    need(all(a['timestamp_ns'] <= b['timestamp_ns'] for a, b in zip(records, records[1:])),
         'Observer timestamps regress')
    return records


def decode(packet):
    need(packet and len(packet) <= 65575, 'Invalid IP packet extent')
    family = packet[0] >> 4
    if family == 4:
        need(len(packet) >= 20, 'Truncated IPv4 header')
        start = (packet[0] & 15) * 4
        need(start >= 20 and start <= len(packet), 'IPv4 IHL')
        need(int.from_bytes(packet[2:4], 'big') == len(packet), 'IPv4 total length')
        need(checksum(packet[:start]) == 0, 'IPv4 checksum')
        flags = int.from_bytes(packet[6:8], 'big')
        offset, more = (flags & 8191) * 8, bool(flags & 8192)
        need(not flags & 32768 and not (flags & 16384 and (offset or more)), 'IPv4 fragment flags')
        source, destination = packet[12:16], packet[16:20]
        identifier = int.from_bytes(packet[4:6], 'big') if offset or more else None
        protocol = packet[9]
    elif family == 6:
        need(len(packet) >= 40 and int.from_bytes(packet[4:6], 'big') + 40 == len(packet),
             'IPv6 payload length')
        source, destination = packet[8:24], packet[24:40]
        start, protocol = 40, packet[6]
        offset, more, identifier = 0, False, None
        while protocol in (0, 43, 60):
            need(start + 2 <= len(packet), 'Truncated IPv6 extension')
            length = (packet[start + 1] + 1) * 8
            need(start + length <= len(packet), 'IPv6 extension extent')
            protocol, start = packet[start], start + length
        if protocol == 44:
            need(start + 8 <= len(packet) and packet[start + 1] == 0, 'IPv6 Fragment extent')
            field = int.from_bytes(packet[start + 2:start + 4], 'big')
            need(field & 6 == 0, 'IPv6 Fragment reserved bits')
            offset, more = field & 65528, bool(field & 1)
            identifier = int.from_bytes(packet[start + 4:start + 8], 'big')
            protocol, start = packet[start], start + 8
    else:
        raise AuditError('Unknown IP version')
    payload = packet[start:]
    need(payload and (not more or len(payload) % 8 == 0), 'Invalid fragment payload/alignment')
    need(offset + len(payload) <= (65515 if family == 4 else 65535), 'IP complete protocol extent')
    return dict(family=family, source=str(ipaddress.ip_address(source)),
                destination=str(ipaddress.ip_address(destination)), protocol=protocol,
                identifier=identifier, offset=offset, more=more, payload=payload)


def audit_datagram(packets, source, destination, source_port, destination_port, payload):
    need(packets, 'No matching IP packets')
    rows = [decode(packet) for packet in packets]
    source, destination = str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination))
    key = (rows[0]['family'], source, destination, 17, rows[0]['identifier'])
    need(all((row['family'], row['source'], row['destination'], row['protocol'], row['identifier']) == key
             for row in rows), 'Mixed packet tuple/protocol/fragment ID')
    need(rows[0]['identifier'] is not None or len(rows) == 1, 'Multiple unfragmented datagrams')
    ordered = sorted(rows, key=lambda row: row['offset'])
    segment = bytearray()
    for index, row in enumerate(ordered):
        need(row['offset'] == len(segment), 'Missing, duplicate or overlapping fragment')
        need(row['more'] == (index != len(ordered) - 1), 'Missing/conflicting terminal fragment')
        segment.extend(row['payload'])
    need(len(segment) >= 8, 'Truncated UDP header')
    sport, dport, length, check = struct.unpack_from('!4H', segment)
    need((sport, dport, length) == (source_port, destination_port, len(segment)), 'UDP tuple/length differs')
    need(bytes(segment[8:]) == payload, 'Complete UDP bytes differ from saved app bytes')
    pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
    pseudo += struct.pack('!BBH', 0, 17, length) if rows[0]['family'] == 4 else struct.pack('!I3xB', length, 17)
    need(check != 0 and checksum(pseudo + segment) == 0, 'UDP checksum missing/invalid')
    return dict(family=rows[0]['family'], fragments=len(rows), identifier=rows[0]['identifier'],
                payload_size=len(payload), payload_sha256=sha(payload), udp_checksum_valid=True,
                largest_packet=max(map(len, packets)))


def audit_tun(records, probe, query, response, observer):
    need(observer['uid'] == 0 and observer['pid'] > 0 and observer['packet_drops'] == 0,
         'Observer identity/drop accounting incomplete')
    need(observer.get('readback_verified') is True and observer.get('writer_flushed') is True,
         'Capture readback/flush not proven')
    need(records and all(r['ifindex'] == observer['ifindex'] for r in records), 'Wrong/empty TUN epoch')
    need(all(observer['started_ns'] <= r['timestamp_ns'] <= observer['finished_ns'] for r in records),
         'Record outside observer window')
    need(probe['uid'] >= 10000 and probe['pid'] > 0, 'Not an ordinary app UID')
    begin, end = probe['send_started_ns'], probe['completed_ns']
    need(observer['started_ns'] <= begin <= end <= observer['finished_ns'], 'Probe not covered by observer')
    outgoing = []
    incoming = []
    for record in records:
        if not begin <= record['timestamp_ns'] <= end:
            continue
        row = decode(record['packet'])
        if row['family'] != probe['family'] or row['protocol'] != 17:
            continue
        pair = (ipaddress.ip_address(row['source']), ipaddress.ip_address(row['destination']))
        expected = (ipaddress.ip_address(probe['local_address']), ipaddress.ip_address(probe['remote_address']))
        if pair == expected:
            outgoing.append((record, row))
        elif pair == tuple(reversed(expected)):
            incoming.append((record, row))

    def select(rows, sport, dport, data):
        firsts = [(record, row) for record, row in rows if row['offset'] == 0
                  and len(row['payload']) >= 10
                  and struct.unpack_from('!HH', row['payload']) == (sport, dport)
                  and row['payload'][8:10] == data[:2]]
        need(len(firsts) == 1, 'Missing/duplicate DNS first packet')
        identifier = firsts[0][1]['identifier']
        if identifier is None:
            return [firsts[0][0]['packet']]
        return [record['packet'] for record, row in rows if row['identifier'] == identifier]

    request = audit_datagram(select(outgoing, probe['local_port'], 53, query),
        probe['local_address'], probe['remote_address'], probe['local_port'], 53, query)
    result = dict(request=request, response_observed=response is not None,
                  return_window_complete=True, matching_return_packet_count=len(incoming))
    if response is not None:
        result['response'] = audit_datagram(select(incoming, 53, probe['local_port'], response),
            probe['remote_address'], probe['local_address'], 53, probe['local_port'], response)
    # Silence narrows the observed return window only. It never attributes Cloudflare loss.
    return result
