#!/usr/bin/env python3
"""Guest-only independent DNS audit from verified private files, never reply_hex.

Install public_dns_requirements.txt in the assigned guest's disk-backed workspace.
This is a saved-byte analysis tool, not a network client or a resolver.
"""
import argparse
import hashlib
import importlib.metadata
import ipaddress
import json
from pathlib import Path

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype


class AuditError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise AuditError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verified_file(directory, descriptor, name):
    original = Path(descriptor['path'])
    need(original.is_absolute() and original.name == name, 'Unexpected private byte filename')
    need(original.parent.name == directory.name and original.parent.parent.name == 'public-dns',
         'Wrong private attempt identity')
    path = directory / name
    need(not path.is_symlink() and path.is_file(), 'Missing/nonregular byte artifact')
    data = path.read_bytes()
    need(len(data) == descriptor['size'] and sha(data) == descriptor['sha256'], 'Byte custody mismatch')
    return data


def query_audit(query):
    need(len(query) in (76, 4096), 'Not a matched public DNS query size')
    message = dns.message.from_wire(query, ignore_trailing=False)
    need(message.flags == dns.flags.RD and message.opcode() == dns.opcode.QUERY, 'Request flags changed')
    need(len(message.question) == 1 and not message.answer and not message.authority
         and not message.additional, 'Request sections changed')
    question = message.question[0]
    need(question.name == dns.name.from_text('example.com.') and question.rdtype == dns.rdatatype.A
         and question.rdclass == dns.rdataclass.IN, 'Request question changed')
    need(message.edns == 0 and message.payload == 4096 and message.ednsflags == 0,
         'EDNS advertisement/version/flags changed')
    need(len(message.options) == 1 and message.options[0].otype == dns.edns.PADDING,
         'Expected sole EDNS Padding option')
    padding = message.options[0].to_wire()
    need(len(padding) == len(query) - 44 and padding[32:] == bytes(len(padding) - 32),
         'Padding nonce/tail differs')
    # Independent library encoder, not Java offsets, reconstructs the complete bytes.
    reference = dns.message.make_query('example.com.', dns.rdatatype.A, dns.rdataclass.IN,
                                      use_edns=0, payload=4096,
                                      options=[dns.edns.GenericOption(dns.edns.PADDING, padding)])
    reference.id = message.id
    need(reference.to_wire() == query, 'Independent request reconstruction differs')
    return message


def response_audit(query, response):
    try:
        message = dns.message.from_wire(response, ignore_trailing=False, one_rr_per_rrset=True)
    except dns.exception.DNSException as error:
        return dict(classification='malformed', usable_a=False, error=type(error).__name__)
    identity = (message.id == query.id and message.flags & dns.flags.QR
                and message.opcode() == dns.opcode.QUERY and message.question == query.question)
    if not identity:
        return dict(classification='wrong-identity', usable_a=False)
    base = dict(rcode=message.rcode(), tc=bool(message.flags & dns.flags.TC),
                answer_count=message.section_count(dns.message.ANSWER))
    if base['tc']:
        return dict(**base, classification='tc', usable_a=False)
    if message.rcode() != dns.rcode.NOERROR:
        return dict(**base, classification='rcode', usable_a=False)
    if not message.answer:
        return dict(**base, classification='no-answer', usable_a=False)
    # Observe the answer chain without sending any subsequent lookup.
    try:
        chain = message.resolve_chaining()
        usable = chain.answer is not None and len(chain.answer) > 0
    except dns.exception.DNSException as error:
        return dict(**base, classification='unusable-answer', usable_a=False,
                    error=type(error).__name__)
    return dict(**base, classification='usable-a' if usable else 'unusable-answer', usable_a=usable)


def audit(directory, receipt_bytes):
    need(directory.is_dir() and not directory.is_symlink(), 'Private bytes directory required')
    receipt = json.loads(receipt_bytes)
    need(receipt['schema'] == 1, 'Unknown receipt schema')
    query = verified_file(directory, receipt['query'], 'query.bin')
    parsed = query_audit(query)
    need(parsed.id == receipt['dns_id'] and len(query) == receipt['request_bytes'], 'Query identity differs')
    need(receipt['family'] in (4, 6) and receipt['remote_port'] == 53, 'Peer family/port differs')
    family = receipt['family']
    peer = ipaddress.ip_address(receipt['remote_address'])
    need(peer == ipaddress.ip_address('1.1.1.1' if family == 4 else '2606:4700:4700::1111'),
         'Not the pinned Cloudflare peer')
    need(receipt['send_calls'] in (0, 1) and receipt['receive_calls'] in (0, 1), 'Probe resent/retried')
    result = dict(schema=1, parser='dnspython', parser_version=importlib.metadata.version('dnspython'),
                  query_sha256=sha(query), query_bytes=len(query), query_valid=True,
                  probe_classification=receipt['classification'], receipt_sha256=sha(receipt_bytes),
                  response_observed='response' in receipt, usable_a=False)
    if 'response' in receipt:
        response = verified_file(directory, receipt['response'], 'response-000.bin')
        need(receipt['receive_calls'] == 1, 'Response without a receive')
        need(len(response) == min(receipt['received'], 65535), 'Received byte count differs')
        result['response_sha256'] = sha(response)
        result['response_bytes'] = len(response)
        if receipt['received'] > len(response):
            result['classification'] = 'truncated-datagram'
        elif (ipaddress.ip_address(receipt['reply_source']) != peer or receipt['reply_port'] != 53):
            result['classification'] = 'wrong-source'
        else:
            result.update(response_audit(parsed, response))
        need(not receipt['semantic_usable_a'] or result['usable_a'],
             'Java claimed usable A but independent decoder did not')
    else:
        need(receipt.get('received', 0) == 0 and not receipt['semantic_usable_a'],
             'Received bytes/success without a saved response')
        need(not (directory / 'response-000.bin').exists()
             and not (directory / 'response-000.bin').is_symlink(), 'Unreported first response')
        result['classification'] = receipt['classification']
    expected_responses = {'response-000.bin'} if 'response' in receipt else set()
    need({path.name for path in directory.glob('response-*.bin')} == expected_responses,
         'Unreported extra response')
    # This verdict proves byte custody and independent analysis, never Cloudflare delivery.
    result['custody_status'] = 'PASS'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bytes-dir', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    args = parser.parse_args()
    raw = args.receipt.read_bytes()
    need(sha(raw) == args.receipt_sha256, 'Receipt transport checksum differs')
    print(json.dumps(audit(args.bytes_dir, raw), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
