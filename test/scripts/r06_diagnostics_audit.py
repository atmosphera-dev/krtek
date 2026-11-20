#!/usr/bin/env python3
"""Check observation marker absence/presence in normal/diagnostic JNI APKs.

This is additional proof, not signer/version/ELF verification or proof that
diagnostic logging has no timing effect. Those inputs stay in the pair receipt.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ABIS = ('armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64')
MARKERS = (b'KRTEK_R06 boundary=', b'physical-connect-begin', b'platform-protect-bind-result',
           b'capture-ingress', b'smoltcp-accept-syn-ok', b'checked-tun-write-result')


def inspect(path, diagnostic):
    rows = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate APK members')
        for abi in ABIS:
            name = 'lib/' + abi + '/libmullvad_jni.so'
            data = archive.read(name)
            present = [marker.decode('ascii') for marker in MARKERS if marker in data]
            if diagnostic and len(present) != len(MARKERS):
                raise ValueError('Diagnostic observations missing in ' + abi)
            if not diagnostic and present:
                raise ValueError('Normal JNI contains diagnostic observations in ' + abi)
            rows.append(dict(abi=abi, size=len(data), sha256=hashlib.sha256(data).hexdigest(), markers=present))
    return dict(apk_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(), diagnostic=diagnostic, jni=rows)


def compare(normal, diagnostic):
    if Path(normal).read_bytes() == Path(diagnostic).read_bytes():
        raise ValueError('Normal and diagnostic APKs are identical')
    return dict(normal=inspect(normal, False), diagnostic=inspect(diagnostic, True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--normal', type=Path, required=True)
    parser.add_argument('--diagnostic', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.normal, args.diagnostic), indent=2))


if __name__ == '__main__':
    main()
