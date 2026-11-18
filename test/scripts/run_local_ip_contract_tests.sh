#!/usr/bin/env bash
# Contract only: no stub/native engine, library download or live forwarding.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${TMPDIR:?Set TMPDIR to the guest disk-backed workspace}"
out="${KRTEK_EVIDENCE_DIR:-$TMPDIR/local-ip-contract}"
mkdir -p -- "$out"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -pedantic \
    "$root/talpid-lan-forwarder/native/tests/contract_test.c" -o "$out/contract_test"
"$out/contract_test"
