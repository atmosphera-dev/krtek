#!/usr/bin/env bash
set -euo pipefail

# Run only inside the assigned builder guest/container. TMPDIR must be disk-backed.
: "${TMPDIR:?Set TMPDIR inside the assigned guest workspace}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
scratch="$(mktemp -d "$TMPDIR/local-udp-harness.XXXXXXXX")"
trap 'rm -r -- "$scratch"' EXIT
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s "$root/test/scripts" -p test_local_udp.py -v
javac -J-Djava.io.tmpdir="$TMPDIR" -d "$scratch" \
  "$root/android/app/src/androidTest/java/net/mullvad/mullvadvpn/talpid/ProbePayloadSummary.java" \
  "$root/android/app/src/androidTest/java/net/mullvad/mullvadvpn/talpid/LocalUdpPayload.java" \
  "$root/test/scripts/LocalUdpPayloadTest.java"
java -Djava.io.tmpdir="$TMPDIR" -cp "$scratch" net.mullvad.mullvadvpn.talpid.LocalUdpPayloadTest
