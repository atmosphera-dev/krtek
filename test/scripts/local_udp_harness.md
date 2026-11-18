# Full Local UDP harness

All commands run inside the assigned project guest, with a disk-backed `TMPDIR`.
The harness is test-only. Its own passing tests do not prove Local forwarding.

## Builder checks

```sh
bash test/scripts/run_local_udp_harness_tests.sh
python3 test/scripts/local_udp_vectors.py "$TMPDIR/local-udp-vectors"
```

The first command runs the Python cases and the Java payload comparison/digest driver.
The second creates binary IP pieces and `manifest.json` for native/Rust drivers.
Each manifest case gives addresses, ports, MTU, payload size, ordered packet paths
and the expected `complete` or `oversized` boundary. Generate into a fresh directory.
The canonical payload nonce is bytes 0 through 31. Reverse/reorder these pieces in
the driver; never use the production packetizer to generate an expected result.

The independent output oracle rejects missing/overlapping/duplicate pieces, mixed
IDs/tuples, invalid lengths/checksums, over-MTU packets and incomplete payloads.
Its strict output acceptance is not an assertion that stock receive reassembly
discards an entire assembly on overlap.

## Device peer

Stage numeric IPv4 and IPv6 addresses/routes on the isolated device guest network,
then run this peer in that guest, not on Ark or shared networking:

```sh
python3 test/scripts/local_udp_peer.py --ipv4 "$PEER4" --ipv6 "$PEER6" \
  --ledger "$WORK/peer.jsonl" --ready "$WORK/peer-ready.json" --duration 600
```

Port is 18081. The peer binds both addresses before readiness, receives complete
datagrams with truncation detection, durably records every request byte and its
peer receive interface, then echoes exactly those bytes. Each echo has its
own send receipt. Wait for terminal `stopped` before the independent final audit;
keep the peer alive through the full negative-observation window. The old
256-byte loopback peer cannot substitute. No inferred IPv6 emulator alias.

## Instrumentation selectors

Use the existing restoration/account/permission harness with the exact built APK
pair. Select one method on `LocalNetworkDeliveryInstrumentedTest` per invocation.

| # | Selector | Required staged policy / outcome |
|---|---|---|
| 1 | `localLargeUdpEcho` | Enabled exact numeric `/32` or `/128` rule in Forwarding; one full matching reply |
| 2 | `localLargeUdpDenied` | Same enabled exact rule, `DifferentWifi`; full send, timeout and no nonce/prefix peer hit |
| 3 | `localUdpOversized` | Enabled exact forwarding rule; maximum+1, no peer hit and no reply |

Arguments: explicit numeric `krtek_peer`, unique `krtek_capture_token`, existing
`krtek_expect_tunnel` (`Disconnected` or `Connected`) and staged lockdown. Optional
`krtek_payload_size` defaults to 4096, or family maximum+1 for the oversized
selector. Run echo separately for 65507 (IPv4) and 65487 (IPv6). Zero/small sizes
are supported; empty payloads cannot carry an on-wire nonce, so isolate their
peer observation window.

The new `local-udp-echo` consumer operation is separate from the unchanged short
`consumerProbe`. It creates an ordinary UDP socket in the neutral APK UID, permits
kernel fragmentation without protect/network binding, sends once and receives
once into a protocol-sized buffer with `MSG_TRUNC`. Source address, port, length
and every payload byte must match. It never retries or accepts a short ACK.
Only bounded metadata crosses Binder: lengths, nonce, request/reply SHA256,
in-process byte/tuple comparison results, tuple and timings. Neither datagram is
serialized into the result. Digests do not replace the complete comparison in the
consumer or the independent full-byte peer and wire audit. The DNS sibling also
reports only a reply digest after retaining its full in-process DNS validation.

The runner must acknowledge both existing capture barriers, retain the exact
consumer JSON reported as `local_udp_*`, collect TUN request/reply bytes and
physical-network selection evidence, and restore the original state afterward.
The selector records a failed result before asserting, so failures retain evidence.
It never changes policy. Denial/oversize selector success alone does not prove
peer silence: that is an independent ledger audit.

IPv4 maximum+1 is refused by the Android kernel with EMSGSIZE before Local sees
it. That device result is not proof of the Local typed oversized boundary; native
and Rust complete-size fixtures own that assertion. IPv6 maximum+1 can be sent
by Android and must not reach the peer. Do not shorten either request.

## Independent final audit

The runner extracts one invocation's exact TUN IP packets into JSON arrays of hex
strings; this module deliberately does not guess trace formats or capture on its
own. For a positive full echo:

```sh
python3 test/scripts/local_udp_audit.py --consumer "$WORK/consumer.json" \
  --peer-ledger "$WORK/peer.jsonl" --expect echo --uid "$CONSUMER_UID" \
  --physical-source "$EXPECTED_PEER_SOURCE" --mtu "$CAPTURE_MTU" \
  --request-packets "$WORK/request.json" --reply-packets "$WORK/reply.json"
```

For negatives use `--expect denied` or `--expect oversized`, the same consumer
and terminal peer receipts, and omit the wire arguments. Missing ledger rows,
nonce-bearing prefix peer requests, harness/create failures and wrong physical
sources cannot masquerade as successful full echoes. A 4096-byte device CLI audit
also requires genuine fragments in both directions. Retain raw capture evidence
and its epoch/UID/protected-network correlation separately from these byte checks.
Derive `EXPECTED_PEER_SOURCE` from the staged network topology, including any
emulator NAT; do not assume it equals Android's pre-NAT address. Peer interface
metadata alone does not establish Android's protected network selection.
