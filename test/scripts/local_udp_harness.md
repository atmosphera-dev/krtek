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

## Deterministic coverage

`stock_lwip_` Rust tests are included in the normal crate gate. Native clock
scenarios are separate processes; never advance the real Rust singleton clock.

| # | Contract | Consumer/fixture |
|---|---|---|
| 1 | Both-family sizes, order, exact fit and maxima | `stock_lwip_full_consumer_size_mtu_order_matrix`: 36 real peer/full reply cases, independent checksum/coverage oracle, MTU 68/1280/65535 |
| 2 | Missing zero/middle/final and interleaved IDs | `stock_lwip_holes_and_interleaved_ids_do_not_authorize_early`: zero authorization/preparation/peer data until each completion |
| 3 | Stock duplicate, overlap and conflicting terminals | `stock_lwip_altered_duplicates_*`, `stock_lwip_conflicting_terminal_*`, native `corners`; first accepted bytes retained, completed transport still validated |
| 4 | First-arrival expiry, idle release and pressure | Native `clock4/clock6/pressure4/pressure6`, original expiry/wrapping driver, wrapper retirement/runtime-loss fixtures |
| 5 | IPv4 options/protocol omission and IPv6 atomic/extensions/Next Header | Native `corners` and original boundary driver; exact inherited refusal/drop/retention outcomes, not a new RFC claim |
| 6 | Corrupt UDP/TCP, IPv6 checksum zero, high offsets, size+1 | `stock_lwip_completed_corrupt_*`, `stock_lwip_typed_family_size_refusals_*`, native boundary and FFI driver |
| 7 | One funded maximum job, credit exhaustion/no spin | C4 full matrix and existing `stock_lwip_scripted_physical_pump_*`, batch backing and receive-readiness regression |
| 8 | EAGAIN at zero/tail/final and capture errors | Full matrix repeated exact retries plus existing checked-drain/fairness/capture-error fixtures |
| 9 | Revocation, close/reopen, simultaneous owners and network replacement | `stock_lwip_scope_revoke_close_*`, native all-node provenance, daemon irreversible receive-scope/network identity fixtures |
| 10 | Compatible MTU changes, queued UDP and TCP SYN/data/FIN/MSS | `stock_lwip_compatible_mtu_*`, `stock_lwip_tcp_queued_syn_data_fin_*`; exact real streams and current-sink packet/MSS limits |
| 11 | Local/Drop/tunnel isolation and ordinary large traffic | Existing frontend classification, packet-attachment and stateless fragment regressions remain in the full gate; ordinary traffic never enters this Local matrix |
| 12 | Callbacks, failed capture/free, repeated close and funding | Existing native allocation/create-close, wrapper callback panic/failed-close/combined-backing and idle-refund fixtures |

## Device peer

Stage numeric IPv4 and IPv6 addresses/routes on the isolated device guest network,
then run this peer in that guest, not on Ark or shared networking:

```sh
python3 test/scripts/local_udp_peer.py --ipv4 "$PEER4" --ipv6 "$PEER6" \
  --ledger "$WORK/peer.jsonl" --ready "$WORK/peer-ready.json" --duration 600 \
  --finish "$WORK/peer-finish.json"
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
| 4 | `localUdpReplySizeLimit` | Enabled exact forwarding rule; short nonce request reaches peer, peer attempts maximum+1 reply, no datagram reaches consumer |

Arguments: explicit numeric `krtek_peer`, unique `krtek_capture_token`, existing
`krtek_expect_tunnel` (`Disconnected` or `Connected`) and staged lockdown. Optional
`krtek_payload_size` defaults to 4096, or family maximum+1 for the oversized
selectors. Run echo separately for 65507 (IPv4) and 65487 (IPv6). Zero/small sizes
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

`localUdpReplySizeLimit` instead uses the separate `local-udp-reply-limit`
operation, sending a fresh 32-byte nonce from the ordinary consumer. Start the
peer with `--reply-size 65508` for IPv4 or `--reply-size 65488` for IPv6. The peer
durably records the entire attempted patterned response. IPv4 requires a peer
kernel EMSGSIZE receipt, not a claim that Local saw it. IPv6 must actually send
all 65488 bytes, then the consumer must time out without receiving ANY datagram.
Native/Rust typed boundary tests distinguish Local refusal from kernel refusal;
device silence alone does not establish an internal refusal type. No prefix,
ACK, short request substitution or whole-message replay can pass this audit.

The original `localStreamSurvivesAllTunnelStates` regression may use this same
controlled peer with `--tcp-port 18080`; its IPv4 stream echo records full chunks
without treating TCP receive boundaries as application messages. The existing
selector still owns its continuity/current-sink assertions and restoration.

## Independent final audit

The runner extracts one invocation's exact TUN IP packets into JSON arrays of hex
strings; this module deliberately does not guess trace formats or capture on its
own. For a positive full echo:

```sh
python3 test/scripts/local_udp_audit.py --consumer "$WORK/consumer.json" \
  --peer-ledger "$WORK/peer.jsonl" --expect echo --uid "$CONSUMER_UID" \
  --observation "$WORK/observation.json" \
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

For `--expect oversized-reply`, provide both wire arrays and observed MTU as in
the echo command. The request must independently decode as the exact short
nonce; the reply array must be empty. One full peer request and one exact
attempt/send-or-kernel-refusal are required. Extra attempts, changed tail bytes,
shortened response records and any consumer receive are failures.

Every audit requires an invocation observation receipt. On the peer guest's
monotonic clock, the runner records `start_ack_monotonic_ns` immediately before
acknowledging the Android start barrier and `finish_seen_monotonic_ns` after
observing its finish barrier. The receipt also contains `token`, consumer `nonce`,
`peer_pid`, guest `boot_id`, and `exclusive: true`. The runner must isolate that
peer endpoint for the invocation. After observing finish, atomically publish
`peer-finish.json` with `peer_pid`, `boot_id`, `token`, `nonce` and
`finish_seen_monotonic_ns` from that receipt, on the peer guest. The peer keeps
polling, drains both UDP sockets, and records `coverage_complete`, the exact
finish receipt and a `coverage_monotonic_ns` receive watermark before stopping.
The auditor requires that watermark to cover finish. Deadline or request-count
termination without that drain is incomplete, even if the stopped timestamp is
later. Use a fresh peer/finish path for each exclusive invocation. Do not compare
Android and guest clocks.

The auditor selects all requests to the exclusive peer endpoint, regardless of
source, after start acknowledgment through peer shutdown, including
queued requests serviced after the finish barrier. Keep the endpoint exclusive
until shutdown. Empty,
short, wrong-source or corrupted datagrams fail negatives and cannot pass an echo.
Positive probes additionally require the expected physical source. Requests
before the start interval do not count merely because a payload prefix matches.
Old receipts without these barriers are not sufficient for this stronger audit;
retain their original results separately rather than inventing missing timing.
