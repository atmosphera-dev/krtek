# Public DNS diagnostic consumer

This test-only app performs one ordinary-UID UDP exchange alongside either
Krtek or an unmodified source-built Mullvad app. It is not a VPN, system DNS
resolver, split-DNS forwarder or Internet test server. The socket is neither
protected nor bound to a physical network. There is no resend or TCP fallback.

## Frozen call inputs

`PublicDnsComparisonInstrumentedTest#publicDnsExchange` requires explicit
`app=krtek|stock`, `family=4|6`, `request_bytes=76|4096`, `dns_id=0..65535`,
`nonce_hex` (32 bytes in lowercase hex), and numeric `peer`. The only comparison
peers are `1.1.1.1:53` and `[2606:4700:4700::1111]:53`. A comparison uses the
same ID/nonce/query vector in both isolated Android data sets. Padding length
is the only small/large query difference; question, RD, EDNS flags and the
advertised 4096-byte response size remain unchanged.

The device owner freezes APK hashes/signers, actual APK instrumentation runner,
instance/boot/serial/UID, relay endpoint/transport/MTU, settings, capture inputs
and query parameters before calling the test. Derive the runner component from
APK metadata, not an assumed package suffix. The same consumer APK pair is used
in both `krtek-d-krtek` and `krtek-d-stock`, one running instance at a time.

## Byte custody and outcomes

`src/shared/java` is compiled into the diagnostic app and Krtek's historical
test consumer, never into the shipping VPN. Each invocation creates one private
`files/public-dns/<attempt>/` directory. `query.bin` is synced before socket I/O;
`response-000.bin` is synced before any truncation, source, identity or DNS
validation. `receipt.json` retains timing, syscall errno, source and byte-file
size/SHA256 metadata. Instrumentation/Binder carries bounded metadata, not full
query or response hex. A rejected response is still evidence, not a timeout.

The historical successful-envelope verdict (`validated`) is separate from
`semantic_usable_a`. TC, nonzero header/extended rcode, empty answers, unrelated
answers and malformed bytes do not become usable A answers. Source mismatch,
datagram truncation, send/receive EAGAIN timeouts and other socket errors have
separate classifications. `recvfrom(MSG_TRUNC)` observes the original byte
count; ancillary recvmsg flags are unavailable and are explicitly unclaimed.
All ordinary UDP payloads fit the 65535-byte receive allocation.

The standalone test can complete after a receive timeout: that means the
diagnostic ran and retained its outcome, not that DNS worked. Tool/custody errors
remain failures. A short A response does not prove large-response delivery.

## Guest-only verification

Builds, tests and saved-byte audits run only inside the assigned Krtek VM on
ark (`krtek-run-11-dev`, `krtek-run-11-builder` or `krtek-run-11-device`), with
disk-backed workspace/TMPDIR and the execution/device owner's lease. Never run
them on the physical host or against the user's phone. Full gates and device
calls are scheduled through INFRA.

The pinned Android build route adds these tasks to the ordinary full gate:

```sh
android/gradlew -p android --console plain --max-workers=4 \
  :test:publicdns:assembleDebug :test:publicdns:assembleDebugAndroidTest \
  :test:publicdns:testDebugUnitTest
```

The actual Java query/parser is exercised by 33 independent literal fixture
groups, exposed as JUnit5 dynamic tests. Five additional tests cover complete
private-file retention, immutable evidence, separate attempts, path refusal and
disk-backed JVM scratch. Public syscall observation requires Android 10 or
later; older versions fail explicitly before attempting a network exchange.
This does not change the shipping app's minimum Android version.
The fixed-ID `0x1234`/nonce `00..1f` query goldens have these SHA256 values:

| # | Bytes | SHA256 |
|---|---|---|
| 1 | 76 | `6309a9cf261976d55b8b78fecf847037de6793d866773a027e0c1edb78720515` |
| 2 | 4096 | `2aefef0df5afa350ede3391bb417f8818659a10328fce84ebf449802f3051d65` |

`test/scripts/public_dns_audit.py` independently reconstructs the query with
pinned dnspython and parses the full response from verified private files.
Install `test/scripts/public_dns_requirements.txt` only in the assigned guest's
disk-backed tooling environment. It accepts the collected attempt directory,
receipt file and externally verified receipt SHA256; it never reads an obsolete
`reply_hex` field or sends a network query. Run its regression tests in that
guest with `python3 -B -m unittest -v test_public_dns_audit` from `test/scripts`.

TUN, carrier-handoff and outer-wire receipts are separate observation boundaries.
Empty/unflushed captures cannot prove absence. Stock cannot expose Krtek-only
internal observations; record that limit and every unmatched relay/backend/build
variable rather than calling the controls equivalent.
