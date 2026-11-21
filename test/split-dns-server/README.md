# Synthetic DNS fixture

This is a non-recursive test service, not the Android product's resolver.
Hickory constructs/decodes complete DNS messages and frames TCP. The service
does not forward queries to the Internet. Unknown zones receive an
authoritative negative response. It is not deployed automatically.

Use only inside `krtek-run-11-device` on ark through INFRA's bound instance,
TAP topology and observation/custody workflow. Never run it on the host.
Home endpoints are `10.77.10.53:53` and `[fd71:7274:656b:10::53]:53`;
the independent Ordinary fixture uses `.54` and `::54`. These are synthetic
test-network addresses, not Mullvad-exit-reachable public receivers.

`krtek-split-dns-fixture serve --help` describes the role, explicit addresses,
output directory, finish path and per-run token. Configure both families with
repeated `--address`. Set TMPDIR below the active instance's disk-backed
workspace. A stale output/finish path is refused rather than overwritten.

The role-specific response engine supplies positive, negative, silent, TC,
large-answer, alias, service and unknown-record cases. A distinct token,
monotone event IDs, connection IDs, complete query/reply byte files and synced
JSONL ledger bind each observation. `tcp-reply-queued` does not claim physical
send completion. Verify the requesting consumer's complete reply separately.

Stop all matched senders before `finish --path <finish> --token <token>`.
That command asserts sender custody; it does not stop the clients for you.
The service drains pending accepts/datagrams and natural TCP closes. An idle
or unfinished TCP connection produces an incomplete terminal result and a
nonzero service exit, never a successful negative observation. Retain raw
bytes, captures and restoration results before retiring its workspace.

Loopback unit tests are development controls only. They do not prove TAP
deployment, Android DNS selection, TLS service identity, packet captures,
Home/Ordinary isolation or an ordinary app's final DNS/connection outcome.
