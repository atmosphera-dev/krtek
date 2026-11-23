


# Mullvad VPN app architecture

This document describes the code architecture and how everything fits together.

For security and anonymity properties, please see [security](security.md).

Some components have specific documentation that go into greater detail:

- [winfw](../windows/winfw/README.md)

## Mullvad vs talpid

Explain the differences between these layers and why the distinction exists.
My thought was that after this section every aspect of the app is explained
under either the Mullvad or the Talpid header. So it's clear which part they
belong to. I yet don't know if this makes sense though.

## The daemon
The client consists of two main parts - the daemon and the GUI, but there's also a CLI. The daemon
is the process that's responsible for upholding the security guarantees of the client, it consists
of an actor system so that it can drive many processes asynchronously, allowing for a multiplicity
of clients.

<img src="diagrams/daemon-components.png">

The daemon receives commands from the [front-ends](#frontends) (GUI and CLI) via the management
interface and these are serviced asynchronously via the daemon, often interacting via various other
components during and after the RPC has been finished. There are various dependencies between the
different components and it's important to ensure no deadlocks occur, and some executions flows that
provide essential behavior can be hard to trace.

<img src="diagrams/update-relay-constraints.png">


## Mullvad part of daemon

### Frontend <-> system service communication
This is done via GRPC ([here's](../mullvad-management-interface/proto) the relevant proto files)
over a Unix domain socket on desktop platforms and via a JNI on Android. In both cases, the
frontends end up sending a message to the daemon that it then services. The servicing of any
message must never block any other message. Frontends can also subscribe to messages from the
daemon, to receive updates about the tunnel state, new settings, new relay lists, version
information and device events.


### Talking to api.mullvad.net.
Reaching the API is done via a direct TLS connection to the API host or via a shadowsocks bridge, to
increase censorship resistance. There are multiple components that interact with the API in an
asynchronous fashion, so to manage them all, there's an actor that specifically deals with sending
REST requests to the API.

The API must be reachable in secured states even if a tunnel is not up, so the API runtime interacts
with the [tunnel state machine](#tunnel-state-machine) to send over the currently used API endpoint.
This can be a source of deadlocks, so no actor should ever be blocked by an API request if the TSM
relies on it to change states.

All API requests can be dropped in flight to allow for resetting the connection whenever a tunnel is
established. The API requests can also be blocked when in the offline state or when it's assumed
that the user hasn't used our client for a period of time.

### Selecting relays
See [this document](relay-selector.md).

### Problem reports

On Android, Krtek support goes to the shared GitHub issues URL, not the Mullvad
report-upload or email endpoints. `ProblemReportRepository` owns the complete
in-process description for its lifetime. Navigation, ViewModel teardown, local
log deletion, copying and browser launch never clear that description. Drafts
are not persisted across process death.

The report editor requires a nonblank description, then creates an immutable
`SupportIssueExport` for explicit review. The displayed title and complete body
(including the device details) are the browser and clipboard inputs, with no
hidden redaction or shortening. Editing invalidates the review, including a
queued export. Each repository edit has a new draft identity, so returning to
identical text cannot revive a prior review even if flow collection conflates
the intermediate edit. The public-disclosure warning precedes review/export. A complete
prefill above the existing 4096-character URL bound uses a bare new-issue link
and complete-body copy instead. A browser launch cannot attest submission.
Other help entry points use the bare issues link without exporting hidden
device or report data. Logs remain locally collected/viewed/deleted; sharing
them is a separate user action, never an automatic issue attachment.

Extensive management-event logging retains upstream non-Local payload details.
Its immutable logging projection removes Local policy before formatting
Settings, and uses a scoped summary for Local status. Unknown envelope/Settings
bytes are omitted because they can contain unrecognized Local data; subscriber
messages are not modified. This is private on-device diagnostics, not automatic
public disclosure.


## Talpid part of daemon

### Tunnel state machine

The tunnel state machine is the part of Talpid that coordinates the events for establishing a VPN
connection. It acts upon requests for establishing a secure VPN connection or for disconnecting an
already established connection and returning the system to its initial state. This involves also
using other parts of Talpid to configure the system so that the security policies are applied and
so that the connection works correctly without any further manual configuration necessary.

The tunnel state machine starts in an initial `Disconnected` state. In this state, no changes are
made to the operating system and no security policies are applied. When a request is sent to the
state machine to establish a connection, the state machine will progress first into a `Connecting`
state that will configure the operating system and setup a tunnel with a connection to a VPN server.
Once the configuration is complete and the connection is verified to be working, the state machine
then proceeds to a `Connected` state.

A request can be made to close the VPN connection. Such request will lead the state machine into
a `Disconnecting` state, which will close the connection to the VPN server and restore the operating
system to its original configuration. After the process is complete, the state machine returns to
the `Disconnected` state.

If an error occurs in the `Connecting` or `Connected` states, the state machine may proceed to an
`Error` state. It might reach this state either immediately (when an error occurs in the
`Connecting` state) or after passing through another state to tear down the tunnel (when an error
occurs in the `Connected` state). Either way, in this state the operating system is configured to
block all connections to avoid leaking any data. The objective is to ensure no data leaks from the
tunnel while the user has requested a secure connection, as defined in the [security document].

A high-level overview of the tunnel state machine can be seen in the diagram below:


                    +--------------+   Request to connect    +------------+
      Start ------->| Disconnected +------------------------>| Connecting |
                    +--------------+                         +----+--+--+-+
                        ^                                      ^  |  ^  |
                        |           Will attempt to reconnect  |  |  |  |
                        |   .----------------------------------'  |  |  |
                        |   |                                     |  |  |
                        |   |                   .-----------------'  |  |
                        |   |                   | Unrecoverable      |  |
                        |   |                   |     error          |  |
                        |   |    Request to     V                    |  |
     System is restored |   |    disconnect +-------+                |  | Connection is configured
       to its initial   |   |   .-----------+ Error +----------------'  |       and working
        configuration   |   |   |           +-------+  Request to       |
                        |   |   |               ^       connect         |
                        |   |   |               |                       |
                        |   |   |  .------------'                       |
                        |   |   |  | Unrecoverable                      |
                        |   |   |  |  error while                       |
                        |   |   |  |  in connected                      |
                        |   |   V  |     state                          V
                     +--+---+------+-+                         +-----------+
                     | Disconnecting |<------------------------+ Connected |
                     +---------------+  Request to disconnect  +-----------+
                                          or unrecoverable
                                               error

[security document]: security.md

#### State machine inputs

There are two types of inputs that the tunnel state machine reacts to. The first one is commands sent
to the state machine, and the second is external events that the state machine listens to. Reacting
to any event can result in the state machine transitioning away to a different state.

<img src="diagrams/tsm-connecting-enter.png">





##### Tunnel commands

Besides the two main commands `Connect` and `Disconnect`, there are a few other commands that can be
sent to the tunnel state machine. The following list includes all the commands the tunnel state
machine can receive.

- *Connect*: establish a secure VPN connection
- *Disconnect*: tear down the active VPN connection and return the operating system to its initial
  configuration
- *Allow LAN*: enable or disable local network sharing, changing the security policies for some of
  the states
- *Block when disconnected*: configures whether the state machine should apply the security policy
  for blocking all connections when it's in the `Disconnected` state, effectively requesting the
  system to never allow connections outside the tunnel

##### External events

Depending on the state of the machine, it will also listen for specific external events and act
on them possibly by changing states. All of these events can be considered as tunnel events, but
they happen on different scenarios and because of different causes.

- *Tunnel is Up*: the tunnel monitor notifies that the tunnel is working correctly
- *Tunnel is Down*: the tunnel monitor notifies that the tunnel has disconnected
- *Tunnel monitor stopped*: communication to the tunnel monitor was lost
- *Is offline*: notify the tunnel state machine if the operating system is connected or not to the
  network, so that it can safely wait for connectivity to be restored without endlessly retrying to
  establish the VPN connection. Some care needs to be taken to not get stuck in the offline state
  for too long on [macOS](allow-macos-network-check.md).

#### State machine outputs

Every time the state machine changes state, it will output a `TunnelStateTransition`. This is an
`enum` type representing which state the tunnel state machine has entered and any associated
metadata that might be useful.

- *Disconnected*
- *Connecting*: includes the information of the endpoint it is trying to connect to
- *Connected*: includes the information of the endpoint it is connected to
- *Disconnecting*: includes the state it will transition to once successfully disconnected, which
  is represented as the action it will take after disconnected, listed below:
  - *Nothing*: proceed to the `Disconnected` state
  - *Block*: proceed to the `Error` state
  - *Reconnect*: proceed to the `Connecting` state
- *Error*: includes the cause of the error and the information if the operating system was
  successfully configured to block all connections

### System DNS management

### Firewall integration

### Connection logic

#### Quantum-resistant tunnels

To establish a quantum-resistant tunnel, a pre-shared key (PSK) is derived using a quantum-safe
key encapsulation mechanism (KEM) with the relay. This is achieved by initiating a regular
WireGuard tunnel to the relay and deriving the PSK within the tunnel.
The PSK is stored in memory on the relay and the client, along with a new client generated ephemeral
WireGuard key. Subsequently, a new tunnel is created using the new WireGuard key and the PSK,
ensuring that the tunnel is quantum-resistant.
See the [protocol definition file](../talpid-tunnel-config-client/proto/ephemeralpeer.proto) for
more details on the protocol.

#### Quantum-resistant tunnels & Multihop

To create a multihop tunnel where both hops are quantum resistant the client must negotiate a unique
PSK with both the entry and the exit relay separately. It must use the same ephemeral WireGuard key
on both relays since the end result (just as with regular multihop tunnels) is two peers on a
single WireGuard interface, which can only have a single key for the local peer.

The PSKs are established by first creating a regular multihop tunnel to the exit via the entry relay
and negotiate a PSK with the exit. Then establish a regular tunnel to just the entry and negotiate a
PSK with it. Lastly the client can set up a multihop tunnel using the new ephemeral WireGuard key
and the two PSKs via the entry to the exit.

### Detecting device offline

The tunnel state machine has an offline monitor that tries to detect when a device will certainly
not be able to connect to a tunnel or reach the API. In doing so, the offline monitor cannot send
any traffic. In general, this involves either relying on platform APIs specifically designed for
this purpose or querying the system's networking config to enumerate network interface state or the
routing table.

#### Windows

On Windows, connectivity is inferred if there is a default route and the machine is not suspended.
The suspend/wakeup events matter because tunnel device drivers might not work correctly early after
wakeup. As such, the offline mode is used to enforce a grace period.

The conditions are affirmed by doing the following:
- Listening for changes to the default route, primarily via [`NotifyRouteChange2`] - receiving
  callbacks whenever a default route is changed or added via winnet.
- Checking if the machine is suspended by listening for power state broadcasts by creating a window
  and listening for power state messages.

#### Linux

On Linux, connectivity is inferred by checking if there exists a route to a public IP address.
Currently the Mullvad API IP is used, but the actual IP does not matter as long as it's not a local
one. This is done via Netlink and the route is queried via the exclusion firewall mark - otherwise,
when a tunnel is connected, the address would always be routable as it'd be routed through the
tunnel interface. As such, the offline monitor is somewhat coupled to routing and split tunnelling
on Linux.

#### macOS

On macOS, the offline monitor detects whether the host is offline by using `SCDynamicStore` to check
if there's any active network service.

##### Issues

After coming back from sleep, the network reachability callback won't be invoked until macOS has
done some verification tasks, some of which may depend on DNS. Since our firewall will block DNS,
the tasks will be delayed, and so will the callback. Circumventing the call back is of no use -
until the timeouts are hit, macOS won't publish a default route to the routing table, which is
needed for routing tunnel traffic.

#### Android

To detect connectivity on Android, the app relies on [`ConnectivityManager`] by listening for
changes to the availability of non-VPN networks that provide internet connectivity. Connectivity
is inferred if such a network exists.

#### iOS

The iOS app uses WireGuard kit's offline detection, which in turn uses [`NWPathMonitor`] to listen
for changes to the route table and assumes connectivity if a default route exists.

### Split tunneling

See the [split tunneling documentation](split-tunneling.md).

## Frontends

### Desktop Electron app

### Android

Krtek's logical Android identity uses the fixed private IPv4 address `172.27.1.1/32`
and RFC 4193 ULA `fdf0:ce4a:801d::172:27:1:1/128`. Actual capture families and MTU
follow Mullvad's upstream effective configuration, with only the enabled Local
route/family union added afterward. A missing target family is not advertised
unless Local needs it; that extra family captures and drops non-Local traffic,
never enabling a physical internet fallback. For an IPv4-only target below 1280,
Local IPv6 requires a capture-only MTU floor of 1280; the target/carrier MTU is
unchanged. Partial capture uses MTU 1280 and enabled CIDRs. With split DNS enabled,
Android 10+ adds the non-VPN default resolver list and its exact host routes;
Android 9 retains the DNS-free Partial profile. The
upstream safe blocking MTU is separately 1380. These app-facing address values
are independent of Mullvad login, key rotation and tunnel assignment.
Tunnel targets translate to their own assigned addresses; Local uses protected,
physical-network-bound sockets. Private networks can still collide with this
fixed pair; private-use addressing does not guarantee collision-free routing.

`Excluded apps skip local rules` defaults to ON, including absent old disk/wire
fields; explicit OFF is retained. It belongs to the canonical Local policy and
its whole-policy compare-and-set token, not a separate preference store. ON
projects Mullvad's effective exclusions into Partial capture. OFF includes those
apps in Partial only, including the retained Partial before target parameters
exist. Full Connecting/Connected, safe blocking and Error retain Mullvad's
exclusions. Disabled split tunneling contributes no exclusions even when names
remain stored. This preference never creates capture without enabled Local routes
and does not itself request a tunnel reconnect.

Descriptor MTU and exposed-family configuration belong to the checked sink epoch,
not the immutable logical session. Necessary sink handovers retain eligible Local
connections; old receipts never authorize writes to a successor. Equal effective
Builder fields reuse the observed sink, including redundant/covered Local routes.
Static inventory found 0 demonstrated avoidable replacements. This is a source
finding, not a measured runtime reduction: equal normalized full and Partial
profiles already reuse. Real route, ordered DNS, MTU, family or UID coverage
changes, forced refresh and actual capture-loss recovery still require their
existing replacement paths. Requested package names do not attest applied UID
coverage; no missing-package/shared-UID optimization or atomic handover is implied.
Local updates its IP-device MTU metadata in place, retaining TCP socket state,
physical sockets, grants and queued output. Its protocol-sized ingress scratch
and byte-credited egress arena already fund maximum-sized packet peaks; a change
does not allocate a new session or depend on fresh root credit. Unsupported MTU
configuration returns a typed refusal. A superseded target cannot acquire
readiness, but does not invalidate an exactly observed Local capture epoch.
DNS and LAN subtraction use the upstream projection once; DNS resolvers are not
globally recaptured or reserved from an explicit Local rule. Mullvad's real gateway
and SOCKS exceptions remain reserved.

Partial unlisted DNS uses its own runtime-only system authority, never a Home
grant or a saved Mullvad target. A passive NOT_VPN + INTERNET observation supplies
the resolver list independently of the app default, which can be Krtek's VPN.
Prefer the Local observer's unambiguous physical network; otherwise prefer
validated networks, then Wi-Fi/Ethernet, refusing tied candidates. Incomplete
observations do not select a network, and an empty selected resolver list never
falls back to another network. Every query and I/O checks Android's live lockdown
gate; only an allowed query can protect and bind to that network. Revoked
incarnations, changed capture sinks and Partial/full transitions retire old work.
TCP classifies each framed message separately, so blocked Ordinary messages do
not acquire Home authority. Connected UDP passthrough and unprotected TCP
upstreams are unchanged. The system authority uses the same joined-preparation
mechanism and credited message/reply storage, and closes with the capture owner.

Managed selection and current Local routes are initialized before tunnel startup.
Normal Connect/Reconnect commands go directly to the upstream tunnel state machine;
they neither pause target admission nor wait for a blocking capture. A pending
target request owns capture configuration/readiness. Explicit Disconnect and
shutdown still revoke Mullvad admission, with exact-request cleanup and joined
descriptor release; eligible Local sessions remain independent.
Changing Android UID coverage can destroy open sockets, including when the new
preference changes a live Partial or OFF makes full/Partial coverage differ.
Local session retention does not override that platform behavior.
Android system Connect follows the same upstream keyguard and command order even
while a Partial, full or failed capture is retained. Capture ownership extends
foreground service lifetime only; it never substitutes for dispatching Connect.

Local status is auxiliary to the original management subscription. Its initial
RPC or a malformed Local event can make Local unavailable without cancelling
tunnel, account, relay or ordinary settings updates. A subscription-scoped
revision watermark also covers malformed samples. Samples retain their exact
subscription generation, including a reply completing after stop/start, so a late
initial result cannot replace a newer event; the next valid sample can recover Local status.
Status decoding runs outside the acceptance lock. Subscription/generation/revision
admission and revision/sample commit then form one atomic step, so a rejected
response cannot leave a watermark or suppress a failed current read's fallback.
The fallback checks for a committed sample, not a partially admitted revision.
The initial Local fetch owns convergence when editor generations move during an
RPC: obsolete success and failure results trigger a read for the new generation,
not a fixed retry count or a wait for a later event. Cancellation or a replaced
subscription ends that fetch owner. A stable read retains normal revision
ordering, including a newer event already accepted while the RPC was pending.
Editor demand has its own generation. Its service owner acknowledges the minimum
usable watcher snapshot sequence after applying demand, and Local status carries
that existing source sequence (zero means no identity). Shared management projects
Wi-Fi as Pending until the acknowledged fence is met. A late pre-stop sample
cannot fill a reopened draft just because its publication revision is newer.
Continuous policy observation can acknowledge the already-live sample without
waiting for a new event; fresh same-SSID observations remain observable. The
editor's five-second explanation deadline does not cancel its pending request.
Policy reads retain exact representable values and their validation result.
Unrepresentable Local protobufs stay at the management conversion boundary and
are exposed as a Local read error, never as an OFF/empty replacement. Local
replacements still require valid input and a representable read. The expected
snapshot is an exact comparison token, including representable invalid policy,
so a valid replacement can repair it without changing unrelated settings.
The exclusion preference participates in that token: a legacy expected policy
with an absent field means ON and conflicts with current OFF. Omitting the whole
expected token retains the existing unconditional update semantics.
Unrepresentable reads remain unavailable. Upstream disk loading, defaults and
malformed-file recovery are unchanged.

The daemon owns policy observation demand through the Local registration, not
through cached management settings. The editor contributes a separate demand
lease. The Local bridge registration outlives its observation demand. With Local off
or no enabled rules and no open editor, there are no Local source subscriptions
or Wi-Fi identity reads. Policy or editor demand starts fresh observation; the
last demand revokes published physical authority before stopping its source.
Old callbacks and samples cannot restore it. Capture observation and the
upstream default-network listener retain their independent lifetimes; Local
feed events do not grant Mullvad retry intent. Default CLI status/listen fetches
and prints Local only for a configured policy, or an explicit `status local`
request. Disabled configured rules remain visible; JSON/debug output retains
its existing valid-settings representation.

Physical observation has two publication responsibilities. Under its event lock,
the watcher hands a monotone, revocation-only witness to the same Rust authority
before coalescing callbacks into a complete status sample. The shared eligibility
evaluator retires affected receive scopes immediately; harmless refreshes retain
eligible scopes. A witness cannot admit new work, replace status, prepare a socket
or call the platform. Its revision fences late complete samples and stale
callbacks. New work waits for a complete sample at the current fence. JNI witness
conversion failure closes authority immediately; platform demand cleanup is
deferred to the async owner outside the event lock. Committed settings publish
their exact Local policy to that same authority before asynchronous listeners or
payload-free settings events can reread a successor. OFF/ON and loss/return cannot
revive retired Local or Home DNS work. Capture configuration and semantic status
still reconcile asynchronously, without a second eligibility evaluator.

Native WireGuard setup stays in its caller's future and retains upstream pinger
construction and Drop timing. Managed setup instead cancels the exact request,
interrupts pending receipt and PQ/DAITA network waits, and joins device/platform
work already started before releasing its owner. Its private IPv4 probe source
is optional: an assignment without IPv4 still supports ordinary IPv6, while a
private send truthfully reports address unavailable. Peer statistics, not private
probe replies, continue to determine connectivity.

The exact attached carrier admits ordinary traffic when GotaTun starts, before
connectivity and obfuscator commitment publish Up. Before carrier start, the
request owns the same bounded outbound bridge that the carrier will consume.
Ordinary ingress is retained there without blocking later Local ingress while
capacity remains. A full bridge retains one already-read exact selection and
stops further descriptor reads, while control, cleanup and available output keep
running. No requested carrier means ordinary traffic stays blocked.

Both bridge directions keep their 256-item bounds. Already-owned return data
waits for queue capacity or exact retirement, with dequeue/close notifications
registered before the locked capacity recheck. Capture owns its credited read
scratch independently of Local. The Local receiver is constructed only on actual
Local ingress and retained across compatible sink changes. Ordinary data never
enters its parser or flow accounting. Unique owned backing moves to native
handoff; retained views require a separately credited copy. Native allocations
after handoff are outside the shared 64 MiB root and region proof.

Managed daemon shutdown closes admission and joins the TSM through its own
completion signal, not public tunnel events or physical-network updates. Local
socket preparations and sole-fd cleanup then join before platform release. A
failed release returns a failure that retains the daemon and exact recovery
record. JNI keeps the runtime and registrations reachable. Initialization retries
only retained failed cleanup before replacement and refuses a live daemon or a
failed retry; successful cleanup
continues through upstream finalization order.

Capture admission and classification select Local, a tunnel target or Drop.
Tunnel targets translate each received packet or fragment immediately, using
address checksum deltas; they do not reassemble, remember fragment identities
or normalize atomic IPv6 headers. Each input produces one owned packet with
the same length and layout, apart from address/checksum/quotation rewrites.
Transmit MTU is native carrier metadata, not an endpoint receive limit: even
larger incoming fragments are injected unchanged. The adapter neither fragments
IP nor generates PMTU errors; real peer/network ICMP and its quotations pass
through translation. Packets retain the exact target attempt through the final
writer. The assigned source filter and separate private-control path remain
unchanged.

Translation discovers address and checksum locations once, without validating
endpoint-owned checksums, flags, ICMP codes or complete TCP options. Native
trailing bytes are retained. IPv4 checksum-bearing later fragments use their
wire offsets; IPv6 tails stay opaque after the Fragment header. Real ICMP quotes
are walked iteratively, rewriting matching endpoints only and propagating word
deltas through enclosing checksums. Quotation-description allocations retain
byte credit. Unique owned packet backing is rewritten without a second copy;
retained immutable views require a separately credited copy and last-owner refund.

Source routes, Home Address options and RH0/RH2/SRH final destinations use their
present pseudo-endpoint fields. A changed AH endpoint cannot be authenticated
without its key. An unknown active routing format, an absent required pseudo-
endpoint or an incomplete required checksum word cannot be translated safely.
These are swap limitations, not protocol admission policy: no-swap packets pass.
Opaque/experimental payloads are not a promise to repair unspecified address-
dependent formats. ESP remains opaque: tunnel mode is supported, encrypted
transport-mode pseudoheaders cannot be repaired without the SA. Invalid IPv6
UDP zero checksums remain zero for the endpoint to reject.

Local is a receiver, not tunnel transit. Pristine pinned lwIP 2.2.1 owns canonical
IPv4/IPv6 receive reassembly and UDP reply fragmentation. The daemon's irreversibly
revocable receive scope contains no ports or transport authority. Every retained
input node carries its logical handle and scope; a completed chain must have one
live owner throughout. Only a complete Rust-validated TCP/UDP segment can authorize
a flow and prepare a protected, physical-network-bound socket. smoltcp retains TCP
sequence/MSS/retransmission ownership; kernel sockets retain physical-side IP
processing. Ordinary tunnel classification, stateless fragment translation and
protocol-sized receive scratch are unchanged.

Local's minimal-header UDP payload ceiling is 65507 bytes for IPv4 and 65487 for
IPv6, not IPv6's 65527-byte protocol maximum. Stock lwIP's 16-bit complete-packet
representation includes the base IP header. Accepted additional header bytes
consume their actual space; larger Local input/replies receive typed oversized
refusal, never truncation or fallback. Fragmented IPv4 options, IPv6
extension-prefixed transport and atomic Fragment input remain unsupported.

One process-global native mutex, monotonic clock and 12 MiB reservation cover all
logical handles. Retirement invalidates a handle immediately but retains scope
guards and funding while tagged input nodes remain; stock idle timers reclaim
them. A core-owned condition-variable worker drives timers independently of
Tokio/runtime replacement, joins before replacement and exits on quiescence. A
late wake catches up the bounded stock reassembly horizon before advancing to
the current clock; ingress first ticks older work before admitting a new node.
Quiescent reopen rebases public lwIP timeouts without resetting process time or
reviving receive state. A failed core refuses new work on every logical handle,
while retirement and reference inspection remain available. Its
bounded stack and bookkeeping are included in the same reservation. Native
callbacks borrow synchronously, never authorize or wait for sockets or TUN, and
unowned control output is suppressed. Rust copies and reply storage retain
separate Local credit; this is not a process RSS or kernel-memory bound.

Each physical UDP reply is received whole into protocol-sized scratch only after
reserving a 192 KiB packed output batch. Admission leaves both existing maximum
TCP producer peaks available in the
same reply arena. Idle UDP sockets do not allocate batches. A queued batch also
retains its exact physical-socket incarnation, not just an endpoint receive scope.
It occupies one existing output job, not a queue entry per fragment, including
the 1365-packet maximum IPv4 reply at
MTU 68. Callback capture failure discards the batch before any emission, even
when lwIP returns success. Every packet/retry retains its flow, receive scope and
grant and passes the exact current sink/MTU check. EAGAIN retains the same packet;
successful writes yield between packets. An MTU shrink cancels a remainder
containing obsolete oversized UDP packets without replaying the message. An
already fitting tail stays eligible. TCP state and retransmission ownership
survive compatible handovers.

Reassembly retains stock five-entry and 2048-pbuf per-family pressure/oldest
eviction behavior and first-arrival 15-second IPv4 / 60-second IPv6 countdowns
(reclamation occurs on stock timer ticks, not an exact sub-tick deadline).
Duplicate/overlap refusal can retain earlier pieces; IPv4's key omits protocol,
IPv6 tail-first Next Header can misclassify completion, and fragment IDs can wrap.
These are inherited limitations, not complete RFC corner-case compliance. See
[known issues](known-issues.md). Dependency updates replace the pristine pin and
rerun native/ABI, maximum-length, provenance and complete-consumer gates; a larger
IPv6 ceiling requires a dependency/API decision, not larger pools.

### iOS

### CLI

[`NotifyRouteChange2`]: https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
[`SCNetworkReachability`]: https://developer.apple.com/documentation/systemconfiguration/scnetworkreachability-g7d
[`SCDynamicStore`]: https://developer.apple.com/documentation/systemconfiguration/scdynamicstore-gb2
[`ConnectivityManager`]: https://developer.android.com/reference/android/net/ConnectivityManager
[`NWPathMonitor`]: https://developer.apple.com/documentation/network/nwpathmonitor
