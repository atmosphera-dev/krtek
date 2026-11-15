


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
unchanged. Local-only capture uses MTU 1280, enabled CIDRs only and no DNS. The
upstream safe blocking MTU is separately 1380. These app-facing address values
are independent of Mullvad login, key rotation and tunnel assignment.
Tunnel targets translate to their own assigned addresses; Local uses protected,
physical-network-bound sockets. Private networks can still collide with this
fixed pair; private-use addressing does not guarantee collision-free routing.

Descriptor MTU and exposed-family configuration belong to the checked sink epoch,
not the immutable logical session. Necessary sink handovers retain eligible Local
connections; old receipts never authorize writes to a successor. Equal effective
Builder fields reuse the observed sink, including redundant/covered Local routes.
Local updates its IP-device MTU metadata in place, retaining TCP socket state,
physical sockets, grants and queued output. Its protocol-sized ingress scratch
and byte-credited egress arena already fund maximum-sized packet peaks; a change
does not allocate a new session or depend on fresh root credit. Unsupported MTU
configuration returns a typed refusal. A superseded target cannot acquire
readiness, but does not invalidate an exactly observed Local capture epoch.
DNS and LAN subtraction use the upstream projection once; DNS resolvers are not
globally recaptured or reserved from an explicit Local rule. Mullvad's real gateway
and SOCKS exceptions remain reserved.

Managed selection and current Local routes are initialized before tunnel startup.
Normal Connect/Reconnect commands go directly to the upstream tunnel state machine;
they neither pause target admission nor wait for a blocking capture. A pending
target request owns capture configuration/readiness. Explicit Disconnect and
shutdown still revoke Mullvad admission, with exact-request cleanup and joined
descriptor release; eligible Local sessions remain independent.
Android system Connect follows the same upstream keyguard and command order even
while a Partial, full or failed capture is retained. Capture ownership extends
foreground service lifetime only; it never substitutes for dispatching Connect.

Local status is auxiliary to the original management subscription. Its initial
RPC or a malformed Local event can make Local unavailable without cancelling
tunnel, account, relay or ordinary settings updates. A subscription-scoped
revision watermark also covers malformed samples. Samples retain their exact
subscription generation, including a reply completing after stop/start, so a late
initial result cannot replace a newer event; the next valid sample can recover Local status.
Policy reads retain exact representable values and their validation result.
Unrepresentable Local protobufs stay at the management conversion boundary and
are exposed as a Local read error, never as an OFF/empty replacement. Local
mutations still require valid input and a valid read. Upstream disk loading,
defaults and malformed-file recovery are unchanged.

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
record. JNI keeps the runtime and registrations reachable and refuses replacement
initialization until an explicit shutdown retry succeeds; successful cleanup
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

Local is a receiver, not tunnel transit. It terminates connections using its
stack and protected, physical-network-bound sockets. Its current pre-stack
parser rejects IPv4/IPv6 fragments. Complete Local datagrams up to the actual
capture MTU are supported; fragmented Local UDP still requires future receiver work.

### iOS

### CLI

[`NotifyRouteChange2`]: https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
[`SCNetworkReachability`]: https://developer.apple.com/documentation/systemconfiguration/scnetworkreachability-g7d
[`SCDynamicStore`]: https://developer.apple.com/documentation/systemconfiguration/scdynamicstore-gb2
[`ConnectivityManager`]: https://developer.android.com/reference/android/net/ConnectivityManager
[`NWPathMonitor`]: https://developer.apple.com/documentation/network/nwpathmonitor
