# Android split DNS

## Implementation status

Split DNS is configured in Settings > VPN settings > Local network sharing, below
the Local rules. Plain UDP/TCP DNS to an advertised resolver is inspected while
Krtek owns capture. With Mullvad off on Android 10+, Partial capture advertises
and captures the passively selected non-VPN network's resolver addresses. Listed
names use the Home path or fail with SERVFAIL. Unlisted queries keep their original bytes
and destination, using a protected socket bound to that underlying network only
when Android's current "Block connections without VPN" setting is off. When it
is on they are dropped, without granting the VPN provider's exemption to apps.
DNS-enabled Partial captures both default routes while lockdown is on so Android's
normal hostname lookup can use its exposed address families. This is still
Partial: no Mullvad carrier or Ordinary forwarding, and non-Local/non-DNS packets
are dropped inside Krtek. Lockdown changes rebuild the profile; open Local
connections may drop during that coverage change. Lockdown off or split DNS
disabled retains host routes only. No resolver-probe address routes are added.
Android 9 cannot expose this current OS gate: split DNS is paused in Partial,
with Android handling DNS as for stock Mullvad. Full capture works on Android 9.

The physical network is the Local observer's unambiguous selection when available.
Otherwise Krtek prefers validated networks, then Wi-Fi/Ethernet. Equal candidates
return immediate SERVFAIL for Ordinary UDP and each TCP message when lockdown is
off, rather than choosing by callback order. With lockdown on they still drop.
Missing or incomplete observation remains unavailable. Observation
is passive: Krtek does not request a new connection or add a network permission.

Krtek's own service lookups (such as GeoIP or API names) are not app split DNS.
With Mullvad off and capture possible, they use only the observed non-VPN
network's resolvers through protected sockets bound to that network. If that
authority or socket preparation fails, there is no default-network fallback.
With no Krtek VPN confirmed, or with Mullvad on, they use the upstream default
resolver path. This does not let unlisted app queries bypass Android lockdown.

## Settings screen

| # | Control | Behavior |
|---|---|---|
| 1 | Use home DNS for listed domains | Saves immediately. Turning it on with an incomplete configuration opens the editor instead; nothing is saved until Save |
| 2 | Summary | Shows where it is used (for example "Used on Wi-Fi: My home"), the home network rule's current status, Home DNS IP, home network and the domains without their final dot |
| 3 | Edit split DNS | One draft for domains, Home DNS IP and home network. Each domain shows the normalized name it matches. Save stores the whole Local policy atomically with the screen's other changes |
| 4 | Home network | Lists the existing Local rules with their network. Choosing one never enables, broadens or otherwise changes that rule |
| 5 | Errors and conflicts | Invalid input names the field to fix and keeps the draft. If the saved split DNS settings changed while editing, the draft stays and a second Save replaces them. Back or Cancel with changes asks before discarding |
| 6 | Invalid saved settings | When only the split DNS part of the stored policy is invalid, the editor stays available to repair it; other Local controls stay locked as before |
| 7 | Private DNS note | Explains that Private DNS and apps' own secure DNS skip split DNS, with a button to Android's network settings. Krtek never changes these settings itself |

## Names and Home DNS

Split DNS chooses a DNS server by the question's domain. It is separate from
app split tunneling and from the IP rules that decide where connections go.

| # | Setting | Meaning |
|---|---|---|
| 1 | Domain | `home`, `.home` and `HOME.` identify the same suffix. It matches `home` and `nas.home`, not `myhome` or `home.example`. Full public domains and valid internationalized names are supported by the policy contract |
| 2 | Home DNS IP | The numeric address of the router or Home DNS server, for example `192.168.1.1`. Krtek's fixed virtual interface addresses are not the Home server |
| 3 | Home network | An existing Local rule covering that server. Saving DNS must not enable the Local master/rule, broaden its addresses or remove its network conditions |
| 4 | Enable | Disabled by default, including old installations without a split-DNS policy. Incomplete disabled configuration can be retained; enabling requires domains, a valid server and a covered rule association |

Entries cover the exact name and its subdomains on DNS label boundaries. Equal
normalized entries deduplicate; overlapping suffixes are harmless. The editor
shows names without the final root dot and previews the normalized identity.
Invalid drafts remain repairable rather than silently disappearing.

Use full names such as `nas.home`: bare `nas` is not expanded. Wildcards, URLs,
paths, port-qualified names and IP literals are not domain entries. Reverse
lookups need the relevant reverse-zone entry. A CNAME, SRV or HTTPS/SVCB target
outside a listed domain does not automatically become Home; a subsequent
question is classified using that target's own name.

## Delivery contract

Listed questions use only the configured Home server under existing live Local
eligibility. If that server cannot be reached, the question fails instead of
trying another resolver. Home negative/error responses do not trigger Ordinary
fallback. Krtek can serve Home only while it owns a usable VPN capture and has
the necessary Local authority; force-stop or VPN permission loss is outside
that promise. Plain UDP/TCP Home DNS is not encrypted by socket protection.
The Home server controls its own recursion and logging.

Unlisted names retain ordinary resolver choice and permission to send: the
admitted Mullvad path, existing private-custom/Local handling or the unsecured
underlying-system path where allowed. Error/OS blocking does not grant a new
physical fallback. If the ordinary resolver was already Home, unlisted names
can still go there. This is not a promise that Home never sees unlisted names.
Advertised endpoints, latency, failure timing and Android network validation
can differ; destination preservation is not packet-for-packet equivalence.

Both UDP and TCP, normal record types, complete messages, TTLs and DNSSEC
material must be preserved. No Krtek answer cache is added. Android and apps
can retain their own cached answers, so policy edits need not change an app's
destination immediately. This forwarder does not claim local DNSSEC validation.

A DNS answer never adds a Local route. Connections still need matching IP
authorization or the ordinary tunnel. A Home answer containing a public IP
does not grant direct internet access. Normal hostname and certificate checks
remain necessary; DNS does not rewrite URLs, SNI or service identity.

## Known limits

- Android Private DNS (DNS over TLS on port 853) and apps' own encrypted DNS
  (DNS over HTTPS, for example Chrome's Secure DNS) do not use the plain DNS
  endpoint, so they skip split DNS. Turn them off to rely on split DNS; Krtek
  must not change them silently. Strict or Automatic Private DNS observations
  are not a compatibility promise. The settings button opens Android's network
  settings, where Private DNS is found; Android has no public direct link.
- Android 9 pauses split DNS while Mullvad is off; see Implementation status.
- Apps outside Krtek's captured UID range or using hardcoded resolvers are not
  universally confined by this feature.
- Android and apps cache answers, so a policy change need not change an app's
  destination immediately.
- A truncated Home answer is retried over TCP only when the client can reach
  Home over TCP; otherwise the listed question fails.

Existing [Android limitations](known-issues.md), including capture transition
gaps and OS bypasses, remain. This work does not resolve the separate fragmented
public-DNS finding or provide physical-phone/cellular certification.
