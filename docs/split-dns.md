# Android split DNS

## Implementation status

Split DNS is under development. The saved policy, message transports and editor
components are foundations only. The normal capture path does not select a
split-DNS forwarder, and the Local settings screen does not expose the new
editor yet. Saving policy through development tooling does not activate DNS
forwarding. The behavior below describes the feature's completion contract,
not verified behavior in this revision.

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

## Android limits

Android Private DNS and apps' own Secure DNS can skip the plain DNS endpoint.
Turn them off to rely on split DNS; Krtek must not change them silently. Strict
or Automatic Private DNS observations are not a compatibility promise. Apps
outside Krtek's captured UID range or using hardcoded/encrypted DNS are not
universally confined by this feature.

Existing [Android limitations](known-issues.md), including capture transition
gaps and OS bypasses, remain. This work does not resolve the separate fragmented
public-DNS finding or provide physical-phone/cellular certification.
