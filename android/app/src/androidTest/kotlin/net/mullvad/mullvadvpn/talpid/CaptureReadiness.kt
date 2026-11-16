package net.mullvad.mullvadvpn.talpid

import java.net.InetAddress

/** Samples from Android and the daemon log converge independently within the caller's deadline. */
internal object CaptureReadiness {
    enum class RouteType {
        Forwarding,
        Unreachable,
    }

    data class Route(val prefix: String, val type: RouteType)

    /** Android adds an unreachable default for a family absent from the VPN's Builder config. */
    fun route(text: String): Route {
        val match =
            checkNotNull(
                Regex(
                        "^\\s*([0-9a-fA-F:.]+/\\d+)(?:\\s+->.*|\\s+(unreachable)(?:\\s+mtu\\s+\\d+)?)?$"
                    )
                    .matchEntire(text)
            ) {
                "Malformed Android route"
            }
        return Route(
            match.groupValues[1],
            if (match.groupValues[2].isEmpty()) RouteType.Forwarding else RouteType.Unreachable,
        )
    }

    fun routePrefix(text: String): String = route(text).prefix

    data class Receipt(val generation: String, val handle: String, val text: String)

    data class PartialReceipt(val generation: String, val session: String, val format: String)

    enum class DnsExpectation {
        Present,
        Absent,
    }

    /** Receives the decoded contents of DnsAddresses, never a bracketed display value. */
    fun dnsMatches(dns: String, expectation: DnsExpectation): Boolean {
        if ('[' in dns || ']' in dns) return false
        return when (expectation) {
            DnsExpectation.Present -> dns.isNotBlank()
            DnsExpectation.Absent -> dns.isBlank()
        }
    }

    fun configurationReady(
        addressesReady: Boolean,
        dns: String,
        mtu: Int,
        routes: Set<String>,
        expectedRoutes: Set<String>,
        requiredMtu: Int? = null,
        exposesIpv6: Boolean = false,
        dnsExpectation: DnsExpectation = DnsExpectation.Present,
        requiredDns: Set<String>? = null,
    ): Boolean =
        addressesReady &&
            dnsMatches(dns, dnsExpectation) &&
            (requiredDns == null ||
                dns.split(',')
                    .filter { it.isNotBlank() }
                    .map { InetAddress.getByName(it.trim().removePrefix("/")).hostAddress }
                    .toSet() ==
                    requiredDns.map { InetAddress.getByName(it).hostAddress }.toSet()) &&
            mtu >= (if (exposesIpv6) 1280 else 1) &&
            (requiredMtu == null || mtu == requiredMtu) &&
            expectedRoutes.all { expected -> routes.any { covers(it, expected) } }

    fun covers(route: String, destination: String): Boolean {
        val network = InetAddress.getByName(route.substringBefore('/')).address
        val address = InetAddress.getByName(destination.substringBefore('/')).address
        val prefix = route.substringAfter('/').toInt()
        if (
            network.size != address.size ||
                prefix !in 0..network.size * 8 ||
                prefix > destination.substringAfter('/').toInt()
        )
            return false
        if (
            (prefix until network.size * 8).any { bit ->
                network[bit / 8].toInt() and (1 shl (7 - bit % 8)) != 0
            }
        )
            return false
        return (0 until prefix).all { bit ->
            val mask = 1 shl (7 - bit % 8)
            network[bit / 8].toInt() and mask == address[bit / 8].toInt() and mask
        }
    }

    fun minimalRoutes(routes: Set<String>): Set<String> =
        routes.filter { route -> routes.none { it != route && covers(it, route) } }.toSet()

    fun partialReceipt(tail: String, previousGeneration: String?): PartialReceipt? {
        val current =
            tail
                .lineSequence()
                .lastOrNull { it.contains("router-authority ") }
                ?.substringAfter(" current=") ?: return null
        if (!current.contains("capture_ready: true") || !current.contains("ordinary_ready: false"))
            return null
        val generation =
            checkNotNull(Regex("capture_generation: Some\\(([0-9]+)\\)").find(current))
                .groupValues[1]
        val session =
            checkNotNull(Regex("session_generation: Some\\(([0-9]+)\\)").find(current))
                .groupValues[1]
        check(generation.toULong() > 0uL && session.toULong() > 0uL)
        if (previousGeneration != null && generation.toULong() <= previousGeneration.toULong())
            return null
        val format =
            tail.lineSequence().lastOrNull { it.contains("capture-format generation=$generation ") }
                ?: return null
        requirePacketFormat(format, "flags")
        return PartialReceipt(generation, session, format)
    }

    fun receipt(
        tail: String,
        iface: String,
        netId: String,
        routes: Set<String>,
        mtu: Int,
        ownerUid: Int,
        previousGeneration: String?,
        canonicalPrefix: (String) -> String,
    ): Receipt? {
        if (mtu <= 0) return null
        val line =
            tail.lineSequence().lastOrNull {
                (it.contains("capture-ready ") || it.contains("capture-lost ")) &&
                    it.contains(" network=$netId interface=$iface ")
            } ?: return null
        if (line.contains("capture-lost ")) return null
        val ready = line.substringAfter("capture-ready ")
        fun token(marker: String): String? =
            ready.substringAfter(marker, "").substringBefore(' ').takeIf { it.isNotEmpty() }
        val generation = checkNotNull(token("generation: ") ?: token("generation="))
        val handle = checkNotNull(token("handle="))
        check(generation.toULong() > 0uL && handle.toULong() > 0uL)
        check(
            ready.contains("requested_routes=") &&
                ready.contains(" observed_routes=") &&
                ready.contains(" api=")
        )
        val requested =
            ready.substringAfter("requested_routes=").substringBefore(" observed_routes=")
        val observed = ready.substringAfter("observed_routes=").substringBefore(" api=")
        // CaptureExpectation projects complete routes, not a bare list of prefixes.
        // Consume the entire debug representation so missing/extra fields cannot pass.
        val routePattern =
            Regex(
                """CaptureRoute \{ destination: CapturePrefix \{ address: ([0-9a-fA-F:.]+), prefix_length: ([0-9]+) \}, gateway: (?:None|Some\([0-9a-fA-F:.]+\)), interface_name: "([^"\\]*)", route_type: (?:None|Some\(-?[0-9]+\)) \}"""
            )
        fun prefixes(text: String): Set<String> {
            val records = routePattern.findAll(text).toList()
            check(records.joinToString(", ", "[", "]") { it.value } == text) {
                "Malformed route receipt"
            }
            return records
                .map { canonicalPrefix("${it.groupValues[1]}/${it.groupValues[2]}") }
                .toSet()
        }
        val requestedPrefixes = prefixes(requested)
        val observedPrefixes = prefixes(observed)
        check(observedPrefixes.containsAll(requestedPrefixes)) {
            "Ready receipt omitted requested routes"
        }
        if (previousGeneration != null && generation.toULong() <= previousGeneration.toULong())
            return null
        if (
            !ready.contains("owner_uid=Some($ownerUid)") ||
                requestedPrefixes.any { required -> routes.none { covers(it, required) } }
        )
            return null
        requirePacketFormat(ready, "tun_flags")
        return Receipt(generation, handle, ready)
    }

    private fun requirePacketFormat(line: String, flagsKey: String) {
        fun token(key: String): String =
            checkNotNull(
                    Regex("(?:^|\\s)${Regex.escape(key)}=([^\\s]*)").findAll(line).singleOrNull()
                )
                .groupValues[1]
        check(token("representation") == "plain-ip")
        val encoded = token(flagsKey)
        check(Regex("0x[0-9a-fA-F]+").matches(encoded))
        val flags = encoded.removePrefix("0x").toUInt(16)
        check(flags and 0x5003u == 0x1001u) { "TUN/NO_PI without TAP or VNET_HDR" }
    }
}
