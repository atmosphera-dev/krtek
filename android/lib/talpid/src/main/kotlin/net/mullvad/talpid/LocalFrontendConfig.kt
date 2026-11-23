package net.mullvad.talpid

import java.net.InetAddress
import net.mullvad.mullvadvpn.lib.model.LocalCidr

/** Partial keeps the exact optional system resolver list, with no empty-DNS fallback. */
internal class LocalFrontendConfig
private constructor(val routes: List<LocalCidr>, val dnsServers: List<InetAddress>) {
    fun configure(address: (String, Int) -> Unit, route: (LocalCidr) -> Unit) {
        address("172.27.1.1", IPV4_HOST_PREFIX)
        address("fdf0:ce4a:801d::172:27:1:1", IPV6_HOST_PREFIX)
        routes.forEach(route)
    }

    companion object {
        private const val IPV4_HOST_PREFIX = 32
        private const val IPV6_HOST_PREFIX = 128

        fun parse(
            routes: Array<String>,
            dnsServers: List<InetAddress> = emptyList(),
        ): LocalFrontendConfig? {
            val parsed = routes.map { LocalCidr.parse(it).getOrNull() ?: return null }
            return parsed.takeIf { it.isNotEmpty() }?.let { LocalFrontendConfig(it, dnsServers) }
        }
    }
}
