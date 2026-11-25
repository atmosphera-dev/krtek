package net.mullvad.talpid

import java.net.InetAddress
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.talpid.model.InetNetwork

/** Partial keeps the exact optional system resolver list, with no empty-DNS fallback. */
internal class LocalFrontendConfig
private constructor(val routes: List<InetNetwork>, val dnsServers: List<InetAddress>) {
    fun configure(address: (String, Int) -> Unit, route: (InetNetwork) -> Unit) {
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
            val parsed = routes.map { text ->
                LocalCidr.parse(text).getOrNull()?.let {
                    InetNetwork(InetAddress.getByAddress(it.networkBytes()), it.prefix.toShort())
                }
                    ?: when {
                        dnsServers.isNotEmpty() && text == "0.0.0.0/0" ->
                            InetNetwork(InetAddress.getByName("0.0.0.0"), 0)
                        dnsServers.isNotEmpty() && text == "::/0" ->
                            InetNetwork(InetAddress.getByName("::"), 0)
                        else -> return null
                    }
            }
            return parsed.takeIf { it.isNotEmpty() }?.let { LocalFrontendConfig(it, dnsServers) }
        }
    }
}
