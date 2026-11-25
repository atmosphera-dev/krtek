package net.mullvad.talpid.model

import java.net.InetAddress

/** Runtime-only, opaque incarnation of the non-VPN default resolver list. */
class SystemDnsSnapshot(
    val token: Long,
    val dnsServers: ArrayList<InetAddress>,
    val interfaceIndex: Int,
) {
    override fun toString(): String = "SystemDnsSnapshot(redacted)"
}
