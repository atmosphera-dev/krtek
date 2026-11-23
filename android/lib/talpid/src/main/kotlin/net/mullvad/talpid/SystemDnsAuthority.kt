package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import net.mullvad.talpid.model.SystemDnsSnapshot

/** Sole system-DNS socket authority. Never accepts the VPN's resolver list. */
internal class SystemDnsAuthority(
    private val lockdown: () -> Boolean,
    private val protect: (Int) -> Boolean,
    private val supported: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
) : ConnectivityManager.NetworkCallback() {
    private var token = 1L
    private var network: Network? = null
    private var resolvers: List<java.net.InetAddress>? = null
    private var physical = false
    private var interfaceIndex = 0

    @Synchronized
    override fun onAvailable(network: Network) {
        if (this.network != network) {
            token++
            this.network = network
            resolvers = null
            physical = false
        }
    }

    @Synchronized
    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
        if (this.network == network) {
            val next = linkProperties.dnsServers.toList()
            val index =
                try {
                    linkProperties.interfaceName?.let {
                        java.net.NetworkInterface.getByName(it)?.index
                    } ?: 0
                } catch (_: java.net.SocketException) {
                    0
                }
            if (resolvers != next || interfaceIndex != index) token++
            resolvers = next
            interfaceIndex = index
        }
    }

    @Synchronized
    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
        if (this.network == network) {
            val next = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            if (next != physical) token++
            physical = next
        }
    }

    @Synchronized
    override fun onLost(network: Network) {
        if (this.network == network) {
            token++
            this.network = null
            resolvers = null
            physical = false
        }
    }

    @Synchronized
    fun snapshot(): SystemDnsSnapshot? =
        if (supported && physical && network != null)
            resolvers?.let { SystemDnsSnapshot(token, ArrayList(it), interfaceIndex) }
        else null

    @Synchronized
    fun current(expected: Long): Boolean = snapshot()?.token == expected && !lockdown()

    @Synchronized
    fun prepare(fd: Int, expected: Long): Int =
        if (current(expected))
            LocalSocketPreparation.prepare(fd, checkNotNull(network), protect).let {
                if (current(expected)) it else LocalSocketPreparation.STALE
            }
        else LocalSocketPreparation.STALE
}
