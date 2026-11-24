package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import java.net.InetAddress
import net.mullvad.talpid.model.SystemDnsSnapshot

/** Sole system-DNS socket authority. Never accepts the VPN's resolver list. */
internal class SystemDnsAuthority(
    private val lockdown: () -> Boolean,
    private val protect: (Int) -> Boolean,
    private val supported: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
    private val localNetwork: () -> Long? = { null },
    private val observeForDaemon: Boolean = false,
) : ConnectivityManager.NetworkCallback() {
    private var token = 1L
    private var connectivity: ConnectivityManager? = null
    private var request: NetworkRequest? = null
    private var closed = false
    private val networks = mutableMapOf<Network, Observation>()
    private val initial = mutableSetOf<Network>()
    private var selected: Binding? = null
    private var ambiguous: Map<Network, Observation> = emptyMap()

    @Synchronized
    @Suppress("DEPRECATION") // Complete the passive callback's initial set on every supported API.
    fun register(manager: ConnectivityManager) {
        check(connectivity == null && !closed)
        if (supported || observeForDaemon) {
            connectivity = manager
            val passive =
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
            request = passive
            manager.registerNetworkCallback(passive, this)
            initial +=
                manager.allNetworks.filter {
                    manager.getNetworkCapabilities(it)?.let(::eligible) == true
                }
            initial.removeAll { networks[it]?.complete == true }
        }
    }

    @Synchronized
    fun close() {
        closed = true
        networks.clear()
        initial.clear()
        refresh()
        connectivity?.unregisterNetworkCallback(this)
        connectivity = null
    }

    @Synchronized
    override fun onAvailable(network: Network) {
        if (!closed) networks[network] = Observation()
        refresh()
    }

    @Synchronized
    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
        networks[network]?.let { observation ->
            val index =
                try {
                    linkProperties.interfaceName?.let {
                        java.net.NetworkInterface.getByName(it)?.index
                    } ?: 0
                } catch (_: java.net.SocketException) {
                    0
                }
            networks[network] =
                observation.copy(
                    binding = Binding(network, linkProperties.dnsServers.toList(), index)
                )
            refresh()
        }
    }

    @Synchronized
    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
        networks[network]?.let {
            networks[network] =
                it.copy(
                    candidate =
                        SystemDnsCandidate(
                            network.networkHandle,
                            capabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_VALIDATED
                            ),
                            AndroidLocalNetworkSource.localTransport(capabilities) != 0,
                        ),
                    eligible = eligible(capabilities),
                )
            refresh()
        }
    }

    @Synchronized
    override fun onLost(network: Network) {
        networks.remove(network)
        initial.remove(network)
        refresh()
    }

    @Synchronized fun snapshot(): SystemDnsSnapshot? = if (supported) ownSnapshot() else null

    @Synchronized
    fun ownSnapshot(): SystemDnsSnapshot? {
        refresh()
        return selected?.let {
            SystemDnsSnapshot(token, ArrayList(it.resolvers), it.interfaceIndex)
        }
    }

    /** Reply-only capability: no selected network, no protect/bind permission. */
    @Synchronized
    fun failureToken(): Long {
        refresh()
        return if (
            supported && ambiguous.isNotEmpty() && runCatching { !lockdown() }.getOrDefault(false)
        )
            token
        else 0L
    }

    private fun refresh() {
        initial.removeAll { networks[it]?.complete == true }
        val candidates = networks.values.filter { it.eligible && it.complete }
        val ready =
            (supported || observeForDaemon) &&
                !closed &&
                initial.isEmpty() &&
                networks.values.all { it.complete }
        val handle =
            if (ready)
                selectSystemDnsNetwork(candidates.mapNotNull { it.candidate }, localNetwork())
            else null
        val next = candidates.singleOrNull { it.candidate?.handle == handle }?.binding
        val tied =
            if (ready && next == null && candidates.size > 1)
                candidates.associateBy { checkNotNull(it.binding).network }
            else emptyMap()
        if (selected != next || ambiguous != tied) {
            token++
            selected = next
            ambiguous = tied
        }
    }

    private fun eligible(capabilities: NetworkCapabilities): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && request != null)
            requestedModern(capabilities, checkNotNull(request))
        else requestedLegacy(capabilities)

    @Synchronized
    fun current(expected: Long, own: Boolean = false): Boolean {
        refresh()
        return selected != null && token == expected && (own || supported && !lockdown())
    }

    @Synchronized
    fun prepare(fd: Int, expected: Long): Int =
        if (current(expected)) {
            prepareOwn(fd, expected).let {
                if (current(expected)) it else LocalSocketPreparation.STALE
            }
        } else LocalSocketPreparation.STALE

    @Synchronized
    fun prepareOwn(fd: Int, expected: Long): Int =
        if (current(expected, own = true))
            LocalSocketPreparation.prepare(fd, checkNotNull(selected).network, protect).let {
                if (current(expected, own = true)) it else LocalSocketPreparation.STALE
            }
        else LocalSocketPreparation.STALE

    private data class Binding(
        val network: Network,
        val resolvers: List<InetAddress>,
        val interfaceIndex: Int,
    )

    private data class Observation(
        val candidate: SystemDnsCandidate? = null,
        val eligible: Boolean = false,
        val binding: Binding? = null,
    ) {
        val complete: Boolean
            get() = candidate != null && binding != null
    }

    companion object {
        /** Initial enumeration must match the passive request, including its platform defaults. */
        @androidx.annotation.RequiresApi(Build.VERSION_CODES.R)
        internal fun requestedModern(
            capabilities: NetworkCapabilities,
            request: NetworkRequest,
        ): Boolean =
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                request.canBeSatisfiedBy(capabilities)

        internal fun requestedLegacy(capabilities: NetworkCapabilities): Boolean =
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
    }
}
