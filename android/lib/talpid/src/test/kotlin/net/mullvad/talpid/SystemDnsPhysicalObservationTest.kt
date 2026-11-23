package net.mullvad.talpid

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import io.mockk.every
import io.mockk.mockk
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemDnsPhysicalObservationTest {
    @Test
    fun `should retain physical DNS when application default becomes a VPN`() {
        val authority = SystemDnsAuthority({ false }, { error("not preparing") }, supported = true)
        fun observe(handle: Long, physical: Boolean, resolver: String) {
            val network = mockk<Network> { every { networkHandle } returns handle }
            val capabilities = mockk<NetworkCapabilities>(relaxed = true)
            every { capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) } returns
                physical
            every {
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            } returns true
            every { capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) } returns
                true
            every {
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            } returns true
            every { capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } returns !physical
            val links = mockk<LinkProperties>(relaxed = true)
            every { links.dnsServers } returns listOf(InetAddress.getByName(resolver))
            authority.onAvailable(network)
            authority.onCapabilitiesChanged(network, capabilities)
            authority.onLinkPropertiesChanged(network, links)
        }
        observe(120, true, "10.77.10.54")
        val physical = checkNotNull(authority.snapshot())
        // Replay the saved platform boundary: the app default is VPN, the physical network lives.
        observe(119, false, "10.64.0.1")
        assertEquals(physical.dnsServers, authority.snapshot()?.dnsServers)
        assertTrue(authority.current(checkNotNull(authority.snapshot()).token))
    }
}
