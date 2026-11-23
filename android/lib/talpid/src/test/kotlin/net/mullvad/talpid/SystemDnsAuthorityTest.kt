package net.mullvad.talpid

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import io.mockk.every
import io.mockk.mockk
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemDnsAuthorityTest {
    private var lockdown = false
    private var protects = 0
    private val authority =
        SystemDnsAuthority(
            { lockdown },
            {
                protects++
                true
            },
            supported = true,
        )
    private val network = mockk<Network>()
    private val dns = InetAddress.getByName("10.77.10.54")

    private fun ready(physical: Boolean = true, authority: SystemDnsAuthority = this.authority) {
        val capabilities = mockk<NetworkCapabilities>()
        every { capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) } returns
            physical
        authority.onAvailable(network)
        authority.onCapabilitiesChanged(network, capabilities)
        val links = mockk<LinkProperties>(relaxed = true)
        every { links.dnsServers } returns listOf(dns)
        authority.onLinkPropertiesChanged(network, links)
    }

    @Test
    fun `should read lockdown every time and never protect denied queries`() {
        ready()
        val snapshot = checkNotNull(authority.snapshot())
        assertEquals(listOf(dns), snapshot.dnsServers)
        assertTrue(authority.current(snapshot.token))
        lockdown = true
        assertFalse(authority.current(snapshot.token))
        assertEquals(LocalSocketPreparation.STALE, authority.prepare(7, snapshot.token))
        assertEquals(0, protects)
        lockdown = false
        assertTrue(authority.current(snapshot.token))
    }

    @Test
    fun `should retire old tokens across loss and identical return`() {
        ready()
        val old = checkNotNull(authority.snapshot()).token
        authority.onLost(network)
        assertNull(authority.snapshot())
        ready()
        assertNotEquals(old, checkNotNull(authority.snapshot()).token)
        assertFalse(authority.current(old))
    }

    @Test
    fun `should exclude VPN resolvers from system snapshots`() {
        ready(physical = false)
        assertNull(authority.snapshot())
    }

    @Test
    fun `should pause Android nine system DNS without querying lockdown`() {
        val unsupported =
            SystemDnsAuthority(
                { error("no API on Android nine") },
                {
                    protects++
                    true
                },
                supported = false,
            )
        ready(authority = unsupported)
        assertNull(unsupported.snapshot())
        assertFalse(unsupported.current(1))
        assertEquals(0, protects)
    }
}
