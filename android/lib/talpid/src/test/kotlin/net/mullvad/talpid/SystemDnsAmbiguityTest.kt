package net.mullvad.talpid

import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import io.mockk.every
import io.mockk.mockk
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemDnsAmbiguityTest {
    private var lockdown = false
    private val authority =
        SystemDnsAuthority(
            { lockdown },
            { error("no physical socket authority") },
            supported = true,
        )
    private val wifi = mockk<Network> { every { networkHandle } returns 120L }
    private val ethernet = mockk<Network> { every { networkHandle } returns 121L }

    private fun links(
        network: Network,
        address: String = "10.77.10.54",
        owner: SystemDnsAuthority = authority,
    ) {
        val links = mockk<LinkProperties>(relaxed = true)
        every { links.dnsServers } returns listOf(InetAddress.getByName(address))
        owner.onLinkPropertiesChanged(network, links)
    }

    private fun ready(network: Network, owner: SystemDnsAuthority = authority) {
        owner.onAvailable(network)
        val capabilities = mockk<NetworkCapabilities>(relaxed = true)
        every { capabilities.hasCapability(any()) } returns true
        every { capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } returns true
        owner.onCapabilitiesChanged(network, capabilities)
        links(network, owner = owner)
    }

    @Test
    fun `should authorize only a complete ambiguous set with live lockdown off`() {
        assertEquals(0L, authority.failureToken())
        ready(wifi)
        assertEquals(0L, authority.failureToken(), "selected is not ambiguity")
        authority.onAvailable(ethernet)
        assertEquals(0L, authority.failureToken(), "incomplete is not ambiguity")
        ready(ethernet)
        assertNull(authority.snapshot())
        val token = authority.failureToken()
        assertTrue(token > 0)
        assertEquals(token, authority.failureToken())
        assertEquals(LocalSocketPreparation.STALE, authority.prepare(7, token))
        lockdown = true
        assertEquals(0L, authority.failureToken())
        lockdown = false
        assertEquals(token, authority.failureToken())
        authority.close()
        assertEquals(0L, authority.failureToken())
    }

    @Test
    fun `should retire ambiguity tokens when tied observations change even without a selected binding`() {
        ready(wifi)
        ready(ethernet)
        val first = authority.failureToken()
        links(ethernet, "10.77.10.55")
        val second = authority.failureToken()
        assertTrue(first > 0 && second > 0)
        assertNotEquals(first, second)
        links(ethernet)
        assertNotEquals(
            first,
            authority.failureToken(),
            "identical values must not revive old replies",
        )
        authority.onLost(ethernet)
        assertEquals(0L, authority.failureToken())
        ready(ethernet)
        assertNotEquals(first, authority.failureToken())
    }

    @Test
    fun `should deny ambiguity authority on unsupported or failed OS gate`() {
        val unsupported =
            SystemDnsAuthority({ error("unsupported") }, { error("protect") }, supported = false)
        assertEquals(0L, unsupported.failureToken())
        val denied =
            SystemDnsAuthority(
                { error("lockdown read failed") },
                { error("protect") },
                supported = true,
            )
        ready(wifi, denied)
        ready(ethernet, denied)
        assertNull(denied.snapshot())
        assertEquals(0L, denied.failureToken())
    }
}
