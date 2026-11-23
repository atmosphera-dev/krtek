package net.mullvad.talpid

import android.net.NetworkCapabilities
import android.net.NetworkRequest
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemDnsSelectionTest {
    private val wifi = SystemDnsCandidate(120, validated = false, local = true)
    private val cell = SystemDnsCandidate(121, validated = true, local = false)

    @Test
    fun `should prefer the unambiguous current Local network`() {
        assertEquals(120L, selectSystemDnsNetwork(listOf(wifi, cell), 120))
    }

    @Test
    fun `should prefer validated then Local transport without a Local selection`() {
        assertEquals(121L, selectSystemDnsNetwork(listOf(wifi, cell), null))
        assertEquals(120L, selectSystemDnsNetwork(listOf(wifi.copy(validated = true), cell), null))
        assertEquals(120L, selectSystemDnsNetwork(listOf(wifi, cell.copy(validated = false)), null))
    }

    @Test
    fun `should fail closed on equal ranked networks regardless of arrival order`() {
        val ethernet = wifi.copy(handle = 122)
        assertNull(selectSystemDnsNetwork(listOf(wifi, ethernet), null))
        assertNull(selectSystemDnsNetwork(listOf(ethernet, wifi), null))
        assertNull(selectSystemDnsNetwork(listOf(cell, cell.copy(handle = 123)), null))
        assertNull(selectSystemDnsNetwork(emptyList(), null))
    }

    @Test
    fun `should ignore a Local handle not present in the current Internet set`() {
        assertEquals(121L, selectSystemDnsNetwork(listOf(cell), 120))
    }

    @Test
    @androidx.annotation.RequiresApi(android.os.Build.VERSION_CODES.R)
    fun `should match the request defaults on Android ten and the exact request on newer APIs`() {
        val caps = mockk<NetworkCapabilities>(relaxed = true)
        val request = mockk<NetworkRequest>()
        every { caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) } returns true
        every { caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } returns true
        every { caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) } returns true
        every { caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) } returns true
        assertTrue(SystemDnsAuthority.requestedLegacy(caps))
        every { caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) } returns false
        assertFalse(SystemDnsAuthority.requestedLegacy(caps))
        every { request.canBeSatisfiedBy(caps) } returns false
        assertFalse(SystemDnsAuthority.requestedModern(caps, request))
        every { request.canBeSatisfiedBy(caps) } returns true
        assertTrue(SystemDnsAuthority.requestedModern(caps, request))
        every { caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } returns true
        assertFalse(SystemDnsAuthority.requestedModern(caps, request))
    }
}
