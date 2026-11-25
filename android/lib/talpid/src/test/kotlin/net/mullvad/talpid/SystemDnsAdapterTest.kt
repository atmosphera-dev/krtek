package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.ParcelFileDescriptor
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import java.io.FileDescriptor
import java.net.InetAddress
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SystemDnsAdapterTest {
    private val wifi = mockk<Network> { every { networkHandle } returns 120L }
    private val cell = mockk<Network> { every { networkHandle } returns 121L }
    private var lockdown = false
    private var localHandle: Long? = null
    private val protect = mockk<(Int) -> Boolean>()
    private val authority =
        SystemDnsAuthority(
            { lockdown },
            protect,
            supported = true,
            localNetwork = { localHandle },
        )

    @AfterEach fun cleanup() = unmockkAll()

    private fun capabilities(validated: Boolean = true, local: Boolean = true) =
        mockk<NetworkCapabilities>(relaxed = true) {
            every { hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) } returns true
            every { hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } returns true
            every { hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) } returns true
            every { hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) } returns true
            every { hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) } returns validated
            every { hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } returns local
            every { hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) } returns !local
        }

    private fun ready(
        network: Network,
        resolver: String,
        validated: Boolean = true,
        local: Boolean = true,
    ) {
        authority.onAvailable(network)
        authority.onCapabilitiesChanged(network, capabilities(validated, local))
        val links = mockk<LinkProperties>(relaxed = true)
        every { links.dnsServers } returns listOf(InetAddress.getByName(resolver))
        authority.onLinkPropertiesChanged(network, links)
    }

    @Suppress("DEPRECATION") // Test the initial-set read used by the passive adapter.
    private fun register(
        initial: Array<Network> = emptyArray(),
        initialCapabilities: Map<Network, NetworkCapabilities> = emptyMap(),
    ): ConnectivityManager {
        mockkConstructor(NetworkRequest.Builder::class)
        val builder = mockk<NetworkRequest.Builder>(relaxed = true)
        every { builder.addCapability(any()) } returns builder
        every { builder.build() } returns mockk()
        every { anyConstructed<NetworkRequest.Builder>().addCapability(any()) } returns builder
        val manager = mockk<ConnectivityManager>(relaxed = true)
        every { manager.allNetworks } returns initial
        initial.forEach {
            every { manager.getNetworkCapabilities(it) } returns
                (initialCapabilities[it] ?: capabilities())
        }
        authority.register(manager)
        verify { builder.addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
        return manager
    }

    @Test
    fun `should register only a passive non VPN Internet feed and unregister exactly it`() {
        val manager = register()
        verify(exactly = 1) { manager.registerNetworkCallback(any<NetworkRequest>(), authority) }
        verify(exactly = 0) {
            manager.registerDefaultNetworkCallback(any<ConnectivityManager.NetworkCallback>())
        }
        verify(exactly = 0) {
            manager.requestNetwork(
                any<NetworkRequest>(),
                any<ConnectivityManager.NetworkCallback>(),
            )
        }
        verify {
            anyConstructed<NetworkRequest.Builder>()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        authority.close()
        verify(exactly = 1) { manager.unregisterNetworkCallback(authority) }
        ready(wifi, "10.77.10.54")
        assertNull(authority.snapshot(), "late callback must not reopen closed ownership")
    }

    @Test
    fun `should await the complete initial set and revoke during ambiguous selection`() {
        register(arrayOf(wifi, cell))
        ready(wifi, "10.77.10.54")
        assertNull(authority.snapshot())
        ready(cell, "10.77.10.55", local = false)
        val first = checkNotNull(authority.snapshot())
        assertEquals(listOf(InetAddress.getByName("10.77.10.54")), first.dnsServers)
        authority.onCapabilitiesChanged(cell, capabilities())
        assertNull(authority.snapshot())
        assertFalse(authority.current(first.token))
        authority.onLost(cell)
        assertNotEquals(first.token, checkNotNull(authority.snapshot()).token)
    }

    @Test
    fun `should protect then bind the selected network and reread lockdown for every operation`() {
        ready(wifi, "10.77.10.54")
        val snapshot = checkNotNull(authority.snapshot())
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        val file = FileDescriptor()
        mockkStatic(ParcelFileDescriptor::class)
        every { ParcelFileDescriptor.fromFd(7) } returns descriptor
        every { descriptor.fileDescriptor } returns file
        every { protect(7) } returns true
        every { wifi.bindSocket(file) } returns Unit
        assertEquals(LocalSocketPreparation.READY, authority.prepare(7, snapshot.token))
        verifyOrder {
            protect(7)
            wifi.bindSocket(file)
            descriptor.close()
        }
        lockdown = true
        assertFalse(authority.current(snapshot.token))
        assertEquals(LocalSocketPreparation.STALE, authority.prepare(7, snapshot.token))
        verify(exactly = 1) { protect(7) }
        lockdown = false
        assertTrue(authority.current(snapshot.token))
    }

    @Test
    fun `should use only the physical resolver and protect before binding under lockdown for own DNS`() {
        ready(wifi, "10.77.10.54")
        ready(cell, "10.77.10.55")
        val vpn = capabilities()
        every { vpn.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } returns true
        authority.onCapabilitiesChanged(cell, vpn)
        lockdown = true

        val snapshot = checkNotNull(authority.ownSnapshot())
        assertEquals(listOf(InetAddress.getByName("10.77.10.54")), snapshot.dnsServers)
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        val file = FileDescriptor()
        mockkStatic(ParcelFileDescriptor::class)
        every { ParcelFileDescriptor.fromFd(9) } returns descriptor
        every { descriptor.fileDescriptor } returns file
        every { protect(9) } returns true
        every { wifi.bindSocket(file) } returns Unit
        assertEquals(LocalSocketPreparation.STALE, authority.prepare(9, snapshot.token))
        assertEquals(LocalSocketPreparation.READY, authority.prepareOwn(9, snapshot.token))
        verifyOrder {
            protect(9)
            wifi.bindSocket(file)
            descriptor.close()
        }
        verify(exactly = 0) { cell.bindSocket(any<FileDescriptor>()) }
    }

    @Test
    fun `should refuse absent ambiguous and stale authority and protection denial for own DNS`() {
        assertNull(authority.ownSnapshot())
        ready(wifi, "10.77.10.54")
        val first = checkNotNull(authority.ownSnapshot())
        every { protect(9) } returns false
        assertEquals(LocalSocketPreparation.PROTECT_FAILED, authority.prepareOwn(9, first.token))
        ready(cell, "10.77.10.55")
        assertNull(authority.ownSnapshot())
        assertEquals(LocalSocketPreparation.STALE, authority.prepareOwn(9, first.token))
        authority.onLost(cell)
        assertNotEquals(first.token, checkNotNull(authority.ownSnapshot()).token)
        assertEquals(LocalSocketPreparation.STALE, authority.prepareOwn(9, first.token))
        authority.onLost(wifi)
        assertNull(authority.ownSnapshot())
        verify(exactly = 1) { protect(9) }
        verify(exactly = 0) { wifi.bindSocket(any<FileDescriptor>()) }
    }

    @Test
    fun `should not enable ordinary DNS from daemon observation on Android nine`() {
        val legacy =
            SystemDnsAuthority(
                { error("no lockdown API") },
                protect,
                supported = false,
                observeForDaemon = true,
            )
        legacy.onAvailable(wifi)
        legacy.onCapabilitiesChanged(wifi, capabilities())
        val links = mockk<LinkProperties>(relaxed = true)
        every { links.dnsServers } returns listOf(InetAddress.getByName("10.77.10.54"))
        legacy.onLinkPropertiesChanged(wifi, links)
        val snapshot = checkNotNull(legacy.ownSnapshot())
        assertNull(legacy.snapshot())
        assertEquals(0L, legacy.failureToken())
        assertEquals(LocalSocketPreparation.STALE, legacy.prepare(9, snapshot.token))
    }

    @Test
    fun `should not substitute a different networks resolvers when the selected list is empty`() {
        ready(wifi, "10.77.10.54")
        ready(cell, "10.77.10.55", local = false)
        val links = mockk<LinkProperties>(relaxed = true)
        every { links.dnsServers } returns emptyList()
        authority.onLinkPropertiesChanged(wifi, links)
        assertEquals(emptyList<InetAddress>(), checkNotNull(authority.snapshot()).dnsServers)
    }

    @Test
    fun `should follow the current Local selection and retire its token when it changes`() {
        ready(wifi, "10.77.10.54", validated = false)
        ready(cell, "10.77.10.55", local = false)
        localHandle = 120
        val local = checkNotNull(authority.snapshot())
        assertEquals(listOf(InetAddress.getByName("10.77.10.54")), local.dnsServers)
        localHandle = null
        assertFalse(authority.current(local.token))
        assertEquals(
            listOf(InetAddress.getByName("10.77.10.55")),
            checkNotNull(authority.snapshot()).dnsServers,
        )
    }

    @Test
    fun `should keep Android nine paused without registering a network request`() {
        val manager = mockk<ConnectivityManager>()
        val unsupported =
            SystemDnsAuthority({ error("no lockdown API") }, protect, supported = false)
        unsupported.register(manager)
        assertNull(unsupported.snapshot())
        unsupported.close()
        verify(exactly = 0) { manager.registerNetworkCallback(any<NetworkRequest>(), unsupported) }
        verify(exactly = 0) { manager.unregisterNetworkCallback(unsupported) }
    }

    @Test
    fun `should not await initial networks that the passive request cannot observe`() {
        val untrusted = capabilities()
        every { untrusted.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED) } returns false
        register(arrayOf(wifi, cell), mapOf(cell to untrusted))
        ready(wifi, "10.77.10.54")
        assertEquals(
            listOf(InetAddress.getByName("10.77.10.54")),
            checkNotNull(authority.snapshot()).dnsServers,
        )
    }
}
