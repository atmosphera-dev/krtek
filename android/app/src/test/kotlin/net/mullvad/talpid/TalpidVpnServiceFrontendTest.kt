package net.mullvad.talpid

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Looper
import android.os.ParcelFileDescriptor
import arrow.core.left
import arrow.core.right
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import java.io.FileDescriptor
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.Prepared
import net.mullvad.talpid.model.CreateTunResult
import net.mullvad.talpid.model.LocalNetworkSnapshot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class TalpidVpnServiceFrontendTest {
    private lateinit var service: FrontendService
    private lateinit var serviceInstance: FrontendService

    @BeforeEach
    fun setup() {
        mockkStatic("net.mullvad.mullvadvpn.lib.common.util.VpnServiceUtilsKt")
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk()
        serviceInstance = FrontendService()
        service = spyk(serviceInstance, recordPrivateCalls = true)
        every { service getProperty "connectivityListener" } returns
            mockk<ConnectivityListener>(relaxed = true)
        every { service.prepareVpnSafe() } returns Prepared.right()
        mockkConstructor(VpnService.Builder::class)
        val builder = mockk<VpnService.Builder>(relaxed = true)
        every { anyConstructed<VpnService.Builder>().addAddress(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addAddress(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) } returns builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().setMtu(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setBlocking(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) } returns
            builder
        val fd = mockk<ParcelFileDescriptor>()
        every { anyConstructed<VpnService.Builder>().establish() } returns fd
        every { fd.fd } returns 7
        every { fd.detachFd() } returns 7
        every { fd.close() } returns Unit
    }

    @AfterEach fun cleanup() = unmockkAll()

    private fun enableCaptureObservation() {
        TalpidVpnService::class.java.getDeclaredField("captureRegistration").apply {
            isAccessible = true
            setLong(service, 1L)
        }
        val connectivity = mockk<ConnectivityManager>(relaxed = true)
        every { service.getSystemService(ConnectivityManager::class.java) } returns connectivity
        every { service.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) } returns
            connectivity
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } returns
            mockk(relaxed = true)
        mockkConstructor(NetworkRequest.Builder::class)
        val request = mockk<NetworkRequest.Builder>()
        every { anyConstructed<NetworkRequest.Builder>().removeCapability(any()) } returns request
        every { request.addTransportType(any()) } returns request
        every { request.build() } returns mockk()
    }

    @Test
    fun `should return typed errors with the established fallback descriptor`() {
        enableCaptureObservation()
        val base =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1"))
            )
        for ((index, ipv6) in listOf(false, true).withIndex()) {
            every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } throws
                IllegalArgumentException("invalid DNS")
            val config =
                if (ipv6) base.copy(dnsServers = arrayListOf(InetAddress.getByName("::1")))
                else base
            val generation = 700L + index
            val result = service.openSecuredFrontend(generation, config)
            assertTrue(result.isOpen)
            if (ipv6) {
                val invalid =
                    assertInstanceOf(CreateTunResult.InvalidIpv6Config::class.java, result)
                assertEquals(config.addresses, invalid.addresses)
                assertEquals(7, invalid.tunFd)
            } else {
                val invalid =
                    assertInstanceOf(CreateTunResult.InvalidDnsServers::class.java, result)
                assertEquals(config.dnsServers, invalid.addresses)
                assertEquals(7, invalid.tunFd)
            }
            val applied =
                result.javaClass.getMethod("getAppliedConfig").invoke(result)
                    as net.mullvad.talpid.model.TunConfig
            assertEquals(
                listOf(InetAddress.getByName(TalpidVpnService.FALLBACK_DUMMY_DNS_SERVER)),
                applied.dnsServers,
            )
            if (ipv6) {
                assertEquals(1280, applied.mtu)
                assertEquals(
                    setOf(
                        InetAddress.getByName("172.27.1.1"),
                        InetAddress.getByName("fdf0:ce4a:801d::172:27:1:1"),
                    ),
                    applied.addresses.toSet(),
                )
                assertEquals(setOf(0), applied.routes.map { it.prefixLength.toInt() }.toSet())
            } else {
                assertEquals(config.addresses, applied.addresses)
                assertEquals(config.mtu, applied.mtu)
            }
            // Revocation must not lose a descriptor-bearing error's exact owner.
            service.onRevoke()
            assertTrue(service.isLocalFrontendActive())
            service.finishLocalFrontend(generation)
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 2) { anyConstructed<VpnService.Builder>().establish() }
        for ((index, error) in
            listOf(
                    net.mullvad.mullvadvpn.lib.model.PrepareError.NotPrepared(mockk()) to
                        CreateTunResult.NotPrepared,
                    net.mullvad.mullvadvpn.lib.model.PrepareError.OtherLegacyAlwaysOnVpn to
                        CreateTunResult.OtherLegacyAlwaysOnVpn,
                    net.mullvad.mullvadvpn.lib.model.PrepareError.OtherAlwaysOnApp("other") to
                        CreateTunResult.OtherAlwaysOnApp("other"),
                )
                .withIndex()) {
            every { service.prepareVpnSafe() } returns error.first.left()
            assertEquals(error.second, service.openSecuredFrontend(710L + index, base))
            assertFalse(service.isLocalFrontendActive())
        }
        every { service.prepareVpnSafe() } returns Prepared.right()
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        assertEquals(CreateTunResult.EstablishError, service.openSecuredFrontend(720, base))
        assertFalse(service.isLocalFrontendActive())
    }

    @Test
    fun `should apply current safe blocking configuration and report failure`() {
        enableCaptureObservation()
        val dummy = InetAddress.getByName(TalpidVpnService.FALLBACK_DUMMY_DNS_SERVER)
        val safe =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                addresses =
                    arrayListOf(
                        InetAddress.getByName("172.27.1.1"),
                        InetAddress.getByName("fdf0:ce4a:801d::172:27:1:1"),
                    ),
                routes =
                    arrayListOf(
                        net.mullvad.talpid.model.InetNetwork(InetAddress.getByName("0.0.0.0"), 0),
                        net.mullvad.talpid.model.InetNetwork(InetAddress.getByName("::"), 0),
                    ),
                dnsServers = arrayListOf(dummy),
                mtu = 1380,
                excludedPackages = arrayListOf("current.excluded"),
            )
        assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(730, safe))
        val next = safe.copy(excludedPackages = arrayListOf("new.excluded"))
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverSecuredFrontend(730, 731, next).result,
        )
        service.finishLocalFrontend(730)
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        val failed = service.handoverSecuredFrontend(731, 732, safe)
        assertEquals(CreateTunResult.EstablishError, failed.result)
        assertFalse(failed.predecessorRetained)
        service.finishLocalFrontend(731)
        service.finishLocalFrontend(732)
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().setMtu(1380) }
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().addDnsServer(dummy) }
        verify(exactly = 1) {
            anyConstructed<VpnService.Builder>().addDisallowedApplication("new.excluded")
        }
        assertFalse(service.isLocalFrontendActive())
    }

    @Test
    fun `should invalidate default network cache on managed establish and close`() {
        enableCaptureObservation()
        val listener = ConnectivityListener(mockk(), mockk())
        every { service getProperty "connectivityListener" } returns listener
        @Suppress("UNCHECKED_CAST")
        val state =
            ConnectivityListener::class
                .java
                .getDeclaredField("_mutableNetworkState")
                .apply {
                    isAccessible = true
                }
                .get(listener)
                as kotlinx.coroutines.flow.MutableStateFlow<net.mullvad.talpid.model.NetworkState?>
        fun stale() {
            state.value =
                net.mullvad.talpid.model.NetworkState(
                    123,
                    arrayListOf<net.mullvad.talpid.model.RouteInfo>(),
                    arrayListOf(InetAddress.getByName("10.0.2.53")),
                )
            assertEquals(1, listener.currentDnsServers.size)
        }
        stale()
        val config =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1"))
            )
        service.openSecuredFrontend(740, config)
        assertEquals(null, listener.currentDefaultNetworkState)
        assertTrue(listener.currentDnsServers.isEmpty())
        stale()
        service.finishLocalFrontend(740)
        assertEquals(null, listener.currentDefaultNetworkState)
        assertTrue(listener.currentDnsServers.isEmpty())
        stale()
        service.openLocalFrontend(741, arrayOf("10.0.2.2/32"))
        assertEquals(null, listener.currentDefaultNetworkState)
        stale()
        service.finishLocalFrontend(741)
        assertEquals(null, listener.currentDefaultNetworkState)
    }

    @Test
    fun `should preserve empty DNS fallback and DNS specific recovery inputs`() {
        enableCaptureObservation()
        val base = TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(dnsServers = arrayListOf())
        assertTrue(service.openSecuredFrontend(750, base).isOpen)
        verify(exactly = 1) {
            anyConstructed<VpnService.Builder>()
                .addDnsServer(TalpidVpnService.FALLBACK_DUMMY_DNS_SERVER)
        }
        val bad = InetAddress.getByName("1.1.1.1")
        every { anyConstructed<VpnService.Builder>().addDnsServer(bad) } throws
            IllegalArgumentException("DNS rejected")
        val rejected =
            service
                .handoverSecuredFrontend(750, 751, base.copy(dnsServers = arrayListOf(bad)))
                .result
        val invalid = assertInstanceOf(CreateTunResult.InvalidDnsServers::class.java, rejected)
        assertEquals(arrayListOf(bad), invalid.addresses)
        service.finishLocalFrontend(750)
        every { anyConstructed<VpnService.Builder>().addDnsServer(bad) } returns
            mockk(relaxed = true)
        assertEquals(
            CreateTunResult.Success(7),
            service
                .handoverSecuredFrontend(751, 752, base.copy(dnsServers = arrayListOf(bad)))
                .result,
        )
        service.finishLocalFrontend(751)
        service.finishLocalFrontend(752)
        service.openLocalFrontend(753, arrayOf("10.0.2.2/32"))
        verify(exactly = 2) {
            anyConstructed<VpnService.Builder>()
                .addDnsServer(TalpidVpnService.FALLBACK_DUMMY_DNS_SERVER)
        }
        service.finishLocalFrontend(753)
    }

    @Test
    fun `should pass supplied Mullvad mtu to initial and handover builders`() {
        enableCaptureObservation()
        for ((index, mtu) in listOf(576, 1280, 1380, 1420).withIndex()) {
            val first = 100L + index * 2
            val config =
                TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                    mtu = mtu,
                    dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1")),
                )
            assertEquals(CreateTunResult.Success(7), service.openSecuredFrontend(first, config))
            assertEquals(
                CreateTunResult.Success(7),
                service.handoverSecuredFrontend(first, first + 1, config).result,
            )
            verify(exactly = 2) { anyConstructed<VpnService.Builder>().setMtu(mtu) }
            service.finishLocalFrontend(first)
            service.finishLocalFrontend(first + 1)
        }
        verify(exactly = 8) { anyConstructed<VpnService.Builder>().establish() }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
    }

    @Test
    fun `should preserve Local only no DNS and exclusions across mtu handover`() {
        enableCaptureObservation()
        val routes = arrayOf("10.0.2.53/32", "fd42::/64")
        val excluded = arrayOf("com.android.deskclock", "com.android.calendar")
        val config =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                mtu = 1380,
                dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1")),
                excludedPackages = ArrayList(excluded.toList()),
            )
        assertEquals(CreateTunResult.Success(7), service.openLocalFrontend(201, routes, excluded))
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverSecuredFrontend(201, 202, config).result,
        )
        service.finishLocalFrontend(201)
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverSecuredFrontend(202, 203, config.copy(mtu = 576)).result,
        )
        service.finishLocalFrontend(202)
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(203, 204, routes, excluded).result,
        )
        service.finishLocalFrontend(203)
        service.finishLocalFrontend(204)
        verify(exactly = 2) { anyConstructed<VpnService.Builder>().setMtu(1280) }
        verify(exactly = 1) { anyConstructed<VpnService.Builder>().setMtu(1380) }
        verify(exactly = 1) { anyConstructed<VpnService.Builder>().setMtu(576) }
        for (app in excluded) {
            verify(exactly = 4) {
                anyConstructed<VpnService.Builder>().addDisallowedApplication(app)
            }
        }
        for (route in routes) {
            verify(exactly = 2) {
                anyConstructed<VpnService.Builder>()
                    .addRoute(
                        InetAddress.getByName(route.substringBefore('/')),
                        route.substringAfter('/').toInt(),
                    )
            }
        }
        verify(exactly = 2) {
            anyConstructed<VpnService.Builder>().addRoute(InetAddress.getByName("0.0.0.0"), 0)
        }
        verify(exactly = 2) {
            anyConstructed<VpnService.Builder>().addDnsServer(InetAddress.getByName("1.1.1.1"))
        }
        verify(exactly = 2) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should configure zero DNS servers on initial and replacement frontends without a watcher`() {
        val expectedRoutes = mutableListOf<Pair<InetAddress, Int>>()
        for (routes in
            listOf(
                arrayOf("10.0.2.2/32"),
                arrayOf("fd42::/64"),
                arrayOf("169.254.0.0/16", "fe80::/10"),
            )) {
            assertEquals(CreateTunResult.Success(7), service.openLocalFrontend(1, routes))
            expectedRoutes += routes.map {
                InetAddress.getByName(it.substringBefore('/')) to it.substringAfter('/').toInt()
            }
            verify(exactly = expectedRoutes.size) {
                anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any())
            }
            for ((address, prefix) in expectedRoutes.distinct()) {
                verify(exactly = expectedRoutes.count { it == (address to prefix) }) {
                    anyConstructed<VpnService.Builder>().addRoute(address, prefix)
                }
            }
            verify(exactly = 0) {
                anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), 0)
            }
            verify(exactly = 0) {
                anyConstructed<VpnService.Builder>().addRoute(any<String>(), any())
            }
            verify(exactly = 0) { anyConstructed<VpnService.Builder>().allowBypass() }
            assertTrue(service.isLocalFrontendActive())
            assertEquals(CreateTunResult.EstablishError, service.openLocalFrontend(1, routes))
            assertEquals(
                CreateTunResult.EstablishError,
                service.openTun(TalpidVpnServiceFallbackDnsTest.baseTunConfig),
            )
            service.onRevoke()
            assertEquals(4, service.prepareLocalSocket(7, 9, 1, false))
            assertTrue(service.isLocalFrontendActive())
            service.finishLocalFrontend(1)
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        verify(exactly = 3) {
            anyConstructed<VpnService.Builder>()
                .addAddress(
                    match<String> {
                        InetAddress.getByName(it) == InetAddress.getByName("172.27.1.1")
                    },
                    32,
                )
        }
        verify(exactly = 3) {
            anyConstructed<VpnService.Builder>()
                .addAddress(
                    match<String> {
                        InetAddress.getByName(it) ==
                            InetAddress.getByName("fdf0:ce4a:801d::172:27:1:1")
                    },
                    128,
                )
        }
        verify(exactly = 3) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should apply exact exclusions on initial and replacement Partial frontends`() {
        val excluded = arrayOf("com.android.deskclock", "com.android.calendar")
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32"), excluded),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32"), excluded).result,
        )
        service.finishLocalFrontend(11)
        service.finishLocalFrontend(12)
        for (app in excluded) {
            verify(exactly = 2) {
                anyConstructed<VpnService.Builder>().addDisallowedApplication(app)
            }
        }
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().addDnsServer(any<String>()) }
        verify(exactly = 0) {
            anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>())
        }
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(13, arrayOf("10.0.2.2/32")),
        )
        verify(exactly = 4) { anyConstructed<VpnService.Builder>().addDisallowedApplication(any()) }
        service.finishLocalFrontend(13)
    }

    @Test
    fun `should reject invalid routes before prepare and establish without acquiring ownership`() {
        for (routes in
            listOf(
                emptyArray(),
                arrayOf("0.0.0.0/0"),
                arrayOf("localhost/32"),
                arrayOf("10.0.2.2/24"),
            )) {
            assertEquals(CreateTunResult.EstablishError, service.openLocalFrontend(1, routes))
            assertFalse(service.isLocalFrontendActive())
        }
        verify(exactly = 0) { service.prepareVpnSafe() }
        verify(exactly = 0) { anyConstructed<VpnService.Builder>().establish() }
    }

    @Test
    fun `should release ownership after establishment failure for a later attempt`() {
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.0.0/8")),
        )
        assertFalse(service.isLocalFrontendActive())
        assertEquals(4, service.prepareLocalSocket(7, 9, 1, false))
    }

    @Test
    fun `should keep foreground after a concurrent frontend open during guarded demotion`() {
        val attempted = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val result = AtomicReference<CreateTunResult>()
        var opener: Thread? = null
        service.demote {
            opener = thread {
                attempted.countDown()
                try {
                    result.set(service.openLocalFrontend(1, arrayOf("10.0.2.2/32")))
                } finally {
                    finished.countDown()
                }
            }
            assertTrue(attempted.await(1, TimeUnit.SECONDS))
            finished.await(100, TimeUnit.MILLISECONDS)
            service.foreground = false
        }
        assertTrue(finished.await(2, TimeUnit.SECONDS))
        opener?.join(2000)
        assertEquals(CreateTunResult.Success(7), result.get())
        assertTrue(service.foreground, "concurrent frontend was demoted after its promotion")
        service.demote { error("an active frontend must not be demoted") }
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should release upstream ownership after a closed open result`() {
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        assertEquals(
            CreateTunResult.EstablishError,
            service.openTun(TalpidVpnServiceFallbackDnsTest.baseTunConfig),
        )
        val fd = mockk<ParcelFileDescriptor>()
        every { anyConstructed<VpnService.Builder>().establish() } returns fd
        every { fd.fd } returns 8
        every { fd.close() } returns Unit
        assertEquals(
            CreateTunResult.Success(8),
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should retain upstream ownership for descriptor bearing errors until close`() {
        mockkStatic(ParcelFileDescriptor::class)
        val closed = mockk<ParcelFileDescriptor>(relaxed = true)
        every { ParcelFileDescriptor.adoptFd(7) } returns closed
        val config =
            TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                dnsServers = arrayListOf(InetAddress.getByName("1.1.1.1"))
            )
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } throws
            IllegalArgumentException("invalid DNS")
        val invalidDns = service.openTun(config)
        assertTrue(invalidDns is CreateTunResult.InvalidDnsServers && invalidDns.isOpen)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.closeTun()
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } returns
            mockk(relaxed = true)
        val invalidIpv6 =
            service.openTun(config.copy(dnsServers = arrayListOf(InetAddress.getByName("::1"))))
        assertTrue(invalidIpv6 is CreateTunResult.InvalidIpv6Config && invalidIpv6.isOpen)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        service.closeTun()
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
        )
        verify(exactly = 2) { closed.close() }
        service.finishLocalFrontend(1)
    }

    private class FrontendService : TalpidVpnService() {
        @Volatile var foreground = false
        var failDemotion = false
        val changes = mutableListOf<Boolean>()

        fun demote(action: () -> Unit) = withoutLocalFrontend(action)

        override fun onLocalFrontendChanged(active: Boolean) {
            if (!active && failDemotion) error("foreground release acknowledgement")
            changes += active
            foreground = active
        }
    }

    @Test
    fun `should retain foreground through handover and ignore predecessor finish after successor opens`() {
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32")),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32")).result,
        )
        service.demote { error("handover lost foreground ownership") }
        service.finishLocalFrontend(11)
        service.finishLocalFrontend(11)
        assertTrue(service.foreground)
        assertTrue(service.changes.all { it })
        service.demote { error("late predecessor finish demoted successor") }
        service.finishLocalFrontend(12)
        assertFalse(service.foreground)
        assertEquals(listOf(true, true, false), service.changes)
        service.demote { service.foreground = false }
    }

    @Test
    fun `should retain final epoch and foreground after failed demotion until exact finish retry`() {
        assertEquals(
            CreateTunResult.Success(7),
            service.openLocalFrontend(11, arrayOf("10.0.2.2/32")),
        )
        assertEquals(
            CreateTunResult.Success(7),
            service.handoverLocalFrontend(11, 12, arrayOf("10.0.2.99/32")).result,
        )
        service.failDemotion = true
        service.finishLocalFrontend(11)
        assertTrue(runCatching { service.finishLocalFrontend(12) }.isFailure)
        assertTrue(service.isLocalFrontendActive())
        assertTrue(service.foreground)
        assertEquals(
            CreateTunResult.EstablishError,
            service.openLocalFrontend(13, arrayOf("10.0.2.99/32")),
        )
        service.failDemotion = false
        service.finishLocalFrontend(11)
        assertTrue(service.foreground)
        service.finishLocalFrontend(12)
        assertFalse(service.foreground)
        assertFalse(service.isLocalFrontendActive())
        assertEquals(listOf(true, true, false), service.changes)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `should prepare through the actual service gate with both framework calls under its lock`() =
        runTest {
            val network = mockk<Network>()
            val fixture =
                WatcherFixture(backgroundScope, StandardTestDispatcher(testScheduler), network)
            TalpidVpnService::class.java.getDeclaredField("localNetworkWatcher").apply {
                isAccessible = true
                set(service, fixture.watcher)
                // spyk copies fields; the demand callback was constructed on
                // the original instance, so both must own this same fixture.
                set(serviceInstance, fixture.watcher)
            }
            assertTrue(service.attachLocalNetwork(1L))
            runCurrent()
            assertEquals(0, fixture.starts)
            assertFalse(service.setLocalNetworkPolicyDemand(2L, 1L, true))
            assertEquals(0, fixture.starts)
            assertTrue(service.setLocalNetworkPolicyDemand(1L, 2L, true))
            runCurrent()
            assertEquals(1, fixture.starts)
            assertTrue(service.setLocalNetworkPolicyDemand(1L, 1L, false))
            service.setLocalNetworkEditorDemand(true)
            assertTrue(service.setLocalNetworkPolicyDemand(1L, 3L, false))
            assertEquals(1, fixture.starts)
            service.setLocalNetworkEditorDemand(false)
            assertTrue(service.setLocalNetworkPolicyDemand(1L, 4L, true))
            runCurrent()
            assertEquals(2, fixture.starts)
            fixture.event("Available", 9L, false)
            runCurrent()
            assertEquals(
                CreateTunResult.Success(7),
                service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
            )
            every { service.protect(7) } returns true
            assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence - 1, false))
            fixture.event("Available", 10L, false)
            assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence, false))
            verify(exactly = 0) { service.protect(any<Int>()) }
            verify(exactly = 0) { network.bindSocket(any<FileDescriptor>()) }
            runCurrent()

            val attempted = CountDownLatch(1)
            val completed = CountDownLatch(1)
            var update: Thread? = null
            mockkStatic(ParcelFileDescriptor::class)
            val duplicate = mockk<ParcelFileDescriptor>()
            val descriptor = FileDescriptor()
            every { ParcelFileDescriptor.fromFd(7) } returns duplicate
            every { duplicate.fileDescriptor } returns descriptor
            every { duplicate.close() } returns Unit
            every { service.protect(7) } answers
                {
                    assertTrue(Thread.holdsLock(fixture.lock), "protect escaped the watcher gate")
                    update = thread {
                        attempted.countDown()
                        fixture.event("Lost", 9L)
                        completed.countDown()
                    }
                    assertTrue(attempted.await(1, TimeUnit.SECONDS))
                    assertFalse(completed.await(100, TimeUnit.MILLISECONDS))
                    true
                }
            every { network.bindSocket(descriptor) } answers
                {
                    assertTrue(Thread.holdsLock(fixture.lock), "bind escaped the watcher gate")
                    assertEquals(1L, completed.count)
                }
            val beforeLoss = fixture.witnesses.last().authorityRevision
            try {
                assertEquals(0, service.prepareLocalSocket(7, 9, fixture.sequence, false))
                assertTrue(completed.await(1, TimeUnit.SECONDS))
                update?.join(1000)
                assertTrue(fixture.witnesses.last().authorityRevision > beforeLoss)
                assertTrue(fixture.witnesses.last().networks.none { it.networkHandle == 9L })
                assertEquals(1, service.prepareLocalSocket(7, 9, fixture.sequence, false))
                verify(exactly = 1) { service.protect(7) }
                verify(exactly = 1) { network.bindSocket(descriptor) }
                verifyOrder {
                    service.protect(7)
                    ParcelFileDescriptor.fromFd(7)
                    network.bindSocket(descriptor)
                    duplicate.close()
                }
            } finally {
                assertTrue(service.detachLocalNetwork(1L))
                fixture.invoke("stop")
                service.finishLocalFrontend(1)
                update?.join(1000)
            }
        }

    /** Reflection is confined to this test: the app must not expose a watcher injection API. */
    private class WatcherFixture(
        scope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
        network: Network,
    ) {
        private val sourceType = Class.forName("net.mullvad.talpid.LocalNetworkSource")
        private val watcherType = Class.forName("net.mullvad.talpid.LocalNetworkWatcher")
        private val publicationType = Class.forName("net.mullvad.talpid.LocalNetworkPublication")
        private var callback: (Any) -> Unit = {}
        var sequence = 0L
        var starts = 0
        val witnesses = mutableListOf<LocalNetworkSnapshot>()
        private val access =
            Class.forName("net.mullvad.talpid.LocalIdentityAccess")
                .getDeclaredConstructor(*Array(5) { Boolean::class.javaPrimitiveType })
                .newInstance(true, true, true, true, true)
        @Suppress("UNCHECKED_CAST")
        private val source =
            Proxy.newProxyInstance(sourceType.classLoader, arrayOf(sourceType)) { _, method, args ->
                when (method.name) {
                    "readAccess" -> access
                    "network" -> network
                    "withLegacyIdentity" -> args[0]
                    "start" -> {
                        starts++
                        callback = args[1] as (Any) -> Unit
                        Unit
                    }
                    "currentNetworks" -> emptySet<Long>()
                    "stop" -> Unit
                    else -> error("Unexpected source call ${method.name}")
                }
            }
        private val publish =
            Proxy.newProxyInstance(publicationType.classLoader, arrayOf(publicationType)) {
                _,
                method,
                args ->
                val record = args[1] as LocalNetworkSnapshot
                when (method.name) {
                    "published" -> {
                        assertFalse(Thread.holdsLock(lock), "status escaped its async boundary")
                        sequence = record.sequence
                    }
                    "revalidate" -> {
                        assertTrue(Thread.holdsLock(lock), "revocation escaped the watcher gate")
                        witnesses += record
                    }
                    else -> error("Unexpected publication call ${method.name}")
                }
                Unit
            }
        val watcher: Any =
            watcherType
                .getDeclaredConstructor(
                    sourceType,
                    CoroutineScope::class.java,
                    CoroutineDispatcher::class.java,
                    publicationType,
                )
                .newInstance(source, scope, dispatcher, publish)
        val lock: Any =
            checkNotNull(
                watcherType.getDeclaredField("lock").apply { isAccessible = true }.get(watcher)
            )

        fun invoke(name: String, vararg args: Any) {
            watcherType.declaredMethods.single { it.name == name }.invoke(watcher, *args)
        }

        fun event(name: String, vararg args: Any) {
            val type = Class.forName("net.mullvad.talpid.LocalNetworkEvent\$$name")
            callback(
                type.declaredConstructors
                    .single { it.parameterCount == args.size }
                    .newInstance(*args)
            )
        }
    }
}
