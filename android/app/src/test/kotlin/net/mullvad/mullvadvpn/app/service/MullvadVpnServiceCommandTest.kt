package net.mullvad.mullvadvpn.app.service

import android.app.KeyguardManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Looper
import android.os.ParcelFileDescriptor
import arrow.core.right
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.app.service.notifications.ForegroundNotificationManager
import net.mullvad.mullvadvpn.lib.common.constant.connectAction
import net.mullvad.mullvadvpn.lib.common.constant.disconnectAction
import net.mullvad.mullvadvpn.lib.common.constant.reconnectAction
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.DisconnectReason
import net.mullvad.mullvadvpn.lib.model.ErrorState
import net.mullvad.mullvadvpn.lib.model.ErrorStateCause
import net.mullvad.mullvadvpn.lib.model.Prepared
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.talpid.TalpidVpnService
import net.mullvad.talpid.TalpidVpnServiceFallbackDnsTest
import net.mullvad.talpid.model.CreateTunResult
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

class MullvadVpnServiceCommandTest {
    @AfterEach fun cleanup() = unmockkAll()

    @Test
    fun `should dispatch system connect with any capture lifetime`() {
        for (lifetime in listOf("none", "Partial", "full", "failed", "retained")) {
            for (locked in listOf(false, true)) {
                for ((action, expected) in
                    listOf(
                        VpnService.SERVICE_INTERFACE to "connect",
                        connectAction(PACKAGE) to "connect",
                        reconnectAction(PACKAGE) to "reconnect",
                        disconnectAction(PACKAGE) to "disconnect",
                        connectAction("net.mullvad.mullvadvpn") to null,
                        null to null,
                    )) {
                    val (service, descriptor) = captureService()
                    if (lifetime != "none") {
                        if (lifetime == "full") {
                            TalpidVpnService::class
                                .java
                                .getDeclaredField("captureRegistration")
                                .apply {
                                    isAccessible = true
                                    setLong(service, 1L)
                                }
                            val connectivity = mockk<ConnectivityManager>(relaxed = true)
                            every {
                                service.getSystemService(ConnectivityManager::class.java)
                            } returns connectivity
                            every {
                                service.getSystemService(
                                    android.content.Context.CONNECTIVITY_SERVICE
                                )
                            } returns connectivity
                            mockkConstructor(NetworkRequest.Builder::class)
                            val builder = mockk<NetworkRequest.Builder>(relaxed = true)
                            every {
                                anyConstructed<NetworkRequest.Builder>().removeCapability(any())
                            } returns builder
                            every { builder.addTransportType(any()) } returns builder
                        }
                        val result =
                            if (lifetime == "full") {
                                service.openSecuredFrontend(
                                    1,
                                    TalpidVpnServiceFallbackDnsTest.baseTunConfig.copy(
                                        dnsServers =
                                            arrayListOf(java.net.InetAddress.getByName("1.1.1.1"))
                                    ),
                                )
                            } else service.openLocalFrontend(1, arrayOf("10.0.2.2/32"))
                        assertEquals(CreateTunResult.Success(7), result)
                        if (lifetime == "failed" || lifetime == "retained") {
                            service.onRevoke()
                            every { descriptor.close() } throws
                                IllegalStateException("retained cleanup")
                            assertFailsWith<IllegalStateException> {
                                service.finishLocalFrontend(1)
                            }
                        }
                        assertTrue(service.isLocalFrontendActive())
                    }
                    val events = mutableListOf<String>()
                    dispatch(service, action, locked, events)
                    assertEquals(
                        if (locked || expected == null) emptyList()
                        else
                            listOfNotNull(
                                "foreground",
                                expected,
                                "demote".takeIf { expected == "disconnect" },
                            ),
                        events,
                        "$lifetime locked=$locked action=$action",
                    )
                    every { descriptor.close() } returns Unit
                    service.finishLocalFrontend(1)
                }
            }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `should retain foreground only while owned capture requires it`() = runTest {
        for (reason in listOf("unbind", "nonblocking Error", "disconnect", "revoke")) {
            for (owned in listOf(false, true)) {
                val (service, descriptor) =
                    captureService(spy = false) { LifecycleService(backgroundScope) }
                val states = MutableSharedFlow<TunnelState>()
                service.observe(states)
                runCurrent()
                val system = mockk<Intent> { every { action } returns VpnService.SERVICE_INTERFACE }
                if (reason == "unbind" || reason == "revoke") service.onBind(system)
                if (owned) {
                    assertEquals(
                        CreateTunResult.Success(7),
                        service.openLocalFrontend(1, arrayOf("10.0.2.2/32")),
                    )
                } else {
                    service.onStartCommand(system, 0, 1)
                    runCurrent()
                }
                assertTrue(service.foreground)
                service.effects.clear()
                when (reason) {
                    "unbind" -> {
                        val app = mockk<Intent> { every { action } returns null }
                        service.onBind(app)
                        service.onUnbind(app)
                        assertTrue(service.foreground, "Only system unbind requests demotion")
                        service.onUnbind(system)
                    }
                    "nonblocking Error" -> {
                        states.emit(TunnelState.Error(ErrorState(ErrorStateCause.IsOffline, true)))
                        runCurrent()
                        assertTrue(service.foreground, "Blocking Error retains upstream foreground")
                        states.emit(TunnelState.Error(ErrorState(ErrorStateCause.IsOffline, false)))
                        runCurrent()
                    }
                    "disconnect" -> {
                        val intent =
                            mockk<Intent> { every { action } returns disconnectAction(PACKAGE) }
                        val app = mockk<Intent> { every { action } returns null }
                        service.onBind(app)
                        service.onStartCommand(intent, 0, 2)
                        runCurrent()
                        assertTrue(
                            service.foreground,
                            "A bound client retains foreground without a capture",
                        )
                        assertEquals(0, service.effects.count { it == "demote" })
                        service.onUnbind(app)
                        service.effects.clear()
                        service.onStartCommand(intent, 0, 2)
                        runCurrent()
                        assertTrue(
                            "disconnect:${DisconnectReason.USER_INITIATED_NOTIFICATION_TILE}" in
                                service.effects
                        )
                    }
                    "revoke" -> {
                        service.onRevoke()
                        assertTrue(
                            "disconnect:${DisconnectReason.SYSTEM_REVOKE}" in service.effects
                        )
                        assertTrue(
                            service.foreground,
                            "Revoke itself delegates disconnect, not demotion",
                        )
                        service.onUnbind(system)
                    }
                }
                assertEquals(owned, service.foreground, "$reason owned=$owned")
                assertEquals(if (owned) 0 else 1, service.effects.count { it == "demote" }, reason)
                service.onRevoke()
                assertEquals(4, service.prepareLocalSocket(7, 9, 1, false))
                service.finishLocalFrontend(999)
                assertEquals(owned, service.isLocalFrontendActive(), "wrong generation")
                if (owned) {
                    every { descriptor.close() } throws IllegalStateException("held cleanup")
                    assertFailsWith<IllegalStateException> { service.finishLocalFrontend(1) }
                    assertTrue(service.foreground, "Failed cleanup retains foreground: $reason")
                    every { descriptor.close() } returns Unit
                    service.finishLocalFrontend(1)
                    assertFalse(service.foreground, "Exact final release demotes: $reason")
                    assertFalse(service.isLocalFrontendActive())
                    assertEquals(1, service.effects.count { it == "demote" }, reason)
                }
            }
        }
    }

    private fun captureService(): Pair<CaptureService, ParcelFileDescriptor> = captureService {
        CaptureService()
    }

    private inline fun <reified T : TalpidVpnService> captureService(
        spy: Boolean = true,
        create: () -> T,
    ): Pair<T, ParcelFileDescriptor> {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk()
        mockkStatic("net.mullvad.mullvadvpn.lib.common.util.VpnServiceUtilsKt")
        mockkConstructor(VpnService.Builder::class)
        every { anyConstructed<VpnService.Builder>().addAddress(any<String>(), any()) } returns
            mockk(relaxed = true)
        every {
            anyConstructed<VpnService.Builder>().addAddress(any<java.net.InetAddress>(), any())
        } returns mockk(relaxed = true)
        every {
            anyConstructed<VpnService.Builder>().addDnsServer(any<java.net.InetAddress>())
        } returns mockk(relaxed = true)
        every {
            anyConstructed<VpnService.Builder>().addRoute(any<java.net.InetAddress>(), any())
        } returns mockk(relaxed = true)
        every { anyConstructed<VpnService.Builder>().setMtu(any()) } returns mockk(relaxed = true)
        every { anyConstructed<VpnService.Builder>().setBlocking(any()) } returns
            mockk(relaxed = true)
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        every { descriptor.fd } returns 7
        every { anyConstructed<VpnService.Builder>().establish() } returns descriptor
        val service = if (spy) spyk(create()) else create()
        every { service.prepareVpnSafe() } returns Prepared.right()
        if (spy) every { service.packageName } returns PACKAGE
        return service to descriptor
    }

    private fun dispatch(
        service: CaptureService,
        action: String?,
        locked: Boolean,
        events: MutableList<String>,
    ) =
        service.dispatchVpnServiceCommand(
            action,
            PACKAGE,
            locked,
            VpnServiceCommandActions(
                { events += "foreground" },
                { events += "connect" },
                { events += "reconnect" },
                { events += "disconnect" },
                { events += "demote" },
            ),
        )

    private class CaptureService : TalpidVpnService()

    private class LifecycleService(override val commandScope: CoroutineScope) :
        MullvadVpnServiceLifecycle() {
        override fun getPackageName() = PACKAGE

        override fun platformStartCommand(call: () -> Int) = START_NOT_STICKY

        override fun platformBind(call: () -> android.os.IBinder?): android.os.IBinder = mockk()

        override val keyguardManager =
            mockk<KeyguardManager> { every { isKeyguardLocked } returns false }
        override val connectionProxy = mockk<ConnectionProxy>()
        override val foregroundNotificationHandler = mockk<ForegroundNotificationManager>()
        val effects = mutableListOf<String>()
        var foreground = false

        init {
            every { foregroundNotificationHandler.startForeground() } answers
                {
                    foreground = true
                    effects += "foreground"
                }
            every { foregroundNotificationHandler.stopForeground() } answers
                {
                    foreground = false
                    effects += "demote"
                }
            coEvery { connectionProxy.connectWithoutPermissionCheck() } returns true.right()
            coEvery { connectionProxy.disconnect(any()) } answers
                {
                    val reason = firstArg<DisconnectReason>()
                    if (reason == DisconnectReason.SYSTEM_REVOKE)
                        assertEquals(
                            4,
                            prepareLocalSocket(7, 9, 1, false),
                            "Base revoke precedes disconnect",
                        )
                    effects += "disconnect:$reason"
                    true.right()
                }
        }

        fun observe(states: MutableSharedFlow<TunnelState>) = observeNonblockingErrors(states)
    }

    companion object {
        private const val PACKAGE = "net.mullvad.krtek"
    }
}
