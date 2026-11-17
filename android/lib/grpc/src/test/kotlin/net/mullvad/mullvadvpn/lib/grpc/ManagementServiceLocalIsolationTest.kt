package net.mullvad.mullvadvpn.lib.grpc

import arrow.core.Either
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import java.io.File
import java.io.IOException
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import mullvad_daemon.management_interface.ApiAccessMethodSettings
import mullvad_daemon.management_interface.ConnectedWifi
import mullvad_daemon.management_interface.CustomDnsOptions
import mullvad_daemon.management_interface.DaemonEvent
import mullvad_daemon.management_interface.DaitaSettings
import mullvad_daemon.management_interface.DefaultDnsOptions
import mullvad_daemon.management_interface.DnsOptions
import mullvad_daemon.management_interface.LocalBypassRule
import mullvad_daemon.management_interface.LocalNetworkAccess
import mullvad_daemon.management_interface.LocalNetworkStatus
import mullvad_daemon.management_interface.ManagementServiceClient
import mullvad_daemon.management_interface.NormalRelaySettings
import mullvad_daemon.management_interface.ObfuscationSettings
import mullvad_daemon.management_interface.QuantumResistantState
import mullvad_daemon.management_interface.RelaySettings
import mullvad_daemon.management_interface.Settings
import mullvad_daemon.management_interface.SplitTunnelSettings
import mullvad_daemon.management_interface.TunnelOptions
import mullvad_daemon.management_interface.TunnelState
import mullvad_daemon.management_interface.WireguardConstraints
import net.mullvad.mullvadvpn.lib.grpc.mapper.toDomain
import net.mullvad.mullvadvpn.lib.model.ApiAccessMethodSetting
import net.mullvad.mullvadvpn.lib.model.AppVersionInfo
import net.mullvad.mullvadvpn.lib.model.DeviceState
import net.mullvad.mullvadvpn.lib.model.RelayList
import net.mullvad.mullvadvpn.lib.model.Settings as ModelSettings
import net.mullvad.mullvadvpn.lib.model.TunnelState as ModelTunnelState
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ManagementServiceLocalIsolationTest {
    private fun status(revision: Long) =
        LocalNetworkStatus(
            revision = revision,
            current_wifi =
                ConnectedWifi(
                    identity = ConnectedWifi.Identity.Unknown(ConnectedWifi.UnknownReason.PENDING)
                ),
        )

    private fun TestScope.service(
        rpc: ManagementServiceClient,
        events: Channel<DaemonEvent>,
    ): ManagementService {
        val service =
            spyk(
                ManagementService(
                    File("unused-isolation.sock"),
                    false,
                    backgroundScope,
                    StandardTestDispatcher(testScheduler),
                ),
                recordPrivateCalls = true,
            )
        every { service getProperty "grpc" } returns rpc
        coEvery { rpc.EventsListen().executeIn(any(), Unit) } returns events
        coEvery { service["getTunnelState"]() } returns ModelTunnelState.Disconnected(null)
        coEvery { service["getDeviceState"]() } returns mockk<DeviceState>()
        coEvery { service["getSettings"]() } returns mockk<ModelSettings>()
        coEvery { service["getVersionInfo"]() } returns Either.Right(mockk<AppVersionInfo>())
        coEvery { service["getRelayList"]() } returns mockk<RelayList>()
        coEvery { service["getCurrentApiAccessMethod"]() } returns mockk<ApiAccessMethodSetting>()
        return service
    }

    @Test
    fun `should keep ordinary startup alive when Local status fails`() = runTest {
        for (failure in
            listOf(IOException("auxiliary"), IllegalArgumentException("conversion"), null)) {
            val rpc = mockk<ManagementServiceClient>(relaxed = true)
            val events = Channel<DaemonEvent>(Channel.UNLIMITED)
            if (failure != null)
                coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } throws failure
            else
                coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns
                    status(2).copy(current_wifi = null)
            val service = service(rpc, events)
            val states = mutableListOf<ModelTunnelState>()
            val settings = mutableListOf<ModelSettings>()
            val account = mutableListOf<DeviceState>()
            val relays = mutableListOf<RelayList>()
            backgroundScope.launch { service.tunnelState.collect { states += it } }
            backgroundScope.launch { service.settings.collect { settings += it } }
            backgroundScope.launch { service.deviceState.collect { account += it } }
            backgroundScope.launch { service.relayList.collect { relays += it } }
            service.start()
            runCurrent()
            assertEquals(1, settings.size)
            assertEquals(1, account.size)
            assertEquals(1, relays.size)
            assertEquals(
                net.mullvad.mullvadvpn.lib.model.ForwardingAvailability.NotAvailable,
                service.localNetworkStatus.value?.forwarding,
            )
            events.send(
                DaemonEvent(
                    event =
                        DaemonEvent.Event.TunnelState(
                            TunnelState(
                                state = TunnelState.State.Connecting(TunnelState.Connecting())
                            )
                        )
                )
            )
            runCurrent()
            assertIs<ModelTunnelState.Connecting>(states.last())
            events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(status(4))))
            runCurrent()
            assertEquals(4uL, service.localNetworkStatus.value?.revision)
            coVerify(exactly = 1) { rpc.EventsListen().executeIn(any(), Unit) }
            service.stop()
            runCurrent()
        }
        val rpc = mockk<ManagementServiceClient>(relaxed = true)
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } throws CancellationException("stop")
        val service = service(rpc, Channel(Channel.UNLIMITED))
        service.start()
        runCurrent()
        val job =
            ManagementService::class
                .java
                .getDeclaredField("job")
                .apply { isAccessible = true }
                .get(service) as Job
        assertTrue(job.isCancelled)
        service.stop()
    }

    @Test
    fun `should recover malformed Local events without losing revision ordering`() = runTest {
        val rpc = mockk<ManagementServiceClient>(relaxed = true)
        val events = Channel<DaemonEvent>(Channel.UNLIMITED)
        val initial = CompletableDeferred<LocalNetworkStatus>()
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } coAnswers { initial.await() }
        val service = service(rpc, events)
        service.start()
        runCurrent()
        for (sample in listOf(status(10), status(11).copy(current_wifi = null))) {
            events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(sample)))
            runCurrent()
        }
        assertEquals(11uL, service.localNetworkStatus.value?.revision)
        assertEquals(false, service.localNetworkStatus.value?.observerAvailable)
        initial.complete(status(9))
        runCurrent()
        assertEquals(11uL, service.localNetworkStatus.value?.revision)
        assertEquals(
            net.mullvad.mullvadvpn.lib.model.ForwardingAvailability.NotAvailable,
            service.localNetworkStatus.value?.forwarding,
        )
        val ids =
            listOf("00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000001")
        val valid =
            status(12)
                .copy(
                    observer_available = true,
                    forwarding = LocalNetworkStatus.ForwardingAvailability.ACTIVE,
                    rules =
                        ids.map {
                            mullvad_daemon.management_interface.LocalRuleStatus(
                                id = it,
                                state =
                                    mullvad_daemon.management_interface.LocalRuleStatus.State
                                        .FORWARDING,
                            )
                        },
                )
        events.send(DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(valid)))
        runCurrent()
        assertEquals(12uL, service.localNetworkStatus.value?.revision)
        assertEquals(ids, service.localNetworkStatus.value?.rules?.map { it.id.toString() })
        service.stop()
        runCurrent()
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns status(1)
        service.start()
        runCurrent()
        assertEquals(1uL, service.localNetworkStatus.value?.revision)
        coVerify(exactly = 2) { rpc.EventsListen().executeIn(any(), Unit) }
        service.stop()
        runCurrent()
        // A cancelled request may already be completing outside a cancellable
        // suspension. Its old daemon lifetime must not win the new reset.
        var oldReply: Continuation<LocalNetworkStatus>? = null
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } coAnswers
            {
                suspendCoroutine { oldReply = it }
            }
        service.start()
        runCurrent()
        service.stop()
        runCurrent()
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns status(2)
        service.start()
        runCurrent()
        checkNotNull(oldReply).resume(status(99))
        runCurrent()
        assertEquals(2uL, service.localNetworkStatus.value?.revision)
        coVerify(exactly = 4) { rpc.EventsListen().executeIn(any(), Unit) }
        service.stop()
    }

    @Test
    fun `should expose unrelated settings when Local policy is unreadable`() = runTest {
        val rpc = mockk<ManagementServiceClient>(relaxed = true)
        val setter = rpc.SetLocalNetworkAccess()
        coEvery { rpc.GetLocalNetworkStatus().execute(Unit) } returns status(1)
        val events = Channel<DaemonEvent>(Channel.UNLIMITED)
        val service = service(rpc, events)
        val reads = mutableListOf<ModelSettings>()
        coEvery { service["getSettings"]() } returns wireSettings(LocalNetworkAccess()).toDomain()
        backgroundScope.launch { service.settings.collect { reads += it } }
        service.start()
        runCurrent()
        val rule = LocalBypassRule(id = "00000000-0000-0000-0000-000000000001", enabled = true)
        for (policy in
            listOf(
                LocalNetworkAccess(enabled = false, rules = listOf(rule)),
                LocalNetworkAccess(rules = listOf(rule.copy(name = "x".repeat(65)))),
                LocalNetworkAccess(rules = listOf(rule, rule)),
                LocalNetworkAccess(rules = listOf(rule.copy(id = "not-a-uuid"))),
            )) {
            val wire = wireSettings(policy)
            events.send(DaemonEvent(event = DaemonEvent.Event.Settings(wire)))
            runCurrent()
            val read = reads.last()
            assertTrue(read.allowLan)
            assertEquals(1400, read.tunnelOptions.mtu?.value)
            if (policy.rules.first().id == "not-a-uuid") assertNull(read.localNetworkAccess)
            else {
                val typed = checkNotNull(read.localNetworkAccess)
                assertEquals(policy.enabled, typed.enabled)
                assertEquals(policy.rules.map { it.name }, typed.rules.map { it.name })
                assertTrue(typed.validationError() != null)
            }
            if (policy.rules.first().id == "not-a-uuid") {
                assertTrue(
                    service
                        .setLocalNetworkAccess(
                            net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess()
                        )
                        .isLeft()
                )
            } else {
                val expected = checkNotNull(read.localNetworkAccess)
                assertTrue(
                    service
                        .setLocalNetworkAccess(
                            net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess(),
                            expected,
                        )
                        .isRight()
                )
                coVerify(exactly = 1) {
                    setter.execute(
                        match { it.expected == policy && it.policy == LocalNetworkAccess() }
                    )
                }
            }
        }
        coVerify(exactly = 3) { setter.execute(any()) }
        val raw =
            ManagementService::class
                .java
                .getDeclaredField("unreadableLocalPolicy")
                .apply { isAccessible = true }
                .get(service) as LocalNetworkAccess
        assertEquals("not-a-uuid", raw.rules.single().id)
        val valid =
            LocalNetworkAccess(
                enabled = true,
                rules = listOf(rule.copy(cidrs = listOf("192.168.240.0/28"))),
            )
        events.send(DaemonEvent(event = DaemonEvent.Event.Settings(wireSettings(valid))))
        runCurrent()
        assertNull(reads.last().localNetworkAccess?.validationError())
        events.send(
            DaemonEvent(
                event = DaemonEvent.Event.Settings(wireSettings(valid.copy(enabled = false)))
            )
        )
        runCurrent()
        assertEquals(false, reads.last().localNetworkAccess?.enabled)
        assertNull(
            ManagementService::class
                .java
                .getDeclaredField("unreadableLocalPolicy")
                .apply { isAccessible = true }
                .get(service)
        )
        service.stop()
    }

    private fun wireSettings(policy: LocalNetworkAccess) =
        Settings(
            allow_lan = true,
            local_network_access = policy,
            relay_settings =
                RelaySettings(
                    endpoint =
                        RelaySettings.Endpoint.Normal(
                            NormalRelaySettings(wireguard_constraints = WireguardConstraints())
                        )
                ),
            obfuscation_settings =
                ObfuscationSettings(
                    udp2tcp = ObfuscationSettings.Udp2TcpObfuscation(),
                    shadowsocks = ObfuscationSettings.Shadowsocks(),
                    wireguard_port = ObfuscationSettings.WireguardPort(),
                    lwo = ObfuscationSettings.Lwo(),
                ),
            tunnel_options =
                TunnelOptions(
                    mtu = 1400,
                    quantum_resistant = QuantumResistantState(),
                    daita = DaitaSettings(),
                    dns_options =
                        DnsOptions(
                            default_options = DefaultDnsOptions(),
                            custom_options = CustomDnsOptions(),
                        ),
                ),
            split_tunnel = SplitTunnelSettings(),
            api_access_methods = ApiAccessMethodSettings(),
        )
}
