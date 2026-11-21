package net.mullvad.mullvadvpn.talpid

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.InetAddresses
import android.net.IpPrefix
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import arrow.core.Either
import co.touchlab.kermit.LogWriter
import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import com.squareup.wire.GrpcClient
import java.io.File
import java.io.RandomAccessFile
import java.net.InetAddress
import java.net.Proxy
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import mullvad_daemon.management_interface.ManagementServiceClient
import mullvad_daemon.management_interface.TunnelState as RpcTunnelState
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.lib.common.constant.GRPC_SOCKET_FILE_NAMED_ARGUMENT
import net.mullvad.mullvadvpn.lib.grpc.ManagementService
import net.mullvad.mullvadvpn.lib.grpc.util.UnixDomainSocketFactory
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.CustomListName
import net.mullvad.mullvadvpn.lib.model.DisconnectReason
import net.mullvad.mullvadvpn.lib.model.DnsState
import net.mullvad.mullvadvpn.lib.model.ErrorStateCause
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.Mtu
import net.mullvad.mullvadvpn.lib.model.MultihopMode
import net.mullvad.mullvadvpn.lib.model.PackageName
import net.mullvad.mullvadvpn.lib.model.ParameterGenerationError
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import net.mullvad.mullvadvpn.lib.repository.SplitTunnelingRepository
import okhttp3.OkHttpClient
import okhttp3.Protocol
import org.json.JSONObject
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin
import org.koin.core.qualifier.named

internal val R06_SEQUENCE_TEST_TIMEOUT: Duration = 4.minutes

/** Restart-safe observations and ordinary-app probes; consumerProbe never writes policy. */
class LocalNetworkDeliveryInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val testPackage = instrumentation.context.packageName
    private val args = InstrumentationRegistry.getArguments()
    private val receiveBoundary by lazy { R06ReceiveBoundaryTest.Observer(instrumentation, args) }
    internal val r06Custody by lazy {
        if (args.getString("krtek_r06_custody", "false") == "true")
            R06FirstFailureCustody.Custody(instrumentation, args)
        else null
    }
    private val peer
        get() = args.getString("krtek_peer", "10.0.2.2")

    private var probeIndex = 0
    private val continuityIntents = mutableListOf<LocalContinuityWindows.Intent>()

    private fun continuityIntent(kind: String) {
        val time = SystemClock.elapsedRealtimeNanos()
        continuityIntents += LocalContinuityWindows.Intent(kind, time)
        report("continuity_intent", JSONObject().put("kind", kind).put("time_ns", time))
    }

    internal fun report(key: String, value: Any) {
        instrumentation.sendStatus(0, Bundle().apply { putString("krtek_$key", value.toString()) })
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand("toybox timeout 5 $command").use {
            descriptor ->
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                LocalContinuityWindows.readBounded(it.reader(Charsets.UTF_8)).trim()
            }
        }

    private fun grant(packageName: String, permission: String = LOCAL_PERMISSION): Boolean =
        target.packageManager.checkPermission(permission, packageName) ==
            PackageManager.PERMISSION_GRANTED

    private fun permissionState(packageName: String, permission: String): Pair<Boolean, String> {
        val line =
            shell("dumpsys package $packageName")
                .lineSequence()
                .map { it.trim() }
                .single {
                    it.startsWith("$permission: granted=")
                }
        return grant(packageName, permission) to
            (delimitedField(line, "flags=[", ']')?.trim() ?: "")
    }

    internal fun withConsumer(
        expectation: ForwardingAvailability?,
        testTimeout: Duration = 1.minutes,
        after: (LocalNetworkEditorInstrumentedTest) -> Unit = {},
        block: (Consumer, SettingsRepository, ConnectionProxy) -> Unit,
    ) {
        withR06Failures {
            LocalNetworkEditorInstrumentedTest().withLocalAccessScreen(testTimeout = testTimeout) {
                editor ->
                val koin = (target.applicationContext as MullvadApplication).getKoin()
                val repository = koin.get<SettingsRepository>()
                val connection = koin.get<ConnectionProxy>()
                runBlocking {
                    withTimeout(30_000) { repository.settingsUpdates.filterNotNull().first() }
                    val expectedTunnel = args.getString("krtek_expect_tunnel", "Disconnected")
                    check(expectedTunnel in setOf("Disconnected", "Connected"))
                    val initial = withTimeout(30_000) { connection.tunnelState.first() }
                    report("initial_tunnel", initial.javaClass.simpleName)
                    val autoConnected =
                        expectedTunnel == "Disconnected" &&
                            (initial is TunnelState.Connecting || initial is TunnelState.Connected)
                    report("auto_connected", autoConnected)
                    if (autoConnected)
                        assertTrue(
                            connection
                                .disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON)
                                .isRight()
                        )
                    val tunnel =
                        withTimeout(if (expectedTunnel == "Connected") 60_000 else 30_000) {
                            connection.tunnelState.first {
                                if (expectedTunnel == "Connected") it is TunnelState.Connected
                                else it is TunnelState.Disconnected
                            }
                        }
                    report("tunnel", tunnel.javaClass.simpleName)
                }
                val lockdown = args.getString("krtek_expect_lockdown", "1")
                check(lockdown in setOf("0", "1"))
                val alwaysOn = shell("settings get secure always_on_vpn_app")
                val observedLockdown = shell("settings get secure always_on_vpn_lockdown")
                report("always_on", alwaysOn)
                report("lockdown", observedLockdown)
                assertEquals(target.packageName, alwaysOn)
                assertEquals(lockdown, observedLockdown)
                val required =
                    listOf(target.packageName to LOCAL_PERMISSION) +
                        LocalNetworkConsumerService.requiredPermissions().map { testPackage to it }
                val before = required.associateWith { (name, permission) ->
                    permissionState(name, permission)
                }
                before.forEach { (key, value) ->
                    val (name, permission) = key
                    report("permission_before_${name}_$permission", value)
                    if (permission == LOCAL_PERMISSION) report("grant_before_$name", value.first)
                }
                assertTrue(before.values.all { it.first }, "Guest runner must stage permissions")
                try {
                    before.keys.forEach { (name, permission) ->
                        assertTrue(grant(name, permission))
                        report("permission_granted_${name}_$permission", true)
                        if (permission == LOCAL_PERMISSION) report("grant_$name", true)
                    }
                    Consumer().use { consumer ->
                        consumer.identity()
                        val configured =
                            checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
                        val forwarding =
                            expectation
                                ?: if (
                                    configured.enabled &&
                                        configured.rules.any { it.enabled && it.cidrs.isNotEmpty() }
                                )
                                    ForwardingAvailability.Active
                                else ForwardingAvailability.Off
                        // Answer r02: observe the daemon's consequence, not a fabricated target
                        // read.
                        awaitState(repository, connection, forwarding, null)
                        block(consumer, repository, connection)
                    }
                    after(editor)
                } catch (error: Throwable) {
                    r06Custody?.recordFailure("consumer-body", error)
                    throw error
                } finally {
                    r06Checked("permission-restoration") {
                        before.forEach { (key, _) ->
                            val (name, permission) = key
                            report(
                                "permission_after_${name}_$permission",
                                permissionState(name, permission),
                            )
                            if (permission == LOCAL_PERMISSION)
                                report("grant_after_$name", grant(name))
                        }
                        assertEquals(
                            before,
                            before.keys.associateWith { (name, permission) ->
                                permissionState(name, permission)
                            },
                            "Restore every staged grant and preserve its permission flags",
                        )
                    }
                }
            }
        }
    }

    private fun withR06Failures(body: () -> Unit) {
        val custody = r06Custody
        if (custody == null) body() else custody.ledger.run(body, {})
    }

    private fun r06Checked(phase: String, body: () -> Unit) {
        try {
            body()
        } catch (error: Throwable) {
            r06Custody?.recordFailure(phase, error)
            throw error
        }
    }

    internal fun awaitState(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        forwarding: ForwardingAvailability,
        ruleState: LocalRuleState?,
        expectedTunnel: String = args.getString("krtek_expect_tunnel", "Disconnected"),
    ): LocalNetworkStatus = runBlocking {
        val policy = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
        val peerRuleIds =
            policy.rules
                .filter { it.enabled && it.cidrs.any { cidr -> cidr.toString() == "$peer/32" } }
                .map { it.id }
        if (ruleState != null) assertTrue(peerRuleIds.isNotEmpty(), "Expected enabled peer rule")
        val status =
            withTimeout(30_000) {
                combine(connection.tunnelState, repository.localNetworkStatus.filterNotNull()) {
                        tunnel,
                        sample ->
                        tunnel to sample
                    }
                    .first { (tunnel, sample) ->
                        val tunnelMatches = tunnel.javaClass.simpleName == expectedTunnel
                        tunnelMatches &&
                            sample.forwarding == forwarding &&
                            (ruleState == null ||
                                peerRuleIds.all { id ->
                                    sample.rules.any { it.id == id && it.state == ruleState }
                                }) &&
                            (ruleState !=
                                LocalRuleState.Inactive(
                                    LocalRuleInactiveReason.ObserverUnavailable
                                ) || !sample.observerAvailable)
                    }
                    .second
            }
        report("forwarding", status.forwarding)
        report("observer_available", status.observerAvailable)
        report(
            "rule_state",
            status.rules.filter { it.id in peerRuleIds }.joinToString { it.state.toString() },
        )
        assertEquals(
            forwarding,
            status.forwarding,
            "Daemon reports forwarding $forwarding while $expectedTunnel",
        )
        if (forwarding == ForwardingAvailability.Active) {
            assertTrue(policy.enabled && policy.rules.any { it.enabled && it.cidrs.isNotEmpty() })
        }
        if (ruleState != null)
            assertTrue(
                peerRuleIds.all { id -> status.rules.any { it.id == id && it.state == ruleState } }
            )
        if (ruleState == LocalRuleState.Inactive(LocalRuleInactiveReason.ObserverUnavailable))
            assertTrue(status.rules.none { it.state == LocalRuleState.Forwarding })
        status
    }

    @Test fun consumerRunsAsAnotherApp() = withConsumer(null) { _, _, _ -> }

    // B1 supplies the ordered raw-event consumer and command baseline. B2-B6
    // extend this same method before the final clean-pair B7 campaign.
    @Test
    fun rulesOffMatchesUpstream() =
        withConsumer(null, testTimeout = 12.minutes, after = { it.verifySupportAndGuide() }) {
            consumer,
            repository,
            connection ->
            withPolicy(repository, LocalNetworkAccess()) {
                withOrderedTunnelEvents { events ->
                    var failure: Throwable? = null
                    var terminalStart = 0
                    var terminalEventExpected = false
                    try {
                        disconnect(connection)
                        appliedConfiguration(
                            LocalNetworkAccess(),
                            ForwardingAvailability.Off,
                            "Disconnected",
                        )
                        val initialConnect = events.cursor()
                        connect(connection)
                        awaitOrderedConnected(events, initialConnect)
                        val before =
                            appliedConfiguration(
                                LocalNetworkAccess(),
                                ForwardingAvailability.Off,
                                "Connected",
                            )
                        runBlocking { assertTrue(connection.connect().isRight()) }
                        val duplicate =
                            appliedConfiguration(
                                LocalNetworkAccess(),
                                ForwardingAvailability.Off,
                                "Connected",
                            )
                        assertEquals(
                            before,
                            duplicate,
                            "duplicate Secured retains the same fd/configuration",
                        )
                        val reconnectStart = events.cursor()
                        connect(connection, reconnect = true)
                        awaitOrderedConnected(events, reconnectStart)
                        assertTrue(
                            events.since(reconnectStart).none {
                                it is RpcTunnelState.State.Disconnected
                            },
                            "Reconnect must not publish Disconnected",
                        )
                        probeExit(consumer, "mullvad")
                        val down = events.cursor()
                        disconnect(connection)
                        awaitOrderedEvent(events, down, 60_000) {
                            it is RpcTunnelState.State.Disconnected
                        }
                        appliedConfiguration(
                            LocalNetworkAccess(),
                            ForwardingAvailability.Off,
                            "Disconnected",
                        )
                        val start = events.cursor()
                        val system = systemConnectAcknowledged()
                        assertEquals(
                            "true",
                            system.changed,
                            "System Connect must initiate the unsecured target",
                        )
                        awaitOrderedConnected(events, start)
                        assertEquals(
                            listOf("Connecting", "Connected"),
                            events.since(start).map { it.javaClass.simpleName },
                        )
                        val systemCapture =
                            appliedConfiguration(
                                LocalNetworkAccess(),
                                ForwardingAvailability.Off,
                                "Connected",
                            )
                        val duplicateStart = events.cursor()
                        val systemDuplicate = systemConnectAcknowledged()
                        assertTrue(systemDuplicate.startId > system.startId)
                        assertEquals(
                            "false",
                            systemDuplicate.changed,
                            "Healthy system Connect is acknowledged as an upstream no-op",
                        )
                        val afterDuplicate =
                            appliedConfiguration(
                                LocalNetworkAccess(),
                                ForwardingAvailability.Off,
                                "Connected",
                            )
                        assertEquals(
                            systemCapture,
                            afterDuplicate,
                            "Healthy system Connect retains the exact capture",
                        )
                        assertTrue(
                            events.lifecycleSince(duplicateStart).isEmpty(),
                            "Acknowledged healthy system Connect must publish no lifecycle transition",
                        )
                        report(
                            "system_connect_ack",
                            "${system.startId}:true,${systemDuplicate.startId}:false",
                        )
                        report("rules_off_command_baseline", "complete")
                        rulesOffParity(repository, connection, events, afterDuplicate)
                        terminalStart = events.cursor()
                        terminalEventExpected = runBlocking {
                            connection.tunnelState.first() !is TunnelState.Disconnected
                        }
                    } catch (error: Throwable) {
                        failure = error
                        throw error
                    } finally {
                        restoreTunnelAfterCase(
                            failure,
                            { disconnect(connection) },
                            {
                                appliedConfiguration(
                                    LocalNetworkAccess(),
                                    ForwardingAvailability.Off,
                                    "Disconnected",
                                )
                            },
                            {
                                if (failure == null && terminalEventExpected)
                                    awaitOrderedEvent(events, terminalStart, 60_000) {
                                        it is RpcTunnelState.State.Disconnected
                                    }
                            },
                        )
                    }
                }
            }
        }

    // Upstream 8fcbcd553e resolve_routes: allow_lan subtracts ALLOWED_LAN_NETS and the LAN
    // multicast nets, keeping the IPv4/IPv6 gateways and the SOCKS range 10.124.0.0/23.
    private val parityTunnelled4 = listOf("1.1.1.1", "10.64.0.1", "10.124.0.1", "10.124.1.254")
    private val parityLan4 =
        listOf(
            "10.0.2.53",
            "10.0.2.2",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "224.0.0.251",
            "239.1.1.1",
            "255.255.255.255",
        )
    private val parityTunnelled6 = listOf("2606:4700:4700::1111", "fc00:bbbb:bbbb:bb01::1")
    private val parityLan6 = listOf("fe80::1", "fd00::1", "ff02::fb", "ff05::2")

    private fun dnsSet(dns: String): Set<String> =
        dns.split(',')
            .filter { it.isNotBlank() }
            .map { checkNotNull(InetAddress.getByName(it.trim().removePrefix("/")).hostAddress) }
            .toSet()

    private fun normalizedDns(addresses: Set<String>): Set<String> =
        addresses.map { checkNotNull(InetAddress.getByName(it).hostAddress) }.toSet()

    private fun assertUpstreamRoutes(
        label: String,
        capture: AppliedCapture,
        ipv6: Boolean,
        allowLan: Boolean,
    ) {
        fun covered(address: String) =
            capture.forwardingRoutes.any {
                CaptureReadiness.covers(it, if (':' in address) "$address/128" else "$address/32")
            }
        (parityTunnelled4 + if (ipv6) parityTunnelled6 else emptyList()).forEach {
            assertTrue(covered(it), "$label: upstream routes $it into the tunnel")
        }
        (parityLan4 + if (ipv6) parityLan6 else emptyList()).forEach {
            assertEquals(!allowLan, covered(it), "$label: allow_lan=$allowLan membership of $it")
        }
        if (ipv6) assertTrue(capture.addresses.any { ':' in it }, "$label: IPv6 address")
        else {
            assertTrue(capture.addresses.none { ':' in it }, "$label: no IPv6 address")
            assertTrue(
                capture.forwardingRoutes.none { ':' in it },
                "$label: upstream forwards no IPv6",
            )
            assertTrue(
                capture.unreachableRoutes.any { CaptureReadiness.covers(it, "::/0") },
                "$label: Android blocks the unconfigured IPv6 family",
            )
        }
    }

    private fun transitionsUntil(events: OrderedTunnelEvents, start: Int, last: String) =
        events
            .lifecycleSince(start)
            .map { it.javaClass.simpleName }
            .let { it.take(it.indexOf(last) + 1) }

    /**
     * Rules-off parity with upstream 8fcbcd553e on the preserved device settings (no MTU override,
     * IPv6 on, allow_lan off, default DNS): every real change is one Reconnect(0) and one
     * establishment, an equivalent change is neither, and NoMatchingRelay blocks with the upstream
     * blocking configuration before and after a target, then recovers.
     */
    private fun rulesOffParity(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        events: OrderedTunnelEvents,
        baseline: AppliedCapture,
    ) {
        val off = LocalNetworkAccess()
        val original = checkNotNull(repository.settingsUpdates.value)
        val originalOptions = original.tunnelOptions
        val originalDns = originalOptions.dnsOptions
        check(
            originalOptions.mtu == null &&
                originalOptions.enableIpv6 &&
                !original.allowLan &&
                originalDns.state == DnsState.Default &&
                !originalDns.defaultOptions.isAnyBlockerEnabled
        ) {
            "Parity expectations assume the preserved device settings"
        }
        val gateways = normalizedDns(setOf("10.64.0.1", "fc00:bbbb:bbbb:bb01::1"))
        // Android link MTU 1280 minus IPv4 WireGuard overhead, clamped to 1280 with IPv6.
        assertEquals(1280, baseline.mtu, "baseline: upstream derived MTU")
        assertEquals(gateways, dnsSet(baseline.dns), "baseline: upstream gateway DNS")
        assertUpstreamRoutes("baseline", baseline, ipv6 = true, allowLan = false)
        var current = baseline
        fun record(label: String, capture: AppliedCapture, transitions: List<String>) =
            report(
                "rules_off_parity",
                JSONObject()
                    .put("case", label)
                    .put("transitions", transitions.joinToString(","))
                    .put("generation", capture.generation)
                    .put("net_id", capture.netId)
                    .put("mtu", capture.mtu)
                    .put("dns", dnsSet(capture.dns).sorted().joinToString(","))
                    .put("addresses", capture.addresses.sorted().joinToString(","))
                    .put("routes", capture.routes.sorted().joinToString(","))
                    .put("forwarding_routes", capture.forwardingRoutes.sorted().joinToString(","))
                    .put(
                        "unreachable_routes",
                        capture.unreachableRoutes.sorted().joinToString(","),
                    ),
            )
        fun apply(
            change: suspend () -> Either<Any?, Any?>,
            settled: (net.mullvad.mullvadvpn.lib.model.Settings) -> Boolean,
        ) = runBlocking {
            assertTrue(change().isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it != null && settled(it) }
            }
        }
        fun step(
            label: String,
            mtu: Int,
            dns: Set<String>,
            ipv6: Boolean,
            allowLan: Boolean,
            change: suspend () -> Either<Any?, Any?>,
            settled: (net.mullvad.mullvadvpn.lib.model.Settings) -> Boolean,
        ) {
            val start = events.cursor()
            apply(change, settled)
            awaitOrderedConnected(events, start)
            val transitions = transitionsUntil(events, start, "Connected")
            assertEquals("Disconnecting", transitions.first(), "$label: upstream Reconnect(0)")
            assertTrue(
                transitions.none { it == "Disconnected" || it == "Error" },
                "$label: reconnect publishes no Disconnected or Error",
            )
            val expectedDns = normalizedDns(dns)
            val next =
                appliedConfiguration(
                    off,
                    ForwardingAvailability.Off,
                    "Connected",
                    current.generation,
                    requiredMtu = mtu,
                    requiredDns = expectedDns,
                )
            assertEquals(
                checkNotNull(current.generation).toULong() + 1uL,
                checkNotNull(next.generation).toULong(),
                "$label: a real change is exactly one establishment",
            )
            SystemClock.sleep(2_000)
            assertEquals(
                next,
                appliedConfiguration(
                    off,
                    ForwardingAvailability.Off,
                    "Connected",
                    requiredMtu = mtu,
                    requiredDns = expectedDns,
                ),
                "$label: no further establishment",
            )
            assertUpstreamRoutes(label, next, ipv6, allowLan)
            record(label, next, transitions)
            current = next
        }
        fun equivalent(
            label: String,
            change: suspend () -> Either<Any?, Any?>,
            settled: (net.mullvad.mullvadvpn.lib.model.Settings) -> Boolean,
        ) {
            val start = events.cursor()
            apply(change, settled)
            SystemClock.sleep(3_000)
            assertTrue(
                events.lifecycleSince(start).isEmpty(),
                "$label: an equivalent setting publishes no lifecycle transition",
            )
            assertEquals(
                current,
                appliedConfiguration(
                    off,
                    ForwardingAvailability.Off,
                    "Connected",
                    requiredMtu = current.mtu,
                    requiredDns = dnsSet(current.dns),
                ),
                "$label: an equivalent setting establishes nothing",
            )
            record(label, current, emptyList())
        }
        fun noMatchingRelay(label: String, fromTarget: Boolean) {
            val start = events.cursor()
            var recoveryStart = 0
            runBlocking {
                withEmptyRelayList(repository) {
                    if (!fromTarget) assertTrue(connection.connect().isRight())
                    val error =
                        withTimeout(60_000) {
                            connection.tunnelState.first { it is TunnelState.Error }
                        }
                            as TunnelState.Error
                    assertEquals(
                        ErrorStateCause.TunnelParameterError(
                            ParameterGenerationError.NoMatchingRelay
                        ),
                        error.errorState.cause,
                    )
                    assertTrue(error.errorState.isBlocking)
                    withTimeout(60_000) {
                        events.await(start) { it is RpcTunnelState.State.Error }
                    }
                    val transitions = transitionsUntil(events, start, "Error")
                    assertEquals(
                        if (fromTarget) listOf("Disconnecting", "Error") else listOf("Error"),
                        transitions,
                        "$label: parameter generation fails before Connecting",
                    )
                    // Upstream blocking_config: MTU 1380, DNS 192.0.2.1, all routes.
                    val blocked =
                        appliedConfiguration(
                            off,
                            ForwardingAvailability.Off,
                            "Error",
                            current.generation,
                        )
                    assertEquals(
                        checkNotNull(current.generation).toULong() + 1uL,
                        checkNotNull(blocked.generation).toULong(),
                        "$label: blocking is exactly one establishment",
                    )
                    assertTrue(
                        "0.0.0.0/0" in blocked.forwardingRoutes &&
                            "::/0" in blocked.forwardingRoutes
                    )
                    record("$label-error", blocked, transitions)
                    current = blocked
                    recoveryStart = events.cursor()
                }
            }
            // Restoring the relay settings reconnects the secured target from Error.
            awaitOrderedConnected(events, recoveryStart)
            val recovery = transitionsUntil(events, recoveryStart, "Connected")
            assertEquals(listOf("Connecting", "Connected"), recovery, "$label: recovery")
            val recovered =
                appliedConfiguration(
                    off,
                    ForwardingAvailability.Off,
                    "Connected",
                    current.generation,
                    requiredMtu = 1280,
                    requiredDns = gateways,
                )
            assertEquals(
                checkNotNull(current.generation).toULong() + 1uL,
                checkNotNull(recovered.generation).toULong(),
                "$label: recovery is exactly one establishment",
            )
            assertUpstreamRoutes("$label-recovery", recovered, ipv6 = true, allowLan = false)
            record("$label-recovery", recovered, recovery)
            current = recovered
        }

        val v6Dns = InetAddress.getByName("2606:4700:4700::1111")
        val privateDns = InetAddress.getByName("10.0.2.53")
        fun custom(addresses: List<InetAddress>): suspend () -> Either<Any?, Any?> = {
            repository.setDnsOptions(DnsState.Custom, addresses, originalDns.defaultOptions)
        }
        fun isCustom(
            settings: net.mullvad.mullvadvpn.lib.model.Settings,
            addresses: List<InetAddress>,
        ) =
            settings.tunnelOptions.dnsOptions.state == DnsState.Custom &&
                settings.tunnelOptions.dnsOptions.customOptions.addresses == addresses
        var failure: Throwable? = null
        try {
            step(
                "mtu-1380",
                1380,
                gateways,
                true,
                false,
                { repository.setWireguardMtu(Mtu(1380)) },
            ) {
                it.tunnelOptions.mtu == Mtu(1380)
            }
            equivalent("mtu-1380-equivalent", { repository.setWireguardMtu(Mtu(1380)) }) {
                it.tunnelOptions.mtu == Mtu(1380)
            }
            step("mtu-reset", 1280, gateways, true, false, { repository.resetWireguardMtu() }) {
                it.tunnelOptions.mtu == null
            }
            // IPv4-only: link 1280 minus 60 bytes of IPv4 WireGuard overhead, no IPv6 clamp.
            step(
                "ipv6-off",
                1220,
                setOf("10.64.0.1"),
                false,
                false,
                {
                    repository.setIpv6Enabled(false)
                },
            ) {
                !it.tunnelOptions.enableIpv6
            }
            // Only an IPv6 resolver while IPv6 is off: upstream's dummy fallback 192.0.2.1.
            step(
                "empty-dns-fallback",
                1220,
                setOf("192.0.2.1"),
                false,
                false,
                custom(listOf(v6Dns)),
            ) {
                isCustom(it, listOf(v6Dns))
            }
            step(
                "ipv6-on",
                1280,
                setOf(checkNotNull(v6Dns.hostAddress)),
                true,
                false,
                {
                    repository.setIpv6Enabled(true)
                },
            ) {
                it.tunnelOptions.enableIpv6
            }
            step("private-dns", 1280, setOf("10.0.2.53"), true, false, custom(listOf(privateDns))) {
                isCustom(it, listOf(privateDns))
            }
            step(
                "allow-lan-private-dns",
                1280,
                setOf("10.0.2.53"),
                true,
                true,
                {
                    repository.setLocalNetworkSharing(true)
                },
            ) {
                it.allowLan
            }
            // Custom with no address is DnsConfig::default: the tunnel gateways.
            step("empty-custom-dns", 1280, gateways, true, true, custom(emptyList())) {
                isCustom(it, emptyList())
            }
            step(
                "allow-lan-off",
                1280,
                gateways,
                true,
                false,
                {
                    repository.setLocalNetworkSharing(false)
                },
            ) {
                !it.allowLan
            }
            equivalent(
                "default-dns-equivalent",
                {
                    repository.setDnsOptions(
                        originalDns.state,
                        originalDns.customOptions.addresses,
                        originalDns.defaultOptions,
                    )
                },
            ) {
                it.tunnelOptions == originalOptions && it.allowLan == original.allowLan
            }
            // Interface name and handle may change across establishments; the configuration
            // Android reports must not.
            fun configuration(capture: AppliedCapture) =
                capture.copy(generation = null, handle = null, interfaceName = "", netId = "")
            assertEquals(
                configuration(baseline),
                configuration(current),
                "Restored settings reproduce the baseline configuration",
            )
            noMatchingRelay("no-matching-relay-after-target", fromTarget = true)
            val down = events.cursor()
            disconnect(connection)
            awaitOrderedEvent(events, down, 60_000) { it is RpcTunnelState.State.Disconnected }
            appliedConfiguration(off, ForwardingAvailability.Off, "Disconnected")
            noMatchingRelay("no-matching-relay-before-target", fromTarget = false)
            report("rules_off_parity_cases", "complete")
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            try {
                runBlocking {
                    val now = checkNotNull(repository.settingsUpdates.value)
                    if (now.tunnelOptions.mtu != originalOptions.mtu)
                        assertTrue(repository.resetWireguardMtu().isRight())
                    if (now.tunnelOptions.enableIpv6 != originalOptions.enableIpv6)
                        assertTrue(repository.setIpv6Enabled(originalOptions.enableIpv6).isRight())
                    if (now.tunnelOptions.dnsOptions != originalDns)
                        assertTrue(
                            repository
                                .setDnsOptions(
                                    originalDns.state,
                                    originalDns.customOptions.addresses,
                                    originalDns.defaultOptions,
                                )
                                .isRight()
                        )
                    if (now.allowLan != original.allowLan)
                        assertTrue(repository.setLocalNetworkSharing(original.allowLan).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first {
                            it?.tunnelOptions == originalOptions && it.allowLan == original.allowLan
                        }
                    }
                }
                report("rules_off_parity_settings_restored", true)
            } catch (restore: Throwable) {
                failure?.addSuppressed(restore) ?: throw restore
            }
        }
    }

    private fun restoreTunnelAfterCase(
        originalFailure: Throwable?,
        disconnect: () -> Unit,
        verifyAbsent: () -> Unit,
        verifyEvents: () -> Unit,
    ) {
        var failure = originalFailure
        for (step in listOf(disconnect, verifyAbsent, verifyEvents)) {
            try {
                step()
            } catch (error: Throwable) {
                if (failure == null) failure = error
                else if (failure !== error) failure.addSuppressed(error)
            }
        }
        failure?.let { throw it }
    }

    private fun awaitOrderedConnected(events: OrderedTunnelEvents, start: Int) = run {
        runBlocking {
            withTimeout(90_000) {
                events.awaitLifecycle(start) { it is RpcTunnelState.State.Connected }
            }
        }
        assertTrue(
            events.lifecycleSince(start).any { it is RpcTunnelState.State.Connecting },
            "Command must reach Connecting",
        )
    }

    private fun awaitOrderedEvent(
        events: OrderedTunnelEvents,
        start: Int,
        timeoutMillis: Long,
        matches: (RpcTunnelState.State) -> Boolean,
    ) = runBlocking {
        withTimeout(timeoutMillis) { events.await(start, matches) }
    }

    private class OrderedTunnelEvents {
        private val records = mutableListOf<RpcTunnelState.State>()
        private val changed = Channel<Unit>(Channel.CONFLATED)
        private var failure: Throwable? = null
        private val local = OrderedLocalStatusWindow.Window()

        @Synchronized
        fun cursor(): Int {
            failure?.let { throw it }
            return records.size
        }

        @Synchronized
        fun since(start: Int): List<RpcTunnelState.State> {
            failure?.let { throw it }
            return records.drop(start)
        }

        @Synchronized
        fun lifecycleSince(start: Int): List<RpcTunnelState.State> {
            failure?.let { throw it }
            return TunnelLifecycleTransitions.since(records, start) { it.javaClass }
        }

        fun append(state: RpcTunnelState.State): Int {
            val index =
                synchronized(this) {
                    records.add(state)
                    records.lastIndex
                }
            changed.trySend(Unit)
            return index
        }

        fun fail(error: Throwable) {
            synchronized(this) { if (failure == null) failure = error }
            changed.close(error)
        }

        suspend fun await(start: Int, matches: (RpcTunnelState.State) -> Boolean) {
            while (since(start).none(matches)) changed.receive()
        }

        suspend fun awaitLifecycle(start: Int, matches: (RpcTunnelState.State) -> Boolean) {
            while (lifecycleSince(start).none(matches)) changed.receive()
        }

        fun appendLocal(revision: ULong, eligible: Boolean) {
            local.append(revision, eligible)
            changed.trySend(Unit)
        }

        suspend fun awaitLocal(start: ULong, finish: ULong) {
            while (true) {
                cursor() // A closed/failed subscription cannot prove continuity.
                if (local.processedThrough(start, finish)) return
                changed.receive()
            }
        }
    }

    private data class SystemConnectReceipt(val startId: Int, val changed: String)

    private fun systemConnectAcknowledged(): SystemConnectReceipt {
        val receipts = Channel<SystemConnectReceipt>(Channel.UNLIMITED)
        val pattern =
            Regex(
                "^VPN command completed action=${Regex.escape(android.net.VpnService.SERVICE_INTERFACE)} startId=(\\d+) changed=(true|false|error)$"
            )
        val writer =
            object : LogWriter() {
                override fun log(
                    severity: Severity,
                    message: String,
                    tag: String,
                    throwable: Throwable?,
                ) {
                    val match = pattern.matchEntire(message) ?: return
                    receipts.trySend(
                        SystemConnectReceipt(match.groupValues[1].toInt(), match.groupValues[2])
                    )
                }
            }
        Logger.addLogWriter(writer)
        try {
            target.startService(
                Intent(android.net.VpnService.SERVICE_INTERFACE)
                    .setClassName(
                        target.packageName,
                        "net.mullvad.mullvadvpn.app.service.MullvadVpnService",
                    )
            )
            return runBlocking { withTimeout(10_000) { receipts.receive() } }
        } finally {
            Logger.setLogWriters(Logger.config.logWriterList.filterNot { it === writer })
            receipts.cancel()
        }
    }

    private fun withOrderedTunnelEvents(block: (OrderedTunnelEvents) -> Unit) =
        withOrderedDaemonEvents { events, _ ->
            block(events)
        }

    private fun withOrderedDaemonEvents(
        localEligible: (mullvad_daemon.management_interface.LocalNetworkStatus) -> Boolean = {
            true
        },
        block: (OrderedTunnelEvents, ManagementServiceClient) -> Unit,
    ) {
        val subscribed = CompletableDeferred<Unit>()
        val socket =
            (target.applicationContext as MullvadApplication)
                .getKoin()
                .get<File>(named(GRPC_SOCKET_FILE_NAMED_ARGUMENT))
        val client =
            OkHttpClient.Builder()
                .socketFactory(UnixDomainSocketFactory(socket))
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .protocols(listOf(Protocol.H2_PRIOR_KNOWLEDGE))
                .proxy(Proxy.NO_PROXY)
                .eventListener(
                    object : okhttp3.EventListener() {
                        override fun responseHeadersEnd(
                            call: okhttp3.Call,
                            response: okhttp3.Response,
                        ) {
                            // events_listen registers the subscription before returning its
                            // response.
                            if (response.isSuccessful) subscribed.complete(Unit)
                            else
                                subscribed.completeExceptionally(
                                    java.io.IOException("EventsListen HTTP ${response.code}")
                                )
                        }

                        override fun callFailed(call: okhttp3.Call, ioe: java.io.IOException) {
                            subscribed.completeExceptionally(ioe)
                        }
                    }
                )
                .build()
        val rpc =
            GrpcClient.Builder()
                .client(client)
                .baseUrl("http://localhost/")
                .minMessageToCompress(Long.MAX_VALUE)
                .build()
                .create(ManagementServiceClient::class)
        val scope = CoroutineScope(Dispatchers.IO)
        val events = OrderedTunnelEvents()
        var collector: Deferred<Unit>? = null
        try {
            val channel = runBlocking {
                withTimeout(10_000) { rpc.EventsListen().executeIn(scope, Unit) }
            }
            collector =
                scope.async(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        for (event in channel) {
                            val local =
                                event.event
                                    as?
                                    mullvad_daemon.management_interface.DaemonEvent.Event.LocalNetworkStatus
                            if (local != null) {
                                events.appendLocal(
                                    local.value.revision.toULong(),
                                    localEligible(local.value),
                                )
                            }
                            val state =
                                event.event
                                    as?
                                    mullvad_daemon.management_interface.DaemonEvent.Event.TunnelState
                                    ?: continue
                            val index = events.append(checkNotNull(state.value.state))
                            report(
                                "ordered_tunnel_event",
                                JSONObject()
                                    .put("index", index)
                                    .put("time_ns", SystemClock.elapsedRealtimeNanos())
                                    .put("state", state.value.toString()),
                            )
                        }
                    } catch (error: Throwable) {
                        events.fail(error)
                        throw error
                    } finally {
                        events.fail(IllegalStateException("Raw tunnel event reader closed"))
                    }
                }
            runBlocking { withTimeout(10_000) { subscribed.await() } }
            block(events, rpc)
        } finally {
            collector?.cancel()
            scope.cancel()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            runBlocking {
                try {
                    collector?.await()
                } catch (_: CancellationException) {
                    /* Own reader cancellation. */
                }
            }
        }
    }

    /** Stable baselines are separate from the same-lifetime transition smoke. */
    @Test fun persistentLocalSessionWhileDisconnected() = stableSession("Disconnected")

    @Test fun persistentLocalSessionWhileConnected() = stableSession("Connected")

    // Each explicit session has a 480-second socket-owner deadline. Allow the
    // 90-second pre-session Connect, two 60-second Disconnect waits (normal and
    // finally), and 60 seconds for UI/configuration/IPC cleanup. Inner socket,
    // packet, tunnel-state and external instrumentation deadlines are unchanged.
    private fun consumerCaseTimeout(sessions: Int = 1): Duration =
        (sessions * 480 + 90 + 2 * 60 + 60).seconds

    private fun stableSession(state: String) =
        withConsumer(null, testTimeout = consumerCaseTimeout()) { consumer, repository, connection
            ->
            withPolicy(repository, peerPolicy()) {
                try {
                    if (state == "Connected") connect(connection)
                    LocalSession(
                            consumer,
                            repository,
                            connection,
                            state,
                            expectedPublic = state == "Connected",
                        )
                        .use { session ->
                            session.dwell(state)
                            session.burst()
                            session.dwell("${state}-large-write")
                            if (state == "Connected") {
                                probeExit(consumer, "mullvad")
                                probeIcmp(consumer, "echo")
                            }
                        }
                } finally {
                    disconnect(connection)
                }
            }
        }

    internal fun connect(connection: ConnectionProxy, reconnect: Boolean = false) = runBlocking {
        continuityIntent(if (reconnect) "reconnect" else "connect")
        report(
            "session_intent",
            JSONObject()
                .put("command", if (reconnect) "reconnect" else "connect")
                .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                .toString(),
        )
        val left =
            if (reconnect)
                async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(60_000) {
                        connection.tunnelState.first { it !is TunnelState.Connected }
                    }
                }
            else null
        if (reconnect) assertTrue(connection.reconnect().isRight())
        else assertTrue(connection.connect().isRight())
        // A reconnect must leave the previous Connected state before accepting its successor.
        left?.await()
        withTimeout(90_000) { connection.tunnelState.first { it is TunnelState.Connected } }
    }

    @Test
    fun localStreamSurvivesConnectReconnectDisconnect() =
        continuityCase { consumer, repository, connection, session ->
            connect(connection)
            continuityConnected(consumer, repository, connection, session, "connected")
            connect(connection, reconnect = true)
            continuityConnected(consumer, repository, connection, session, "reconnected")
        }

    @Test
    fun appExclusionChangeAllowsFreshLocalConnections() =
        exclusionContinuityCase(connectWithExclusion = false)

    @Test
    fun localStreamSurvivesUnrelatedAppExclusionHandover() =
        exclusionContinuityCase(connectWithExclusion = true)

    private fun exclusionContinuityCase(connectWithExclusion: Boolean) =
        connectedCase(testTimeout = consumerCaseTimeout(sessions = 2)) {
            consumer,
            repository,
            connection,
            policy ->
            // Android replaces the NetworkAgent for changed app lists. Unlike
            // tunnel transitions, that platform operation may destroy old TCP.
            val original = checkNotNull(repository.settingsUpdates.value).splitTunnelSettings
            val split =
                (target.applicationContext as MullvadApplication)
                    .getKoin()
                    .get<SplitTunnelingRepository>()
            val excluded =
                PackageName(args.getString("krtek_exclusion_package", "com.android.deskclock"))
            val consumerUid = target.packageManager.getApplicationInfo(testPackage, 0).uid
            val excludedUid = target.packageManager.getApplicationInfo(excluded.value, 0).uid
            assertNotEquals(Process.myUid(), excludedUid)
            assertNotEquals(consumerUid, excludedUid)
            assertTrue(excluded !in original.excludedApps)
            assertTrue(PackageName(testPackage) !in original.excludedApps)
            try {
                LocalSession(consumer, repository, connection, "Connected").use { session ->
                    session.dwell("before-app-list-change")
                    // Upstream applies the app list through the reconnect's new
                    // interface; the old capture stays until then. Require that
                    // newer capture on a rebuilt network, not the pre-change one.
                    val beforeChange =
                        appliedConfiguration(
                            policy,
                            ForwardingAvailability.Active,
                            "Connected",
                            fixedCapture = true,
                        )
                    assertTrue(uidIncluded(beforeChange.uids, excludedUid))
                    session.markAppListChange()
                    runBlocking {
                        assertTrue(split.excludeApp(excluded).isRight())
                        assertTrue(split.enableSplitTunneling(true).isRight())
                        withTimeout(10_000) {
                            repository.settingsUpdates.first {
                                it?.splitTunnelSettings?.let { settings ->
                                    settings.enabled && excluded in settings.excludedApps
                                } == true
                            }
                        }
                    }
                    val config =
                        appliedConfiguration(
                            policy,
                            ForwardingAvailability.Active,
                            "Connected",
                            previousGeneration = checkNotNull(beforeChange.generation),
                            fixedCapture = true,
                        )
                    assertNotEquals(
                        beforeChange.netId,
                        config.netId,
                        "An app-list change must rebuild the Android VPN network",
                    )
                    assertTrue(!uidIncluded(config.uids, excludedUid))
                    assertTrue(uidIncluded(config.uids, consumerUid))
                    report("continuity_excluded_uid", excludedUid)
                    report("continuity_consumer_uid", consumerUid)
                }
                // Android closes connections open at the app-list change (run-05
                // item-4-answer-r02); fresh ones to the same peer work right away.
                listOf("tcp", "udp").forEach {
                    probeSocket(consumer, it, "reply", sessionFrame = true)
                }
                report("fresh_after_app_list_change", "tcp,udp")
                // Finish the list-changing lifetime before the static-list cycle.
                // Only that explicit app-list change may destroy the old TCP stream.
                if (connectWithExclusion) {
                    disconnect(connection)
                    val begin = SystemClock.elapsedRealtimeNanos()
                    android.util.Log.i(
                        "KrtekContinuity",
                        "static-exclusion-cycle begin boottime_ns=$begin",
                    )
                    report("static_exclusion_cycle_begin_ns", begin)
                    val configs = mutableListOf<AppliedCapture>()
                    configs +=
                        appliedConfiguration(policy, ForwardingAvailability.Active, "Disconnected")
                    // These are explicitly new sockets, with the original deadlines.
                    LocalSession(consumer, repository, connection, "Disconnected").use { recovered
                        ->
                        recovered.dwell("initial-partial-with-exclusion")
                        connect(connection)
                        configs +=
                            continuityConnected(
                                consumer,
                                repository,
                                connection,
                                recovered,
                                "connect-with-exclusion",
                            )
                        disconnect(connection)
                        configs +=
                            appliedConfiguration(
                                policy,
                                ForwardingAvailability.Active,
                                "Disconnected",
                            )
                        recovered.dwell("partial-with-exclusion")
                        connect(connection)
                        configs +=
                            continuityConnected(
                                consumer,
                                repository,
                                connection,
                                recovered,
                                "reconnect-with-exclusion",
                            )
                        assertEquals(1, configs.map { it.uids }.distinct().size)
                        configs.forEach { config ->
                            assertTrue(!uidIncluded(config.uids, excludedUid))
                            assertTrue(uidIncluded(config.uids, consumerUid))
                        }
                    }
                    val end = SystemClock.elapsedRealtimeNanos()
                    android.util.Log.i(
                        "KrtekContinuity",
                        "static-exclusion-cycle end boottime_ns=$end",
                    )
                    report("static_exclusion_cycle_end_ns", end)
                } else {
                    LocalSession(
                            consumer,
                            repository,
                            connection,
                            "Connected",
                            expectedPublic = true,
                        )
                        .use { recovered ->
                            continuityConnected(
                                consumer,
                                repository,
                                connection,
                                recovered,
                                "fresh-after-app-list-change",
                            )
                        }
                }
            } finally {
                runBlocking {
                    assertTrue(split.includeApp(excluded).isRight())
                    assertTrue(split.enableSplitTunneling(original.enabled).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.splitTunnelSettings == original }
                    }
                }
                report("continuity_exclusion_restored", true)
            }
        }

    @Test
    fun localStreamSurvivesAllTunnelStates() =
        continuityCase { consumer, repository, connection, session ->
            connect(connection)
            val before = continuityConnected(consumer, repository, connection, session, "connected")
            continuitySinkConfiguration(repository, connection, session, before)
            connect(connection, reconnect = true)
            continuityConnected(consumer, repository, connection, session, "reconnected")
            parameterError(repository, connection, session)
            connect(connection)
            continuityConnected(consumer, repository, connection, session, "recovered")
        }

    @Test
    fun localStreamSurvivesParameterErrorBeforeAnyTunnel() =
        continuityCase { consumer, repository, connection, session ->
            parameterError(repository, connection, session)
            connect(connection)
            continuityConnected(consumer, repository, connection, session, "first-target-recovery")
        }

    private fun continuitySinkConfiguration(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        session: LocalSession,
        before: AppliedCapture,
    ) {
        val original = checkNotNull(repository.settingsUpdates.value).tunnelOptions
        val changedMtu = if (before.mtu == 1280) Mtu(1380) else Mtu(1280)
        var lastGeneration = before.generation
        fun record(stage: String, config: AppliedCapture) {
            report(
                "sink_configuration",
                JSONObject()
                    .put("stage", stage)
                    .put("session_id", session.id)
                    .put("generation", config.generation)
                    .put("handle", config.handle)
                    .put("mtu", config.mtu)
                    .put("addresses", config.addresses.sorted().joinToString(","))
                    .put("interface", config.interfaceName)
                    .put("net_id", config.netId),
            )
        }
        record("before", before)
        try {
            continuityIntent("sink-configuration")
            runBlocking {
                assertTrue(repository.setWireguardMtu(changedMtu).isRight())
                assertTrue(repository.setIpv6Enabled(!original.enableIpv6).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first {
                        it?.tunnelOptions?.let { options ->
                            options.mtu == changedMtu && options.enableIpv6 != original.enableIpv6
                        } == true
                    }
                }
            }
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Connected",
            )
            val changed =
                appliedConfiguration(
                    peerPolicy(),
                    ForwardingAvailability.Active,
                    "Connected",
                    before.generation,
                    requiredMtu = changedMtu.value,
                )
            lastGeneration = changed.generation
            assertNotEquals(before.mtu, changed.mtu)
            assertNotEquals(
                before.addresses,
                changed.addresses,
                "IPv4-only Local does not pin the target's IPv6 exposure",
            )
            record("changed", changed)
            session.burst()
            session.dwell("sink-mtu-family-changed")
        } finally {
            continuityIntent("sink-configuration-restore")
            runBlocking {
                assertTrue(
                    (original.mtu?.let { repository.setWireguardMtu(it) }
                            ?: repository.resetWireguardMtu())
                        .isRight()
                )
                assertTrue(repository.setIpv6Enabled(original.enableIpv6).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first { it?.tunnelOptions == original }
                }
            }
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Connected",
            )
            val restored =
                appliedConfiguration(
                    peerPolicy(),
                    ForwardingAvailability.Active,
                    "Connected",
                    lastGeneration,
                    requiredMtu = before.mtu,
                )
            assertEquals(before.addresses, restored.addresses)
            assertEquals(before.routes, restored.routes)
            assertEquals(before.dns, restored.dns)
            assertEquals(before.mtu, restored.mtu)
            assertEquals(before.uids, restored.uids)
            record("restored", restored)
            session.burst()
            session.dwell("sink-mtu-family-restored")
            report("sink_configuration_restored", true)
        }
    }

    @Test
    fun localRevocationDoesNotFallThroughDuringReconnect() =
        withConsumer(null, testTimeout = consumerCaseTimeout(sessions = 2)) {
            consumer,
            repository,
            connection ->
            val original = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            val policy = peerPolicy()
            try {
                setPolicy(repository, policy)
                LocalSession(consumer, repository, connection, "Disconnected").use { session ->
                    session.dwell("initial-local")
                    connect(connection)
                    continuityConnected(
                        consumer,
                        repository,
                        connection,
                        session,
                        "before-revocation",
                    )
                    val different =
                        checkNotNull(SsidIdentity.fromUserText("krtek-m3-different-wifi"))
                    val known = runBlocking {
                        withTimeout(30_000) {
                                repository.localNetworkStatus.filterNotNull().first {
                                    it.currentWifi is ConnectedWifi.Known
                                }
                            }
                            .currentWifi as ConnectedWifi.Known
                    }
                    assertNotEquals(known.ssid, different)
                    session.markRevocation()
                    runBlocking { assertTrue(connection.reconnect().isRight()) }
                    setPolicy(
                        repository,
                        policy.copy(
                            rules = policy.rules.map { it.copy(ssidIds = listOf(different)) }
                        ),
                    )
                    report("revocation_policy_applied_ns", SystemClock.elapsedRealtimeNanos())
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Inactive(LocalRuleInactiveReason.DifferentWifi),
                        "Connected",
                    )
                    session.revocationApplied()
                    repeat(3) { probeSocket(consumer, "udp", "blocked", sessionFrame = true) }
                    probeSocket(consumer, "tcp", "blocked", sessionFrame = true)
                    probeExit(consumer, "mullvad")
                }
                setPolicy(repository, policy)
                LocalSession(consumer, repository, connection, "Connected").use { recovery ->
                    recovery.dwell("new-session-after-revocation")
                    probeExit(consumer, "mullvad")
                }
            } finally {
                disconnect(connection)
                setPolicy(repository, original)
                report("policy_restored", true)
            }
        }

    private fun continuityCase(
        block: (Consumer, SettingsRepository, ConnectionProxy, LocalSession) -> Unit
    ) =
        withConsumer(null, testTimeout = consumerCaseTimeout()) { consumer, repository, connection
            ->
            val original = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            val policy = peerPolicy()
            val timeline = File(target.filesDir, "krtek-probes/${UUID.randomUUID()}-states.jsonl")
            timeline.parentFile?.mkdirs()
            val scope = CoroutineScope(Dispatchers.Default)
            val monitor =
                scope.launch(start = CoroutineStart.UNDISPATCHED) {
                    connection.tunnelState.collect { state ->
                        val event =
                            JSONObject()
                                .put("state", state.javaClass.simpleName)
                                .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                                .put("app_pid", Process.myPid())
                        synchronized(timeline) { timeline.appendText(event.toString() + "\n") }
                        report("session_state", event.toString())
                    }
                }
            try {
                setPolicy(repository, policy)
                LocalSession(consumer, repository, connection, "Disconnected").use { session ->
                    session.dwell("initial-disconnected")
                    session.burst()
                    session.dwell("large-write-before-handover")
                    block(consumer, repository, connection, session)
                    disconnect(connection)
                    awaitAppliedState(repository, connection, "Disconnected")
                    session.burst()
                    session.dwell("final-disconnected")
                }
            } finally {
                try {
                    disconnect(connection)
                } finally {
                    setPolicy(repository, original)
                    scope.cancel()
                    runBlocking { monitor.join() }
                    report("session_state_trace", timeline.name)
                    report("policy_restored", true)
                }
            }
        }

    private fun continuityConnected(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        session: LocalSession,
        stage: String,
    ): AppliedCapture {
        val config = awaitAppliedState(repository, connection, "Connected")
        session.burst()
        session.dwell(stage)
        probeExit(consumer, "mullvad")
        probeIcmp(consumer, "echo")
        return config
    }

    private fun parameterError(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        session: LocalSession,
    ) = runBlocking {
        continuityIntent("error")
        withEmptyRelayList(repository) {
            assertTrue(connection.connect().isRight())
            val error =
                withTimeout(60_000) {
                    connection.tunnelState.first { it is TunnelState.Error }
                }
                    as TunnelState.Error
            assertEquals(
                ErrorStateCause.TunnelParameterError(ParameterGenerationError.NoMatchingRelay),
                error.errorState.cause,
            )
            assertTrue(error.errorState.isBlocking)
            report("parameter_error_observed", "NoMatchingRelay")
            appliedConfiguration(
                checkNotNull(repository.settingsUpdates.value?.localNetworkAccess),
                ForwardingAvailability.Active,
                "Error",
                fixedCapture = true,
            )
            session.dwell("error-no-matching-relay", 2000)
        }
    }

    /**
     * Selects an owned empty custom list (NoMatchingRelay), then restores the exact relay proto.
     */
    internal suspend fun <T> withEmptyRelayList(
        repository: SettingsRepository,
        block: suspend () -> T,
    ): T {
        val koin = (target.applicationContext as MullvadApplication).getKoin()
        val management = koin.get<ManagementService>()
        // Preserve the complete proto, including Constraint.Any, using the normal API.
        val socket = koin.get<File>(named(GRPC_SOCKET_FILE_NAMED_ARGUMENT))
        val client =
            OkHttpClient.Builder()
                .socketFactory(UnixDomainSocketFactory(socket))
                .protocols(listOf(Protocol.H2_PRIOR_KNOWLEDGE))
                .proxy(Proxy.NO_PROXY)
                .callTimeout(10, TimeUnit.SECONDS)
                .build()
        val rpc =
            GrpcClient.Builder()
                .client(client)
                .baseUrl("http://localhost/")
                .minMessageToCompress(Long.MAX_VALUE)
                .build()
                .create(ManagementServiceClient::class)
        val saved = checkNotNull(rpc.GetSettings().execute(Unit).relay_settings)
        val before = checkNotNull(repository.settingsUpdates.value).relaySettings
        val list =
            checkNotNull(
                management
                    .createCustomList(
                        CustomListName.fromString("krtek-run05-${UUID.randomUUID()}"),
                        emptyList(),
                    )
                    .getOrNull()
            )
        report("owned_error_list_created", list.value)
        try {
            assertTrue(
                management.setRelayLocationMultihop(MultihopMode.NEVER, null, list).isRight()
            )
            return block()
        } finally {
            try {
                rpc.SetRelaySettings().execute(saved)
                assertEquals(saved, rpc.GetSettings().execute(Unit).relay_settings)
                withTimeout(10_000) {
                    repository.settingsUpdates.first { it?.relaySettings == before }
                }
                report("relay_settings_restored", true)
                assertTrue(management.deleteCustomList(list).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first { settings ->
                        settings != null && settings.customLists.none { it.id == list }
                    }
                }
                assertEquals(saved, rpc.GetSettings().execute(Unit).relay_settings)
                report("owned_error_list_deleted", list.value)
            } finally {
                client.connectionPool.evictAll()
                client.dispatcher.executorService.shutdown()
            }
        }
    }

    private inner class LocalSession(
        private val consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        expectedTunnel: String,
        private val expectedPublic: Boolean? = null,
    ) : AutoCloseable {
        val id: String
        private val appPid = Process.myPid()
        private val consumerPid: Int
        private var socketIdentity: String? = null
        private val directory =
            File(target.filesDir, "krtek-probes").apply { check(isDirectory || mkdir()) }
        private var closed = false
        private var requestedBursts = 0
        private var revokedAt: Long? = null
        private var revokedAppliedAt: Long? = null
        private var appListChangeAt: Long? = null
        private val clockMarker = UUID.randomUUID().toString()
        private val logSinceMillis = System.currentTimeMillis()
        private val clockMarks = mutableListOf<LocalContinuityWindows.ClockMark>()

        private fun clockMark(kind: String) {
            val before = SystemClock.elapsedRealtimeNanos()
            android.util.Log.i("KrtekContinuityClock", "$clockMarker $kind boottime_ns=$before")
            clockMarks +=
                LocalContinuityWindows.ClockMark(kind, before, SystemClock.elapsedRealtimeNanos())
        }

        fun markAppListChange() {
            command("session-snapshot") // A pre-existing Local failure is never expected.
            continuityIntent("app-list-change")
            appListChangeAt = SystemClock.elapsedRealtimeNanos()
            report(
                "session_app_list_change",
                JSONObject().put("session_id", id).put("elapsed_ns", appListChangeAt).toString(),
            )
        }

        fun markRevocation() {
            command("session-snapshot") // Do not hide a pre-existing harness or Local failure.
            revokedAt = SystemClock.elapsedRealtimeNanos()
            report(
                "session_revocation_intent",
                JSONObject().put("session_id", id).put("elapsed_ns", revokedAt).toString(),
            )
        }

        fun revocationApplied() {
            check(revokedAt != null)
            revokedAppliedAt = SystemClock.elapsedRealtimeNanos()
            report(
                "session_revocation_observed",
                JSONObject().put("session_id", id).put("elapsed_ns", revokedAppliedAt).toString(),
            )
            // Keep the old sockets sending while eligibility is denied. Waiting
            // here observes their original immutable deadlines, not a retry.
            Thread.sleep(5500)
        }

        init {
            awaitAppliedState(repository, connection, expectedTunnel)
            clockMark("begin")
            val response =
                consumer.request(
                    Bundle().apply {
                        putString("transport", "session-start")
                        putString("destination", peer)
                        putInt("duration_ms", 480_000)
                    }
                )
            assertEquals("session", response.getString("outcome"))
            id = checkNotNull(response.getString("session_id"))
            consumerPid = response.getInt("pid")
            assertTrue(consumerPid > 0 && consumerPid != appPid)
            report("session_start", checkNotNull(response.getString("session_report")))
        }

        private fun command(operation: String, local: Int = 0, public: Int = 0): JSONObject {
            val response =
                consumer.request(
                    Bundle().apply {
                        putString("transport", operation)
                        putString("session_id", id)
                        if (operation == "session-snapshot") {
                            putInt("local_cursor", local)
                            putInt("public_cursor", public)
                        }
                    }
                )
            assertEquals("session", response.getString("outcome"))
            assertEquals(consumerPid, response.getInt("pid"))
            assertEquals(appPid, Process.myPid())
            return JSONObject(checkNotNull(response.getString("session_report"))).also {
                assertEquals(id, it.getString("session_id"))
                assertEquals("CLOCK_BOOTTIME", it.getString("clock"))
                assertEquals(consumerPid, it.getInt("pid"))
                r06Custody?.observeSession(it)
                r06Checked("session-command") {
                    assertEquals(
                        "",
                        it.getString("failure"),
                        "Session failure must not become a blocking pass",
                    )
                }
            }
        }

        fun burst() {
            command("session-burst")
            requestedBursts++
        }

        private fun records(root: JSONObject, key: String): List<JSONObject> =
            root.getJSONArray(key).let { page ->
                (0 until page.length()).map { page.getJSONObject(it) }
            }

        fun dwell(stage: String, milliseconds: Long = 2000) {
            val begin = SystemClock.elapsedRealtimeNanos()
            Thread.sleep(milliseconds)
            val local = mutableListOf<JSONObject>()
            val public = mutableListOf<JSONObject>()
            var lc = 0
            var pc = 0
            var root: JSONObject
            do {
                root = command("session-snapshot", lc, pc)
                local += records(root, "local")
                public += records(root, "public")
                lc = root.getInt("next_local_cursor")
                pc = root.getInt("next_public_cursor")
            } while (lc < root.getInt("local_count") || pc < root.getInt("public_count"))
            val identity =
                root.getJSONObject("tcp_socket").toString() +
                    root.getJSONObject("udp_socket").toString()
            assertTrue(root.getJSONObject("tcp_socket").getInt("local_port") > 0)
            assertTrue(root.getJSONObject("udp_socket").getInt("local_port") > 0)
            if (socketIdentity == null) socketIdentity = identity
            else assertEquals(socketIdentity, identity)
            for (transport in listOf("tcp", "udp")) {
                assertTrue(
                    local.count {
                        it.getString("transport") == transport &&
                            it.getString("outcome") == "reply" &&
                            it.getLong("scheduled_ns") >= begin
                    } >= 3,
                    "Three replies per transport in stable dwell $stage",
                )
            }
            report(
                "session_dwell",
                JSONObject()
                    .put("stage", stage)
                    .put("begin_ns", begin)
                    .put("end_ns", SystemClock.elapsedRealtimeNanos())
                    .put("session_id", id)
                    .toString(),
            )
        }

        override fun close() {
            if (closed) return
            closed = true
            // Stop first, then collect immutable pages. Keep raw reports even when assertions fail.
            val response =
                consumer.request(
                    Bundle().apply {
                        putString("transport", "session-stop")
                        putString("session_id", id)
                    }
                )
            val stop = JSONObject(checkNotNull(response.getString("session_report")))
            val file = File(directory, "$id-session.jsonl")
            file.writeText(stop.toString() + "\n")
            val local = mutableListOf<JSONObject>()
            val public = mutableListOf<JSONObject>()
            var lc = 0
            var pc = 0
            do {
                val pageResponse =
                    consumer.request(
                        Bundle().apply {
                            putString("transport", "session-snapshot")
                            putString("session_id", id)
                            putInt("local_cursor", lc)
                            putInt("public_cursor", pc)
                        }
                    )
                val text = checkNotNull(pageResponse.getString("session_report"))
                file.appendText(text + "\n")
                val page = JSONObject(text)
                local += records(page, "local")
                public += records(page, "public")
                lc = page.getInt("next_local_cursor")
                pc = page.getInt("next_public_cursor")
            } while (lc < stop.getInt("local_count") || pc < stop.getInt("public_count"))
            report("session_trace", file.name)
            report("session_stop", stop.toString())
            clockMark("end")
            val failedUdp = local.filter {
                it.getString("outcome") in setOf("udp-send-error", "udp-reply-missing")
            }
            report(
                "rebuild_clock_marks",
                clockMarks.joinToString { "${it.kind}:${it.before}:${it.after}" },
            )
            val windows =
                if (failedUdp.isEmpty()) emptyList()
                else {
                    val log = shell(LocalContinuityWindows.logCommand(logSinceMillis))
                    val logFile = File(directory, "$id-rebuild.log")
                    logFile.writeText(log)
                    report("rebuild_log", logFile.name)
                    LocalContinuityWindows.measured(
                        log,
                        clockMarker,
                        continuityIntents,
                        clockMarks,
                        peer,
                    )
                }
            val usedRebuilds = mutableSetOf<Int>()
            r06Checked("session-stop") {
                try {
                    if (appListChangeAt != null) {
                        assertTrue(stop.getString("failure") in setOf("", "tcp-exchange"))
                        if (stop.getString("failure") == "tcp-exchange") {
                            assertTrue(
                                local.any {
                                    it.getString("transport") == "tcp" &&
                                        it.getString("outcome") in setOf("error", "cancelled") &&
                                        it.optString("error_class") == "java.net.SocketException" &&
                                        it.getLong("return_ns") >= checkNotNull(appListChangeAt)
                                },
                                "Only Android's post-app-list socket destruction is expected",
                            )
                        }
                        report("app_list_existing_socket_failure", stop.getString("failure"))
                    } else if (revokedAt == null) assertEquals("", stop.getString("failure"))
                    else
                        assertTrue(
                            stop.getString("failure") in
                                setOf(
                                    "tcp-exchange",
                                    "udp-exchange",
                                    "tcp-frame-watchdog",
                                    "udp-frame-watchdog",
                                ),
                            "Only the intentional Local retirement may fail",
                        )
                } catch (error: Throwable) {
                    r06Custody?.observeSession(stop)
                    throw error
                }
            }
            assertEquals("requested", stop.getString("stop_reason"))
            assertTrue(stop.getLong("stopped_ns") > stop.getLong("started_ns"))
            assertEquals(stop.getInt("local_count"), local.size)
            assertEquals(stop.getInt("public_count"), public.size)
            assertTrue(local.size >= 6 && local.size <= 4096)
            revokedAppliedAt?.let { applied ->
                val denied = local.filter { it.optLong("send_ns", Long.MIN_VALUE) >= applied }
                for (sample in denied) {
                    assertNotEquals(
                        "reply",
                        sample.getString("outcome"),
                        "Old Local socket replied after revocation",
                    )
                    sample.getString("nonce_frames").chunked(45).forEach { nonce ->
                        report(
                            "expect_none_${probeIndex++}",
                            "${sample.getString("transport")}:$nonce",
                        )
                    }
                }
                report("session_denied_queued_samples", denied.size)
            }
            assertEquals(
                requestedBursts,
                local.count { it.optInt("frame_count") == 40 },
                "Every requested larger-than-MTU write must be observed",
            )
            var maxLatency = 0L
            var maxGap = 0L
            for (transport in listOf("tcp", "udp")) {
                val samples = local.filter { it.getString("transport") == transport }
                samples.forEachIndexed { index, sample ->
                    assertEquals(index, sample.getInt("tick"))
                    val sendFailure =
                        if (sample.getString("outcome") == "udp-send-error")
                            LocalContinuityLedger.UdpSendFailure(
                                expectedScheduled =
                                    stop.getLong("started_ns") + index * 250_000_000L,
                                scheduled = sample.getLong("scheduled_ns"),
                                start = sample.getLong("start_ns"),
                                send = sample.getLong("send_ns"),
                                returned = sample.getLong("return_ns"),
                                errorClass = sample.getString("error_class"),
                                ioException = sample.getString("send_ioexception"),
                            )
                        else null
                    appListChangeAt?.let { boundary ->
                        if (sample.getString("outcome") in setOf("error", "cancelled")) {
                            assertTrue(sample.getString("outcome") in setOf("error", "cancelled"))
                            assertTrue(
                                maxOf(sample.optLong("return_ns"), sample.optLong("cancel_ns")) >=
                                    boundary
                            )
                            return@forEachIndexed
                        }
                        if (
                            sample.getString("outcome") == "udp-reply-missing" &&
                                sample.getLong("scheduled_ns") + 5_000_000_000L >= boundary
                        ) {
                            assertTrue(sample.getLong("expired_ns") >= boundary)
                            return@forEachIndexed
                        }
                        // Android closes the pre-existing UDP socket's path at the change too.
                        if (
                            sendFailure != null &&
                                LocalContinuityLedger.appListSocketDrop(
                                    transport,
                                    sendFailure,
                                    boundary,
                                    sample.getInt("socket_id"),
                                    stop.getJSONObject("udp_socket").getInt("object_id"),
                                )
                        ) {
                            report(
                                "app_list_udp_send_drop",
                                JSONObject()
                                    .put("session_id", id)
                                    .put("tick", index)
                                    .put("send_ns", sendFailure.send)
                                    .put("change_ns", boundary)
                                    .put("send_ioexception", sample.getString("send_ioexception")),
                            )
                            return@forEachIndexed
                        }
                    }
                    if (
                        LocalContinuityLedger.retirementOutcome(
                            transport,
                            sample.getString("outcome"),
                            sample.getLong("scheduled_ns"),
                            revokedAt,
                            sendFailure,
                        )
                    ) {
                        return@forEachIndexed
                    }
                    if (
                        sample.getString("outcome") in setOf("udp-send-error", "udp-reply-missing")
                    ) {
                        assertEquals("udp", transport)
                        val scheduled = stop.getLong("started_ns") + index * 250_000_000L
                        val deadline = scheduled + 5_000_000_000L
                        val send = sample.getLong("send_ns")
                        assertEquals(scheduled, sample.getLong("scheduled_ns"))
                        assertTrue(sample.getLong("start_ns") in scheduled..send)
                        assertTrue(sample.getLong("start_ns") - scheduled < 250_000_000L)
                        assertTrue(send <= deadline)
                        if (sample.getString("outcome") == "udp-send-error") {
                            checkNotNull(sendFailure)
                        } else {
                            assertEquals(deadline, sample.getLong("deadline_ns"))
                            assertTrue(sample.getLong("send_return_ns") in send..deadline)
                            assertTrue(
                                sample.getLong("expired_ns") in deadline..stop.getLong("stopped_ns")
                            )
                            assertFalse(sample.has("reply_ns"))
                            assertFalse(sample.has("send_ioexception"))
                        }
                        assertEquals(
                            stop.getJSONObject("udp_socket").getInt("object_id"),
                            sample.getInt("socket_id"),
                        )
                        assertEquals(
                            stop.getJSONObject("udp_socket").getInt("local_port"),
                            sample.getInt("local_port"),
                        )
                        assertEquals(
                            stop.getJSONObject("udp_socket").getString("local_address"),
                            sample.getString("local_address"),
                        )
                        val next = samples[LocalContinuityLedger.recoveryIndex(index, samples.size)]
                        assertEquals(index + 1, next.getInt("tick"))
                        assertEquals("reply", next.getString("outcome"))
                        assertEquals(scheduled + 250_000_000L, next.getLong("scheduled_ns"))
                        assertTrue(
                            next.getLong("start_ns") in
                                next.getLong("scheduled_ns")..next.getLong("send_ns")
                        )
                        assertTrue(
                            next.getLong("start_ns") - next.getLong("scheduled_ns") < 250_000_000L
                        )
                        assertTrue(
                            next.getLong("reply_ns") in
                                next.getLong("send_ns")..(next.getLong("scheduled_ns") +
                                        5_000_000_000L)
                        )
                        assertTrue(
                            next.getLong("send_return_ns") in
                                next.getLong("send_ns")..(next.getLong("scheduled_ns") +
                                        5_000_000_000L)
                        )
                        assertEquals(sample.getInt("socket_id"), next.getInt("socket_id"))
                        assertEquals(sample.getInt("local_port"), next.getInt("local_port"))
                        assertEquals(
                            sample.getString("local_address"),
                            next.getString("local_address"),
                        )
                        assertEquals(sample.getInt("socket_id"), next.getInt("reply_socket_id"))
                        assertEquals(sample.getInt("local_port"), next.getInt("reply_local_port"))
                        // The request or its reply may cross the gap. Only the send
                        // start uses the explicit 100 ms pre-DOWN exchange margin.
                        val window =
                            LocalContinuityWindows.accept(
                                send,
                                windows,
                                usedRebuilds,
                            )
                        maxGap = maxOf(maxGap, sample.getLong("cadence_gap_ns"))
                        report(
                            "tolerated_udp_exchange",
                            JSONObject()
                                .put("session_id", id)
                                .put("tick", index)
                                .put("outcome", sample.getString("outcome"))
                                .put("send_ns", send)
                                .put("down_ns", window.down)
                                .put("route_ns", window.installed)
                                .put("rebuild", window.rebuild),
                        )
                        return@forEachIndexed
                    }
                    assertEquals("reply", sample.getString("outcome"))
                    assertEquals(
                        stop.getLong("started_ns") + index * 250_000_000L,
                        sample.getLong("scheduled_ns"),
                    )
                    val latency = sample.getLong("reply_ns") - sample.getLong("scheduled_ns")
                    assertTrue(latency in 0..5_000_000_000L)
                    maxLatency = maxOf(maxLatency, latency)
                    maxGap = maxOf(maxGap, sample.getLong("cadence_gap_ns"))
                    assertEquals(45 * sample.getInt("frame_count"), sample.getInt("bytes"))
                    assertEquals(sample.getInt("bytes"), sample.getString("nonce_frames").length)
                }
            }
            public.forEachIndexed { index, sample ->
                assertEquals(index, sample.getInt("tick"))
                assertEquals(
                    stop.getLong("started_ns") + index * 500_000_000L,
                    sample.getLong("scheduled_ns"),
                )
                val cancelledByRevocation =
                    sample.getString("outcome") == "cancelled" &&
                        (revokedAt ?: appListChangeAt)?.let { sample.getLong("return_ns") >= it } ==
                            true
                assertTrue(
                    cancelledByRevocation ||
                        sample.getString("outcome") in setOf("connected", "network-error")
                )
                if (cancelledByRevocation && !sample.has("start_ns")) return@forEachIndexed
                assertTrue(sample.getLong("start_ns") >= sample.getLong("scheduled_ns"))
                assertTrue(
                    sample.getLong("return_ns") - sample.getLong("scheduled_ns") <= 1_000_000_000L
                )
                assertTrue(sample.getLong("close_ns") >= sample.getLong("return_ns"))
            }
            expectedPublic?.let { connected ->
                val successes = public.count { it.getString("outcome") == "connected" }
                if (connected)
                    assertTrue(successes > 0, "Stable Connected needs a public-pump positive")
                else assertEquals(0, successes, "Stable Disconnected must not connect publicly")
            }
            report(
                "session_counts",
                "local=${local.size},public=${public.size},max_latency_ns=$maxLatency,max_gap_ns=$maxGap",
            )
            report("failed_udp_exchange_count", failedUdp.size)
        }
    }

    internal fun peerPolicy(
        enabled: Boolean = true,
        ruleEnabled: Boolean = true,
        cidr: String = "$peer/32",
        wifi: List<SsidIdentity> = emptyList(),
    ) =
        LocalNetworkAccess(
            enabled,
            listOf(
                LocalBypassRule(
                    UUID.randomUUID(),
                    "Krtek delivery fixture",
                    ruleEnabled,
                    listOf(checkNotNull(LocalCidr.parse(cidr).getOrNull())),
                    wifi,
                )
            ),
            skipLocalRulesForExcludedApps = true,
        )

    private fun withPolicy(
        repository: SettingsRepository,
        policy: LocalNetworkAccess,
        block: () -> Unit,
    ) = runBlocking {
        val original = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
        try {
            assertTrue(repository.setLocalNetworkAccess(policy, original).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == policy }
            }
            block()
        } finally {
            val current = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            check(current == original || current == policy) { "Concurrent configuration retained" }
            if (current != original)
                assertTrue(repository.setLocalNetworkAccess(original, current).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == original }
            }
            report("policy_restored", true)
        }
    }

    private fun deliveryCase(
        policy: LocalNetworkAccess,
        forwarding: ForwardingAvailability,
        expect: String,
        ruleState: LocalRuleState? = null,
        transports: List<String> = listOf("tcp", "udp"),
    ) =
        withConsumer(null) { consumer, repository, connection ->
            withPolicy(repository, policy) {
                awaitState(repository, connection, forwarding, ruleState)
                transports.forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, forwarding)
                    probeSocket(consumer, transport, expect)
                }
            }
        }

    @Test
    fun approvedPeerAnswersTcpAndUdpWhileDisconnected() =
        deliveryCase(
            peerPolicy(),
            ForwardingAvailability.Active,
            "reply",
            LocalRuleState.Forwarding,
        )

    @Test
    fun unapprovedAddressStaysBlocked() =
        deliveryCase(
            peerPolicy(cidr = args.getString("krtek_unapproved_rule", "10.0.2.99/32")),
            ForwardingAvailability.Active,
            "blocked",
        )

    @Test
    fun disabledRuleStaysBlocked() =
        deliveryCase(peerPolicy(ruleEnabled = false), ForwardingAvailability.Off, "blocked")

    @Test
    fun policyOffStaysBlocked() =
        deliveryCase(peerPolicy(enabled = false), ForwardingAvailability.Off, "blocked")

    @Test
    fun publicAddressStaysBlocked() =
        deliveryCase(
            peerPolicy(),
            ForwardingAvailability.Active,
            "blocked",
            transports = listOf("tcp-connect"),
        )

    @Test
    fun announcedRuleWithUnmetConditionsIsDropped() =
        withConsumer(null) { consumer, repository, connection ->
            // Revocation kills this process. The guest runner owns staging and exact
            // restoration, with separate invocations around revoke and re-grant.
            val stage = args.getString("krtek_location_stage", "granted")
            check(stage in setOf("granted", "denied", "regranted"))
            val granted = stage != "denied"
            assertEquals("3", shell("settings get secure location_mode"))
            listOf(
                    "android.permission.ACCESS_COARSE_LOCATION",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_BACKGROUND_LOCATION",
                )
                .forEach { permission ->
                    val observed = permissionState(target.packageName, permission)
                    report("location_$permission", observed)
                    assertEquals(
                        granted,
                        observed.first,
                        "Location permissions must be staged externally",
                    )
                }
            report("location_stage", stage)
            val synthetic = checkNotNull(SsidIdentity.fromUserText("krtek-m3-different-wifi"))
            val policy = peerPolicy(wifi = listOf(synthetic))
            withPolicy(repository, policy) {
                // The enabled policy is the observation demand; rules off would observe nothing.
                if (granted) {
                    val known = runBlocking {
                        withTimeout(30_000) {
                                repository.localNetworkStatus.filterNotNull().first {
                                    it.currentWifi is ConnectedWifi.Known
                                }
                            }
                            .currentWifi as ConnectedWifi.Known
                    }
                    assertNotEquals(known.ssid, synthetic)
                    report("location_wifi", "Known")
                }
                awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Active,
                    LocalRuleState.Inactive(
                        if (granted) LocalRuleInactiveReason.DifferentWifi
                        else LocalRuleInactiveReason.LocationPermissionMissing
                    ),
                )
                listOf("tcp", "udp").forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    probeSocket(consumer, transport, "blocked")
                }
            }
        }

    @Test
    fun connectDeliversAndDisconnectResumes() =
        withConsumer(null) { consumer, repository, connection ->
            val policy = peerPolicy()
            withPolicy(repository, policy) {
                try {
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                    )
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    runBlocking {
                        assertTrue(connection.connect().isRight())
                        withTimeout(60_000) {
                            connection.tunnelState.first { it is TunnelState.Connected }
                        }
                    }
                    report("cycle_tunnel", "Connected")
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                        "Connected",
                    )
                    listOf("tcp", "udp").forEach { transport ->
                        consumer.identity()
                        appliedConfiguration(policy, ForwardingAvailability.Active, "Connected")
                        probeSocket(consumer, transport, "reply")
                    }
                    probeExit(consumer, "mullvad")
                    probeIcmp(consumer, "echo")
                } finally {
                    runBlocking {
                        assertTrue(
                            connection
                                .disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON)
                                .isRight()
                        )
                        withTimeout(30_000) {
                            connection.tunnelState.first { it is TunnelState.Disconnected }
                        }
                    }
                    report("cycle_tunnel", "Disconnected")
                }
                awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Active,
                    LocalRuleState.Forwarding,
                )
                listOf("tcp", "udp").forEach { transport ->
                    consumer.identity()
                    appliedConfiguration(policy, ForwardingAvailability.Active)
                    probeSocket(consumer, transport, "reply")
                }
            }
        }

    @Test
    fun mullvadLargeUdpFragments() =
        withConsumer(null, testTimeout = 3.minutes) { consumer, repository, connection ->
            // Instrumentation replaces the app process/TUN. Attach only after
            // this invocation has acknowledged its own final Connected capture.
            runBlocking {
                val state = withTimeout(30_000) { connection.tunnelState.first() }
                assertTrue(state is TunnelState.Connected)
            }
            val policy = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            val forwarding =
                if (policy.enabled && policy.rules.any { it.enabled && it.cidrs.isNotEmpty() })
                    ForwardingAvailability.Active
                else ForwardingAvailability.Off
            awaitState(repository, connection, forwarding, null, "Connected")
            val capture = appliedConfiguration(policy, forwarding, "Connected")
            probeExit(consumer, "mullvad")
            val token = checkNotNull(args.getString("krtek_capture_token"))
            check(token.matches(Regex("[a-z0-9-]{1,64}")))
            captureBarrier(token, "start", capture)
            try {
                // Both small controls precede either large echo. Failure is a
                // real observation, never silently retried with another peer.
                listOf(32, 3072).forEach { size ->
                    listOf(4, 6).forEach { family ->
                        consumer.identity()
                        val result =
                            consumer.request(
                                Bundle().apply {
                                    putString("transport", "gateway-echo")
                                    putInt("family", family)
                                    putInt("payload_size", size)
                                }
                            )
                        val raw = checkNotNull(result.getString("echo_report"))
                        saveLargeProbe("echo_report_${family}_$size", raw)
                        val decoded = JSONObject(raw)
                        assertEquals(family, decoded.getInt("family"))
                        assertEquals(result.getInt("uid"), decoded.getInt("uid"))
                        assertEquals("gateway-echo", result.getString("outcome"), raw)
                        assertTrue(decoded.getBoolean("validated"))
                        assertEquals(size + 8, decoded.getInt("sent"))
                        assertEquals(size + 8, decoded.getInt("received"))
                        assertEquals(size * 2, decoded.getString("payload_hex").length)
                        assertTrue(decoded.getBoolean("option_set"))
                    }
                }
                listOf(4, 6).forEach { family ->
                    consumer.identity()
                    val result =
                        consumer.request(
                            Bundle().apply {
                                putString("transport", "fragmented-udp")
                                putInt("family", family)
                            }
                        )
                    val raw = checkNotNull(result.getString("fragment_report"))
                    saveLargeProbe("fragment_report_$family", raw)
                    val decoded = JSONObject(raw)
                    assertEquals(family, decoded.getInt("family"))
                    assertEquals(result.getInt("uid"), decoded.getInt("uid"))
                    // DNS is informational: retain the complete success or failure
                    // receipt and independent outgoing-fragment audit either way.
                    report("dns_outcome_$family", checkNotNull(result.getString("outcome")))
                    if (result.getString("outcome") == "fragmented-udp") {
                        assertTrue(decoded.getBoolean("validated"))
                        assertEquals(4096, decoded.getInt("sent"))
                        assertEquals(8192, decoded.getString("query_hex").length)
                        assertEquals(0, decoded.getInt("option_value"))
                        assertTrue(decoded.getBoolean("option_set"))
                    }
                    runBlocking {
                        val state = withTimeout(30_000) { connection.tunnelState.first() }
                        assertTrue(state is TunnelState.Connected)
                    }
                }
                probeExit(consumer, "mullvad")
            } finally {
                val finalCapture = appliedConfiguration(policy, forwarding, "Connected")
                assertEquals(capture, finalCapture, "Capture epoch changed during probes")
                captureBarrier(token, "finish", finalCapture)
            }
        }

    /** Explicit selectors: the runner stages numeric peers, policy and capture observer. */
    @Test fun localLargeUdpEcho() = localUdpCase("echo")

    @Test fun localLargeUdpDenied() = localUdpCase("denied")

    @Test fun localUdpOversized() = localUdpCase("oversized")

    @Test fun localUdpReplySizeLimit() = localUdpCase("oversized-reply")

    private fun localUdpCase(expect: String) {
        val method =
            when (expect) {
                "echo" -> "localLargeUdpEcho"
                "denied" -> "localLargeUdpDenied"
                "oversized" -> "localUdpOversized"
                else -> "localUdpReplySizeLimit"
            }
        assumeTrue(
            args.getString("class").orEmpty().split(',').contains("${javaClass.name}#$method"),
            "Select this staged Local UDP method explicitly",
        )
        val destination = checkNotNull(args.getString("krtek_peer"))
        check(InetAddresses.isNumericAddress(destination))
        val address = InetAddresses.parseNumericAddress(destination)
        val family = if (address.address.size == 4) 4 else 6
        val cidr = canonicalPrefix("$destination/${if (family == 4) 32 else 128}")
        val maximum = if (family == 4) 65507 else 65487
        val size =
            args
                .getString(
                    "krtek_payload_size",
                    if (expect.startsWith("oversized")) "${maximum + 1}" else "4096",
                )
                .toInt()
        check(if (expect.startsWith("oversized")) size == maximum + 1 else size in 0..maximum)
        val requestSize = if (expect == "oversized-reply") 32 else size
        val token = checkNotNull(args.getString("krtek_capture_token"))
        check(token.matches(Regex("[a-z0-9-]{1,64}")))
        withConsumer(ForwardingAvailability.Active, testTimeout = 3.minutes) {
            consumer,
            repository,
            _ ->
            val policy = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            val rule =
                policy.rules.single { rule ->
                    rule.enabled && rule.cidrs.any { canonicalPrefix(it.toString()) == cidr }
                }
            assertTrue(policy.enabled)
            val expectedRule =
                if (expect == "denied")
                    LocalRuleState.Inactive(LocalRuleInactiveReason.DifferentWifi)
                else LocalRuleState.Forwarding
            // The old short-probe helper intentionally retains its IPv4 /32 contract.
            // This operation observes its own explicit family-sized rule instead.
            runBlocking {
                withTimeout(30_000) {
                    repository.localNetworkStatus.filterNotNull().first { status ->
                        status.forwarding == ForwardingAvailability.Active &&
                            status.rules.any { it.id == rule.id && it.state == expectedRule }
                    }
                }
            }
            report("local_udp_rule", "$cidr:$expectedRule")
            val capture = appliedConfiguration(policy, ForwardingAvailability.Active)
            consumer.identity()
            val eligible: (mullvad_daemon.management_interface.LocalNetworkStatus) -> Boolean =
                { status ->
                    val selected = status.rules.singleOrNull { it.id == rule.id.toString() }
                    status.forwarding ==
                        mullvad_daemon.management_interface.LocalNetworkStatus
                            .ForwardingAvailability
                            .ACTIVE &&
                        selected != null &&
                        if (expect == "denied") {
                            selected.state ==
                                mullvad_daemon.management_interface.LocalRuleStatus.State
                                    .INACTIVE &&
                                selected.reason ==
                                    mullvad_daemon.management_interface.LocalRuleInactiveReason
                                        .DIFFERENT_WIFI
                        } else {
                            selected.state ==
                                mullvad_daemon.management_interface.LocalRuleStatus.State
                                    .FORWARDING && selected.reason == null
                        }
                }
            withOrderedDaemonEvents(eligible) { events, rpc ->
                // Subscribe before the initial snapshot. Its revision excludes
                // earlier events; the end RPC fences all later publications.
                val start = runBlocking {
                    withTimeout(10_000) { rpc.GetLocalNetworkStatus().execute(Unit) }
                }
                assertTrue(eligible(start), "Unexpected Local status before UDP probe")
                captureBarrier(token, "start", capture)
                try {
                    val result = runBlocking {
                        withContext(Dispatchers.IO) {
                            consumer
                                .request(
                                    Bundle().apply {
                                        putString(
                                            "transport",
                                            if (expect == "oversized-reply") "local-udp-reply-limit"
                                            else "local-udp-echo",
                                        )
                                        putString("destination", destination)
                                        putInt("payload_size", size)
                                    }
                                )
                                .also {
                                    // Preserve raw evidence before checking the
                                    // ordered status window or terminal fence.
                                    saveLargeProbe(
                                        "local_udp_${expect}_${family}_$size",
                                        checkNotNull(it.getString("local_udp_report")),
                                    )
                                }
                        }
                    }
                    val finish = runBlocking {
                        withTimeout(10_000) { rpc.GetLocalNetworkStatus().execute(Unit) }
                    }
                    assertTrue(eligible(finish), "Unexpected Local status at UDP probe end")
                    runBlocking {
                        withTimeout(10_000) {
                            events.awaitLocal(start.revision.toULong(), finish.revision.toULong())
                        }
                    }
                    val raw = checkNotNull(result.getString("local_udp_report"))
                    val decoded = JSONObject(raw)
                    assertEquals(family, decoded.getInt("family"))
                    assertEquals(result.getInt("uid"), decoded.getInt("uid"))
                    assertEquals(requestSize, decoded.getInt("payload_size"))
                    assertEquals(18081, decoded.getInt("remote_port"))
                    assertTrue(decoded.getBoolean("option_set"))
                    val expectedPayload =
                        LocalUdpPayload.create(
                            requestSize,
                            decoded
                                .getString("nonce")
                                .chunked(2)
                                .map { it.toInt(16).toByte() }
                                .toByteArray(),
                        )
                    assertEquals(
                        ProbePayloadSummary.sha256(expectedPayload, expectedPayload.size),
                        decoded.getString("payload_sha256"),
                    )
                    assertFalse(decoded.has("payload_hex"))
                    assertFalse(decoded.has("reply_hex"))
                    if (expect == "oversized-reply") {
                        assertEquals(size, decoded.getInt("requested_reply_size"))
                    }
                    if (expect == "echo") {
                        assertEquals("local-udp-echo", result.getString("outcome"), raw)
                        assertTrue(decoded.getBoolean("validated"))
                        assertEquals(size, decoded.getInt("sent"))
                        assertEquals(size, decoded.getInt("received"))
                        assertTrue(decoded.getBoolean("bytes_equal"))
                        assertTrue(decoded.getBoolean("source_matches"))
                        assertEquals(
                            decoded.getString("payload_sha256"),
                            decoded.getString("reply_sha256"),
                        )
                        assertEquals(
                            address,
                            InetAddresses.parseNumericAddress(decoded.getString("reply_source")),
                        )
                        assertEquals(18081, decoded.getInt("reply_port"))
                    } else {
                        assertEquals("failed", result.getString("outcome"), raw)
                        assertFalse(decoded.optBoolean("validated"))
                        assertFalse(
                            decoded.has("received"),
                            "No shortened or other datagram is allowed",
                        )
                        if (expect == "oversized" && family == 4) {
                            // IPv4's protocol maximum is also the kernel send limit.
                            // This is EMSGSIZE, not proof of the Local typed boundary.
                            assertEquals("send", decoded.getString("error_stage"))
                            assertEquals(
                                android.system.OsConstants.EMSGSIZE,
                                decoded.getInt("errno"),
                            )
                        } else {
                            assertEquals(requestSize, decoded.getInt("sent"))
                            assertEquals("receive", decoded.getString("error_stage"))
                            assertTrue(
                                decoded.getInt("errno") in
                                    setOf(
                                        android.system.OsConstants.EAGAIN,
                                        android.system.OsConstants.ETIMEDOUT,
                                    )
                            )
                        }
                        report(
                            if (expect == "oversized-reply")
                                "local_udp_requires_peer_reply_limit_audit"
                            else "local_udp_requires_peer_silence_audit",
                            true,
                        )
                    }
                } finally {
                    val finalCapture = appliedConfiguration(policy, ForwardingAvailability.Active)
                    assertEquals(
                        capture,
                        finalCapture,
                        "Capture epoch changed during Local UDP probe",
                    )
                    captureBarrier(token, "finish", finalCapture)
                }
            }
        }
    }

    private fun saveLargeProbe(name: String, raw: String) {
        val folder =
            File(target.filesDir, "krtek-probes").apply {
                check(isDirectory || mkdir())
            }
        val file = File(folder, "$name-${UUID.randomUUID()}.json")
        file.writeText(raw)
        report(name, file.absolutePath)
    }

    private fun captureBarrier(token: String, phase: String, capture: AppliedCapture) =
        runBlocking {
            val folder = File(target.filesDir, "krtek-probes")
            val ready = File(folder, "$token-$phase.json")
            val ack = File(folder, "$token-$phase.ack")
            check(!ready.exists() && !ack.exists())
            val raw =
                JSONObject()
                    .apply {
                        put("token", token)
                        put("phase", phase)
                        put("pid", Process.myPid())
                        put("generation", capture.generation)
                        put("handle", capture.handle)
                        put("interface", capture.interfaceName)
                        put("net_id", capture.netId)
                        put(
                            "ifindex",
                            java.net.NetworkInterface.getByName(capture.interfaceName).index,
                        )
                        put("ready_ns", SystemClock.elapsedRealtimeNanos())
                    }
                    .toString()
            ready.writeText(raw)
            report("capture_barrier_$phase", ready.absolutePath)
            withTimeout(45_000) {
                while (!ack.isFile) delay(100)
            }
            assertEquals(raw, ack.readText(), "Observer must acknowledge this exact epoch")
        }

    @Test
    fun consumerProbe() {
        val transport = args.getString("krtek_probe_transport")
        val expect = args.getString("krtek_probe_expect")
        val state = args.getString("krtek_probe_forwarding")
        assumeTrue(transport != null && expect != null && state != null, "Probe arguments required")
        check(transport in setOf("tcp", "udp", "tcp-connect", "lookup", "exit-check", "icmp-check"))
        val forwarding = ForwardingAvailability.valueOf(checkNotNull(state))
        check(
            forwarding in
                setOf(
                    ForwardingAvailability.Active,
                    ForwardingAvailability.Off,
                    ForwardingAvailability.PausedWhileConnected,
                )
        )
        check(
            when (transport) {
                "lookup" ->
                    expect == "record" && forwarding != ForwardingAvailability.PausedWhileConnected
                "exit-check" -> expect in setOf("mullvad", "direct", "record")
                "icmp-check" -> expect in setOf("echo", "record", "blocked")
                else -> expect in setOf("reply", "connected", "blocked")
            }
        )
        val explicitReason =
            args.getString("krtek_probe_rule_state")?.let {
                check(it in setOf("DifferentWifi", "ObserverUnavailable"))
                LocalRuleState.Inactive(LocalRuleInactiveReason.valueOf(it))
            }
        val ruleState =
            explicitReason
                ?: if (forwarding == ForwardingAvailability.Active && expect == "reply")
                    LocalRuleState.Forwarding
                else null
        withConsumer(forwarding) { consumer, repository, connection ->
            consumer.identity()
            awaitState(repository, connection, forwarding, ruleState)
            appliedConfiguration(
                checkNotNull(repository.settingsUpdates.value?.localNetworkAccess),
                forwarding,
            )
            if (transport == "exit-check") {
                probeExit(consumer, checkNotNull(expect))
            } else if (transport == "icmp-check") {
                probeIcmp(consumer, checkNotNull(expect))
            } else if (transport == "lookup") {
                val hostname = args.getString("krtek_lookup_host", "example.com")
                assertEquals("example.com", hostname)
                val result =
                    consumer.request(
                        Bundle().apply {
                            putString("transport", "lookup")
                            putString("hostname", hostname)
                        }
                    )
                assertEquals(
                    "lookup",
                    result.getString("outcome"),
                    "Lookup must complete, not a harness/IPC/deadline failure",
                )
                val outcome = result.getString("lookup_outcome")
                check(outcome == "resolved" || outcome == "failed")
                if (outcome == "resolved") assertTrue(result.getInt("address_count") > 0)
                else {
                    assertTrue(checkNotNull(result.getString("error_class")).contains('.'))
                    assertEquals(0, result.getInt("address_count"))
                }
                report("lookup_hostname", hostname)
                report("lookup_outcome", checkNotNull(outcome))
                report("lookup_address_count", result.getInt("address_count"))
                result.getString("error_class")?.let { report("lookup_error_class", it) }
                report("lookup_elapsed_ms", result.getLong("elapsed_ms"))
            } else {
                probeSocket(consumer, checkNotNull(transport), checkNotNull(expect))
            }
        }
    }

    internal fun setPolicy(repository: SettingsRepository, policy: LocalNetworkAccess) =
        runBlocking {
            val current = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            assertTrue(repository.setLocalNetworkAccess(policy, current).isRight())
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == policy }
            }
            // Status revisions describe semantic status, not every policy edit.
            // A covered CIDR edit can leave the same rule rows and ready capture.
            withTimeout(30_000) {
                repository.localNetworkStatus.filterNotNull().first { status ->
                    status.rules.map { it.id } == policy.rules.map { it.id }
                }
            }
        }

    internal fun disconnect(connection: ConnectionProxy) = runBlocking {
        continuityIntent("disconnect")
        assertTrue(
            connection.disconnect(DisconnectReason.USER_INITIATED_DISCONNECT_BUTTON).isRight()
        )
        withTimeout(60_000) { connection.tunnelState.first { it is TunnelState.Disconnected } }
        report("cycle_tunnel", "Disconnected")
    }

    internal fun connectedCase(
        testTimeout: Duration = 1.minutes,
        block: (Consumer, SettingsRepository, ConnectionProxy, LocalNetworkAccess) -> Unit,
    ) =
        withConsumer(null, testTimeout = testTimeout) { consumer, repository, connection ->
            val original = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            val policy = peerPolicy()
            try {
                setPolicy(repository, policy)
                runBlocking {
                    assertTrue(connection.connect().isRight())
                    withTimeout(90_000) {
                        connection.tunnelState.first { it is TunnelState.Connected }
                    }
                }
                report("cycle_tunnel", "Connected")
                awaitAppliedState(repository, connection, "Connected")
                block(consumer, repository, connection, policy)
            } catch (error: Throwable) {
                r06Custody?.recordFailure("connected-body", error)
                throw error
            } finally {
                r06Checked("policy-restoration") {
                    // Disconnect first so restoration never reconnects after instrumentation exits.
                    disconnect(connection)
                    setPolicy(repository, original)
                    awaitState(
                        repository,
                        connection,
                        if (
                            original.enabled &&
                                original.rules.any { it.enabled && it.cidrs.isNotEmpty() }
                        )
                            ForwardingAvailability.Active
                        else ForwardingAvailability.Off,
                        null,
                        "Disconnected",
                    )
                    report("policy_restored", true)
                }
            }
        }

    internal fun connectedProof(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        previousGeneration: String? = null,
    ): AppliedCapture {
        val config =
            awaitAppliedState(
                repository,
                connection,
                "Connected",
                previousGeneration = previousGeneration,
            )
        consumer.identity()
        listOf("tcp", "udp").forEach { probeSocket(consumer, it, "reply") }
        probeExit(consumer, "mullvad")
        return config
    }

    private fun nativeProof(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
    ): AppliedCapture {
        val config =
            awaitAppliedState(repository, connection, "Connected", ForwardingAvailability.Off, null)
        consumer.identity()
        probeExit(consumer, "mullvad")
        return config
    }

    private fun awaitAppliedState(
        repository: SettingsRepository,
        connection: ConnectionProxy,
        expectedTunnel: String,
        forwarding: ForwardingAvailability = ForwardingAvailability.Active,
        ruleState: LocalRuleState? = LocalRuleState.Forwarding,
        previousGeneration: String? = null,
    ): AppliedCapture {
        val policy = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
        awaitState(repository, connection, forwarding, ruleState, expectedTunnel)
        val capture = appliedConfiguration(policy, forwarding, expectedTunnel, previousGeneration)
        val uid = target.packageManager.getApplicationInfo(testPackage, 0).uid
        assertTrue(uidIncluded(capture.uids, uid), "Applied capture must include the consumer UID")
        report(
            "applied_state",
            JSONObject()
                .put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
                .put("tunnel", expectedTunnel)
                .put("forwarding", forwarding.toString())
                .put("capture_generation", capture.generation)
                .put("net_id", capture.netId)
                .put("consumer_uid", uid),
        )
        return capture
    }

    private fun normalConfiguration(
        native: AppliedCapture,
        managed: AppliedCapture,
        policy: LocalNetworkAccess,
    ) {
        assertEquals(native.addresses, managed.addresses, "Local off retains fixed capture sources")
        assertEquals(native.dns, managed.dns, "Local off retains ordinary target DNS")
        assertEquals(native.mtu, managed.mtu, "Local off retains upstream capture MTU")
        val local =
            policy.rules
                .filter { policy.enabled && it.enabled }
                .flatMap { it.cidrs }
                .map { canonicalPrefix(it.toString()) }
                .toSet()
        assertEquals(
            CaptureReadiness.minimalRoutes(native.routes + local) +
                (managed.routes intersect managed.addresses),
            managed.routes,
            "Only announced local routes augment the ordinary router projection",
        )
        assertEquals(native.uids, managed.uids, "Local off retains ordinary app exclusions")
        report("normal_configuration_equal", true)
    }

    internal fun withNativeControl(
        consumer: Consumer,
        repository: SettingsRepository,
        connection: ConnectionProxy,
        policy: LocalNetworkAccess,
    ): AppliedCapture {
        setPolicy(repository, policy.copy(enabled = false))
        val native = nativeProof(consumer, repository, connection)
        setPolicy(repository, policy)
        val managed = connectedProof(consumer, repository, connection)
        normalConfiguration(native, managed, policy)
        return managed
    }

    @Test
    fun approvedPeerAnswersWhileConnectedThroughMullvad() =
        connectedCase { consumer, repository, connection, policy ->
            withNativeControl(consumer, repository, connection, policy)
        }

    @Test
    fun unmetConnectedRuleDoesNotFallThroughToRelay() =
        connectedCase { consumer, repository, connection, policy ->
            val before = connectedProof(consumer, repository, connection)
            val known = runBlocking {
                withTimeout(30_000) {
                        repository.localNetworkStatus.filterNotNull().first {
                            it.currentWifi is ConnectedWifi.Known
                        }
                    }
                    .currentWifi as ConnectedWifi.Known
            }
            val different = checkNotNull(SsidIdentity.fromUserText("krtek-m3-different-wifi"))
            assertNotEquals(known.ssid, different)
            val unmet =
                policy.copy(rules = policy.rules.map { it.copy(ssidIds = listOf(different)) })
            setPolicy(repository, unmet)
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Inactive(LocalRuleInactiveReason.DifferentWifi),
                "Connected",
            )
            assertEquals(
                before,
                appliedConfiguration(unmet, ForwardingAvailability.Active, "Connected"),
                "Condition changes retain capture identity",
            )
            listOf("tcp", "udp").forEach { probeSocket(consumer, it, "blocked") }
            probeExit(consumer, "mullvad")
            setPolicy(repository, policy)
            assertEquals(
                before,
                connectedProof(consumer, repository, connection),
                "Recovery occurs before instrumentation restarts",
            )
            report("condition_identity_retained", true)
        }

    @Test
    fun connectedPolicyOffKeepsNativeVpnWorking() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            withNativeControl(consumer, repository, connection, policy)
        }

    @Test
    fun lastEnabledDestinationSwitchesCaptureMode() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            val disabled = policy.copy(rules = policy.rules.map { it.copy(enabled = false) })
            setPolicy(repository, disabled)
            val disabledNative = nativeProof(consumer, repository, connection)
            setPolicy(repository, policy)
            normalConfiguration(
                disabledNative,
                connectedProof(consumer, repository, connection),
                policy,
            )
            // Deleting the rule is the valid way to remove its last destination.
            setPolicy(repository, policy.copy(rules = emptyList()))
            val emptyNative = nativeProof(consumer, repository, connection)
            setPolicy(repository, policy)
            normalConfiguration(
                emptyNative,
                connectedProof(consumer, repository, connection),
                policy,
            )
            report("last_destination_controls", "disabled,deleted")
        }

    @Test
    fun disconnectRestoresPartialRoutesAndBlocking() =
        connectedCase { consumer, repository, connection, policy ->
            connectedProof(consumer, repository, connection)
            disconnect(connection)
            awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Disconnected",
            )
            appliedConfiguration(policy, ForwardingAvailability.Active, "Disconnected")
            listOf("tcp", "udp").forEach { probeSocket(consumer, it, "reply") }
            probeSocket(consumer, "tcp-connect", "blocked")
        }

    @Test
    fun connectedConfigurationChangesReconcileBeforeDelivery() =
        connectedCase(testTimeout = R06_SEQUENCE_TEST_TIMEOUT) {
            consumer,
            repository,
            connection,
            policy ->
            val original = checkNotNull(repository.settingsUpdates.value)
            val split =
                (target.applicationContext as MullvadApplication)
                    .getKoin()
                    .get<SplitTunnelingRepository>()
            val excluded =
                PackageName(args.getString("krtek_exclusion_package", "com.android.deskclock"))
            val excludedUid = target.packageManager.getApplicationInfo(excluded.value, 0).uid
            assertNotEquals(target.applicationInfo.uid, excludedUid)
            assertNotEquals(
                target.packageManager.getApplicationInfo(testPackage, 0).uid,
                excludedUid,
            )
            assertTrue(PackageName(testPackage) !in original.splitTunnelSettings.excludedApps)
            assertTrue(excluded !in original.splitTunnelSettings.excludedApps)
            val before = connectedProof(consumer, repository, connection)
            try {
                val announced =
                    policy.copy(
                        rules =
                            policy.rules.map {
                                it.copy(
                                    cidrs =
                                        it.cidrs +
                                            checkNotNull(
                                                LocalCidr.parse("10.0.2.99/32").getOrNull()
                                            )
                                )
                            }
                    )
                setPolicy(repository, announced)
                val added = connectedProof(consumer, repository, connection)
                assertEquals(before, added, "Default-covered CIDRs reuse the entire capture")

                // The peer must become newly authorized by the added rule, not
                // keep replying through its original rule or the Mullvad path.
                val withoutPeer =
                    policy.copy(
                        rules =
                            policy.rules.map {
                                it.copy(
                                    id = UUID.randomUUID(),
                                    cidrs =
                                        listOf(
                                            checkNotNull(
                                                LocalCidr.parse("10.0.2.99/32").getOrNull()
                                            )
                                        ),
                                )
                            }
                    )
                setPolicy(repository, withoutPeer)
                assertEquals(
                    before,
                    appliedConfiguration(withoutPeer, ForwardingAvailability.Active, "Connected"),
                )
                listOf("tcp", "udp").forEach { probeSocket(consumer, it, "blocked") }
                val editedExisting =
                    withoutPeer.copy(
                        rules =
                            withoutPeer.rules.map { it.copy(cidrs = policy.rules.single().cidrs) }
                    )
                assertEquals(withoutPeer.rules.map { it.id }, editedExisting.rules.map { it.id })
                setPolicy(repository, editedExisting)
                assertEquals(
                    before,
                    connectedProof(consumer, repository, connection),
                    "Editing the same rule ID newly authorizes TCP/UDP without a new capture",
                )
                report("edited_rule_destination_delivered", peer)
                setPolicy(repository, withoutPeer)
                appliedConfiguration(withoutPeer, ForwardingAvailability.Active, "Connected")
                listOf("tcp", "udp").forEach { probeSocket(consumer, it, "blocked") }
                val previousRevision = checkNotNull(repository.localNetworkStatus.value).revision
                val peerRule = policy.rules.single().copy(id = UUID.randomUUID())
                val newRule = withoutPeer.copy(rules = withoutPeer.rules + peerRule)
                setPolicy(repository, newRule)
                val newStatus =
                    awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                        "Connected",
                    )
                assertTrue(newStatus.revision > previousRevision, "A new rule row is published")
                assertEquals(newRule.rules.map { it.id }, newStatus.rules.map { it.id })
                assertEquals(
                    before,
                    connectedProof(consumer, repository, connection),
                    "Newly authorized TCP/UDP delivery does not require a new capture",
                )
                report("new_rule_destination_delivered", peer)
                report(
                    "new_rule_status_revision",
                    "before=$previousRevision,after=${newStatus.revision}",
                )
                report("covered_route_reuses_capture", true)
                setPolicy(repository, policy)
                val restoredRoutes = connectedProof(consumer, repository, connection)
                assertEquals(
                    before,
                    restoredRoutes,
                    "Removing covered CIDRs retains capture identity",
                )

                runBlocking {
                    assertTrue(repository.setLocalNetworkSharing(!original.allowLan).isRight())
                }
                runBlocking {
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.allowLan == !original.allowLan }
                    }
                }
                val legacy =
                    connectedProof(consumer, repository, connection, restoredRoutes.generation)
                assertNotEquals(
                    restoredRoutes.routes,
                    legacy.routes,
                    "Legacy bypass changes the effective route set",
                )
                val legacyControl = withNativeControl(consumer, repository, connection, policy)
                assertEquals(legacy.routes, legacyControl.routes)
                runBlocking {
                    assertTrue(repository.setLocalNetworkSharing(original.allowLan).isRight())
                }
                runBlocking {
                    withTimeout(10_000) {
                        repository.settingsUpdates.first { it?.allowLan == original.allowLan }
                    }
                }
                val restoredLegacy =
                    connectedProof(consumer, repository, connection, legacyControl.generation)
                assertEquals(before.routes, restoredLegacy.routes)

                runBlocking {
                    assertTrue(split.excludeApp(excluded).isRight())
                    assertTrue(split.enableSplitTunneling(true).isRight())
                    withTimeout(10_000) {
                        repository.settingsUpdates.first {
                            it?.splitTunnelSettings?.let { settings ->
                                settings.enabled && excluded in settings.excludedApps
                            } == true
                        }
                    }
                }
                val exclusions =
                    connectedProof(consumer, repository, connection, restoredLegacy.generation)
                assertNotEquals(
                    restoredLegacy.uids,
                    exclusions.uids,
                    "Applied UID ranges must change",
                )
                assertTrue(
                    uidIncluded(
                        exclusions.uids,
                        target.packageManager.getApplicationInfo(testPackage, 0).uid,
                    )
                )
                assertTrue(!uidIncluded(exclusions.uids, excludedUid))
                report("excluded_uid", excludedUid)
                report("consumer_included", true)
                val exclusionControl = withNativeControl(consumer, repository, connection, policy)
                assertEquals(exclusions.uids, exclusionControl.uids)
            } catch (error: Throwable) {
                r06Custody?.recordFailure("settings-body", error)
                throw error
            } finally {
                r06Checked("settings-restoration") {
                    runBlocking {
                        assertTrue(split.includeApp(excluded).isRight())
                        assertTrue(
                            split
                                .enableSplitTunneling(original.splitTunnelSettings.enabled)
                                .isRight()
                        )
                        assertTrue(repository.setLocalNetworkSharing(original.allowLan).isRight())
                        withTimeout(10_000) {
                            repository.settingsUpdates.first {
                                it?.allowLan == original.allowLan &&
                                    it.splitTunnelSettings == original.splitTunnelSettings
                            }
                        }
                    }
                    setPolicy(repository, policy)
                    val restored = connectedProof(consumer, repository, connection)
                    assertEquals(before.routes, restored.routes)
                    assertEquals(before.uids, restored.uids)
                    report("settings_restored", true)
                }
            }
        }

    @Test
    fun connectedRawRelayCarriesPublicIcmp() =
        connectedCase { consumer, repository, connection, policy ->
            setPolicy(repository, policy.copy(enabled = false))
            val native = nativeProof(consumer, repository, connection)
            probeIcmp(consumer, "echo")
            setPolicy(repository, policy)
            val managed = connectedProof(consumer, repository, connection)
            normalConfiguration(native, managed, policy)
            probeIcmp(consumer, "echo")
        }

    internal data class AppliedCapture(
        val addresses: Set<String>,
        val routeTypes: Set<CaptureReadiness.Route>,
        val dns: String,
        val mtu: Int,
        val uids: String,
        val generation: String?,
        val handle: String?,
        val interfaceName: String,
        val netId: String,
    ) {
        val routes: Set<String>
            get() = routeTypes.map { it.prefix }.toSet()

        val forwardingRoutes: Set<String>
            get() =
                routeTypes
                    .filter { it.type == CaptureReadiness.RouteType.Forwarding }
                    .map { it.prefix }
                    .toSet()

        val unreachableRoutes: Set<String>
            get() =
                routeTypes
                    .filter { it.type == CaptureReadiness.RouteType.Unreachable }
                    .map { it.prefix }
                    .toSet()
    }

    internal fun uidIncluded(ranges: String, uid: Int): Boolean =
        ranges.split(',').any { range ->
            val bounds = range.trim().split('-').map { it.toInt() }
            uid >= bounds.first() && uid <= bounds.last()
        }

    private fun probeExit(consumer: Consumer, expect: String) {
        val result = consumer.request(Bundle().apply { putString("transport", "exit-check") })
        report("exit_outcome", checkNotNull(result.getString("outcome")))
        report("exit_elapsed_ms", result.getLong("elapsed_ms"))
        result.getString("error_kind")?.let { report("exit_error_kind", it) }
        result.getString("error_class")?.let { report("exit_error_class", it) }
        assertEquals(
            "exit-check",
            result.getString("outcome"),
            "Exit response, not harness failure",
        )
        assertEquals(200, result.getInt("http_status"))
        assertTrue(result.containsKey("mullvad_exit_ip"))
        val exit = result.getBoolean("mullvad_exit_ip")
        val ip = checkNotNull(result.getString("ip"))
        assertTrue(InetAddresses.isNumericAddress(ip))
        assertEquals(if (ip.contains(':')) 6 else 4, result.getInt("family"))
        report("exit_mullvad", exit)
        report("exit_ip", ip)
        report("exit_family", result.getInt("family"))
        if (expect != "record") assertEquals(expect == "mullvad", exit)
    }

    private fun probeIcmp(consumer: Consumer, expect: String) {
        val result = consumer.request(Bundle().apply { putString("transport", "icmp-check") })
        report("icmp_outcome", checkNotNull(result.getString("outcome")))
        report("icmp_elapsed_ms", result.getLong("elapsed_ms"))
        result.getString("error_class")?.let { report("icmp_error_class", it) }
        result.getString("error_reason")?.let { report("icmp_error_reason", it) }
        assertEquals(
            "icmp-check",
            result.getString("outcome"),
            "Parsed result, not harness failure",
        )
        assertEquals("icmp-dgram", result.getString("socket_kind"))
        assertEquals(2, result.getInt("attempted"))
        val nonce = checkNotNull(result.getByteArray("request_payload"))
        assertEquals(32, nonce.size)
        report("icmp_socket_uid", result.getInt("uid"))
        report("icmp_socket_kind", checkNotNull(result.getString("socket_kind")))
        report("icmp_request_payload", nonce.joinToString("") { "%02x".format(it) })
        val received = result.getInt("received")
        assertTrue(received in 0..2)
        assertEquals(received.toLong(), result.getLong("echo_replies"))
        var verified = 0
        for (sequence in 1..2) {
            result.getByteArray("reply_$sequence")?.let { reply ->
                assertContentEquals(nonce, reply, "Echo must carry this request's nonce")
                val packet = checkNotNull(result.getByteArray("packet_$sequence"))
                assertEquals(40, packet.size)
                assertEquals(0, packet[0].toInt())
                assertEquals(0, packet[1].toInt())
                assertEquals(
                    sequence,
                    (packet[6].toInt() and 255) * 256 + (packet[7].toInt() and 255),
                )
                assertContentEquals(nonce, packet.copyOfRange(8, packet.size))
                report("icmp_reply_$sequence", reply.joinToString("") { "%02x".format(it) })
                report("icmp_packet_$sequence", packet.joinToString("") { "%02x".format(it) })
                verified++
            }
            result
                .getInt("network_errno_$sequence")
                .takeIf { it != 0 }
                ?.let { report("icmp_errno_$sequence", it) }
        }
        assertEquals(received, verified)
        report("icmp_attempted", result.getInt("attempted"))
        report("icmp_transmitted", result.getInt("transmitted"))
        report("icmp_received", received)
        assertTrue(result.getInt("transmitted") in 0..2)
        if (received > 0 || expect == "echo") assertEquals(2, result.getInt("transmitted"))
        if (expect == "echo") assertTrue(received > 0, "Actual public ICMP echo replies required")
        if (expect == "blocked") assertEquals(0, received, "Public ICMP must remain blocked")
    }

    internal fun probeSocket(
        consumer: Consumer,
        transport: String,
        expect: String,
        sessionFrame: Boolean = false,
    ): Bundle {
        // Denied probes against the strict session peer must be valid frames:
        // a peer's format rejection must never masquerade as network blocking.
        val nonce =
            if (sessionFrame) {
                val id = UUID.randomUUID().toString().replace("-", "").take(29)
                "krtek-m3-$id-${transport.first()}-0000"
            } else "krtek-m3-" + UUID.randomUUID()
        val index = probeIndex++
        if (transport != "tcp-connect")
            report(
                if (expect == "reply") "expect_hit_$index" else "expect_none_$index",
                "$transport:$nonce",
            )
        val destination =
            if (transport == "tcp-connect") args.getString("krtek_public", "1.1.1.1") else peer
        val port =
            if (transport == "tcp-connect") 443
            else
                args
                    .getString(
                        if (transport == "tcp") "krtek_tcp_port" else "krtek_udp_port",
                        if (transport == "tcp") "18080" else "18081",
                    )
                    .toInt()
        receiveBoundary.beforeConnect(index, transport, expect, nonce)
        val result =
            consumer.request(
                Bundle().apply {
                    putString("transport", transport)
                    putString("destination", destination)
                    putInt("port", port)
                    putString("nonce", nonce)
                    putInt("timeout_ms", 5_000)
                }
            )
        report("probe_index", index)
        report("probe_consumer_uid", result.getInt("uid"))
        report("probe_consumer_package", checkNotNull(result.getString("package")))
        report("probe_transport", checkNotNull(transport))
        report("probe_outcome", checkNotNull(result.getString("outcome")))
        result.getString("error_class")?.let { report("probe_error_class", it) }
        result.getString("socket_report")?.let { report("socket_report", it) }
        try {
            if (expect in setOf("reply", "connected")) r06Custody?.observe(transport, result)
            assertEquals(
                when (expect) {
                    "reply" -> "reply"
                    "connected" -> "connected"
                    else -> "failed"
                },
                result.getString("outcome"),
            )
            if (expect == "reply")
                assertContentEquals(
                    nonce.toByteArray(Charsets.US_ASCII),
                    result.getByteArray("reply"),
                )
            if (expect == "blocked")
                assertTrue(checkNotNull(result.getString("error_class")).contains('.'))
        } catch (error: Throwable) {
            r06Custody?.recordFailure("socket-probe-$index", error)
            throw error
        }
        return result
    }

    private fun canonicalPrefix(text: String): String =
        IpPrefix(
                InetAddresses.parseNumericAddress(text.substringBefore('/')),
                text.substringAfter('/').toInt(),
            )
            .toString()

    // Dumpsys punctuation is literal, not a pattern in Android's ICU regex dialect.
    private fun delimitedField(text: String, marker: String, end: Char): String? {
        val markerStart = text.indexOf(marker)
        if (markerStart < 0) return null
        val start = markerStart + marker.length
        val finish = text.indexOf(end, start)
        if (finish < 0) return null
        return text.substring(start, finish)
    }

    private fun tokenField(text: String, marker: String): String? =
        delimitedField(text, marker, ' ')?.takeIf { it.isNotEmpty() }

    internal fun appliedConfiguration(
        policy: LocalNetworkAccess,
        forwarding: ForwardingAvailability,
        expectedTunnel: String = args.getString("krtek_expect_tunnel", "Disconnected"),
        previousGeneration: String? = null,
        fixedCapture: Boolean = true,
        requiredMtu: Int? = null,
        requiredDns: Set<String>? = null,
    ): AppliedCapture = runBlocking {
        val expected =
            policy.rules
                .filter { policy.enabled && it.enabled }
                .flatMap { it.cidrs }
                .map { canonicalPrefix(it.toString()) }
                .toSet()
        val id = UUID.randomUUID().toString()
        val directory =
            File(target.filesDir, "krtek-probes").apply { check(isDirectory || mkdir()) }
        withTimeout(30_000) {
            while (isActive) {
                val vpn = shell("dumpsys vpn_management")
                val connectivity = shell("dumpsys connectivity")
                File(directory, "$id-vpn.txt").writeText(vpn)
                File(directory, "$id-connectivity.txt").writeText(connectivity)
                report("config_dump_id", id)
                check(vpn.contains("Active package name: ${target.packageName}"))
                // Vpn.dump does not print VpnConfig. Read the active VPN's actual
                // LinkProperties from ConnectivityService, not a physical network
                // or a historical route/configuration record.
                val agents =
                    connectivity
                        .lineSequence()
                        .filter {
                            it.contains("NetworkAgentInfo{") &&
                                tokenField(it, "Transports: ")?.split('|')?.contains("VPN") ==
                                    true &&
                                tokenField(it, "OwnerUid: ") ==
                                    target.applicationInfo.uid.toString()
                        }
                        .toList()
                val agent = agents.singleOrNull()
                val active = vpn.contains("Active vpn type: 1")
                if (forwarding == ForwardingAvailability.Off && expectedTunnel == "Disconnected") {
                    if (vpn.contains("Active vpn type: -1") && agents.isEmpty()) {
                        report("frontend", "absent")
                        return@withTimeout AppliedCapture(
                            emptySet(),
                            emptySet(),
                            "[]",
                            0,
                            "",
                            null,
                            null,
                            "",
                            "",
                        )
                    }
                } else if (active && agent != null) {
                    val addressText = checkNotNull(delimitedField(agent, "LinkAddresses: [", ']'))
                    val addresses =
                        addressText
                            .split(',')
                            .filter { it.isNotBlank() }
                            .map { canonicalPrefix(it.trim()) }
                            .toSet()
                    val bookkeeping =
                        setOf(
                            canonicalPrefix("172.27.1.1/32"),
                            canonicalPrefix("fdf0:ce4a:801d::172:27:1:1/128"),
                        )
                    val options =
                        (target.applicationContext as MullvadApplication)
                            .getKoin()
                            .get<SettingsRepository>()
                            .settingsUpdates
                            .value
                            ?.tunnelOptions
                    val connectedFamilies =
                        if (expectedTunnel == "Connected")
                            bookkeeping
                                .filter {
                                    ':' !in it ||
                                        options?.enableIpv6 == true ||
                                        expected.any { route -> ':' in route }
                                }
                                .toSet()
                        else bookkeeping
                    val frontend = addresses == connectedFamilies
                    val routeText = checkNotNull(delimitedField(agent, "Routes: [", ']'))
                    val dns = checkNotNull(delimitedField(agent, "DnsAddresses: [", ']')).trim()
                    val routeTypes =
                        routeText
                            .split(',')
                            .filter { it.isNotBlank() }
                            .map {
                                CaptureReadiness.route(it).let { route ->
                                    route.copy(prefix = canonicalPrefix(route.prefix))
                                }
                            }
                            .toSet()
                    val allRoutes = routeTypes.map { it.prefix }.toSet()
                    val routes = allRoutes - bookkeeping
                    val iface = tokenField(agent, "InterfaceName: ")
                    val netId =
                        delimitedField(agent, "network{", '}')?.takeIf { value ->
                            value.isNotEmpty() && value.all { it in '0'..'9' }
                        }
                    if (expectedTunnel != "Disconnected") {
                        val mtu = checkNotNull(tokenField(agent, "MTU: ")).toInt()
                        if (
                            iface == null ||
                                netId == null ||
                                !CaptureReadiness.configurationReady(
                                    frontend == fixedCapture && addresses.isNotEmpty(),
                                    dns,
                                    mtu,
                                    CaptureReadiness.forwardingPrefixes(routeTypes),
                                    expected,
                                    requiredMtu
                                        ?: if (expectedTunnel == "Connected") options?.mtu?.value
                                        else if (expectedTunnel == "Error") 1380 else null,
                                    addresses.any { ':' in it },
                                    requiredDns =
                                        requiredDns
                                            ?: if (expectedTunnel == "Error") setOf("192.0.2.1")
                                            else null,
                                )
                        ) {
                            delay(100)
                            continue
                        }
                        val identity =
                            captureReceipt(iface, netId, allRoutes, mtu, previousGeneration)
                        if (identity == null) {
                            delay(100)
                            continue
                        }
                        if (forwarding == ForwardingAvailability.Active) {
                            assertTrue(policy.enabled && expected.isNotEmpty())
                            report("frontend", "present-managed")
                        } else {
                            assertEquals(ForwardingAvailability.Off, forwarding)
                            assertTrue(expected.isEmpty())
                            report("frontend", "present-managed-local-off")
                        }
                        report("frontend_interface", iface)
                        report("frontend_net_id", netId)
                        report("frontend_routes", allRoutes.sorted().joinToString(","))
                        report("frontend_addresses", addresses.sorted().joinToString(","))
                        report("frontend_dns", dns)
                        report("frontend_mtu", mtu)
                        report("vpn_config", agent)
                        val uids = checkNotNull(delimitedField(agent, "Uids: <{", '}'))
                        report("frontend_uids", uids)
                        return@withTimeout AppliedCapture(
                            addresses,
                            routeTypes,
                            dns,
                            mtu,
                            uids,
                            identity.first,
                            identity.second,
                            iface,
                            netId,
                        )
                    }
                    if (
                        frontend &&
                            routes == expected &&
                            CaptureReadiness.dnsMatches(
                                dns,
                                CaptureReadiness.DnsExpectation.Absent,
                            ) &&
                            iface != null &&
                            netId != null
                    ) {
                        assertTrue(routes.none { it.endsWith("/0") })
                        assertEquals(1280, checkNotNull(tokenField(agent, "MTU: ")).toInt())
                        val generation = partialCaptureFormat(previousGeneration)
                        if (generation == null) {
                            delay(100)
                            continue
                        }
                        report("frontend", "present")
                        report("frontend_interface", iface)
                        report("frontend_net_id", netId)
                        report("frontend_routes", routes.sorted().joinToString(","))
                        report("frontend_dns", "[]")
                        report(
                            "frontend_bookkeeping_routes",
                            (allRoutes intersect bookkeeping).sorted().joinToString(","),
                        )
                        report("frontend_addresses", addresses.sorted().joinToString(","))
                        val uids = checkNotNull(delimitedField(agent, "Uids: <{", '}'))
                        report("frontend_uids", uids)
                        return@withTimeout AppliedCapture(
                            addresses,
                            routeTypes.filter { it.prefix !in bookkeeping }.toSet(),
                            "[]",
                            1280,
                            uids,
                            generation,
                            null,
                            iface,
                            netId,
                        )
                    }
                }
                delay(500)
            }
            error("Configuration deadline")
        }
    }

    private fun daemonTail(): String =
        RandomAccessFile(File(target.filesDir, "daemon.log"), "r").use { log ->
            val size = minOf(log.length(), 256 * 1024L).toInt()
            log.seek(log.length() - size)
            ByteArray(size).also { log.readFully(it) }.toString(Charsets.UTF_8)
        }

    private fun partialCaptureFormat(previousGeneration: String?): String? {
        if (!File(target.filesDir, "daemon.log").isFile) return null
        val receipt =
            CaptureReadiness.partialReceipt(daemonTail(), previousGeneration) ?: return null
        report("capture_generation", receipt.generation)
        report("capture_session_generation", receipt.session)
        report("capture_format", receipt.format)
        return receipt.generation
    }

    private fun captureReceipt(
        iface: String,
        netId: String,
        routes: Set<String>,
        mtu: Int,
        previousGeneration: String?,
    ): Pair<String, String>? {
        val file = File(target.filesDir, "daemon.log")
        if (!file.isFile) return null
        val tail =
            RandomAccessFile(file, "r").use { log ->
                val size = minOf(log.length(), 256 * 1024L).toInt()
                log.seek(log.length() - size)
                ByteArray(size).also { log.readFully(it) }.toString(Charsets.UTF_8)
            }
        val receipt =
            CaptureReadiness.receipt(
                tail,
                iface,
                netId,
                routes,
                mtu,
                target.applicationInfo.uid,
                previousGeneration,
                ::canonicalPrefix,
            ) ?: return null
        report("capture_generation", receipt.generation)
        report("capture_handle", receipt.handle)
        report("capture_receipt", receipt.text)
        return receipt.generation to receipt.handle
    }

    internal inner class Consumer(private val packageName: String = testPackage) : AutoCloseable {
        private val service = CompletableFuture<Messenger>()
        @Volatile private var pending: Pair<String, CompletableFuture<Bundle>>? = null
        private val reply =
            Messenger(
                object : Handler(Looper.getMainLooper()) {
                    override fun handleMessage(message: Message) {
                        val result = Bundle(message.data)
                        pending
                            ?.takeIf { it.first == result.getString("request_id") }
                            ?.second
                            ?.complete(result)
                    }
                }
            )
        private val intent =
            Intent()
                .setComponent(
                    ComponentName(
                        packageName,
                        LocalNetworkConsumerService::class.java.name,
                    )
                )
        private val connection =
            object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    service.complete(Messenger(binder))
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    pending
                        ?.second
                        ?.completeExceptionally(IllegalStateException("Consumer disconnected"))
                }
            }
        private val bound = target.bindService(intent, connection, Context.BIND_AUTO_CREATE)

        init {
            check(bound)
        }

        fun request(command: Bundle): Bundle {
            val id = UUID.randomUUID().toString()
            val result = CompletableFuture<Bundle>()
            pending = id to result
            try {
                command.putString("request_id", id)
                service
                    .get(10, TimeUnit.SECONDS)
                    .send(
                        Message.obtain().apply {
                            data = command
                            replyTo = reply
                        }
                    )
                return result.get(35, TimeUnit.SECONDS).also {
                    assertEquals(packageName, it.getString("package"))
                    assertEquals(
                        target.packageManager.getApplicationInfo(packageName, 0).uid,
                        it.getInt("uid"),
                    )
                    assertNotEquals(Process.myUid(), it.getInt("uid"))
                    LocalNetworkConsumerService.requiredPermissions().forEach { permission ->
                        val granted = it.getBoolean("permission_$permission")
                        report("consumer_permission_$permission", granted)
                        assertTrue(
                            granted,
                            "Consumer UID requires $permission before any network result",
                        )
                    }
                }
            } finally {
                pending = null
            }
        }

        fun identity() {
            val result = request(Bundle().apply { putString("transport", "identity") })
            assertEquals("identity", result.getString("outcome"))
            assertEquals("android.app.Application", result.getString("application_class"))
            assertEquals(
                target.packageManager.getApplicationInfo(packageName, 0).uid,
                result.getInt("uid"),
            )
            assertEquals(target.applicationInfo.uid, Process.myUid())
            report("consumer_uid", result.getInt("uid"))
            report("consumer_package", checkNotNull(result.getString("package")))
            report("krtek_uid", Process.myUid())
        }

        override fun close() {
            if (bound) target.unbindService(connection)
            target.stopService(intent)
        }
    }

    private companion object {
        const val LOCAL_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    }
}
