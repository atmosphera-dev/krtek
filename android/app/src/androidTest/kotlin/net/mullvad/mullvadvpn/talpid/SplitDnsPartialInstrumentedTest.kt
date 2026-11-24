package net.mullvad.mullvadvpn.talpid

import android.net.InetAddresses
import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import java.net.Inet4Address
import java.net.InetAddress
import java.util.Locale
import java.util.UUID
import kotlin.time.Duration.Companion.minutes
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Runner stages/restores system fixture DNS, Private DNS and OS lockdown. */
class SplitDnsPartialInstrumentedTest {
    private val harness = LocalNetworkDeliveryInstrumentedTest()
    private val args = InstrumentationRegistry.getArguments()
    private val liveLegs = listOf("initial_off" to false, "on" to true, "final_off" to false)

    @Test
    fun vpnLockdownSettingsDriver() =
        LocalNetworkEditorInstrumentedTest().withForegroundActivity {
            val lockdown = PartialLockdownSettingsTest(harness::shell)
            assertFalse(lockdown.read(), "Stage lockdown OFF at entry")
            try {
                lockdown.set(true)
                harness.report("vpn_lockdown_settings_framework_on", true)
            } finally {
                lockdown.set(false)
            }
            harness.report("vpn_lockdown_settings_framework_off", true)
        }

    @Test
    fun splitDnsPartial() = withPartialPolicy { consumer, _, policy, _, resolver ->
        verifyLeg(
            consumer,
            policy,
            resolver,
            args.getString("krtek_expect_lockdown") == "1",
            checkNotNull(args.getString("krtek_dns_tcp_vectors")),
        )
    }

    @Test fun splitDnsPartialLiveLockdownInitialOff() = verifyLiveLockdown(liveLegs.take(1))

    @Test fun splitDnsPartialLiveLockdown() = verifyLiveLockdown(liveLegs)

    private fun verifyLiveLockdown(legs: List<Pair<String, Boolean>>) {
        assertEquals("0", args.getString("krtek_expect_lockdown"), "Stage lockdown OFF at entry")
        val vectors = liveLegs.associate { (name, _) ->
            name to checkNotNull(args.getString("krtek_dns_tcp_vectors_$name"))
        }
        // Fixture vectors are uncompressed single-question queries. Compare QNAMEs, not IDs.
        val names =
            vectors.values.flatMap { text ->
                val messages = JSONObject(text).getJSONArray("messages")
                (0 until messages.length()).map {
                    messages
                        .getJSONObject(it)
                        .getString("query_hex")
                        .drop(24)
                        .dropLast(8)
                        .lowercase(Locale.ROOT)
                }
            }
        assertEquals(9, names.toSet().size, "Each TCP question must have a fresh name")
        withPartialPolicy(live = true) { consumer, repository, policy, home, resolver ->
            assertEquals(4, home.addressBytes().size)
            assertTrue(resolver is Inet4Address)
            val lockdown = PartialLockdownSettingsTest(harness::shell)
            val entry = lockdown.read()
            assertFalse(entry)
            var failure: Throwable? = null
            try {
                var generation: String? = null
                legs.forEach { (name, enabled) ->
                    harness.report("split_dns_partial_leg", name)
                    lockdown.set(enabled)
                    generation =
                        verifyLeg(
                            consumer,
                            policy,
                            resolver,
                            enabled,
                            vectors.getValue(name),
                            generation,
                        )
                    assertEquals(policy, repository.settingsUpdates.value?.localNetworkAccess)
                    harness.report("split_dns_partial_leg_passed", name)
                }
            } catch (error: Throwable) {
                failure = error
                throw error
            } finally {
                try {
                    lockdown.set(entry)
                    assertEquals(entry, lockdown.read())
                    harness.report("split_dns_partial_lockdown_restored", true)
                } catch (restore: Throwable) {
                    failure?.addSuppressed(restore) ?: throw restore
                }
            }
        }
    }

    private fun withPartialPolicy(
        live: Boolean = false,
        block:
            (
                LocalNetworkDeliveryInstrumentedTest.Consumer,
                SettingsRepository,
                LocalNetworkAccess,
                HomeDnsResolver,
                InetAddress,
            ) -> Unit,
    ) {
        val verify:
            (
                LocalNetworkDeliveryInstrumentedTest.Consumer,
                SettingsRepository,
                ConnectionProxy,
            ) -> Unit =
            { consumer, repository, connection ->
                assertEquals("Disconnected", args.getString("krtek_expect_tunnel"))
                val before = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
                val home =
                    checkNotNull(
                        HomeDnsResolver.parse(
                            checkNotNull(args.getString("krtek_home_dns", "10.77.10.53"))
                        )
                    )
                val rule =
                    LocalBypassRule(
                        id = UUID.randomUUID(),
                        name = "Home DNS fixture",
                        enabled = true,
                        cidrs =
                            listOf(
                                checkNotNull(
                                    LocalCidr.parse(
                                            "${home.numericAddress}/${if (home.addressBytes().size == 4) 32 else 128}"
                                        )
                                        .getOrNull()
                                )
                            ),
                    )
                val policy =
                    harness.peerPolicy().let {
                        it.copy(
                            rules = it.rules + rule,
                            splitDns =
                                SplitDnsPolicy(
                                    enabled = true,
                                    suffixes = listOf("home."),
                                    homeResolver = home,
                                    localRuleId = rule.id,
                                ),
                        )
                    }
                var failure: Throwable? = null
                try {
                    harness.disconnect(connection)
                    harness.setPolicy(repository, policy)
                    harness.awaitState(
                        repository,
                        connection,
                        ForwardingAvailability.Active,
                        LocalRuleState.Forwarding,
                        "Disconnected",
                    )
                    val resolver =
                        InetAddresses.parseNumericAddress(
                            checkNotNull(args.getString("krtek_dns_tcp_resolver"))
                        )
                    block(consumer, repository, policy, home, resolver)
                } catch (error: Throwable) {
                    failure = error
                    throw error
                } finally {
                    try {
                        harness.setPolicy(repository, before)
                        harness.report("split_dns_partial_restored", true)
                    } catch (restore: Throwable) {
                        failure?.addSuppressed(restore) ?: throw restore
                    }
                }
            }
        if (live) harness.withForegroundConsumer(verify)
        else harness.withConsumer(null, testTimeout = 4.minutes, block = verify)
    }

    private fun verifyLeg(
        consumer: LocalNetworkDeliveryInstrumentedTest.Consumer,
        policy: LocalNetworkAccess,
        resolver: InetAddress,
        lockdown: Boolean,
        tcpVectors: String,
        previousGeneration: String? = null,
    ): String {
        val capture =
            harness.appliedConfiguration(
                policy,
                ForwardingAvailability.Active,
                "Disconnected",
                previousGeneration = previousGeneration,
                requiredDns = setOf(checkNotNull(resolver.hostAddress)),
                partialLockdown = lockdown,
            )
        assertTrue(
            capture.dns
                .split(',')
                .map { InetAddresses.parseNumericAddress(it.trim().removePrefix("/")) }
                .contains(resolver)
        )
        val listed = lookup(consumer, "run11-${UUID.randomUUID().toString().replace("-", "")}.home")
        assertEquals("resolved", listed.getString("lookup_outcome"))
        assertTrue(harness.uidIncluded(capture.uids, listed.getInt("uid")))
        val addresses = checkNotNull(listed.getStringArrayList("addresses"))
        assertFalse(addresses.isEmpty())
        assertTrue(
            addresses.all {
                InetAddresses.parseNumericAddress(it) in
                    setOf(
                        InetAddresses.parseNumericAddress("10.77.10.1"),
                        InetAddresses.parseNumericAddress("fd71:7274:656b:10::1"),
                    )
            }
        )
        val ordinary =
            lookup(
                consumer,
                "run11-${UUID.randomUUID().toString().replace("-", "")}.ordinary.test",
            )
        if (lockdown) assertEquals("failed", ordinary.getString("lookup_outcome"))
        else {
            assertEquals("resolved", ordinary.getString("lookup_outcome"))
            assertTrue(
                checkNotNull(ordinary.getStringArrayList("addresses")).all {
                    InetAddresses.parseNumericAddress(it) in
                        setOf(
                            InetAddresses.parseNumericAddress("10.77.10.54"),
                            InetAddresses.parseNumericAddress("fd71:7274:656b:10::54"),
                        )
                }
            )
        }
        val tcp =
            consumer.request(
                Bundle().apply {
                    putString("transport", "split-dns-tcp")
                    putString("tcp_resolver", resolver.hostAddress)
                    putString("tcp_vectors", tcpVectors)
                    putBoolean("ordinary_blocked", lockdown)
                }
            )
        harness.report("split_dns_partial_tcp", tcp)
        assertEquals("split-dns-tcp", tcp.getString("outcome"))
        assertEquals(if (lockdown) 2 else 3, tcp.getInt("message_count"))
        assertEquals(2, tcp.getInt("home_exact"))
        assertEquals(lockdown, tcp.getBoolean("ordinary_blocked"))
        if (lockdown) {
            // The system resolver is not Local; non-DNS packets to it must
            // enter the default capture but never reach the physical fixture.
            val destination = checkNotNull(resolver.hostAddress)
            assertTrue(
                policy.rules
                    .flatMap { it.cidrs }
                    .none {
                        CaptureReadiness.covers(
                            it.toString(),
                            "$destination/${if (':' in destination) 128 else 32}",
                        )
                    }
            )
            for (transport in listOf("udp", "tcp")) {
                val result =
                    consumer.request(
                        Bundle().apply {
                            putString("transport", transport)
                            putString("destination", destination)
                            putInt("port", if (transport == "tcp") 18080 else 18081)
                            putString("nonce", "krtek-m3-${UUID.randomUUID()}")
                            putInt("timeout_ms", 5_000)
                        }
                    )
                harness.report("split_dns_partial_non_dns_$transport", result)
                harness.report(
                    "socket_report",
                    checkNotNull(result.getString("socket_report")),
                )
                assertTrue(harness.uidIncluded(capture.uids, result.getInt("uid")))
                assertEquals("failed", result.getString("outcome"))
                assertTrue(checkNotNull(result.getString("error_class")).contains('.'))
            }
        }
        return checkNotNull(capture.generation)
    }

    private fun lookup(
        consumer: LocalNetworkDeliveryInstrumentedTest.Consumer,
        name: String,
    ): Bundle {
        val result =
            consumer.request(
                Bundle().apply {
                    putString("transport", "split-dns-lookup")
                    putString("hostname", name)
                }
            )
        harness.report("split_dns_partial_lookup", result)
        assertEquals("split-dns-lookup", result.getString("outcome"))
        return result
    }
}
