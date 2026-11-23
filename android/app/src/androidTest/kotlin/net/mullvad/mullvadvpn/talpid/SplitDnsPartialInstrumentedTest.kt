package net.mullvad.mullvadvpn.talpid

import android.net.InetAddresses
import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import kotlin.time.Duration.Companion.minutes
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Runner stages/restores system fixture DNS, Private DNS and OS lockdown. */
class SplitDnsPartialInstrumentedTest {
    private val harness = LocalNetworkDeliveryInstrumentedTest()
    private val args = InstrumentationRegistry.getArguments()

    @Test
    fun splitDnsPartial() =
        harness.withConsumer(null, testTimeout = 4.minutes) { consumer, repository, connection ->
            assertEquals("Disconnected", args.getString("krtek_expect_tunnel"))
            val lockdown = args.getString("krtek_expect_lockdown") == "1"
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
                val capture =
                    harness.appliedConfiguration(
                        policy,
                        ForwardingAvailability.Active,
                        "Disconnected",
                        requiredDns = setOf(checkNotNull(resolver.hostAddress)),
                    )
                assertTrue(
                    capture.dns
                        .split(',')
                        .map { InetAddresses.parseNumericAddress(it.trim().removePrefix("/")) }
                        .contains(resolver)
                )
                val listed =
                    lookup(consumer, "run11-${UUID.randomUUID().toString().replace("-", "")}.home")
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
                            putString(
                                "tcp_vectors",
                                checkNotNull(args.getString("krtek_dns_tcp_vectors")),
                            )
                            putBoolean("ordinary_blocked", lockdown)
                        }
                    )
                harness.report("split_dns_partial_tcp", tcp)
                assertEquals("split-dns-tcp", tcp.getString("outcome"))
                assertEquals(if (lockdown) 2 else 3, tcp.getInt("message_count"))
                assertEquals(2, tcp.getInt("home_exact"))
                assertEquals(lockdown, tcp.getBoolean("ordinary_blocked"))
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
