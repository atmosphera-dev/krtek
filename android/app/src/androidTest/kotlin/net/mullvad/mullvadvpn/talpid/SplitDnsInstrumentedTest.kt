package net.mullvad.mullvadvpn.talpid

import android.net.InetAddresses
import android.os.Bundle
import android.os.ParcelFileDescriptor
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

/** First full-capture UDP milestone, not the all-state/TCP B3 campaign. */
class SplitDnsInstrumentedTest {
    private val harness = LocalNetworkDeliveryInstrumentedTest()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()

    @Test
    fun splitDnsFullUdp() =
        harness.connectedCase(3.minutes) { consumer, repository, connection, base ->
            val privateDns =
                instrumentation.uiAutomation
                    .executeShellCommand("settings get global private_dns_mode")
                    .use { fd ->
                        ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().use {
                            it.readText().trim()
                        }
                    }
            assertEquals(
                "off",
                privateDns,
                "Runner must stage and restore Private DNS; test does not change it",
            )
            val resolver =
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
                                        "${resolver.numericAddress}/${if (resolver.addressBytes().size == 4) 32 else 128}"
                                    )
                                    .getOrNull()
                            )
                        ),
                )
            val enabled =
                base.copy(
                    rules = base.rules + rule,
                    splitDns =
                        SplitDnsPolicy(
                            enabled = true,
                            suffixes = listOf("home."),
                            homeResolver = resolver,
                            localRuleId = rule.id,
                        ),
                )
            val before =
                harness.appliedConfiguration(base, ForwardingAvailability.Active, "Connected")
            harness.setPolicy(repository, enabled)
            harness.awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Connected",
            )
            val after =
                harness.appliedConfiguration(enabled, ForwardingAvailability.Active, "Connected")
            assertEquals(
                before.dns,
                after.dns,
                "Split DNS must not substitute Android's resolver list",
            )
            val hostname = "run11-${UUID.randomUUID().toString().replace("-", "")}.home"
            val result =
                consumer.request(
                    Bundle().apply {
                        putString("transport", "split-dns-lookup")
                        putString("hostname", hostname)
                    }
                )
            harness.report("split_dns_listed", result)
            assertEquals("split-dns-lookup", result.getString("outcome"))
            assertEquals("resolved", result.getString("lookup_outcome"))
            assertTrue(
                harness.uidIncluded(after.uids, result.getInt("uid")),
                "The ordinary consumer must be included in this capture",
            )
            val answers = checkNotNull(result.getStringArrayList("addresses"))
            assertFalse(answers.isEmpty())
            val expected =
                setOf(
                    InetAddresses.parseNumericAddress("10.77.10.1"),
                    InetAddresses.parseNumericAddress("fd71:7274:656b:10::1"),
                )
            assertTrue(
                answers.map { InetAddresses.parseNumericAddress(it) }.all { it in expected },
                "Only the fixture's Home addresses may reach the ordinary consumer",
            )
            val ordinary =
                consumer.request(
                    Bundle().apply {
                        putString("transport", "lookup")
                        putString("hostname", "example.com")
                    }
                )
            harness.report("split_dns_ordinary", ordinary)
            assertEquals("resolved", ordinary.getString("lookup_outcome"))
            harness.report(
                "split_dns_cache_limit",
                "Platform lookup may use Android/app cache; packet attribution remains a separate runner gate",
            )
        }
}
