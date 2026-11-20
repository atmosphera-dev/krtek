package net.mullvad.mullvadvpn.talpid

import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SplitDnsDomain
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicyError
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Uses the real Android ICU, never Java IDNA2003 or an Android unit-test stub. */
class SplitDnsNormalizationInstrumentedTest {
    @Test
    fun sharedRustAcceptanceMatchesPlatformEditorNormalization() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val fixture =
            context.assets.open("split_dns_names.json").bufferedReader().use { it.readText() }
        val vectors = JSONObject(fixture)
        val accepted = vectors.getJSONArray("accepted")
        val rejected = vectors.getJSONArray("rejected")
        assertTrue(accepted.length() > 0 && rejected.length() > 0)
        for (index in 0 until accepted.length()) {
            val case = accepted.getJSONObject(index)
            assertEquals(
                case.getString("canonical"),
                SplitDnsDomain.normalize(case.getString("input")),
            )
        }
        for (index in 0 until rejected.length()) {
            assertNull(SplitDnsDomain.normalize(rejected.getString(index)), "vector $index")
        }
        assertNull(SplitDnsDomain.normalize("${"a".repeat(64)}.home"))
        assertNull(SplitDnsDomain.normalize(List(4) { "a".repeat(63) }.joinToString(".")))
        val maximum =
            listOf("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)).joinToString(".")
        assertEquals("$maximum.", SplitDnsDomain.normalize(maximum))
    }

    @Test
    fun completePolicyUsesExistingCoverageWithoutEnablingLocalOrChangingRawDraft() {
        val rule =
            LocalBypassRule(
                id = UUID(0, 11),
                name = "synthetic",
                enabled = false,
                cidrs = listOf(checkNotNull(LocalCidr.parse("10.77.10.0/24").getOrNull())),
            )
        val dns =
            SplitDnsPolicy(
                enabled = true,
                suffixes = listOf(".HOME.", "home"),
                homeResolver = HomeDnsResolver.parse("10.77.10.53"),
                localRuleId = rule.id,
            )
        val local =
            LocalNetworkAccess(
                rules = listOf(rule),
                skipLocalRulesForExcludedApps = false,
                splitDns = dns,
            )
        assertNull(local.validationError())
        assertFalse(
            local.enabled || local.rules.single().enabled || local.skipLocalRulesForExcludedApps
        )
        assertEquals(listOf(".HOME.", "home"), local.splitDns.suffixes)
        assertEquals(
            SplitDnsPolicyError.MissingResolver,
            dns.copy(homeResolver = null).validationError(local.rules),
        )
        assertEquals(
            SplitDnsPolicyError.MissingAssociation,
            dns.copy(localRuleId = null).validationError(local.rules),
        )
        assertEquals(SplitDnsPolicyError.UnknownAssociation, dns.validationError(emptyList()))
        assertEquals(
            SplitDnsPolicyError.ResolverNotCovered,
            dns.copy(homeResolver = HomeDnsResolver.parse("1.1.1.1")).validationError(local.rules),
        )
        assertNull(
            dns.copy(enabled = false, homeResolver = null, localRuleId = null)
                .validationError(emptyList())
        )
    }
}
