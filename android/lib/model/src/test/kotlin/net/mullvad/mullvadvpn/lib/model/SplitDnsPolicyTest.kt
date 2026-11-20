package net.mullvad.mullvadvpn.lib.model

import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

class SplitDnsPolicyTest {
    @Test
    fun `should parse numeric resolvers without looking up names or collapsing mapped IPv6`() {
        for (input in listOf("10.77.10.53", "fd71:7274:656b:10::53", "::ffff:192.0.2.1")) {
            val resolver = assertNotNull(HomeDnsResolver.parse(input))
            assertEquals(resolver, HomeDnsResolver.parse(resolver.numericAddress))
            assertEquals("HomeDnsResolver(redacted)", resolver.toString())
            val copy = resolver.addressBytes()
            copy.fill(0)
            assertEquals(resolver, HomeDnsResolver.parse(input))
        }
        val mapped = assertNotNull(HomeDnsResolver.parse("::ffff:192.0.2.1"))
        assertEquals(16, mapped.addressBytes().size)
        assertNotEquals(mapped, HomeDnsResolver.parse("192.0.2.1"))
        assertEquals(
            HomeDnsResolver.parse("FD00:0:0:0:0:0:0:53"),
            HomeDnsResolver.parse("fd00::53"),
        )
        for (input in
            listOf(
                "resolver.home",
                "",
                "10.77.10.53:53",
                "[fd00::53]",
                "fe80::53%3",
                " 10.77.10.53",
                "127.00.0.1",
            )) {
            assertNull(HomeDnsResolver.parse(input))
        }
    }

    @Test
    fun `should default absent split DNS off and preserve incomplete disabled associations`() {
        val original = LocalNetworkAccess(true, emptyList(), false)
        assertEquals(SplitDnsPolicy(), original.splitDns)
        assertFalse(original.splitDns.enabled)
        val incomplete = SplitDnsPolicy(localRuleId = UUID(0, 99))
        assertNull(incomplete.validationError(emptyList()))
        val draft = original.copy(splitDns = incomplete)
        assertEquals(incomplete, draft.copy(enabled = false).splitDns)
        assertEquals(incomplete, draft.copy(skipLocalRulesForExcludedApps = true).splitDns)
        assertFalse(draft.skipLocalRulesForExcludedApps)
        assertNull(draft.validationError())
        assertEquals(
            SplitDnsPolicyError.MissingSuffix,
            incomplete.copy(enabled = true).validationError(emptyList()),
        )
    }

    @Test
    fun `should retain invalid represented suffixes and redact DNS values from diagnostics`() {
        val policy =
            SplitDnsPolicy(
                enabled = true,
                suffixes = listOf("*.private-domain-marker", "*.private-domain-marker"),
                homeResolver = HomeDnsResolver.parse("10.77.10.53"),
                localRuleId = UUID(0, 13),
            )
        val local = LocalNetworkAccess(splitDns = policy)
        assertEquals(SplitDnsPolicyError.InvalidDomain, policy.validationError(emptyList()))
        assertEquals(LocalPolicyValidationError.InvalidSplitDns, local.validationError())
        assertEquals(policy, local.copy(enabled = true).splitDns)
        assertEquals(listOf("*.private-domain-marker", "*.private-domain-marker"), policy.suffixes)
        val diagnostic = "$local $policy ${policy.homeResolver}"
        for (secret in listOf("private-domain-marker", "10.77", UUID(0, 13).toString())) {
            assertFalse(diagnostic.contains(secret))
        }
    }
}
