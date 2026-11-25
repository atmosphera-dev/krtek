package net.mullvad.mullvadvpn.feature.lansharing.impl

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SplitDnsDomain
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/** Draft plumbing only. Real Android ICU acceptance is instrumented separately. */
class SplitDnsDraftTest {
    private val rule =
        LocalBypassRule(
            UUID.randomUUID(),
            "My home",
            true,
            listOf(assertNotNull(LocalCidr.parse("192.168.1.0/24").getOrNull())),
            listOf(assertNotNull(SsidIdentity.fromUserText("My Wi-Fi"))),
        )
    private val policy =
        SplitDnsPolicy(true, listOf("home."), HomeDnsResolver.parse("192.168.1.1"), rule.id)

    @BeforeEach
    fun setUp() {
        // JVM Android stubs do not implement ICU. Supply explicit advisory
        // results, not a substitute normalizer or an IDNA acceptance claim.
        val advisory =
            mapOf(
                "home" to "home.",
                "home." to "home.",
                "HOME." to "home.",
                ".home" to "home.",
                "nas.home" to "nas.home.",
                "nas.home." to "nas.home.",
            )
        mockkObject(SplitDnsDomain)
        every { SplitDnsDomain.normalize(any()) } answers { advisory[firstArg<String>()] }
    }

    @AfterEach
    fun tearDown() {
        unmockkObject(SplitDnsDomain)
    }

    @Test
    fun `should show canonical suffixes without root dots and preserve the saved policy`() {
        val draft = SplitDnsDraft.from(policy)
        assertEquals("home", draft.domains.single().text)
        assertEquals("home", draft.domains.single().preview())
        assertEquals(policy, draft.policy(listOf(rule)))
    }

    @Test
    fun `should retain exact invalid represented text for repair`() {
        val invalid = "  https://wrong.example/  "
        val draft = SplitDnsDraft.from(policy.copy(suffixes = listOf(invalid)))
        assertEquals(invalid, draft.domains.single().text)
        assertNull(draft.domains.single().preview())
        assertNull(draft.policy(listOf(rule)))
        assertEquals(invalid, draft.domains.single().text)
    }

    @Test
    fun `should deduplicate advisory canonical identities without removing overlaps`() {
        val draft =
            SplitDnsDraft.from(policy).copy(domains = rows("HOME.", ".home", "nas.home", "home"))
        assertEquals(listOf("home.", "nas.home."), draft.policy(listOf(rule))?.suffixes)
        assertEquals(listOf("HOME.", ".home", "nas.home", "home"), draft.domains.map { it.text })
    }

    @Test
    fun `should reject empty and invalid rows rather than silently drop them`() {
        val draft = SplitDnsDraft.from(policy)
        for (invalid in listOf("", " ", "*.home", "https://home/")) {
            assertNull(draft.copy(domains = rows("home", invalid)).policy(listOf(rule)))
        }
    }

    @Test
    fun `should preserve incomplete disabled configuration without enabling it`() {
        val empty = SplitDnsDraft.from(SplitDnsPolicy())
        assertEquals(SplitDnsPolicy(), empty.policy(emptyList()))
        val partial = empty.copy(domains = rows("home"))
        assertEquals(SplitDnsPolicy(suffixes = listOf("home.")), partial.policy(emptyList()))
        assertNull(partial.copy(enabled = true).policy(emptyList()))
    }

    @Test
    fun `should require all enabling fields and a valid association`() {
        val draft = SplitDnsDraft.from(policy)
        val alternatives =
            listOf(
                draft.copy(domains = emptyList()),
                draft.copy(homeResolver = ""),
                draft.copy(homeResolver = "router.home"),
                draft.copy(localRuleId = null),
                draft.copy(localRuleId = "not-a-uuid"),
                draft.copy(localRuleId = UUID.randomUUID().toString()),
            )
        alternatives.forEach { assertNull(it.policy(listOf(rule))) }
    }

    @Test
    fun `should preserve disabled and unconditional rules without changing their eligibility`() {
        val draft = SplitDnsDraft.from(policy)
        val alternatives =
            listOf(
                rule.copy(enabled = false),
                rule.copy(ssidIds = emptyList()),
            )
        alternatives.forEach { candidate ->
            val current = LocalNetworkAccess(rules = listOf(candidate))
            assertEquals(current.copy(splitDns = policy), draft.replacement(current))
            assertEquals(listOf(candidate), current.rules)
        }
    }

    @Test
    fun `should refuse a resolver outside the associated rule without broadening it`() {
        val uncovered =
            rule.copy(cidrs = listOf(assertNotNull(LocalCidr.parse("10.0.0.0/24").getOrNull())))
        val current = LocalNetworkAccess(rules = listOf(uncovered))
        assertNull(SplitDnsDraft.from(policy).replacement(current))
        assertEquals(listOf(uncovered), current.rules)
    }

    @Test
    fun `should replace only split DNS in the current complete Local policy`() {
        val other = rule.copy(id = UUID.randomUUID(), name = "Other network")
        val current =
            LocalNetworkAccess(
                enabled = false,
                rules = listOf(other, rule),
                skipLocalRulesForExcludedApps = false,
            )
        val replacement = assertNotNull(SplitDnsDraft.from(policy).replacement(current))
        assertEquals(current.copy(splitDns = policy), replacement)
        assertFalse(replacement.enabled)
        assertFalse(replacement.skipLocalRulesForExcludedApps)
        assertEquals(current.rules, replacement.rules)
        assertEquals(SplitDnsPolicy(), current.splitDns)
    }

    @Test
    fun `should refuse an invalid complete Local policy instead of repairing unrelated fields`() {
        val current = LocalNetworkAccess(rules = listOf(rule, rule))
        assertNull(SplitDnsDraft.from(policy).replacement(current))
        assertEquals(2, current.rules.size)
    }

    @Test
    fun `should retain separate stable row identities for equal domain text`() {
        val draft = SplitDnsDraft.from(policy.copy(suffixes = listOf("home.", "home.")))
        assertNotEquals(draft.domains[0].id, draft.domains[1].id)
        val first = draft.domains[0]
        val second = draft.domains[1]
        assertEquals(first.id, first.copy(text = "nas.home").id)
        assertEquals(second, draft.copy(domains = listOf(second)).domains.single())
    }

    @Test
    fun `should close unchanged editors and preserve dirty edits for explicit discard`() {
        val draft = SplitDnsDraft.from(policy)
        val open = SplitDnsEditorState(draft, draft)
        assertFalse(open.dirty)
        assertEquals(SplitDnsEditorState(), open.requestClose())
        val edited = open.copy(draft = draft.copy(homeResolver = "192.168.1.2"))
        val closing = edited.requestClose()
        assertTrue(closing.dirty)
        assertTrue(closing.confirmDiscard)
        assertEquals(edited.draft, closing.draft)
        assertEquals(draft, closing.baseline)
        assertEquals(edited, closing.copy(confirmDiscard = false))
    }

    @Test
    fun `should treat row order enable and association changes as dirty`() {
        val draft = SplitDnsDraft.from(policy.copy(suffixes = listOf("home.", "nas.home.")))
        val changes =
            listOf(
                draft.copy(domains = draft.domains.reversed()),
                draft.copy(enabled = false),
                draft.copy(localRuleId = null),
            )
        changes.forEach { assertTrue(SplitDnsEditorState(it, draft).requestClose().confirmDiscard) }
    }

    @Test
    fun `should not print domain address or association in draft diagnostics`() {
        val draft = SplitDnsDraft.from(policy)
        assertEquals("SplitDnsDraft(redacted)", draft.toString())
        assertEquals("SplitDnsDomainDraft(redacted)", draft.domains.single().toString())
        assertEquals(
            "SplitDnsEditorState(dirty=false)",
            SplitDnsEditorState(draft, draft).toString(),
        )
    }

    @Test
    fun `should not print domains address or network in screen state diagnostics`() {
        val draft = SplitDnsDraft.from(policy)
        val text =
            LocalNetworkSharingUiState(
                    lanSharingEnabled = true,
                    policy = LocalNetworkAccess(rules = listOf(rule), splitDns = policy),
                    splitDnsEditor = SplitDnsEditorState(draft, draft),
                )
                .toString()
        for (secret in listOf("home", "192.168", "My home", "My Wi-Fi", rule.id.toString())) {
            assertFalse(secret in text, "Screen state diagnostics must stay redacted")
        }
    }

    private fun rows(vararg text: String): List<SplitDnsDomainDraft> = text.map {
        SplitDnsDomainDraft(UUID.randomUUID().toString(), it)
    }
}
