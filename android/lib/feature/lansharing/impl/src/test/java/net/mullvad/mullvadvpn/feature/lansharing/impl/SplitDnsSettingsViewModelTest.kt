package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import arrow.core.left
import arrow.core.right
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.model.SplitDnsDomain
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

/** Real ViewModel and saved state; only the repository and JVM-missing ICU are replaced. */
@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class SplitDnsSettingsViewModelTest {
    private val rule =
        LocalBypassRule(
            UUID.randomUUID(),
            "Home",
            true,
            listOf(assertNotNull(LocalCidr.parse("192.168.1.0/24").getOrNull())),
        )
    private val policy = LocalNetworkAccess(enabled = true, rules = listOf(rule))
    private val configured =
        SplitDnsPolicy(false, listOf("home."), HomeDnsResolver.parse("192.168.1.1"), rule.id)
    private val settings = MutableStateFlow<Settings?>(null)
    private val status = MutableStateFlow<LocalNetworkStatus?>(null)
    private val repository =
        mockk<SettingsRepository> {
            every { settingsUpdates } returns settings
            every { localNetworkStatus } returns status
            coEvery { observeLocalNetworkForEditor() } coAnswers
                {
                    kotlinx.coroutines.awaitCancellation()
                }
        }
    private lateinit var viewModel: LocalNetworkSharingViewModel

    private fun publish(value: LocalNetworkAccess) {
        settings.value =
            mockk<Settings> {
                every { allowLan } returns true
                every { localNetworkAccess } returns value
            }
    }

    private fun content() = (viewModel.uiState.value as Lc.Content).value

    private fun dns(action: SplitDnsAction) = viewModel.onSplitDns(action)

    private fun update(change: (SplitDnsDraft) -> SplitDnsDraft) =
        dns(SplitDnsAction.Update(change))

    @BeforeEach
    fun setup() {
        // JVM Android stubs do not implement ICU; advisory names only, as in SplitDnsDraftTest.
        val advisory = mapOf("home" to "home.", "home." to "home.", "HOME." to "home.")
        mockkObject(SplitDnsDomain)
        every { SplitDnsDomain.normalize(any()) } answers { advisory[firstArg<String>()] }
        publish(policy)
        viewModel = LocalNetworkSharingViewModel(false, repository, SavedStateHandle())
    }

    @AfterEach
    fun tearDown() {
        viewModel.viewModelScope.cancel()
        unmockkObject(SplitDnsDomain)
    }

    @Test
    fun `should open the editor without saving when an incomplete policy is turned on`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Enabled(true))
            runCurrent()
            val draft = assertNotNull(content().splitDnsEditor.draft)
            assertTrue(draft.enabled)
            assertTrue(content().editing)
            dns(SplitDnsAction.Close)
            runCurrent()
            assertTrue(content().splitDnsEditor.confirmDiscard)
            dns(SplitDnsAction.Discard)
            runCurrent()
            assertNull(content().splitDnsEditor.draft)
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should replace only split DNS against the current policy and close on save`() = runTest {
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Edit)
            update {
                it.copy(
                    domains = listOf(SplitDnsDomainDraft("row", "HOME.")),
                    homeResolver = "192.168.1.1",
                    localRuleId = rule.id.toString(),
                )
            }
            dns(SplitDnsAction.Save)
            runCurrent()
            coVerify(exactly = 1) {
                repository.setLocalNetworkAccess(policy.copy(splitDns = configured), policy)
            }
            assertNull(content().splitDnsEditor.draft)
            assertNull(content().error)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should name the field to fix and keep the draft without saving invalid input`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Enabled(true))
            val cases =
                listOf<Pair<(SplitDnsDraft) -> SplitDnsDraft, Int>>(
                    { d: SplitDnsDraft ->
                        d.copy(domains = listOf(SplitDnsDomainDraft("a", "x/")))
                    } to R.string.split_dns_invalid_domain,
                    { d: SplitDnsDraft ->
                        d.copy(domains = emptyList())
                    } to R.string.split_dns_missing_domain,
                    { d: SplitDnsDraft ->
                        d.copy(
                            domains = listOf(SplitDnsDomainDraft("a", "home")),
                            homeResolver = "1.2",
                        )
                    } to R.string.split_dns_invalid_home_ip,
                    { d: SplitDnsDraft ->
                        d.copy(homeResolver = "192.168.1.1")
                    } to R.string.split_dns_missing_home_network,
                    { d: SplitDnsDraft ->
                        d.copy(homeResolver = "10.0.0.1", localRuleId = rule.id.toString())
                    } to R.string.split_dns_home_ip_not_covered,
                )
            for ((change, message) in cases) {
                dns(SplitDnsAction.Update(change))
                runCurrent()
                val draft = content().splitDnsEditor.draft
                dns(SplitDnsAction.Save)
                runCurrent()
                assertEquals(message, content().error)
                assertEquals(draft, content().splitDnsEditor.draft)
            }
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should keep the draft and map the error when the repository fails`() = runTest {
        publish(policy.copy(splitDns = configured))
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns
            SetLocalNetworkAccessError.Conflict.left()
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Edit)
            update { it.copy(enabled = true) }
            runCurrent()
            val draft = content().splitDnsEditor.draft
            dns(SplitDnsAction.Save)
            runCurrent()
            assertEquals(R.string.local_access_conflict, content().error)
            assertEquals(draft, content().splitDnsEditor.draft)
            assertFalse(content().saving)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should need a second save when saved DNS changed behind the draft`() = runTest {
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Edit)
            update {
                it.copy(domains = listOf(SplitDnsDomainDraft("a", "home")))
            }
            runCurrent()
            val draft = content().splitDnsEditor.draft
            val concurrent = policy.copy(splitDns = configured)
            publish(concurrent)
            dns(SplitDnsAction.Save)
            runCurrent()
            assertEquals(R.string.local_access_conflict, content().error)
            assertEquals(draft, content().splitDnsEditor.draft)
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            dns(SplitDnsAction.Save)
            runCurrent()
            coVerify(exactly = 1) {
                repository.setLocalNetworkAccess(
                    concurrent.copy(splitDns = SplitDnsPolicy(suffixes = listOf("home."))),
                    concurrent,
                )
            }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should save immediately when turned off`() = runTest {
        val on = policy.copy(splitDns = configured.copy(enabled = true))
        publish(on)
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.uiState.test {
            awaitItem()
            dns(SplitDnsAction.Enabled(false))
            runCurrent()
            coVerify(exactly = 1) {
                repository.setLocalNetworkAccess(on.copy(splitDns = configured), on)
            }
            assertNull(content().splitDnsEditor.draft)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should let only the DNS editor repair DNS-invalid saved settings`() = runTest {
        val invalid = policy.copy(splitDns = SplitDnsPolicy(enabled = true))
        publish(invalid)
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        viewModel.uiState.test {
            awaitItem()
            runCurrent()
            assertTrue(content().splitDnsRepairable)
            assertFalse(content().policyEditable)
            viewModel.edit(null)
            viewModel.setPolicyEnabled(false)
            dns(SplitDnsAction.Enabled(false))
            runCurrent()
            assertNull(content().editor.draft)
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            dns(SplitDnsAction.Edit)
            update {
                it.copy(
                    domains = listOf(SplitDnsDomainDraft("a", "home")),
                    homeResolver = "192.168.1.1",
                    localRuleId = rule.id.toString(),
                )
            }
            dns(SplitDnsAction.Save)
            runCurrent()
            coVerify(exactly = 1) {
                repository.setLocalNetworkAccess(
                    invalid.copy(splitDns = configured.copy(enabled = true)),
                    invalid,
                )
            }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should keep the rule editor and the DNS editor exclusive`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.edit(null)
            dns(SplitDnsAction.Edit)
            dns(SplitDnsAction.Enabled(true))
            runCurrent()
            assertNotNull(content().editor.draft)
            assertNull(content().splitDnsEditor.draft)
            viewModel.discard()
            dns(SplitDnsAction.Edit)
            viewModel.edit(rule)
            viewModel.requestDelete(rule)
            runCurrent()
            assertNotNull(content().splitDnsEditor.draft)
            assertNull(content().editor.draft)
            assertNull(content().deleteTarget)
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            cancelAndIgnoreRemainingEvents()
        }
    }
}
