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
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class ExcludedAppsPreferenceViewModelTest {
    private val rule =
        checkNotNull(LocalRuleDraft(UUID.randomUUID().toString(), addresses = "10.0.0.0/8").rule())
    private val policy = LocalNetworkAccess(enabled = true, rules = listOf(rule))
    private val settings = MutableStateFlow<Settings?>(sample(policy))
    private val repository =
        mockk<SettingsRepository> {
            every { settingsUpdates } returns settings
            every { localNetworkStatus } returns MutableStateFlow<LocalNetworkStatus?>(null)
            coEvery { observeLocalNetworkForEditor() } coAnswers
                {
                    kotlinx.coroutines.awaitCancellation()
                }
        }
    private lateinit var viewModel: LocalNetworkSharingViewModel

    @BeforeEach
    fun setup() {
        viewModel = LocalNetworkSharingViewModel(false, repository, SavedStateHandle())
    }

    private fun sample(policy: LocalNetworkAccess?): Settings = mockk {
        every { allowLan } returns true
        every { localNetworkAccess } returns policy
    }

    private fun content() = (viewModel.uiState.value as Lc.Content).value

    @AfterEach fun tearDown() = viewModel.viewModelScope.cancel()

    @Test
    fun `should save only the exclusion field with the complete current expected policy`() =
        runTest {
            coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
            viewModel.uiState.test {
                awaitItem()
                runCurrent()
                assertTrue(content().policy.skipLocalRulesForExcludedApps)
                viewModel.setExcludedAppsSkipLocalRules(false)
                runCurrent()
                coVerify(exactly = 1) {
                    repository.setLocalNetworkAccess(
                        policy.copy(skipLocalRulesForExcludedApps = false),
                        policy,
                    )
                }
                // Command acknowledgement is not a persisted-settings update.
                assertTrue(content().policy.skipLocalRulesForExcludedApps)
                settings.value = sample(policy.copy(skipLocalRulesForExcludedApps = false))
                runCurrent()
                assertFalse(content().policy.skipLocalRulesForExcludedApps)
                assertEquals(policy.rules, content().policy.rules)
                assertEquals(policy.enabled, content().policy.enabled)
                coVerify(exactly = 0) { repository.observeLocalNetworkForEditor() }
                cancelAndIgnoreRemainingEvents()
            }
            viewModel.uiSideEffect.test { expectNoEvents() }
        }

    @Test
    fun `should gate repeated policy actions until the exclusion save completes`() = runTest {
        val finish = CompletableDeferred<Unit>()
        coEvery { repository.setLocalNetworkAccess(any(), any()) } coAnswers
            {
                finish.await()
                Unit.right()
            }
        viewModel.uiState.test {
            awaitItem()
            viewModel.setExcludedAppsSkipLocalRules(false)
            runCurrent()
            assertTrue(content().saving)
            viewModel.setExcludedAppsSkipLocalRules(true)
            viewModel.setPolicyEnabled(false)
            viewModel.edit(rule)
            runCurrent()
            coVerify(exactly = 1) { repository.setLocalNetworkAccess(any(), any()) }
            assertEquals(null, content().editor.draft)
            finish.complete(Unit)
            runCurrent()
            assertFalse(content().saving)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should show typed save failures without optimistic values or rule loss`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            for ((failure, message) in
                listOf(
                    SetLocalNetworkAccessError.Conflict to R.string.local_access_conflict,
                    SetLocalNetworkAccessError.Invalid to R.string.local_access_invalid_rule,
                    SetLocalNetworkAccessError.Unknown(IllegalStateException()) to
                        R.string.local_access_save_failed,
                )) {
                coEvery { repository.setLocalNetworkAccess(any(), any()) } returns failure.left()
                viewModel.setExcludedAppsSkipLocalRules(false)
                runCurrent()
                assertEquals(policy, content().policy)
                assertEquals(message, content().error)
                assertFalse(content().saving)
            }
            coVerify(exactly = 3) { repository.setLocalNetworkAccess(any(), policy) }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should gate unreadable invalid and dirty editor policy mutations`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            for (unreadable in
                listOf(null, policy.copy(rules = listOf(rule.copy(cidrs = emptyList()))))) {
                settings.value = sample(unreadable)
                runCurrent()
                assertFalse(content().policyEditable)
                viewModel.setExcludedAppsSkipLocalRules(false)
            }
            settings.value = sample(policy)
            viewModel.edit(rule)
            viewModel.updateDraft { it.copy(name = "Unsaved printer") }
            runCurrent()
            val draft = content().editor.draft
            assertNotNull(draft)
            viewModel.setExcludedAppsSkipLocalRules(false)
            viewModel.setPolicyEnabled(false)
            runCurrent()
            assertEquals(draft, content().editor.draft)
            assertEquals(policy, content().policy)
            coVerify(exactly = 0) { repository.setLocalNetworkAccess(any(), any()) }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should preserve an externally updated exclusion value when saving a rule draft`() =
        runTest {
            coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
            viewModel.uiState.test {
                awaitItem()
                viewModel.edit(rule)
                viewModel.updateDraft { it.copy(name = "Printer") }
                val current = policy.copy(skipLocalRulesForExcludedApps = false)
                settings.value = sample(current)
                runCurrent()
                viewModel.save()
                runCurrent()
                coVerify(exactly = 1) {
                    repository.setLocalNetworkAccess(
                        current.copy(rules = listOf(rule.copy(name = "Printer"))),
                        current,
                    )
                }
                cancelAndIgnoreRemainingEvents()
            }
        }
}
