package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.click
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.test.platform.app.InstrumentationRegistry
import de.mannodermaus.junit5.compose.ComposeContext
import io.mockk.MockKAnnotations
import java.util.UUID
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.toLc
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.ui.tag.CIRCULAR_PROGRESS_INDICATOR_TEST_TAG
import net.mullvad.mullvadvpn.screen.test.createEdgeToEdgeComposeExtension
import net.mullvad.mullvadvpn.screen.test.setContentWithTheme
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.RegisterExtension

@OptIn(ExperimentalTestApi::class)
class LocalNetworkSharingScreenTest {
    @JvmField @RegisterExtension val composeExtension = createEdgeToEdgeComposeExtension()

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this)
    }

    private fun copy(id: Int) =
        InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    private fun createDefaultUiState(
        isModal: Boolean = false,
        isLanSharingEnabled: Boolean = false,
    ) = LocalNetworkSharingUiState(isModal = isModal, lanSharingEnabled = isLanSharingEnabled)

    private fun ComposeContext.initScreen(
        state: Lc<Boolean, LocalNetworkSharingUiState> = createDefaultUiState().toLc(),
        onLocalNetworkSharingEnable: (Boolean) -> Unit = {},
        onBackClick: () -> Unit = {},
        policyActions: LocalPolicyActions = LocalPolicyActions(),
    ) {
        setContentWithTheme {
            LocalNetworkSharingScreen(
                state = state,
                onBackClick = onBackClick,
                onLocalNetworkSharingEnable = onLocalNetworkSharingEnable,
                policyActions = policyActions,
            )
        }
    }

    @Test
    fun testDefaultState() = composeExtension.use {
        // Arrange
        initScreen()

        // Assert
        onNodeWithText("Local network sharing").assertExists()
    }

    @Test
    fun givenLoadingStateShouldShowLoadingSpinner() = composeExtension.use {
        // Arrange
        initScreen(state = Lc.Loading(true))

        // Assert
        onNodeWithTag(CIRCULAR_PROGRESS_INDICATOR_TEST_TAG).assertExists()
    }

    @Test
    fun excludedAppsSwitchSavesImmediatelyBelowMasterWithoutConfirmation() = composeExtension.use {
        val saved = mutableListOf<Boolean>()
        initScreen(
            policyActions = LocalPolicyActions(onExcludedAppsSkipLocalRules = { saved.add(it) })
        )
        val label = "Excluded apps skip local rules"
        onNodeWithTag("local_excluded_apps_skip").performScrollTo()
        val master = onNodeWithTag("local_policy_enabled").fetchSemanticsNode().boundsInRoot
        val exclusion = onNodeWithText(label).fetchSemanticsNode().boundsInRoot
        assertTrue(exclusion.top >= master.bottom)
        onNode(
                isToggleable() and hasAnyAncestor(hasTestTag("local_excluded_apps_skip")),
                useUnmergedTree = true,
            )
            .performClick()
        assertEquals(listOf(false), saved)
        onNodeWithText("Enable local network rules?").assertDoesNotExist()
        onNodeWithText(label).assertExists()
    }

    @Test
    fun policyRowLabelTapOpensConfirmationAndSavesMaster() = composeExtension.use {
        val saved = mutableListOf<Boolean>()
        initScreen(policyActions = LocalPolicyActions(onEnabled = { saved.add(it) }))
        onNodeWithTag("local_policy_enabled").performScrollTo()
        onNode(
                hasText(copy(R.string.local_access_enable)) and
                    hasAnyAncestor(hasTestTag("local_policy_enabled")),
                useUnmergedTree = true,
            )
            .performTouchInput { click() }
        onNodeWithText("Enable local network rules?").assertExists()
        assertTrue(saved.isEmpty())
        onNodeWithText(copy(R.string.enable)).performClick()
        assertEquals(listOf(true), saved)
    }

    @Test
    fun excludedAppsRowLabelTapSavesWithoutConfirmation() = composeExtension.use {
        val saved = mutableListOf<Boolean>()
        initScreen(
            policyActions = LocalPolicyActions(onExcludedAppsSkipLocalRules = { saved.add(it) })
        )
        onNodeWithTag("local_excluded_apps_skip").performScrollTo()
        // Inject a pointer on the label, not a semantics action on the trailing switch.
        onNode(
                hasText("Excluded apps skip local rules") and
                    hasAnyAncestor(hasTestTag("local_excluded_apps_skip")),
                useUnmergedTree = true,
            )
            .performTouchInput { click() }
        assertEquals(listOf(false), saved)
        onNodeWithText("Enable local network rules?").assertDoesNotExist()
    }

    @Test
    fun savingHidesBothPolicySwitches() = composeExtension.use {
        initScreen(state = createDefaultUiState().copy(saving = true).toLc())
        onNodeWithTag("local_excluded_apps_skip").assertDoesNotExist()
        onNodeWithTag("local_policy_enabled").assertDoesNotExist()
        onNode(isToggleable(), useUnmergedTree = true).assertExists()
        // The remaining switch belongs to the independent connected bypass, not Local policy.
        onNodeWithText(copy(R.string.local_access_saving)).assertExists()
    }

    @Test
    fun dirtyEditorKeepsExclusionSwitchGatedWithoutDiscardingDraft() = composeExtension.use {
        val draft = LocalRuleDraft(UUID.randomUUID().toString(), name = "Unsaved printer")
        initScreen(
            state = createDefaultUiState().copy(editor = LocalEditorState(draft, draft)).toLc()
        )
        onNodeWithTag("local_excluded_apps_skip").assertDoesNotExist()
        onNodeWithText("Unsaved printer", useUnmergedTree = true).assertExists()
    }

    @Test
    fun unreadablePolicyDoesNotExposeAnEditableDefaultSwitch() = composeExtension.use {
        initScreen(state = createDefaultUiState().copy(policyReadable = false).toLc())
        onNodeWithTag("local_excluded_apps_skip").assertDoesNotExist()
    }

    @Test
    fun offAndConflictShowPersistedValueAndInlineError() = composeExtension.use {
        initScreen(
            state =
                createDefaultUiState()
                    .copy(
                        policy = LocalNetworkAccess(skipLocalRulesForExcludedApps = false),
                        error = R.string.local_access_conflict,
                    )
                    .toLc()
        )
        onNodeWithTag("local_excluded_apps_skip").performScrollTo()
        onNodeWithText("Excluded apps skip local rules").assertExists()
        onNode(
                isToggleable() and hasAnyAncestor(hasTestTag("local_excluded_apps_skip")),
                useUnmergedTree = true,
            )
            .assertIsOff()
        onNodeWithText(copy(R.string.local_access_conflict)).assertExists()
    }
}
