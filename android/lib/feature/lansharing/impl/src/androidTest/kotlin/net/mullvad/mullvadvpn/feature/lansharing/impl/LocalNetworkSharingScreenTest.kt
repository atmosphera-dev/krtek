package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.os.Build
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.click
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.onAllNodesWithText
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
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.LocalRuleStatus
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
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
        sdkInt: Int = Build.VERSION.SDK_INT,
    ) {
        setContentWithTheme {
            LocalNetworkSharingScreen(
                state = state,
                onBackClick = onBackClick,
                onLocalNetworkSharingEnable = onLocalNetworkSharingEnable,
                policyActions = policyActions,
                sdkInt = sdkInt,
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

    private val homeRule =
        LocalBypassRule(
            UUID.randomUUID(),
            "Home",
            true,
            listOf(checkNotNull(LocalCidr.parse("192.168.1.0/24").getOrNull())),
        )
    private val splitDns =
        SplitDnsPolicy(true, listOf("home."), HomeDnsResolver.parse("192.168.1.1"), homeRule.id)

    @Test
    fun splitDnsSummaryFollowsRulesAndUsesCallbacks() = composeExtension.use {
        val enabled = mutableListOf<Boolean>()
        var edits = 0
        var privateDns = 0
        initScreen(
            state =
                createDefaultUiState()
                    .copy(
                        policy = LocalNetworkAccess(rules = listOf(homeRule), splitDns = splitDns)
                    )
                    .toLc(),
            policyActions =
                LocalPolicyActions(
                    splitDns =
                        SplitDnsActions(
                            onEnabled = { enabled.add(it) },
                            onEdit = { edits++ },
                            onPrivateDnsSettings = { privateDns++ },
                        )
                ),
        )
        onNodeWithTag("split_dns_enabled").performScrollTo()
        val addRule = onNodeWithTag("local_access_add_rule").fetchSemanticsNode().boundsInRoot
        val dns = onNodeWithTag("split_dns_enabled").fetchSemanticsNode().boundsInRoot
        assertTrue(dns.top >= addRule.bottom)
        onNodeWithText(copy(R.string.split_dns_enable)).assertExists()
        onNodeWithText(copy(R.string.split_dns_used_on_any_network)).assertExists()
        onNodeWithText("home").assertExists()
        onNodeWithText("home.").assertDoesNotExist()
        onNodeWithText("192.168.1.1").assertExists()
        onNode(
                isToggleable() and hasAnyAncestor(hasTestTag("split_dns_enabled")),
                useUnmergedTree = true,
            )
            .assertIsOn()
            .performClick()
        assertEquals(listOf(false), enabled)
        onNodeWithTag("split_dns_edit").performScrollTo().performClick()
        assertEquals(1, edits)
        onNodeWithText(copy(R.string.split_dns_private_dns)).performScrollTo().assertExists()
        onNodeWithTag("split_dns_private_dns_settings").performScrollTo().performClick()
        assertEquals(1, privateDns)
    }

    @Test fun splitDnsSummaryShouldExplainAndroid9Pause() = assertSplitDnsSummary(sdkInt = 28)

    @Test
    fun splitDnsSummaryShouldNotShowAndroid9NoteOnAndroid10() = assertSplitDnsSummary(sdkInt = 29)

    @Test
    fun splitDnsSummaryShouldNotShowAndroid9NoteOnCurrentAndroid() =
        assertSplitDnsSummary(sdkInt = 37)

    private fun assertSplitDnsSummary(sdkInt: Int) = composeExtension.use {
        val state =
            createDefaultUiState()
                .copy(
                    policy = LocalNetworkAccess(rules = listOf(homeRule), splitDns = splitDns),
                    status =
                        LocalNetworkStatus(
                            revision = 1uL,
                            observerAvailable = true,
                            forwarding = ForwardingAvailability.Active,
                            currentWifi = ConnectedWifi.Unknown(WifiUnknownReason.NotOnWifi),
                            rules = listOf(LocalRuleStatus(homeRule.id, LocalRuleState.Forwarding)),
                        ),
                )
        initScreen(state = state.toLc(), sdkInt = sdkInt)
        // The Local rule keeps its status; the Split DNS summary must not repeat it.
        onAllNodesWithText(copy(R.string.local_access_forwarding)).assertCountEquals(1)
        onNodeWithText(copy(R.string.local_access_forwarding)).performScrollTo().assertIsDisplayed()
        onNodeWithText(copy(R.string.split_dns_used_on_any_network)).assertExists()
        val note = onNodeWithText(copy(R.string.split_dns_android_9_pause))
        if (sdkInt == 28) note.performScrollTo().assertIsDisplayed() else note.assertDoesNotExist()
    }

    @Test
    fun splitDnsEditorReplacesListsAndOwnsSaveAndCancel() = composeExtension.use {
        var saves = 0
        var closes = 0
        var localSaves = 0
        val draft =
            SplitDnsDraft.from(splitDns).copy(domains = listOf(SplitDnsDomainDraft("a", "HOME.")))
        initScreen(
            state =
                createDefaultUiState()
                    .copy(
                        policy = LocalNetworkAccess(rules = listOf(homeRule), splitDns = splitDns),
                        splitDnsEditor = SplitDnsEditorState(draft, SplitDnsDraft.from(splitDns)),
                    )
                    .toLc(),
            policyActions =
                LocalPolicyActions(
                    onSave = { localSaves++ },
                    splitDns = SplitDnsActions(onSave = { saves++ }, onClose = { closes++ }),
                ),
        )
        onNodeWithTag("local_policy_enabled").assertDoesNotExist()
        onNodeWithTag("local_excluded_apps_skip").assertDoesNotExist()
        onNodeWithTag("local_access_add_rule").assertDoesNotExist()
        onNodeWithTag("split_dns_enabled").assertDoesNotExist()
        val preview =
            InstrumentationRegistry.getInstrumentation()
                .targetContext
                .getString(R.string.split_dns_domain_preview, "home")
        onNodeWithText(preview).performScrollTo().assertExists()
        onNodeWithText("Home - " + copy(R.string.local_access_any_network)).assertExists()
        onNodeWithTag("split_dns_save").performClick()
        onNodeWithTag("split_dns_editor_cancel").performClick()
        assertEquals(1 to 1, saves to closes)
        assertEquals(0, localSaves)
    }

    @Test
    fun invalidSavedSplitDnsCanOnlyBeRepairedInItsEditor() = composeExtension.use {
        var edits = 0
        initScreen(
            state =
                createDefaultUiState()
                    .copy(
                        policy =
                            LocalNetworkAccess(
                                rules = listOf(homeRule),
                                splitDns = SplitDnsPolicy(enabled = true),
                            )
                    )
                    .toLc(),
            policyActions = LocalPolicyActions(splitDns = SplitDnsActions(onEdit = { edits++ })),
        )
        onNodeWithText(copy(R.string.local_access_policy_invalid)).assertExists()
        onNodeWithText(copy(R.string.split_dns_policy_invalid)).assertExists()
        onNodeWithTag("local_policy_enabled").assertDoesNotExist()
        onNodeWithTag("local_access_add_rule").assertDoesNotExist()
        onNode(
                isToggleable() and hasAnyAncestor(hasTestTag("split_dns_enabled")),
                useUnmergedTree = true,
            )
            .assertIsNotEnabled()
        onNodeWithTag("split_dns_edit").performScrollTo().performClick()
        assertEquals(1, edits)
    }
}
