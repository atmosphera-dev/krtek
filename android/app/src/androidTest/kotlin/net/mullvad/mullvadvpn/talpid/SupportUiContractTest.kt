package net.mullvad.mullvadvpn.talpid

import androidx.compose.ui.semantics.AccessibilityAction
import androidx.compose.ui.semantics.ScrollAxisRange
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsConfiguration
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isEnabled
import androidx.compose.ui.text.AnnotatedString
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import net.mullvad.mullvadvpn.lib.ui.tag.LAZY_LIST_TEST_TAG
import org.junit.jupiter.api.Test

class SupportUiContractTest {
    private fun node(
        parent: SemanticsNode? = null,
        configure: SemanticsConfiguration.() -> Unit,
    ): SemanticsNode {
        val semantics = SemanticsConfiguration().apply(configure)
        return mockk {
            every { config } returns semantics
            every { this@mockk.parent } returns parent
        }
    }

    private fun SemanticsConfiguration.click() {
        this[SemanticsActions.OnClick] = AccessibilityAction(null) { true }
    }

    @Test
    fun reportTitleAndReviewedTitleNeverAuthorizeTheSettingsEntryAction() {
        val title = node {
            this[SemanticsProperties.Text] = listOf(AnnotatedString("Report a problem"))
        }
        val button = node {
            this[SemanticsProperties.Text] = listOf(AnnotatedString("Report a problem"))
            click()
        }
        assertTrue(
            hasText("Report a problem").matches(title),
            "The old text-first selector admits it",
        )
        assertFalse(SupportUiContract.action("Report a problem").matches(title))
        assertTrue(SupportUiContract.action("Report a problem").matches(button))
        assertTrue(SupportUiContract.pageTitle("Report a problem").matches(title))
        assertFalse(SupportUiContract.pageTitle("Report a problem").matches(button))
    }

    @Test
    fun listActionBelongsToTheExistingListOwnerNotAnotherScreen() {
        val list = node { this[SemanticsProperties.TestTag] = LAZY_LIST_TEST_TAG }
        val entry =
            node(list) {
                this[SemanticsProperties.Text] = listOf(AnnotatedString("Report a problem"))
                click()
            }
        val outside = node {
            this[SemanticsProperties.Text] = listOf(AnnotatedString("Report a problem"))
            click()
        }
        assertTrue(
            SupportUiContract.listAction("Report a problem", SupportUiListOwner.Settings)
                .matches(entry)
        )
        assertFalse(
            SupportUiContract.listAction("Report a problem", SupportUiListOwner.Settings)
                .matches(outside)
        )
        assertFalse(
            SupportUiContract.listAction("Report a problem", SupportUiListOwner.Vpn).matches(entry)
        )
        val vpnList = node { this[SemanticsProperties.TestTag] = SupportUiListOwner.Vpn.tag }
        val vpnEntry =
            node(vpnList) {
                this[SemanticsProperties.Text] = listOf(AnnotatedString("Local network sharing"))
                click()
            }
        assertTrue(
            SupportUiContract.listAction("Local network sharing", SupportUiListOwner.Vpn)
                .matches(vpnEntry)
        )
        assertFalse(
            SupportUiContract.listAction("Local network sharing", SupportUiListOwner.Settings)
                .matches(vpnEntry)
        )
    }

    @Test
    fun horizontalGuidePagerCannotBeAnIndexedVerticalSettingsList() {
        val pager = node {
            this[SemanticsActions.ScrollToIndex] = AccessibilityAction(null) { _: Int -> true }
            this[SemanticsProperties.HorizontalScrollAxisRange] = ScrollAxisRange({ 0f }, { 2f })
        }
        val list = node {
            this[SemanticsActions.ScrollToIndex] = AccessibilityAction(null) { _: Int -> true }
            this[SemanticsProperties.VerticalScrollAxisRange] = ScrollAxisRange({ 0f }, { 20f })
        }
        assertTrue(SupportUiContract.horizontalPager().matches(pager))
        assertFalse(SupportUiContract.horizontalPager().matches(list))
        assertFalse(SupportUiContract.verticalColumn().matches(list))
    }

    @Test
    fun verticalGuideOwnerAndModalGuardsKeepTheirDistinctContracts() {
        val vertical = node {
            this[SemanticsActions.ScrollBy] =
                AccessibilityAction(null) { _: Float, _: Float -> true }
            this[SemanticsProperties.VerticalScrollAxisRange] = ScrollAxisRange({ 0f }, { 100f })
        }
        val dialog = node { this[SemanticsProperties.IsDialog] = Unit }
        val popup = node { this[SemanticsProperties.IsPopup] = Unit }
        assertTrue(SupportUiContract.verticalColumn().matches(vertical))
        assertFalse(SupportUiContract.horizontalPager().matches(vertical))
        assertFalse(SupportUiContract.modal().matches(vertical))
        assertTrue(SupportUiContract.modal().matches(dialog))
        assertTrue(SupportUiContract.modal().matches(popup))
    }

    @Test
    fun disabledActionsRemainDisabledAndIconsAreMatchedByDescription() {
        val back = node {
            this[SemanticsProperties.ContentDescription] = listOf("Back")
            click()
        }
        val disabled = node {
            this[SemanticsProperties.Text] = listOf(AnnotatedString("Review issue"))
            this[SemanticsProperties.Disabled] = Unit
            click()
        }
        assertTrue(SupportUiContract.action("Back").matches(back))
        assertFalse(isEnabled().matches(disabled))
        assertTrue(
            SupportUiContract.action("Review issue").matches(disabled),
            "The driver must assert enabled, not silently skip it",
        )
    }

    @Test
    fun warningMarkupIsRequiredAndDecodedWithoutChangingTheExpectedWords() {
        assertEquals(
            "Warning: A & B",
            SupportUiContract.warning("prefix <b>Warning: A &amp; B</b>") {
                it.replace("&amp;", "&")
            },
        )
        for (bad in listOf("no markup", "<b></b>", "<b>missing close", "</b>wrong order<b>")) {
            assertFails { SupportUiContract.warning(bad) { it } }
        }
    }
}
