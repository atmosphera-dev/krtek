package net.mullvad.mullvadvpn.talpid

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isPopup
import net.mullvad.mullvadvpn.lib.ui.tag.LAZY_LIST_TEST_TAG
import net.mullvad.mullvadvpn.lib.ui.tag.LAZY_LIST_VPN_SETTINGS_TEST_TAG

internal typealias SupportUiListOwner = SupportUiContract.ListOwner

/** Live semantic contracts, not cached accessibility text matches across navigation. */
internal object SupportUiContract {
    enum class ListOwner(val tag: String) {
        Settings(LAZY_LIST_TEST_TAG),
        Vpn(LAZY_LIST_VPN_SETTINGS_TEST_TAG),
    }

    fun action(label: String): SemanticsMatcher =
        (hasText(label) or hasContentDescription(label)) and hasClickAction()

    fun listAction(label: String, owner: ListOwner): SemanticsMatcher =
        action(label) and hasAnyAncestor(hasTestTag(owner.tag))

    fun pageTitle(label: String): SemanticsMatcher = hasText(label) and hasClickAction().not()

    fun horizontalPager(): SemanticsMatcher =
        hasScrollToIndexAction() and
            SemanticsMatcher.keyIsDefined(SemanticsProperties.HorizontalScrollAxisRange)

    fun verticalColumn(): SemanticsMatcher =
        hasScrollAction() and
            SemanticsMatcher.keyIsDefined(SemanticsProperties.VerticalScrollAxisRange) and
            hasScrollToIndexAction().not()

    fun modal(): SemanticsMatcher = isDialog() or isPopup()

    fun warning(html: String, decode: (String) -> String): String {
        val start = html.indexOf("<b>")
        val end = html.indexOf("</b>", start + 3)
        check(start >= 0 && end > start + 3) { "Localized guide warning must remain explicit" }
        return decode(html.substring(start + 3, end)).also { check(it.isNotBlank()) }
    }
}
