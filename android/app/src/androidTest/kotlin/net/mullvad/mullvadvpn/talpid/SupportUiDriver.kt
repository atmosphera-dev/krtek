package net.mullvad.mullvadvpn.talpid

import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextReplacement
import androidx.core.text.HtmlCompat
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Owns all support-flow page/actions; it never changes navigation or product state directly. */
@OptIn(ExperimentalTestApi::class)
internal object SupportUiDriver {
    class Actions(
        private val compose: ComposeUiTest,
        private val androidIdle: () -> Unit,
        private val receipt: (String, String) -> Unit,
    ) {
        private fun complete() =
            ExternalUiActionCompletion.settle(androidIdle, compose::waitForIdle)

        private fun noModal() {
            compose
                .onAllNodes(SupportUiContract.modal(), useUnmergedTree = true)
                .assertCountEquals(0)
        }

        private fun step(phase: String, action: () -> Unit) {
            complete()
            receipt(phase, "before")
            noModal()
            action()
            complete()
            receipt(phase, "after")
        }

        fun localPage(phase: String) =
            step(phase) {
                compose
                    .onNode(
                        hasTestTag("local_network_sharing_screen_test_tag"),
                        useUnmergedTree = true,
                    )
                    .assertIsDisplayed()
            }

        private fun assertListPage(owner: SupportUiContract.ListOwner, title: String) {
            compose.onNode(SupportUiContract.pageTitle(title)).assertIsDisplayed()
            compose.onAllNodes(hasTestTag(owner.tag)).assertCountEquals(1)
            compose.onAllNodes(hasSetTextAction(), useUnmergedTree = true).assertCountEquals(0)
        }

        fun listPage(owner: SupportUiContract.ListOwner, title: String, phase: String) =
            step(phase) { assertListPage(owner, title) }

        fun listAction(
            owner: SupportUiContract.ListOwner,
            title: String,
            label: String,
            phase: String,
        ) =
            step(phase) {
                assertListPage(owner, title)
                val action = SupportUiContract.listAction(label, owner)
                compose.onNode(hasTestTag(owner.tag)).performScrollToNode(action)
                compose.onNode(action).assertIsEnabled().assertIsDisplayed().performClick()
            }

        fun toolbarBack(label: String, phase: String) =
            step(phase) {
                compose
                    .onNode(SupportUiContract.action(label))
                    .assertIsEnabled()
                    .assertIsDisplayed()
                    .performClick()
            }

        fun reportPage(disclosure: String, phase: String) =
            step(phase) {
                compose.onAllNodes(hasSetTextAction(), useUnmergedTree = true).assertCountEquals(1)
                compose
                    .onNode(hasText(disclosure), useUnmergedTree = true)
                    .performScrollTo()
                    .assertIsDisplayed()
            }

        fun replaceMessage(text: String, phase: String) =
            step(phase) {
                compose
                    .onNode(hasSetTextAction(), useUnmergedTree = true)
                    .performScrollTo()
                    .performTextReplacement(text)
                complete()
                assertMessage(text)
            }

        private fun assertMessage(text: String) {
            assertEquals(
                text,
                compose
                    .onNode(hasSetTextAction(), useUnmergedTree = true)
                    .fetchSemanticsNode()
                    .config[SemanticsProperties.EditableText]
                    .text,
            )
        }

        fun requireMessage(text: String, phase: String) = step(phase) { assertMessage(text) }

        fun noText(text: String, phase: String) =
            step(phase) {
                compose.onNode(hasText(text), useUnmergedTree = true).assertDoesNotExist()
            }

        fun contentText(text: String, phase: String) =
            step(phase) {
                compose
                    .onNode(hasText(text), useUnmergedTree = true)
                    .performScrollTo()
                    .assertIsDisplayed()
            }

        fun reviewBody(text: String, phase: String) =
            step(phase) {
                // The complete oversized body need not fit the viewport, but must remain rendered
                // in
                // full.
                assertEquals(
                    text,
                    compose
                        .onNode(hasText(text), useUnmergedTree = true)
                        .fetchSemanticsNode()
                        .config[SemanticsProperties.Text]
                        .single()
                        .text,
                )
            }

        fun reportAction(label: String, phase: String) =
            step(phase) {
                compose
                    .onNode(SupportUiContract.action(label))
                    .performScrollTo()
                    .assertIsEnabled()
                    .assertIsDisplayed()
                    .performClick()
            }

        fun guideWarning(title: String, html: String, phase: String) =
            step(phase) {
                compose.onNode(SupportUiContract.pageTitle(title)).assertIsDisplayed()
                compose.onAllNodes(SupportUiContract.horizontalPager()).assertCountEquals(1)
                compose.onNode(SupportUiContract.horizontalPager()).performScrollToIndex(2)
                complete()
                // The paragraph's closest scroll parent is horizontal. Explicitly own the vertical
                // one.
                val vertical = compose.onNode(SupportUiContract.verticalColumn())
                val range =
                    vertical
                        .fetchSemanticsNode()
                        .config[SemanticsProperties.VerticalScrollAxisRange]
                val end = range.maxValue()
                vertical.performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, end) }
                complete()
                val settled =
                    vertical
                        .fetchSemanticsNode()
                        .config[SemanticsProperties.VerticalScrollAxisRange]
                assertTrue(
                    settled.value() >= settled.maxValue(),
                    "Guide vertical content reached its end",
                )
                val warning =
                    SupportUiContract.warning(html) {
                        HtmlCompat.fromHtml(it, HtmlCompat.FROM_HTML_MODE_COMPACT).toString()
                    }
                compose
                    .onNode(hasText(warning, substring = true), useUnmergedTree = true)
                    .assertIsDisplayed()
            }
    }
}
