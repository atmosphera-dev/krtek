package net.mullvad.mullvadvpn.talpid

import android.app.Instrumentation
import android.view.WindowInsets
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import net.mullvad.mullvadvpn.app.MainActivity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse

/** Owns the distinction between dismissing input and navigating a dirty editor. */
@OptIn(ExperimentalTestApi::class)
internal object EditorBackNavigationTest {
    fun toDiscardDialog(instrumentation: Instrumentation, compose: ComposeUiTest) {
        var phase = "before-back"
        var imeBefore: Boolean? = null
        try {
            compose.waitForIdle()
            // A pre-existing dialog must not make a missed Back look successful.
            assertEquals(
                0,
                compose
                    .onAllNodes(hasTestTag("local_access_dialog_cancel"), true)
                    .fetchSemanticsNodes()
                    .size,
                "Dirty editor must not already have a discard dialog",
            )
            imeBefore = imeVisible(instrumentation)
            if (imeBefore) {
                phase = "hide-ime"
                instrumentation.runOnMainSync {
                    val activity =
                        ActivityLifecycleMonitorRegistry.getInstance()
                            .getActivitiesInStage(Stage.RESUMED)
                            .filterIsInstance<MainActivity>()
                            .single()
                    checkNotNull(activity.window.insetsController).hide(WindowInsets.Type.ime())
                }
                compose.waitUntil(timeoutMillis = 15_000) { !imeVisible(instrumentation) }
            }
            assertFalse(imeVisible(instrumentation), "IME must be hidden before editor Back")
            phase = "editor-back"
            systemBack(instrumentation)
            phase = "discard-dialog"
            compose.waitUntil(timeoutMillis = 15_000) {
                compose
                    .onAllNodes(hasTestTag("local_access_dialog_cancel"), true)
                    .fetchSemanticsNodes()
                    .size == 1
            }
            for (tag in listOf("local_access_dialog_cancel", "local_access_dialog_confirm")) {
                compose.onNode(hasTestTag(tag), useUnmergedTree = true).assertIsDisplayed()
            }
            // Back reached the editor rather than leaving its route or closing the draft.
            compose.onNode(hasTestTag("local_access_name"), useUnmergedTree = true).assertExists()
        } catch (failure: Throwable) {
            if (failure !is AssertionError && failure !is ComposeTimeoutException) throw failure
            // Never export an arbitrary semantics tree, which can contain account data.
            throw AssertionError(
                "Editor Back failed: phase=$phase, imeBefore=$imeBefore, " +
                    "expected=discard-dialog, failure=${failure.javaClass.simpleName}"
            )
        }
    }

    private fun imeVisible(instrumentation: Instrumentation): Boolean {
        var visible = false
        instrumentation.runOnMainSync {
            val activity =
                ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<MainActivity>()
                    .single()
            visible =
                checkNotNull(activity.window.decorView.rootWindowInsets)
                    .isVisible(WindowInsets.Type.ime())
        }
        return visible
    }

    /** System settings owns its own window-by-window acknowledgment in the caller. */
    fun systemBack(instrumentation: Instrumentation) {
        instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_BACK").use {
            descriptor ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }
        instrumentation.uiAutomation.waitForIdle(500, 5_000)
        instrumentation.waitForIdleSync()
    }
}
