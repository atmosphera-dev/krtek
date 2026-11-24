package net.mullvad.mullvadvpn.talpid

import android.app.Activity
import android.app.Instrumentation
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.os.Looper
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasAnyDescendant
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.v2.AndroidComposeUiTestEnvironment
import androidx.compose.ui.test.v2.runEmptyComposeUiTest
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MainActivity
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.feature.lansharing.impl.R
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.repository.ProblemReportRepository
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import net.mullvad.mullvadvpn.lib.ui.resource.R as CommonR
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

private fun SemanticsNode.editorInteractionDescription(): String =
    "id=$id, enabled=${!config.contains(SemanticsProperties.Disabled)}, " +
        "OnClick=${config.getOrNull(SemanticsActions.OnClick)?.action != null}, " +
        "Toggleable=${config.contains(SemanticsProperties.ToggleableState)}, " +
        "SetText=${config.getOrNull(SemanticsActions.SetText)?.action != null}, " +
        "boundsInRoot=$boundsInRoot, boundsInWindow=$boundsInWindow"

/** Drives the real feature navigation. Never retains raw trees or account-screen values. */
@OptIn(ExperimentalTestApi::class)
class LocalNetworkEditorInstrumentedTest {
    private lateinit var compose: ComposeUiTest
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext

    private fun withLiveActivity(block: () -> Unit) = withResumedMainActivity {
        compose.waitForIdle()
        block()
    }

    internal fun withForegroundActivity(block: () -> Unit) = runEmptyComposeUiTest {
        compose = this
        withLiveActivity { block() }
    }

    private fun nodes(): List<AccessibilityNodeInfo> {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return emptyList()
        if (root.packageName?.toString() != target.packageName) return emptyList()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        val result = mutableListOf<AccessibilityNodeInfo>()
        queue.add(root)
        while (queue.isNotEmpty() && result.size < 2048) {
            val node = queue.removeFirst()
            result.add(node)
            for (index in 0 until node.childCount) node.getChild(index)?.let(queue::add)
        }
        return result
    }

    private fun awaitNode(
        scroll: Boolean = false,
        predicate: (AccessibilityNodeInfo) -> Boolean,
    ): AccessibilityNodeInfo {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var nextScroll = 0L
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            val current = nodes()
            current.firstOrNull(predicate)?.let {
                return it
            }
            if (scroll && System.nanoTime() >= nextScroll) {
                current
                    .firstOrNull { it.isScrollable }
                    ?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
                nextScroll = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(350)
            }
            Thread.sleep(25)
        }
        error("Expected allowlisted editor action did not render")
    }

    internal fun copy(id: Int, vararg args: Any): String = target.getString(id, *args)

    /** Select live Compose ownership, never an Android accessibility snapshot/ancestor. */
    private fun interact(
        matcher: SemanticsMatcher,
        name: String,
        unmerged: Boolean = true,
        action: SemanticsNodeInteraction.((String) -> Unit) -> Unit,
    ) {
        var diagnostic = "node=$name, semantics=unavailable, bounds=unavailable"
        var phase = "await-node"
        try {
            compose.waitForIdle()
            // Lazy settings lists may not have composed the requested entry yet.
            if (compose.onAllNodes(matcher, unmerged).fetchSemanticsNodes().isEmpty()) {
                val lists = compose.onAllNodes(hasScrollToIndexAction())
                if (lists.fetchSemanticsNodes().size == 1) lists[0].performScrollToNode(matcher)
            }
            compose.waitUntil(timeoutMillis = 15_000) {
                compose.onAllNodes(matcher, unmerged).fetchSemanticsNodes().isNotEmpty()
            }
            val matches = compose.onAllNodes(matcher, unmerged).fetchSemanticsNodes()
            diagnostic =
                "node=$name, matches=${matches.joinToString { it.editorInteractionDescription() }}"
            assertEquals(1, matches.size, "Expected exactly one tagged node")
            val node = compose.onNode(matcher, useUnmergedTree = unmerged)
            fun describe() {
                val current = node.fetchSemanticsNode()
                diagnostic = "node=$name, ${current.editorInteractionDescription()}"
            }
            describe()
            phase = "scroll"
            val parents = generateSequence(node.fetchSemanticsNode().parent) { it.parent }
            if (parents.any { it.config.contains(SemanticsActions.ScrollBy) }) {
                node.performScrollTo()
            }
            compose.waitForIdle()
            describe()
            phase = "enabled-displayed-action"
            node.assertIsDisplayed().assertIsEnabled().action { diagnostic += ", $it" }
            ExternalUiActionCompletion.settle(
                instrumentation::waitForIdleSync,
                compose::waitForIdle,
            )
        } catch (failure: Throwable) {
            if (failure !is AssertionError && failure !is ComposeTimeoutException) throw failure
            // Compose assertion causes can dump an account screen. Retain only allowlisted facts.
            throw AssertionError(
                "Rendered editor interaction failed: phase=$phase, $diagnostic, " +
                    "failure=${failure.javaClass.simpleName}"
            )
        }
    }

    internal fun clickTag(tag: String, text: String) =
        interact(hasTestTag(tag), "tag=$tag, label=$text") { record ->
            val tagged = fetchSemanticsNode()
            fun describe(node: SemanticsNode): String {
                val facts = node.editorInteractionDescription()
                record(facts)
                return facts
            }
            val owner =
                TaggedActionResolver.resolve(
                    tagged,
                    { it.children },
                    { it.parent },
                    {
                        it.config.getOrNull(SemanticsActions.OnClick)?.action != null
                    },
                    { it.config.contains(SemanticsProperties.ToggleableState) },
                    ::describe,
                )
            describe(owner)
            val action =
                compose.onNode(
                    SemanticsMatcher("resolved action for tag=$tag") { it.id == owner.id },
                    useUnmergedTree = true,
                )
            val label = hasText(text) or hasContentDescription(text)
            val labelledControl = label or hasAnyDescendant(label)
            // A wrapper can own the label next to its only toggle; a tagged icon
            // can instead inherit its label from the clickable button around it.
            assertTrue(
                labelledControl.matches(tagged) || labelledControl.matches(owner),
                "Expected label inside the tagged control or its resolved action owner",
            )
            action.assertIsDisplayed().assertIsEnabled()
            assertTrue(
                action.fetchSemanticsNode().config.getOrNull(SemanticsActions.OnClick)?.action !=
                    null,
                "Expected a live OnClick semantics action for tag=$tag, id=${owner.id}",
            )
            action.assertHasClickAction().performClick()
        }

    private fun field(tag: String): AccessibilityNodeInfo {
        interact(hasTestTag(tag) and hasSetTextAction(), "field=$tag", unmerged = true) {}
        return awaitNode { it.viewIdResourceName == tag && it.isEditable }
    }

    internal fun enter(tag: String, value: String) {
        val matcher = hasTestTag(tag) and hasSetTextAction()
        interact(matcher, "field=$tag", unmerged = true) { performTextReplacement(value) }
        compose.waitForIdle()
        assertEquals(
            value,
            compose
                .onNode(matcher, useUnmergedTree = true)
                .fetchSemanticsNode()
                .config[SemanticsProperties.EditableText]
                .text,
            "Actual editable semantics did not consume the Compose action: tag=$tag",
        )
        val rendered = awaitNode {
            it.viewIdResourceName == tag && it.isEditable && it.text?.toString() == value
        }
        assertEquals(value, rendered.text?.toString())
    }

    internal fun back(editorField: String = "local_access_name") =
        EditorBackNavigationTest.toDiscardDialog(instrumentation, compose, editorField)

    /** Full display capture for the final screenshot set; the IME is hidden first. */
    internal fun screenshot(): android.graphics.Bitmap {
        if (EditorBackNavigationTest.imeVisible(instrumentation)) {
            EditorBackNavigationTest.hideIme(instrumentation)
            compose.waitUntil(timeoutMillis = 15_000) {
                !EditorBackNavigationTest.imeVisible(instrumentation)
            }
        }
        ExternalUiActionCompletion.settle(instrumentation::waitForIdleSync, compose::waitForIdle)
        return checkNotNull(instrumentation.uiAutomation.takeScreenshot())
    }

    private fun mainActivityResumed(): Boolean {
        var resumed = false
        instrumentation.runOnMainSync {
            resumed =
                ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .any { it is MainActivity }
        }
        return resumed
    }

    /** One Back per acknowledged system window; resumption forbids further navigation. */
    internal fun returnFromSystemSettings(step: String, requireSettingsVisit: Boolean = false) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var departingWindow: Int? = null
        var observedSettings = false
        fun record(action: String, window: Int) {
            instrumentation.sendStatus(
                0,
                Bundle().apply { putString("krtek_settings_return", "$step:$action:$window") },
            )
        }
        while (System.nanoTime() < deadline) {
            val root = instrumentation.uiAutomation.rootInActiveWindow
            val owner = root?.packageName?.toString()
            val resumed = mainActivityResumed()
            if (
                resumed &&
                    owner == target.packageName &&
                    (!requireSettingsVisit || observedSettings)
            ) {
                compose.waitForIdle()
                assertTrue(
                    compose
                        .onAllNodes(
                            hasTestTag("local_network_sharing_screen_test_tag"),
                            useUnmergedTree = true,
                        )
                        .fetchSemanticsNodes()
                        .size == 1,
                    "System return left the original Local network sharing route",
                )
                departingWindow?.let { record("ack", it) }
                record("local-screen", checkNotNull(root).windowId)
                return
            }
            // Lifecycle and accessibility are independent channels. A stale system root
            // after MainActivity resumes must never authorize a Back into the app.
            if (!resumed && root != null && owner != target.packageName) {
                check(
                    owner == "com.android.settings" || owner == "com.android.permissioncontroller"
                ) {
                    "Refuse to navigate an unrelated system window"
                }
                if (root.windowId != departingWindow && root.refresh() && !mainActivityResumed()) {
                    departingWindow?.let { record("ack", it) }
                    departingWindow = root.windowId
                    if (owner == "com.android.settings") observedSettings = true
                    record("back", root.windowId)
                    EditorBackNavigationTest.systemBack(instrumentation)
                }
            }
            Thread.sleep(25)
        }
        check(!requireSettingsVisit || observedSettings) {
            "Android Settings window was not observed"
        }
        error("System return transition was not acknowledged on the original route")
    }

    /** Reuses the proven async MainActivity environment for additional shipped-UI outcomes. */
    internal fun withLocalAccessScreen(
        testTimeout: Duration = 1.minutes,
        block: (LocalNetworkEditorInstrumentedTest) -> Unit,
    ) {
        val body: ComposeUiTest.() -> Unit = {
            compose = this
            withLiveActivity {
                clickTag(
                    "top_bar_settings_button_test_tag",
                    copy(CommonR.string.settings),
                )
                clickTag(
                    "vpn_settings_cell_test_tag",
                    target.getString(net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings_vpn),
                )
                clickTag(
                    "local_network_sharing_entry",
                    target.getString(
                        net.mullvad.mullvadvpn.lib.ui.resource.R.string.local_network_sharing
                    ),
                )
                block(this@LocalNetworkEditorInstrumentedTest)
            }
        }
        if (testTimeout == 1.minutes) {
            runEmptyComposeUiTest(body)
        } else {
            // runEmptyComposeUiTest exposes no timeout overload. Reuse its
            // underlying empty environment without launching another Activity.
            AndroidComposeUiTestEnvironment<MainActivity>(testTimeout = testTimeout) {
                    error("Launch the owned Activity inside the test body")
                }
                .runTest(body)
        }
    }

    internal fun requireNoIdentityPrompt() {
        val prompts =
            setOf(
                copy(R.string.local_access_fine_title),
                copy(R.string.local_access_background_title),
            )
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            assertTrue(
                instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() !=
                    "com.android.permissioncontroller",
                "Unexpected permission prompt",
            )
            assertTrue(
                nodes().none { it.text?.toString() in prompts },
                "Already satisfied prerequisites prompted again",
            )
            Thread.sleep(25)
        }
    }

    internal fun settleAction() = compose.waitForIdle()

    internal fun requireRenderedText(expected: String) {
        awaitNode(true) { it.text?.toString() == expected }
    }

    internal fun requireToggle(tag: String, expected: Boolean) =
        interact(hasTestTag(tag), "toggle=$tag") {
            val toggle =
                compose.onNode(
                    isToggleable() and hasAnyAncestor(hasTestTag(tag)),
                    useUnmergedTree = true,
                )
            if (expected) toggle.assertIsOn() else toggle.assertIsOff()
        }

    internal fun requireAbsentControl(tag: String) {
        assertTrue(
            compose
                .onAllNodes(hasTestTag(tag), useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        )
    }

    internal fun requireFieldText(tag: String, expected: String) {
        assertEquals(expected, field(tag).text?.toString())
    }

    internal fun requireSingleLineText(text: String) {
        compose.waitForIdle()
        val result = mutableListOf<TextLayoutResult>()
        compose.onNode(hasText(text), useUnmergedTree = true).performSemanticsAction(
            SemanticsActions.GetTextLayoutResult
        ) { action ->
            assertTrue(action(result))
        }
        val layout = result.single()
        val diagnostics = buildString {
            append("didOverflowWidth=${layout.didOverflowWidth}, ")
            append("didOverflowHeight=${layout.didOverflowHeight}, size=${layout.size}, ")
            append("constraints=${layout.layoutInput.constraints}, ")
            append("paragraph=${layout.multiParagraph.width}x${layout.multiParagraph.height}, ")
            append("lineCount=${layout.lineCount}, ")
            for (line in 0 until layout.lineCount) {
                append("line[$line]=(${layout.getLineLeft(line)},${layout.getLineTop(line)},")
                append("${layout.getLineRight(line)},${layout.getLineBottom(line)}), ")
                append("end=${layout.getLineEnd(line, visibleEnd = true)}, ")
                append("ellipsis=${layout.isLineEllipsized(line)}; ")
            }
        }
        assertEquals(1, layout.lineCount, diagnostics)
        assertFalse(
            layout.didOverflowHeight,
            "The full preference label must fit the native row height: $diagnostics",
        )
        assertTrue(
            layout.getLineRight(0) <= layout.size.width,
            "The full preference label must fit the measured row width: $diagnostics",
        )
        assertFalse(
            layout.isLineEllipsized(0),
            "The full label must not be ellipsized: $diagnostics",
        )
        assertEquals(text.length, layout.getLineEnd(0, visibleEnd = true), diagnostics)
    }

    /** B7 only: real shipped UI and intercepted Android intents, never a public request. */
    internal fun verifySupportAndGuide() {
        var stepIndex = 0
        fun supportStep(phase: String, event: String) {
            instrumentation.sendStatus(
                0,
                Bundle().apply {
                    putString(
                        "krtek_support_step",
                        JSONObject()
                            .put("index", stepIndex++)
                            .put("phase", phase)
                            .put("event", event)
                            .toString(),
                    )
                },
            )
        }
        val ui = SupportUiDriver.Actions(compose, instrumentation::waitForIdleSync, ::supportStep)
        val settingsTitle = copy(CommonR.string.settings)
        val vpnTitle = copy(CommonR.string.settings_vpn)
        val reportTitle = copy(CommonR.string.report_a_problem)
        val backLabel = copy(CommonR.string.back)
        val disclosure =
            copy(CommonR.string.problem_report_github_description, copy(CommonR.string.app_name))
        val koin = (target.applicationContext as MullvadApplication).getKoin()
        val repository = koin.get<ProblemReportRepository>()
        val support = koin.get<SupportIssueUseCase>()
        val original = repository.problemReport.value.description
        lateinit var clipboard: ClipboardManager
        var savedClip: ClipData? = null
        fun requireFocusedApp() {
            check(Looper.myLooper() == Looper.getMainLooper())
            val activity =
                ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<MainActivity>()
                    .single()
            check(activity.hasWindowFocus()) { "Owned app window must have clipboard input focus" }
        }
        instrumentation.runOnMainSync {
            requireFocusedApp()
            clipboard =
                checkNotNull(
                    target.applicationContext.getSystemService(ClipboardManager::class.java)
                )
            savedClip = clipboard.primaryClip?.let { ClipData(it) }
            check(
                ClipboardRestoreContract.restorable(
                    savedClip?.let { clip ->
                        (0 until clip.itemCount).map { index ->
                            val item = clip.getItemAt(index)
                            item.uri?.scheme to item.intent?.data?.scheme
                        }
                    } ?: emptyList()
                )
            ) {
                "Clipboard has URI authority this test cannot restore; no state was changed"
            }
        }
        val outgoing = LinkedBlockingQueue<Intent>()
        val monitor =
            object : Instrumentation.ActivityMonitor() {
                override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult {
                    // Block every external start, including an unexpected email/share regression.
                    outgoing.add(Intent(intent))
                    return Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
                }
            }
        instrumentation.addMonitor(monitor)
        fun copiedText(): String? {
            var text: String? = null
            instrumentation.runOnMainSync {
                requireFocusedApp()
                text = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            }
            return text
        }
        try {
            // Local screen -> VPN settings -> Settings. No settings are changed.
            ui.localPage("initial-local")
            ui.toolbarBack(backLabel, "local-back")
            ui.listPage(SupportUiListOwner.Vpn, vpnTitle, "initial-vpn")
            ui.toolbarBack(backLabel, "vpn-back")
            ui.listPage(SupportUiListOwner.Settings, settingsTitle, "initial-settings")
            ui.listAction(SupportUiListOwner.Settings, settingsTitle, reportTitle, "open-report")
            ui.reportPage(disclosure, "initial-report")
            ui.noText(copy(CommonR.string.open_github_issue), "initial-unreviewed")
            ui.replaceMessage(" \n\t ", "blank-message")
            ui.reportAction(copy(CommonR.string.problem_report_review), "blank-review")
            ui.contentText(copy(CommonR.string.report_problem_message_is_empty), "blank-error")
            for ((caseIndex, message) in
                listOf(
                        "  B7 🦔 & 中文 1234 5678 9012 3456\nUnsent original  ",
                        "B7 中文🦔& ".repeat(500),
                    )
                    .withIndex()) {
                val caseId = if (caseIndex == 0) "short" else "oversized"
                ui.replaceMessage(message, "$caseId-message")
                ui.noText(copy(CommonR.string.report_problem_message_is_empty), "$caseId-no-error")
                ui.noText(copy(CommonR.string.open_github_issue), "$caseId-unreviewed")
                ui.reportAction(copy(CommonR.string.problem_report_review), "$caseId-review")
                val expected = support(message, copy(CommonR.string.report_a_problem))
                assertTrue(expected.body.startsWith(message + "\n\n"))
                ui.reviewBody(expected.body, "$caseId-review-body")
                if (expected.prefilledUrl == null) {
                    ui.contentText(
                        copy(CommonR.string.problem_report_copy_fallback),
                        "$caseId-copy-fallback",
                    )
                    ui.contentText(expected.issuePageUrl, "$caseId-issue-link")
                }
                val clipboardChanged = CountDownLatch(1)
                var notificationOnMain = false
                val listener = ClipboardManager.OnPrimaryClipChangedListener {
                    notificationOnMain = Looper.myLooper() == Looper.getMainLooper()
                    clipboardChanged.countDown()
                }
                instrumentation.runOnMainSync {
                    requireFocusedApp()
                    clipboard.addPrimaryClipChangedListener(listener)
                }
                try {
                    ui.reportAction(copy(CommonR.string.problem_report_copy), "$caseId-copy")
                    assertTrue(
                        clipboardChanged.await(10, TimeUnit.SECONDS),
                        "Actual clipboard change did not arrive",
                    )
                    assertTrue(notificationOnMain, "Native clipboard notification must reach main")
                    val observed = checkNotNull(copiedText())
                    assertEquals(
                        expected.body,
                        observed,
                        "Actual clipboard equals the complete review",
                    )
                    fun digest(text: String) =
                        MessageDigest.getInstance("SHA-256")
                            .digest(text.toByteArray(Charsets.UTF_8))
                            .joinToString("") { "%02x".format(it) }
                    instrumentation.sendStatus(
                        0,
                        Bundle().apply {
                            putString(
                                "krtek_clipboard_observation",
                                JSONObject()
                                    .put("callback", true)
                                    .put("listener_main", notificationOnMain)
                                    .put("focused", true)
                                    .put("expected_chars", expected.body.length)
                                    .put("observed_chars", observed.length)
                                    .put("expected_sha256", digest(expected.body))
                                    .put("observed_sha256", digest(observed))
                                    .toString(),
                            )
                        },
                    )
                } finally {
                    instrumentation.runOnMainSync {
                        clipboard.removePrimaryClipChangedListener(listener)
                    }
                }
                ui.reportAction(copy(CommonR.string.open_github_issue), "$caseId-open-browser")
                val intent =
                    checkNotNull(outgoing.poll(10, TimeUnit.SECONDS)) {
                        "Reviewed action did not reach Android"
                    }
                assertEquals(Intent.ACTION_VIEW, intent.action)
                assertEquals(expected.url, intent.dataString)
                check(intent.extras == null && intent.clipData == null && intent.type == null) {
                    "Unexpected support attachment; private data withheld"
                }
                assertTrue(
                    outgoing.isEmpty(),
                    "One deliberate action emits exactly one browser intent",
                )
                assertEquals(
                    message,
                    repository.problemReport.value.description,
                    "Browser launch is not issue submission",
                )
                // Leave and recreate the screen; the repository still owns the full original.
                ui.toolbarBack(backLabel, "$caseId-leave-report")
                ui.listPage(SupportUiListOwner.Settings, settingsTitle, "$caseId-settings-returned")
                ui.listAction(
                    SupportUiListOwner.Settings,
                    settingsTitle,
                    reportTitle,
                    "$caseId-reenter-report",
                )
                ui.reportPage(disclosure, "$caseId-report-returned")
                ui.requireMessage(message, "$caseId-draft-retained")
                ui.noText(copy(CommonR.string.open_github_issue), "$caseId-review-invalidated")
            }
            ui.toolbarBack(backLabel, "final-report-back")
            ui.listPage(SupportUiListOwner.Settings, settingsTitle, "guide-settings")
            ui.listAction(SupportUiListOwner.Settings, settingsTitle, vpnTitle, "guide-vpn-entry")
            ui.listPage(SupportUiListOwner.Vpn, vpnTitle, "guide-vpn-page")
            val guideTitle = copy(CommonR.string.auto_connect_and_lockdown_mode)
            ui.listAction(SupportUiListOwner.Vpn, vpnTitle, guideTitle, "guide-entry")
            ui.guideWarning(
                guideTitle,
                copy(CommonR.string.auto_connect_carousel_third_slide_bottom_text),
                "guide-warning",
            )
            ui.toolbarBack(backLabel, "guide-back")
            ui.listPage(SupportUiListOwner.Vpn, vpnTitle, "guide-vpn-returned")
            ui.listAction(
                SupportUiListOwner.Vpn,
                vpnTitle,
                copy(CommonR.string.local_network_sharing),
                "guide-local-entry",
            )
            ui.localPage("guide-local-returned")
            instrumentation.runOnMainSync { requireFocusedApp() }
        } finally {
            supportStep("restore", "before")
            instrumentation.removeMonitor(monitor)
            instrumentation.runOnMainSync {
                repository.setDescription(original)
                savedClip?.let(clipboard::setPrimaryClip) ?: clipboard.clearPrimaryClip()
                val restored = clipboard.primaryClip
                check(restored?.itemCount == savedClip?.itemCount) {
                    "Clipboard restoration failed"
                }
                savedClip?.let { saved ->
                    val actual = checkNotNull(restored)
                    for (index in 0 until saved.itemCount) {
                        val expectedItem = saved.getItemAt(index)
                        val actualItem = actual.getItemAt(index)
                        check(
                            expectedItem.text?.toString() == actualItem.text?.toString() &&
                                expectedItem.htmlText == actualItem.htmlText &&
                                expectedItem.uri == actualItem.uri &&
                                expectedItem.intent?.toUri(0) == actualItem.intent?.toUri(0)
                        ) {
                            "Clipboard contents changed; private data withheld"
                        }
                    }
                }
            }
            check(repository.problemReport.value.description == original) {
                "Support draft restoration failed; private text withheld"
            }
            supportStep("restore", "after")
        }
        instrumentation.sendStatus(
            0,
            Bundle().apply {
                putString(
                    "krtek_support_review",
                    "PASS: complete short/oversized review, clipboard and blocked ACTION_VIEW, retained draft, localized lockdown guide",
                )
            },
        )
    }

    internal fun requireConnectedDraft(ssid: SsidIdentity) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        val expected = ssid.displayText()
        while (System.nanoTime() < deadline) {
            compose.waitForIdle()
            if (field("local_access_wifi_0").text?.toString() == expected) return
            Thread.sleep(25)
        }
        error("Fresh connected Wi-Fi name did not reach the exact editor field")
    }

    @Test
    fun realEditorRejectsBroadeningRetainsDirtyStateAndPersistsThenDeletesRule() =
        runEmptyComposeUiTest {
            compose = this
            withLiveActivity {
                val repository =
                    (target.applicationContext as MullvadApplication)
                        .getKoin()
                        .get<SettingsRepository>()
                runBlocking {
                    val original =
                        withTimeout(10_000) { repository.settingsUpdates.first { it != null } }
                            ?.localNetworkAccess
                    assertEquals(
                        LocalNetworkAccess(),
                        original,
                        "Preserve unexpected configured policy",
                    )
                    val beforePermissions =
                        listOf(
                                "ACCESS_LOCAL_NETWORK",
                                "ACCESS_COARSE_LOCATION",
                                "ACCESS_FINE_LOCATION",
                                "ACCESS_BACKGROUND_LOCATION",
                            )
                            .associateWith { target.checkSelfPermission("android.permission.$it") }
                    val name = "Krtek editor fixture"
                    try {
                        clickTag(
                            "top_bar_settings_button_test_tag",
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings
                            ),
                        )
                        clickTag(
                            "vpn_settings_cell_test_tag",
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string.settings_vpn
                            ),
                        )
                        clickTag(
                            "local_network_sharing_entry",
                            target.getString(
                                net.mullvad.mullvadvpn.lib.ui.resource.R.string
                                    .local_network_sharing
                            ),
                        )
                        clickTag("local_access_add_rule", copy(R.string.local_access_add_rule))
                        enter("local_access_name", name)
                        enter("local_access_addresses", "192.168.240.11/28")
                        clickTag("local_access_save", copy(R.string.local_access_save))
                        // The noncanonical prefix is rejected in place, with the canonical
                        // suggestion rendered under the addresses field.
                        val feedback = awaitNode {
                            it.text?.toString() == copy(R.string.local_access_invalid_rule)
                        }
                        val save = awaitNode {
                            it.text?.toString() == copy(R.string.local_access_save)
                        }
                        val feedbackBounds = Rect().also(feedback::getBoundsInScreen)
                        val saveBounds = Rect().also(save::getBoundsInScreen)
                        assertTrue(
                            feedbackBounds.bottom <= saveBounds.top,
                            "Validation feedback must be visible directly above Save",
                        )
                        // Return to the field that owns the canonical suggestion; scrolling
                        // only forward from Save cannot reach an earlier field.
                        field("local_access_addresses")
                        awaitNode(scroll = true) {
                            it.text?.toString() ==
                                copy(R.string.local_access_canonical_suggestion, "192.168.240.0/28")
                        }
                        assertEquals(
                            "192.168.240.11/28",
                            field("local_access_addresses").text?.toString(),
                        )
                        assertEquals(original, repository.settingsUpdates.value?.localNetworkAccess)
                        back()
                        clickTag(
                            "local_access_dialog_cancel",
                            copy(R.string.local_access_keep_editing),
                        )
                        assertEquals(name, field("local_access_name").text?.toString())
                        enter("local_access_addresses", "192.168.240.10/32")
                        clickTag("local_access_save", copy(R.string.local_access_save))
                        val saved =
                            withTimeout(10_000) {
                                    repository.settingsUpdates.first {
                                        it?.localNetworkAccess?.rules?.singleOrNull()?.name == name
                                    }
                                }
                                ?.localNetworkAccess
                        assertTrue(saved != null && !saved.enabled)
                        assertEquals(
                            listOf("192.168.240.10/32"),
                            saved.rules.single().cidrs.map { it.toString() },
                        )
                        awaitNode(true) { it.text?.toString() == name }
                        clickTag(
                            "local_access_edit_${saved.rules.single().id}",
                            copy(R.string.local_access_edit),
                        )
                        enter("local_access_name", "Krtek unsaved fixture")
                        back()
                        clickTag("local_access_dialog_confirm", copy(R.string.local_access_discard))
                        assertEquals(saved, repository.settingsUpdates.value?.localNetworkAccess)
                        clickTag(
                            "local_access_delete_${saved.rules.single().id}",
                            copy(R.string.local_access_delete),
                        )
                        requireRenderedText(copy(R.string.local_access_delete_description, name))
                        clickTag("local_access_dialog_cancel", copy(android.R.string.cancel))
                        assertEquals(saved, repository.settingsUpdates.value?.localNetworkAccess)
                        clickTag(
                            "local_access_delete_${saved.rules.single().id}",
                            copy(R.string.local_access_delete),
                        )
                        requireRenderedText(copy(R.string.local_access_delete_description, name))
                        clickTag("local_access_dialog_confirm", copy(R.string.local_access_delete))
                        withTimeout(10_000) {
                            repository.settingsUpdates.first { it?.localNetworkAccess == original }
                        }
                        assertEquals(
                            beforePermissions,
                            beforePermissions.keys.associateWith {
                                target.checkSelfPermission("android.permission.$it")
                            },
                        )
                    } finally {
                        val current = repository.settingsUpdates.value?.localNetworkAccess
                        check(
                            current == original ||
                                (current?.enabled == false && current.rules.all { it.name == name })
                        ) {
                            "Concurrent configuration retained for investigation"
                        }
                        if (current != original) {
                            assertTrue(
                                repository
                                    .setLocalNetworkAccess(
                                        checkNotNull(original),
                                        checkNotNull(current),
                                    )
                                    .isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.localNetworkAccess == original
                                }
                            }
                        }
                    }
                }
            }
        }
}
