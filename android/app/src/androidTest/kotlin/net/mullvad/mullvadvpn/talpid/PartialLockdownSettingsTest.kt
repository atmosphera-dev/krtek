package net.mullvad.mullvadvpn.talpid

import android.accessibilityservice.AccessibilityServiceInfo
import android.graphics.Rect
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.jupiter.api.Assertions.assertEquals

/** Drives the same Android VPN Settings control as the device harness. */
internal class PartialLockdownSettingsTest(private val shell: (String) -> String) {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val app = instrumentation.targetContext.packageName
    private val settings = "com.android.settings"

    fun read(): Boolean =
        when (val value = shell("settings get secure always_on_vpn_lockdown")) {
            "0" -> false
            "1" -> true
            else -> error("Unexpected VPN lockdown setting: $value")
        }

    fun set(enabled: Boolean) {
        if (read() == enabled) return
        await("Krtek window before opening VPN Settings") {
            true.takeIf { automation.rootInActiveWindow?.packageName == app }
        }
        val previousEvent = latestModeChange()
        var failure: Throwable? = null
        try {
            val launch = shell("am start -W -f 0x10008000 -a android.settings.VPN_SETTINGS")
            check("Status: ok" in launch) { "Could not open Android VPN Settings: $launch" }
            changeLockdown(enabled, previousEvent)
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            try {
                closeVpnSettings()
            } catch (cleanup: Throwable) {
                failure?.addSuppressed(cleanup) ?: throw cleanup
            }
        }
    }

    private fun changeLockdown(enabled: Boolean, previousEvent: String?) {
        settleSettingsTransition()
        // The Settings setter changes the framework mode as well as persisting the secure key.
        val appLabel =
            instrumentation.targetContext.applicationInfo
                .loadLabel(instrumentation.targetContext.packageManager)
                .toString()
        tap(
            awaitNode("VPN settings button") { nodes ->
                val title =
                    nodes.singleOrNull { it.text?.toString() == appLabel } ?: return@awaitNode null
                nodes.singleOrNull {
                    it.viewIdResourceName == "com.android.settings:id/settings_button" &&
                        it.bounds().let { bounds ->
                            title.bounds().centerY() in bounds.top until bounds.bottom
                        }
                }
            }
        )
        settleSettingsTransition()
        val toggle =
            awaitNode("Block connections without VPN switch") { nodes ->
                val title =
                    nodes.singleOrNull { it.text?.toString() == "Block connections without VPN" }
                        ?: return@awaitNode null
                nodes.singleOrNull {
                    it.viewIdResourceName == "com.android.settings:id/switchWidget" &&
                        it.isEnabled &&
                        it.bounds().let { bounds ->
                            title.bounds().centerY() in bounds.top until bounds.bottom
                        }
                }
            }
        assertEquals(
            if (enabled) AccessibilityNodeInfoCompat.CHECKED_STATE_FALSE
            else AccessibilityNodeInfoCompat.CHECKED_STATE_TRUE,
            AccessibilityNodeInfoCompat.wrap(toggle).checked,
            "Lockdown switch before the change",
        )
        tap(toggle)
        if (enabled) {
            settleSettingsTransition()
            confirmLockdown()
        }
        await("new framework lockdown=$enabled event") {
            val event = latestModeChange()
            true.takeIf {
                read() == enabled &&
                    event != previousEvent &&
                    event?.contains("Mode changed: lockdown=$enabled alwaysOn=true") == true
            }
        }
        assertEquals(app, shell("settings get secure always_on_vpn_app"))
    }

    private fun closeVpnSettings() {
        var departingWindow: Int? = null
        await("Krtek window after VPN Settings") {
            val root = automation.rootInActiveWindow ?: return@await null
            if (root.packageName == app) return@await true
            // Wait for each Back to be acknowledged before sending another one.
            if (
                root.packageName == settings && root.windowId != departingWindow && root.refresh()
            ) {
                val current = automation.rootInActiveWindow
                if (current?.packageName == settings && current.windowId == root.windowId) {
                    departingWindow = root.windowId
                    EditorBackNavigationTest.systemBack(instrumentation)
                }
            }
            null
        }
    }

    private val automation
        get() = instrumentation.uiAutomation

    private fun latestModeChange(): String? =
        shell("dumpsys vpn_management").lineSequence().firstOrNull {
            "[LockdownAlwaysOn] Mode changed" in it
        }

    private fun AccessibilityNodeInfo.bounds(): Rect = Rect().also(::getBoundsInScreen)

    private fun tap(node: AccessibilityNodeInfo) {
        val bounds = node.bounds()
        check(!bounds.isEmpty)
        shell("input tap ${bounds.centerX()} ${bounds.centerY()}")
    }

    private fun confirmLockdown() {
        val info = automation.serviceInfo
        val originalFlags = info.flags
        info.flags = originalFlags or AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        automation.serviceInfo = info
        try {
            val button =
                await("Require VPN connection confirmation") {
                    // Settings publishes this dialog as a separate window during the transition.
                    automation.windows
                        .asSequence()
                        .filter { it.isFocused }
                        .mapNotNull { it.root }
                        .map(::settingsNodes)
                        .filter { nodes ->
                            nodes.any {
                                it.viewIdResourceName == "com.android.settings:id/alertTitle" &&
                                    it.hasLabel("Require VPN connection?")
                            }
                        }
                        .mapNotNull { nodes ->
                            nodes.singleOrNull {
                                it.viewIdResourceName == "android:id/button1" &&
                                    it.hasLabel("Turn on") &&
                                    it.isEnabled &&
                                    it.isClickable
                            }
                        }
                        .singleOrNull()
                }
            tap(button)
        } finally {
            info.flags = originalFlags
            automation.serviceInfo = info
        }
    }

    private fun AccessibilityNodeInfo.hasLabel(label: String): Boolean =
        text?.toString() == label || contentDescription?.toString() == label

    // Match the device harness: a node may be visible while its window bounds are still moving.
    private fun settleSettingsTransition() = SystemClock.sleep(2_000)

    private fun settingsNodes(
        root: AccessibilityNodeInfo? = automation.rootInActiveWindow
    ): List<AccessibilityNodeInfo> {
        if (root == null || root.packageName != settings) return emptyList()
        return buildList {
            add(root)
            var index = 0
            while (index < size) {
                val node = get(index++)
                repeat(node.childCount) { node.getChild(it)?.let(::add) }
            }
        }
            .filter { it.isVisibleToUser }
    }

    private fun awaitNode(
        description: String,
        select: (List<AccessibilityNodeInfo>) -> AccessibilityNodeInfo?,
    ): AccessibilityNodeInfo = await(description) { select(settingsNodes()) }

    private fun <T : Any> await(description: String, read: () -> T?): T {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        do {
            read()?.let {
                return it
            }
            SystemClock.sleep(100)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Android VPN Settings did not reach $description")
    }
}
