package net.mullvad.mullvadvpn.talpid

import android.net.InetAddresses
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.feature.lansharing.impl.R
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.PackageName
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import net.mullvad.mullvadvpn.lib.repository.SplitTunnelingRepository
import net.mullvad.talpid.TalpidVpnService
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Two ordinary UIDs; Binder control is independent of either UID's data route. */
class ExcludedAppsLocalRulesInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val args = InstrumentationRegistry.getArguments()
    private val harness = LocalNetworkDeliveryInstrumentedTest()
    private val excludedPackage = instrumentation.context.packageName
    private val includedPackage = "net.mullvad.mullvadvpn.test.mockapi"

    private fun skip(): Boolean =
        checkNotNull(args.getString("skip"))
            .also { check(it in setOf("true", "false")) }
            .toBoolean()

    private fun fixture(initialSkip: Boolean = skip(), block: Fixture.() -> Unit) =
        harness.withConsumer(null, testTimeout = 8.minutes) { excluded, repository, connection ->
            harness.Consumer(includedPackage).use { included ->
                included.identity()
                val before = checkNotNull(repository.settingsUpdates.value)
                val split =
                    (target.applicationContext as MullvadApplication)
                        .getKoin()
                        .get<SplitTunnelingRepository>()
                val excludedName = PackageName(excludedPackage)
                val includedName = PackageName(includedPackage)
                assertTrue(excludedName !in before.splitTunnelSettings.excludedApps)
                assertTrue(includedName !in before.splitTunnelSettings.excludedApps)
                val excludedUid = target.packageManager.getApplicationInfo(excludedPackage, 0).uid
                val includedUid = target.packageManager.getApplicationInfo(includedPackage, 0).uid
                assertNotEquals(excludedUid, includedUid)
                assertNotEquals(target.applicationInfo.uid, includedUid)
                assertNotEquals(target.applicationInfo.uid, excludedUid)
                harness.report("excluded_consumer_uid", excludedUid)
                harness.report("included_control_uid", includedUid)
                val policy = harness.peerPolicy().copy(skipLocalRulesForExcludedApps = initialSkip)
                var bodyFailure: Throwable? = null
                try {
                    harness.disconnect(connection)
                    runBlocking {
                        assertTrue(split.excludeApp(excludedName).isRight())
                        assertTrue(split.enableSplitTunneling(true).isRight())
                        withTimeout(10_000) {
                            repository.settingsUpdates.first {
                                it?.splitTunnelSettings?.let { splitSettings ->
                                    splitSettings.enabled &&
                                        excludedName in splitSettings.excludedApps
                                } == true
                            }
                        }
                    }
                    harness.setPolicy(repository, policy)
                    Fixture(
                            excluded,
                            included,
                            repository,
                            connection,
                            split,
                            excludedUid,
                            includedUid,
                        )
                        .block()
                } catch (failure: Throwable) {
                    bodyFailure = failure
                    harness.report("excluded_apps_body_failure", failure.javaClass.name)
                    throw failure
                } finally {
                    // The runner also independently checks exact saved settings/restoration.
                    try {
                        harness.disconnect(connection)
                        runBlocking {
                            assertTrue(split.includeApp(excludedName).isRight())
                            assertTrue(
                                split
                                    .enableSplitTunneling(before.splitTunnelSettings.enabled)
                                    .isRight()
                            )
                            withTimeout(10_000) {
                                repository.settingsUpdates.first {
                                    it?.splitTunnelSettings == before.splitTunnelSettings
                                }
                            }
                        }
                        harness.setPolicy(repository, checkNotNull(before.localNetworkAccess))
                        harness.report("excluded_apps_settings_restored", true)
                    } catch (restorationFailure: Throwable) {
                        harness.report(
                            "excluded_apps_restoration_failure",
                            restorationFailure.javaClass.name,
                        )
                        val primary = bodyFailure
                        if (primary == null) throw restorationFailure
                        primary.addSuppressed(restorationFailure)
                    }
                }
            }
        }

    private inner class Fixture(
        val excluded: LocalNetworkDeliveryInstrumentedTest.Consumer,
        val included: LocalNetworkDeliveryInstrumentedTest.Consumer,
        val repository: SettingsRepository,
        val connection: ConnectionProxy,
        val split: SplitTunnelingRepository,
        val excludedUid: Int,
        val includedUid: Int,
    ) {
        fun policy() = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)

        fun capture(
            state: String,
            excludedIncluded: Boolean,
        ): LocalNetworkDeliveryInstrumentedTest.AppliedCapture = runBlocking {
            withTimeout(30_000) {
                while (isActive) {
                    val config =
                        harness.appliedConfiguration(policy(), ForwardingAvailability.Active, state)
                    if (
                        harness.uidIncluded(config.uids, excludedUid) == excludedIncluded &&
                            harness.uidIncluded(config.uids, includedUid)
                    )
                        return@withTimeout config
                    delay(100)
                }
                error("Unreachable coverage deadline")
            }
        }

        fun proof(state: String): LocalNetworkDeliveryInstrumentedTest.AppliedCapture {
            val excludedIncluded =
                state == "Disconnected" && !policy().skipLocalRulesForExcludedApps
            harness.awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                state,
            )
            val config = capture(state, excludedIncluded)
            for (transport in listOf("tcp", "udp")) {
                val control = harness.probeSocket(included, transport, "reply")
                assertLocalSource(control.getString("socket_report"))
                val lockdown = args.getString("krtek_expect_lockdown", "1") == "1"
                val expectReply = excludedIncluded || !lockdown
                val result =
                    harness.probeSocket(
                        excluded,
                        transport,
                        if (expectReply) "reply" else "blocked",
                    )
                if (excludedIncluded) assertLocalSource(result.getString("socket_report"))
                else if (expectReply) {
                    val source =
                        JSONObject(checkNotNull(result.getString("socket_report")))
                            .getString("local_address")
                    assertFalse(
                        InetAddresses.parseNumericAddress(source) ==
                            InetAddresses.parseNumericAddress("172.27.1.1")
                    )
                }
                harness.report(
                    "excluded_consumer_path",
                    if (excludedIncluded) "Local"
                    else if (expectReply) "Android-direct-not-Local"
                    else "Android-blocked-outside-capture",
                )
            }
            harness.report("builder_entries", TalpidVpnService.builderEstablishAttempts())
            return config
        }

        fun flag(value: Boolean) {
            harness.setPolicy(repository, policy().copy(skipLocalRulesForExcludedApps = value))
            assertEquals(value, policy().skipLocalRulesForExcludedApps)
        }

        fun error(block: () -> Unit) = runBlocking {
            harness.withEmptyRelayList(repository) {
                assertTrue(connection.connect().isRight())
                val state =
                    withTimeout(60_000) { connection.tunnelState.first { it is TunnelState.Error } }
                        as TunnelState.Error
                assertTrue(state.errorState.isBlocking)
                block()
                harness.disconnect(connection)
            }
        }
    }

    private fun assertLocalSource(report: String?) {
        assertEquals(
            InetAddresses.parseNumericAddress("172.27.1.1"),
            InetAddresses.parseNumericAddress(
                JSONObject(checkNotNull(report)).getString("local_address")
            ),
            "Ordinary consumer must enter fixed-source Local capture; peer hits alone are insufficient",
        )
        // INFRA additionally correlates TUN/protected physical/peer bytes and selected network.
    }

    @Test
    fun excludedConsumerState() = fixture {
        when (checkNotNull(args.getString("state"))) {
            "disconnected" -> proof("Disconnected")
            "connected" -> {
                harness.connect(connection)
                proof("Connected")
            }
            "error" -> error { proof("Error") }
            else -> error("Unknown frozen state")
        }
    }

    @Test
    fun excludedConsumerTransitions() = fixture {
        val initial = policy().skipLocalRulesForExcludedApps
        proof("Disconnected")
        for (value in listOf(!initial, initial)) {
            val before = TalpidVpnService.builderEstablishAttempts()
            flag(value)
            proof("Disconnected")
            assertEquals(
                before + 1,
                TalpidVpnService.builderEstablishAttempts(),
                "One actual Partial coverage replacement",
            )
        }
        val beforeConnect = TalpidVpnService.builderEstablishAttempts()
        harness.report("pre_target_partial", capture("Disconnected", !initial).toString())
        harness.connect(connection)
        proof("Connected")
        assertEquals(
            beforeConnect + 1,
            TalpidVpnService.builderEstablishAttempts(),
            "Only the real target establishes full capture; no pre-Connect full establish",
        )
        for (value in listOf(!initial, initial)) {
            val before = proof("Connected")
            val entries = TalpidVpnService.builderEstablishAttempts()
            val begin = SystemClock.elapsedRealtimeNanos()
            flag(value)
            runBlocking { delay(1_000) }
            val after = proof("Connected")
            assertEquals(before, after)
            assertEquals(
                entries,
                TalpidVpnService.builderEstablishAttempts(),
                "Flag-only unchanged full profile must not establish",
            )
            harness.report(
                "full_flag_zero_establish_window_ns",
                SystemClock.elapsedRealtimeNanos() - begin,
            )
        }
        harness.connect(connection, reconnect = true)
        proof("Connected")
        error { proof("Error") }
        proof("Disconnected")
        harness.report(
            "coverage_transition_socket_contract",
            "Fresh settled TCP/UDP required; OFF coverage changes can destroy old sockets. Static ON continuity is covered by the original selector.",
        )
    }

    @Test
    fun excludedConsumerNoCaptureControls() =
        fixture(initialSkip = true) {
            val original = policy()
            for (configured in
                listOf(original.copy(enabled = false), original.copy(rules = emptyList()))) {
                harness.setPolicy(repository, configured)
                harness.awaitState(
                    repository,
                    connection,
                    ForwardingAvailability.Off,
                    null,
                    "Disconnected",
                )
                val before = TalpidVpnService.builderEstablishAttempts()
                for (value in listOf(false, true)) {
                    flag(value)
                    val capture =
                        harness.appliedConfiguration(
                            policy(),
                            ForwardingAvailability.Off,
                            "Disconnected",
                        )
                    assertEquals("", capture.netId)
                    assertEquals(before, TalpidVpnService.builderEstablishAttempts())
                }
            }
            harness.setPolicy(repository, original)
            runBlocking {
                assertTrue(split.enableSplitTunneling(false).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first { it?.splitTunnelSettings?.enabled == false }
                }
            }
            assertTrue(
                PackageName(excludedPackage) in
                    checkNotNull(repository.settingsUpdates.value).splitTunnelSettings.excludedApps
            )
            capture("Disconnected", true)
            val entries = TalpidVpnService.builderEstablishAttempts()
            for (value in listOf(false, true)) {
                flag(value)
                capture("Disconnected", true)
                harness.probeSocket(excluded, "tcp", "reply")
                harness.probeSocket(excluded, "udp", "reply")
                assertEquals(
                    entries,
                    TalpidVpnService.builderEstablishAttempts(),
                    "Disabled split must not resurrect stored names",
                )
            }
        }

    /** The runner stages the real install/restart/upgrade before this assertion process. */
    @Test
    fun excludedPreferenceLifecycle() {
        val case = checkNotNull(args.getString("case"))
        check(case in setOf("fresh", "legacy-policy-absent", "legacy-field-absent", "off-upgrade"))
        val expected = case != "off-upgrade"
        val permissions =
            listOf("ACCESS_LOCAL_NETWORK", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION")
                .associateWith { target.checkSelfPermission("android.permission.$it") }
        val editor = LocalNetworkEditorInstrumentedTest()
        // The live Activity owns service binding for both the snapshot and restoration.
        editor.withLocalAccessScreen(testTimeout = 2.minutes) { ui ->
            runBlocking {
                val repository =
                    (target.applicationContext as MullvadApplication)
                        .getKoin()
                        .get<SettingsRepository>()
                var snapshot: LocalNetworkAccess? = null
                var bodyFailure: Throwable? = null
                try {
                    val before =
                        checkNotNull(
                            withTimeout(10_000) { repository.settingsUpdates.first { it != null } }
                                ?.localNetworkAccess
                        )
                    snapshot = before
                    assertEquals(
                        expected,
                        before.skipLocalRulesForExcludedApps,
                        "Real persisted lifecycle value",
                    )
                    val label = ui.copy(R.string.local_access_excluded_apps_skip)
                    ui.requireToggle("local_excluded_apps_skip", expected)
                    ui.requireSingleLineText(label)
                    ui.requireRenderedText(ui.copy(R.string.local_access_excluded_apps_description))
                    for (value in listOf(!expected, expected)) {
                        ui.clickTag("local_excluded_apps_skip", label)
                        withTimeout(10_000) {
                            repository.settingsUpdates.first {
                                it?.localNetworkAccess ==
                                    before.copy(skipLocalRulesForExcludedApps = value)
                            }
                        }
                        ui.requireToggle("local_excluded_apps_skip", value)
                    }
                    ui.clickTag("local_access_add_rule", ui.copy(R.string.local_access_add_rule))
                    val name = "Krtek unsaved exclusion fixture"
                    ui.enter("local_access_name", name)
                    ui.requireAbsentControl("local_policy_enabled")
                    ui.requireAbsentControl("local_excluded_apps_skip")
                    ui.back()
                    ui.clickTag(
                        "local_access_dialog_cancel",
                        ui.copy(R.string.local_access_keep_editing),
                    )
                    ui.requireFieldText("local_access_name", name)
                    assertEquals(before, repository.settingsUpdates.value?.localNetworkAccess)
                    ui.back()
                    ui.clickTag(
                        "local_access_dialog_confirm",
                        ui.copy(R.string.local_access_discard),
                    )
                    ui.requireToggle("local_excluded_apps_skip", expected)
                    assertEquals(before, repository.settingsUpdates.value?.localNetworkAccess)
                    assertEquals(
                        permissions,
                        permissions.keys.associateWith {
                            target.checkSelfPermission("android.permission.$it")
                        },
                    )
                    harness.report("excluded_preference_lifecycle_case", case)
                    harness.report("excluded_preference_lifecycle_value", expected)
                    harness.report("excluded_preference_real_ui_save_and_draft", "PASS")
                } catch (failure: Throwable) {
                    bodyFailure = failure
                    harness.report(
                        "excluded_preference_lifecycle_body_failure",
                        failure.javaClass.name,
                    )
                    throw failure
                } finally {
                    try {
                        // No policy mutation is possible until the snapshot has been acquired.
                        val before = snapshot
                        if (before == null) {
                            harness.report(
                                "excluded_preference_lifecycle_snapshot_unavailable",
                                true,
                            )
                        } else {
                            val current =
                                checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
                            check(
                                current.copy(skipLocalRulesForExcludedApps = expected) == before
                            ) {
                                "Preserve concurrent non-preference changes for investigation"
                            }
                            if (current != before) {
                                assertTrue(
                                    repository.setLocalNetworkAccess(before, current).isRight()
                                )
                                withTimeout(10_000) {
                                    repository.settingsUpdates.first {
                                        it?.localNetworkAccess == before
                                    }
                                }
                            }
                            harness.report("excluded_preference_lifecycle_restored", true)
                        }
                    } catch (restorationFailure: Throwable) {
                        harness.report(
                            "excluded_preference_lifecycle_restoration_failure",
                            restorationFailure.javaClass.name,
                        )
                        val primary = bodyFailure
                        if (primary == null) throw restorationFailure
                        primary.addSuppressed(restorationFailure)
                    }
                }
            }
        }
    }
}
