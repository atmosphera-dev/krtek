package net.mullvad.mullvadvpn.talpid

import android.graphics.Bitmap
import android.net.InetAddresses
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.mullvad.mullvadvpn.app.MullvadApplication
import net.mullvad.mullvadvpn.feature.lansharing.impl.R
import net.mullvad.mullvadvpn.feature.lansharing.impl.SplitDnsDomainDraft
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalRuleState
import net.mullvad.mullvadvpn.lib.model.SplitDnsDomain
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.koin.android.ext.android.getKoin

/** Connected DNS consumers, not the all-state B3 campaign. */
class SplitDnsInstrumentedTest {
    private val harness = LocalNetworkDeliveryInstrumentedTest()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val args = InstrumentationRegistry.getArguments()

    private fun fullDnsCase(
        probe:
            (
                LocalNetworkDeliveryInstrumentedTest.Consumer,
                LocalNetworkDeliveryInstrumentedTest.AppliedCapture,
            ) -> Unit
    ) =
        harness.connectedCase(3.minutes) { consumer, repository, connection, base ->
            val privateDns =
                instrumentation.uiAutomation
                    .executeShellCommand("settings get global private_dns_mode")
                    .use { fd ->
                        ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().use {
                            it.readText().trim()
                        }
                    }
            assertEquals(
                "off",
                privateDns,
                "Runner must stage and restore Private DNS; test does not change it",
            )
            val resolver =
                checkNotNull(
                    HomeDnsResolver.parse(
                        checkNotNull(args.getString("krtek_home_dns", "10.77.10.53"))
                    )
                )
            val rule =
                LocalBypassRule(
                    id = UUID.randomUUID(),
                    name = "Home DNS fixture",
                    enabled = true,
                    cidrs =
                        listOf(
                            checkNotNull(
                                LocalCidr.parse(
                                        "${resolver.numericAddress}/${if (resolver.addressBytes().size == 4) 32 else 128}"
                                    )
                                    .getOrNull()
                            )
                        ),
                )
            val enabled =
                base.copy(
                    rules = base.rules + rule,
                    splitDns =
                        SplitDnsPolicy(
                            enabled = true,
                            suffixes = listOf("home."),
                            homeResolver = resolver,
                            localRuleId = rule.id,
                        ),
                )
            val before =
                harness.appliedConfiguration(base, ForwardingAvailability.Active, "Connected")
            harness.setPolicy(repository, enabled)
            harness.awaitState(
                repository,
                connection,
                ForwardingAvailability.Active,
                LocalRuleState.Forwarding,
                "Connected",
            )
            val after =
                harness.appliedConfiguration(enabled, ForwardingAvailability.Active, "Connected")
            assertEquals(
                before.dns,
                after.dns,
                "Split DNS must not substitute Android's resolver list",
            )
            probe(consumer, after)
        }

    @Test
    fun splitDnsFullTcp() = fullDnsCase { consumer, after ->
        val peer =
            InetAddresses.parseNumericAddress(
                checkNotNull(args.getString("krtek_dns_tcp_resolver"))
            )
        val advertised =
            after.dns
                .split(',')
                .filter { it.isNotBlank() }
                .map { InetAddresses.parseNumericAddress(it.trim().removePrefix("/")) }
        assertTrue(peer in advertised, "TCP must target an actually advertised resolver")
        val result =
            consumer.request(
                Bundle().apply {
                    putString("transport", "split-dns-tcp")
                    putString("tcp_resolver", peer.hostAddress)
                    putString("tcp_vectors", checkNotNull(args.getString("krtek_dns_tcp_vectors")))
                }
            )
        harness.report("split_dns_tcp", result)
        assertEquals("split-dns-tcp", result.getString("outcome"))
        assertEquals(3, result.getInt("message_count"))
        assertEquals(2, result.getInt("home_exact"))
        assertTrue(result.getBoolean("ordinary_usable"))
        assertTrue(harness.uidIncluded(after.uids, result.getInt("uid")))
        assertTrue(result.getInt("local_port") > 0)
    }

    @Test
    fun splitDnsFullUdp() = fullDnsCase { consumer, after ->
        val hostname = "run11-${UUID.randomUUID().toString().replace("-", "")}.home"
        val result =
            consumer.request(
                Bundle().apply {
                    putString("transport", "split-dns-lookup")
                    putString("hostname", hostname)
                }
            )
        harness.report("split_dns_listed", result)
        assertEquals("split-dns-lookup", result.getString("outcome"))
        assertEquals("resolved", result.getString("lookup_outcome"))
        assertTrue(
            harness.uidIncluded(after.uids, result.getInt("uid")),
            "The ordinary consumer must be included in this capture",
        )
        val answers = checkNotNull(result.getStringArrayList("addresses"))
        assertFalse(answers.isEmpty())
        val expected =
            setOf(
                InetAddresses.parseNumericAddress("10.77.10.1"),
                InetAddresses.parseNumericAddress("fd71:7274:656b:10::1"),
            )
        assertTrue(
            answers.map { InetAddresses.parseNumericAddress(it) }.all { it in expected },
            "Only the fixture's Home addresses may reach the ordinary consumer",
        )
        val ordinary =
            consumer.request(
                Bundle().apply {
                    putString("transport", "lookup")
                    putString("hostname", "example.com")
                }
            )
        harness.report("split_dns_ordinary", ordinary)
        assertEquals("resolved", ordinary.getString("lookup_outcome"))
        harness.report(
            "split_dns_cache_limit",
            "Platform lookup may use Android/app cache; packet attribution remains a separate runner gate",
        )
    }

    /**
     * B-U: shipped settings UI over the real repository. Restart and upgrade staging happen outside
     * this process before the call; this call only reads and drives the result.
     */
    @Test
    fun splitDnsSettingsLifecycle() {
        val case = checkNotNull(args.getString("case"))
        check(case in setOf("legacy-default", "configured-upgrade", "ui-and-dns-note"))
        val permissions =
            listOf("ACCESS_LOCAL_NETWORK", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION")
                .associateWith { target.checkSelfPermission("android.permission.$it") }
        val privateDns = privateDnsMode()
        harness.report("split_dns_settings_private_dns_before", privateDns)
        LocalNetworkEditorInstrumentedTest().withLocalAccessScreen(testTimeout = 4.minutes) { ui ->
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
                    val settings = SettingsUi(ui, repository, before)
                    when (case) {
                        "legacy-default" -> settings.legacyDefault()
                        "configured-upgrade" -> settings.configuredUpgrade()
                        else -> settings.createEditAndNote()
                    }
                    assertEquals(privateDns, privateDnsMode(), "Krtek must not change Private DNS")
                    assertEquals(
                        permissions,
                        permissions.keys.associateWith {
                            target.checkSelfPermission("android.permission.$it")
                        },
                    )
                    harness.report("split_dns_settings_case", case)
                    harness.report("split_dns_settings_real_ui", "PASS")
                } catch (failure: Throwable) {
                    bodyFailure = failure
                    harness.report("split_dns_settings_body_failure", failure.javaClass.name)
                    throw failure
                } finally {
                    restoreSettings(repository, snapshot, bodyFailure)
                }
            }
        }
    }

    private suspend fun restoreSettings(
        repository: SettingsRepository,
        snapshot: LocalNetworkAccess?,
        bodyFailure: Throwable?,
    ) {
        try {
            // No policy mutation is possible until the snapshot has been acquired.
            if (snapshot == null) {
                harness.report("split_dns_settings_snapshot_unavailable", true)
                return
            }
            val current = checkNotNull(repository.settingsUpdates.value?.localNetworkAccess)
            if (current != snapshot) {
                assertTrue(repository.setLocalNetworkAccess(snapshot, current).isRight())
                withTimeout(10_000) {
                    repository.settingsUpdates.first { it?.localNetworkAccess == snapshot }
                }
            }
            harness.report("split_dns_settings_restored", true)
        } catch (restorationFailure: Throwable) {
            harness.report(
                "split_dns_settings_restoration_failure",
                restorationFailure.javaClass.name,
            )
            if (bodyFailure == null) throw restorationFailure
            bodyFailure.addSuppressed(restorationFailure)
        }
    }

    private fun privateDnsMode(): String =
        instrumentation.uiAutomation
            .executeShellCommand("settings get global private_dns_mode")
            .use { fd ->
                ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().use {
                    it.readText().trim()
                }
            }

    private inner class SettingsUi(
        private val ui: LocalNetworkEditorInstrumentedTest,
        private val repository: SettingsRepository,
        private val before: LocalNetworkAccess,
    ) {
        private val enable = ui.copy(R.string.split_dns_enable)

        private suspend fun awaitPolicy(expected: LocalNetworkAccess) =
            withTimeout(10_000) {
                repository.settingsUpdates.first { it?.localNetworkAccess == expected }
            }

        private fun stored() = repository.settingsUpdates.value?.localNetworkAccess

        /** Fixture write outside the UI, against the exact current value. */
        private suspend fun replace(policy: LocalNetworkAccess) {
            assertTrue(repository.setLocalNetworkAccess(policy, checkNotNull(stored())).isRight())
            awaitPolicy(policy)
        }

        /** Old settings without split DNS read as disabled; a dirty draft is never saved. */
        suspend fun legacyDefault() {
            assertEquals(SplitDnsPolicy(), before.splitDns, "Absent split DNS means disabled")
            ui.requireToggle("split_dns_enabled", false)
            ui.requireSingleLineText(enable)
            ui.requireRenderedText(ui.copy(R.string.split_dns_private_dns))
            ui.clickTag("split_dns_edit", ui.copy(R.string.split_dns_edit))
            ui.clickTag("split_dns_add_domain", ui.copy(R.string.split_dns_add_domain))
            ui.enter("split_dns_domain_0", "nas.home")
            ui.requireAbsentControl("split_dns_enabled")
            ui.requireAbsentControl("local_policy_enabled")
            ui.back("split_dns_domain_0")
            ui.clickTag("local_access_dialog_cancel", ui.copy(R.string.local_access_keep_editing))
            ui.requireFieldText("split_dns_domain_0", "nas.home")
            ui.back("split_dns_domain_0")
            ui.clickTag("local_access_dialog_confirm", ui.copy(R.string.local_access_discard))
            ui.requireToggle("split_dns_enabled", false)
            assertEquals(before, stored())
            harness.report("split_dns_settings_legacy_disabled", true)
        }

        /** A configured policy survives restart/upgrade and still saves from its switch. */
        suspend fun configuredUpgrade() {
            val split = before.splitDns
            assertTrue(split.enabled, "Staged configured policy must be enabled")
            assertEquals(null, before.validationError())
            val resolver = checkNotNull(split.homeResolver)
            ui.requireToggle("split_dns_enabled", true)
            split.suffixes.forEach { ui.requireRenderedText(SplitDnsDomainDraft.from(it).text) }
            ui.requireRenderedText(resolver.numericAddress)
            val off = before.copy(splitDns = split.copy(enabled = false))
            ui.clickTag("split_dns_enabled", enable)
            awaitPolicy(off)
            ui.requireToggle("split_dns_enabled", false)
            ui.clickTag("split_dns_enabled", enable)
            awaitPolicy(before)
            ui.requireToggle("split_dns_enabled", true)
            harness.report("split_dns_settings_configured_suffix_count", split.suffixes.size)
        }

        /** Create from the switch, reject bad input, survive a conflict, then the note. */
        suspend fun createEditAndNote() {
            assertFalse(before.splitDns.enabled, "Staged policy must start with split DNS off")
            val resolver =
                checkNotNull(HomeDnsResolver.parse(args.getString("krtek_home_dns", "10.77.10.53")))
            val rule = homeRule(resolver)
            val staged = before.copy(rules = before.rules + rule)
            replace(staged)
            ui.clickTag("split_dns_enabled", enable)
            // Incomplete settings open the editor instead of saving.
            ui.requireAbsentControl("split_dns_enabled")
            assertEquals(staged, stored())
            fillDraft(rule, resolver)
            capture("editor")
            val concurrent = staged.copy(splitDns = SplitDnsPolicy(suffixes = listOf("example.")))
            replace(concurrent)
            ui.clickTag("split_dns_save", ui.copy(R.string.split_dns_save))
            ui.requireRenderedText(ui.copy(R.string.local_access_conflict))
            ui.requireFieldText("split_dns_domain_0", "HOME.")
            assertEquals(concurrent, stored())
            ui.clickTag("split_dns_save", ui.copy(R.string.split_dns_save))
            val saved =
                concurrent.copy(
                    splitDns =
                        SplitDnsPolicy(
                            true,
                            listOf(checkNotNull(SplitDnsDomain.normalize("HOME."))),
                            resolver,
                            rule.id,
                        )
                )
            awaitPolicy(saved)
            summaryAndSwitch(saved)
            discardDirtyEdit(saved)
            privateDnsNote()
        }

        private fun homeRule(resolver: HomeDnsResolver): LocalBypassRule {
            val prefix = if (resolver.addressBytes().size == 4) 32 else 128
            return LocalBypassRule(
                id = UUID.randomUUID(),
                name = "Home DNS fixture",
                enabled = true,
                cidrs =
                    listOf(
                        checkNotNull(
                            LocalCidr.parse("${resolver.numericAddress}/$prefix").getOrNull()
                        )
                    ),
            )
        }

        private fun fillDraft(rule: LocalBypassRule, resolver: HomeDnsResolver) {
            val save = ui.copy(R.string.split_dns_save)
            ui.clickTag("split_dns_add_domain", ui.copy(R.string.split_dns_add_domain))
            ui.enter("split_dns_domain_0", "HOME.")
            ui.requireRenderedText(ui.copy(R.string.split_dns_domain_preview, "home"))
            ui.clickTag("split_dns_add_domain", ui.copy(R.string.split_dns_add_domain))
            ui.enter("split_dns_domain_1", "bad..name")
            ui.clickTag("split_dns_save", save)
            ui.requireRenderedText(ui.copy(R.string.split_dns_invalid_domain))
            ui.requireFieldText("split_dns_domain_1", "bad..name")
            ui.clickTag("split_dns_remove_1", ui.copy(R.string.split_dns_remove_domain))
            ui.enter("split_dns_home_ip", resolver.numericAddress)
            ui.clickTag("split_dns_save", save)
            ui.requireRenderedText(ui.copy(R.string.split_dns_missing_home_network))
            val label =
                ui.copy(
                    R.string.split_dns_rule_network,
                    rule.name,
                    ui.copy(R.string.local_access_any_network),
                )
            ui.clickTag("split_dns_home_network", ui.copy(R.string.split_dns_home_network))
            ui.clickTag("split_dns_home_network_${rule.id}", label)
            ui.requireRenderedText(label)
        }

        private suspend fun summaryAndSwitch(saved: LocalNetworkAccess) {
            ui.requireToggle("split_dns_enabled", true)
            ui.requireSingleLineText(enable)
            ui.requireRenderedText("home")
            ui.requireRenderedText(checkNotNull(saved.splitDns.homeResolver).numericAddress)
            ui.requireRenderedText(ui.copy(R.string.split_dns_used_on_any_network))
            capture("summary-on")
            val off = saved.copy(splitDns = saved.splitDns.copy(enabled = false))
            ui.clickTag("split_dns_enabled", enable)
            awaitPolicy(off)
            // A complete policy saves immediately when turned back on.
            ui.clickTag("split_dns_enabled", enable)
            awaitPolicy(saved)
            ui.requireToggle("split_dns_enabled", true)
        }

        private fun discardDirtyEdit(saved: LocalNetworkAccess) {
            ui.clickTag("split_dns_edit", ui.copy(R.string.split_dns_edit))
            ui.requireFieldText("split_dns_domain_0", "home")
            ui.enter("split_dns_domain_0", "changed.home")
            ui.back("split_dns_domain_0")
            ui.clickTag("local_access_dialog_cancel", ui.copy(R.string.local_access_keep_editing))
            ui.requireFieldText("split_dns_domain_0", "changed.home")
            ui.back("split_dns_domain_0")
            ui.clickTag("local_access_dialog_confirm", ui.copy(R.string.local_access_discard))
            ui.requireToggle("split_dns_enabled", true)
            assertEquals(saved, stored())
        }

        private fun privateDnsNote() {
            ui.requireRenderedText(ui.copy(R.string.split_dns_private_dns))
            ui.clickTag(
                "split_dns_private_dns_settings",
                ui.copy(R.string.split_dns_open_private_dns),
            )
            ui.returnFromSystemSettings("split-dns-private-dns", requireSettingsVisit = true)
            ui.requireToggle("split_dns_enabled", true)
            harness.report("split_dns_settings_private_dns_note", "PASS")
        }

        /** Opt-in final screenshots, written inside the emulator for the runner to collect. */
        private fun capture(name: String) {
            if (args.getString("krtek_screenshots") != "true") return
            val directory =
                File(checkNotNull(target.getExternalFilesDir(null)), "krtek-screenshots")
            check(directory.isDirectory || directory.mkdirs())
            val file = File(directory, "split-dns-$name.png")
            val bitmap = ui.screenshot()
            try {
                file.outputStream().use {
                    check(bitmap.compress(Bitmap.CompressFormat.PNG, PNG_QUALITY, it))
                }
            } finally {
                bitmap.recycle()
            }
            harness.report("split_dns_settings_screenshot_$name", file.absolutePath)
        }
    }

    private companion object {
        const val PNG_QUALITY = 100
    }
}
