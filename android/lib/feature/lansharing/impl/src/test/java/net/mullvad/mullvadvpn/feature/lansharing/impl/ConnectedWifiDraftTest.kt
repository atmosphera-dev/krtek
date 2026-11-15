package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import arrow.core.right
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.ForwardingAvailability
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.LocalRuleInactiveReason
import net.mullvad.mullvadvpn.lib.model.Settings
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class ConnectedWifiDraftTest {
    private val status = MutableStateFlow<LocalNetworkStatus?>(null)
    private val settings =
        MutableStateFlow<Settings?>(
            mockk {
                every { allowLan } returns false
                every { localNetworkAccess } returns LocalNetworkAccess()
            }
        )
    private val repository =
        mockk<SettingsRepository> {
            every { settingsUpdates } returns settings
            every { localNetworkStatus } returns status
            coEvery { observeLocalNetworkForEditor() } coAnswers
                {
                    kotlinx.coroutines.awaitCancellation()
                }
        }
    private lateinit var vm: LocalNetworkSharingViewModel

    @BeforeEach
    fun setup() {
        vm = LocalNetworkSharingViewModel(false, repository, SavedStateHandle())
    }

    @AfterEach
    fun tearDown() {
        vm.viewModelScope.cancel()
    }

    private fun edit() = (vm.uiState.value as Lc.Content).value.editor

    private fun observe(wifi: ConnectedWifi) {
        status.value =
            LocalNetworkStatus(1u, true, ForwardingAvailability.NotAvailable, wifi, emptyList())
    }

    @Test
    fun `should fill known binary wifi losslessly and avoid duplicates`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            val identity = SsidIdentity.fromBytes(byteArrayOf(-1, 0, -2))!!
            observe(ConnectedWifi.Known(identity))
            vm.useConnectedWifi()
            vm.useConnectedWifi()
            runCurrent()
            assertEquals(listOf(identity), edit().draft?.wifiNames?.map { it.identity() })
            assertNull(edit().wifiMessage)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should request missing access and fill from the daemon event after granting`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            observe(ConnectedWifi.Unknown(WifiUnknownReason.PermissionMissing))
            vm.uiSideEffect.test {
                vm.useConnectedWifi()
                assertEquals(LocalNetworkSharingSideEffect(true), awaitItem())
            }
            runCurrent()
            assertNull(edit().draft?.copy(addresses = "10.0.0.0/8")?.rule())
            val identity = SsidIdentity.fromUserText("  café, office  ")!!
            observe(ConnectedWifi.Known(identity))
            runCurrent()
            assertEquals(identity, edit().draft?.wifiNames?.single()?.identity())
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should explain unknown wifi and never save an unintended unconditional rule`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            listOf(
                    WifiUnknownReason.NotOnWifi,
                    WifiUnknownReason.LocationOff,
                    WifiUnknownReason.MultipleWifi,
                    WifiUnknownReason.Pending,
                )
                .forEach {
                    observe(ConnectedWifi.Unknown(it))
                    vm.useConnectedWifi()
                    runCurrent()
                    assertEquals(it.message(), edit().wifiMessage)
                    assertNull(edit().draft?.copy(addresses = "10.0.0.0/8")?.rule())
                }
            vm.uiSideEffect.test { expectNoEvents() }
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should fill from the fresh observation when asked while it is pending`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            observe(ConnectedWifi.Unknown(WifiUnknownReason.Pending))
            vm.uiSideEffect.test {
                vm.useConnectedWifi()
                runCurrent()
                expectNoEvents()
            }
            assertEquals(WifiUnknownReason.Pending.message(), edit().wifiMessage)
            assertNull(edit().draft?.copy(addresses = "10.0.0.0/8")?.rule())
            val identity = SsidIdentity.fromUserText("Fresh office")!!
            observe(ConnectedWifi.Known(identity))
            runCurrent()
            assertEquals(listOf(identity), edit().draft?.wifiNames?.map { it.identity() })
            assertNull(edit().wifiMessage)
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should replace the pending answer with the observed reason and not fill later`() =
        runTest {
            vm.uiState.test {
                awaitItem()
                vm.edit(null)
                vm.useConnectedWifi()
                runCurrent()
                assertEquals(WifiUnknownReason.Pending.message(), edit().wifiMessage)
                observe(ConnectedWifi.Unknown(WifiUnknownReason.NotOnWifi))
                runCurrent()
                assertEquals(WifiUnknownReason.NotOnWifi.message(), edit().wifiMessage)
                assertFalse(edit().waitingForWifi)
                observe(ConnectedWifi.Known(SsidIdentity.fromUserText("Later")!!))
                runCurrent()
                assertEquals(listOf(""), edit().draft?.wifiNames?.map { it.text })
                cancelAndIgnoreRemainingEvents()
            }
        }

    @Test
    fun `should keep a pending request across name address and enabled edits`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            vm.useConnectedWifi()
            vm.updateDraft { it.copy(name = "Office printer") }
            vm.updateDraft { it.copy(addresses = "192.168.1.20/32") }
            vm.updateDraft { it.copy(enabled = false) }
            runCurrent()
            assertTrue(edit().waitingForWifi)
            val identity = SsidIdentity.fromUserText("Office")!!
            observe(ConnectedWifi.Known(identity))
            runCurrent()
            assertEquals(listOf(identity), edit().draft?.wifiNames?.map { it.identity() })
            assertEquals("Office printer", edit().draft?.name)
            assertEquals("192.168.1.20/32", edit().draft?.addresses)
            assertFalse(checkNotNull(edit().draft).enabled)
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should explain an unanswered request at the deadline and still fill later`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            vm.useConnectedWifi()
            advanceTimeBy(4.seconds)
            runCurrent()
            assertEquals(WifiUnknownReason.Pending.message(), edit().wifiMessage)
            advanceTimeBy(2.seconds)
            runCurrent()
            assertEquals(R.string.local_access_wifi_not_available, edit().wifiMessage)
            assertTrue(edit().waitingForWifi)
            val identity = SsidIdentity.fromUserText("Late office")!!
            observe(ConnectedWifi.Known(identity))
            runCurrent()
            assertEquals(listOf(identity), edit().draft?.wifiNames?.map { it.identity() })
            assertNull(edit().wifiMessage)
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should end the deadline with a manual wifi edit or a closed draft`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            vm.useConnectedWifi()
            vm.updateDraft { it.copy(wifiNames = listOf(LocalWifiDraft("Typed"))) }
            advanceTimeBy(6.seconds)
            runCurrent()
            assertNull(edit().wifiMessage)
            assertEquals(listOf("Typed"), edit().draft?.wifiNames?.map { it.text })
            vm.discard()
            vm.edit(null)
            vm.useConnectedWifi()
            vm.discard()
            vm.edit(null)
            advanceTimeBy(6.seconds)
            runCurrent()
            assertNull(edit().wifiMessage)
            assertFalse(edit().waitingForWifi)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should never let an old deadline reach a replacement draft`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            vm.useConnectedWifi()
            advanceTimeBy(3.seconds)
            vm.discard()
            vm.edit(null)
            vm.useConnectedWifi()
            advanceTimeBy(2500.milliseconds)
            runCurrent()
            // Five and a half seconds after the first request: only the new one counts, and it
            // has run for two and a half.
            assertEquals(WifiUnknownReason.Pending.message(), edit().wifiMessage)
            advanceTimeBy(3.seconds)
            runCurrent()
            assertEquals(R.string.local_access_wifi_not_available, edit().wifiMessage)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should give a pending answer only to the draft that asked`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            vm.useConnectedWifi()
            vm.discard()
            vm.edit(null)
            runCurrent()
            observe(ConnectedWifi.Known(SsidIdentity.fromUserText("Office")!!))
            runCurrent()
            assertEquals(emptyList<LocalWifiDraft>(), edit().draft?.wifiNames)
            assertNull(edit().wifiMessage)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should keep manual names instead of overwriting them with a later wifi event`() = runTest {
        vm.uiState.test {
            awaitItem()
            vm.edit(null)
            observe(ConnectedWifi.Unknown(WifiUnknownReason.PermissionMissing))
            vm.useConnectedWifi()
            vm.updateDraft { it.copy(wifiNames = listOf(LocalWifiDraft("Manual"))) }
            observe(ConnectedWifi.Known(SsidIdentity.fromUserText("Observed")!!))
            runCurrent()
            assertEquals("Manual", edit().draft?.wifiNames?.single()?.text)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `should request access only after successful saves for plain and wifi rules`() = runTest {
        coEvery { repository.setLocalNetworkAccess(any(), any()) } returns Unit.right()
        vm.uiSideEffect.test {
            listOf(false, true).forEach { wifi ->
                vm.edit(null)
                vm.updateDraft {
                    it.copy(
                        addresses = "10.0.0.0/8",
                        wifiNames = if (wifi) listOf(LocalWifiDraft("Office")) else emptyList(),
                    )
                }
                vm.save()
                assertEquals(LocalNetworkSharingSideEffect(wifi), awaitItem())
            }
        }
    }

    @Test
    fun `should offer retry only for the three missing permission reasons`() {
        assertEquals(
            listOf(
                LocalRuleInactiveReason.LocalPermissionMissing,
                LocalRuleInactiveReason.LocationPermissionMissing,
                LocalRuleInactiveReason.BackgroundLocationMissing,
            ),
            LocalRuleInactiveReason.entries.filter { it.isMissingPermission() },
        )
        assertFalse((null as LocalRuleInactiveReason?).isMissingPermission())
    }
}
