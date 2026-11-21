package net.mullvad.mullvadvpn.lib.repository

import arrow.core.left
import arrow.core.right
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.grpc.ManagementService
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import org.junit.jupiter.api.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class LocalNetworkAccessRepositoryTest {
    @Test
    fun `should forward expected policy and retain typed command failures`() = runTest {
        val policy = LocalNetworkAccess(skipLocalRulesForExcludedApps = false)
        val expected = LocalNetworkAccess()
        val status = MutableStateFlow<LocalNetworkStatus?>(null)
        val service =
            mockk<ManagementService> {
                every { settings } returns emptyFlow()
                every { localNetworkStatus } returns status
                every { beginLocalNetworkEditor() } returns 1L.right()
                every { endLocalNetworkEditor(any()) } returns Unit.right()
                coEvery { setLocalNetworkAccess(policy, expected) } returns
                    SetLocalNetworkAccessError.Conflict.left()
            }
        val repository = SettingsRepository(service, StandardTestDispatcher(testScheduler))
        assertSame(status, repository.localNetworkStatus)
        assertEquals(
            SetLocalNetworkAccessError.Conflict.left(),
            repository.setLocalNetworkAccess(policy, expected),
        )
        coVerify(exactly = 1) { service.setLocalNetworkAccess(policy, expected) }
        // Editor lifetime is repository/controller state, not an RPC command.
        val demands = mutableListOf<Boolean>()
        backgroundScope.launch { repository.localNetworkEditorDemand.collect { demands += it } }
        runCurrent()
        assertEquals(listOf(false), demands)
        val editorOne = backgroundScope.launch { repository.observeLocalNetworkForEditor() }
        val editorTwo = backgroundScope.launch { repository.observeLocalNetworkForEditor() }
        runCurrent()
        assertEquals(listOf(false, true), demands)
        editorOne.cancel()
        runCurrent()
        assertEquals(true, demands.last())
        editorTwo.cancel()
        runCurrent()
        assertEquals(listOf(false, true, false), demands)
        io.mockk.verify(exactly = 1) { service.beginLocalNetworkEditor() }
        io.mockk.verify(exactly = 1) { service.endLocalNetworkEditor(1L) }
    }

    @Test
    fun `should keep a new editor generation through conflated close and reopen`() = runTest {
        val service =
            mockk<ManagementService> {
                every { settings } returns emptyFlow()
                every { beginLocalNetworkEditor() } returnsMany listOf(1L.right(), 3L.right())
                every { endLocalNetworkEditor(any()) } returns Unit.right()
                every { acknowledgeLocalNetworkEditor(any(), any()) } returns Unit.right()
            }
        val repository = SettingsRepository(service, StandardTestDispatcher(testScheduler))
        val first = backgroundScope.launch { repository.observeLocalNetworkForEditor() }
        runCurrent()
        assertEquals(
            LocalNetworkEditorRequest(1L, true),
            repository.localNetworkEditorRequests.value,
        )
        first.cancel()
        val second = backgroundScope.launch { repository.observeLocalNetworkForEditor() }
        runCurrent()
        assertEquals(
            LocalNetworkEditorRequest(3L, true),
            repository.localNetworkEditorRequests.value,
        )
        repository.acknowledgeLocalNetworkEditor(3L, 41L)
        io.mockk.verify(exactly = 1) { service.acknowledgeLocalNetworkEditor(3L, 41L) }
        second.cancel()
        runCurrent()
        assertEquals(
            LocalNetworkEditorRequest(3L, false),
            repository.localNetworkEditorRequests.value,
        )
    }
}
