package net.mullvad.mullvadvpn.feature.problemreport.impl

import android.content.Context
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewModelScope
import app.cash.turbine.test
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.verify
import java.io.File
import java.net.URLDecoder
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.mullvadvpn.lib.common.test.TestCoroutineRule
import net.mullvad.mullvadvpn.lib.model.BuildVersion
import net.mullvad.mullvadvpn.lib.repository.ProblemReportRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueExport
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith

@OptIn(ExperimentalCoroutinesApi::class)
@ExtendWith(TestCoroutineRule::class)
class ReportProblemViewModelTest {
    private val context =
        mockk<Context> {
            every { filesDir } returns
                File(requireNotNull(System.getenv("TMPDIR")), "support-viewmodel-test")
        }
    private val repository = spyk(ProblemReportRepository(context, "logs", mockk()))
    private val issuesUrl = "https://example.test/issues"
    private val title = "Report a problem"
    private val useCase =
        SupportIssueUseCase(issuesUrl, BuildVersion("test", 1), "16", 36, "Example", "Phone")
    private lateinit var viewModel: ReportProblemViewModel

    @BeforeEach
    fun setup() {
        coEvery { repository.collectLogs() } returns true
        viewModel = ReportProblemViewModel(repository, useCase)
    }

    @AfterEach
    fun tearDown() {
        viewModel.viewModelScope.cancel()
    }

    @Test
    fun `successful log collection should enable viewing logs`() = runTest {
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Success, awaitItem().logCollectingState)
        }
        coVerify(exactly = 1) { repository.collectLogs() }
    }

    @Test
    fun `pending collection should stay loading while an issue can still be opened`() = runTest {
        viewModel.viewModelScope.cancel()
        val collected = CompletableDeferred<Boolean>()
        coEvery { repository.collectLogs() } coAnswers { collected.await() }
        viewModel = ReportProblemViewModel(repository, useCase)
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Loading, awaitItem().logCollectingState)
            viewModel.updateMessage("Pending logs")
            viewModel.reviewIssue(title)
            runCurrent()
            val reviewed = requireNotNull(expectMostRecentItem().reviewedIssue)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue(reviewed)
                assertEquals(ReportProblemSideEffect.OpenIssue(reviewed), awaitItem())
            }
            collected.complete(true)
            runCurrent()
            assertEquals(LogCollectingState.Success, expectMostRecentItem().logCollectingState)
        }
    }

    @Test
    fun `failed log collection should not prevent opening an issue`() = runTest {
        viewModel.viewModelScope.cancel()
        coEvery { repository.collectLogs() } returns false
        viewModel = ReportProblemViewModel(repository, useCase)
        viewModel.uiState.test {
            assertEquals(LogCollectingState.Failed, awaitItem().logCollectingState)
            viewModel.updateMessage("No logs")
            viewModel.reviewIssue(title)
            runCurrent()
            val reviewed = requireNotNull(expectMostRecentItem().reviewedIssue)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue(reviewed)
                assertEquals(ReportProblemSideEffect.OpenIssue(reviewed), awaitItem())
            }
        }
    }

    @Test
    fun `opening an issue should emit the encoded message and details without reading logs`() =
        runTest {
            val message = "Connection & DNS?\nÅ test"
            viewModel.uiState.test {
                awaitItem()
                viewModel.updateMessage(message)
                viewModel.reviewIssue(title)
                runCurrent()
                val reviewed = requireNotNull(expectMostRecentItem().reviewedIssue)
                viewModel.uiSideEffect.test {
                    viewModel.openSupportIssue(reviewed)
                    val effect = awaitItem() as ReportProblemSideEffect.OpenIssue
                    assertEquals(useCase(message, title), effect.issue)
                    assertTrue(effect.issue.url.startsWith("$issuesUrl/new?"))
                    assertTrue(URLDecoder.decode(effect.issue.url, "UTF-8").contains(message))
                }
            }
            coVerify(exactly = 0) { repository.readLogs() }
            verify(exactly = 0) { repository.deleteLogs() }
        }

    @Test
    fun `blank editor descriptions should show upstream validation until corrected`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            for (message in listOf("", " \n\t ", " \r\n ")) {
                viewModel.updateMessage(message)
                viewModel.reviewIssue(title)
                runCurrent()
                val invalid = expectMostRecentItem()
                assertEquals(message, invalid.message)
                assertEquals(DescriptionError.Empty, invalid.descriptionError)
                assertNull(invalid.reviewedIssue)
            }
            val valid = "  A corrected description 🦔  "
            viewModel.updateMessage(valid)
            runCurrent()
            assertNull(expectMostRecentItem().descriptionError)
            viewModel.reviewIssue(title)
            runCurrent()
            val corrected = expectMostRecentItem()
            assertEquals(valid, corrected.message)
            assertEquals(useCase(valid, title), corrected.reviewedIssue)
            assertNull(corrected.descriptionError)
        }
    }

    @Test
    fun `browser failure and retry should keep the message and require a fresh review`() = runTest {
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMessage("First message")
            viewModel.reviewIssue(title)
            runCurrent()
            val first = requireNotNull(expectMostRecentItem().reviewedIssue)
            viewModel.onBrowserUnavailable(first)
            runCurrent()
            assertEquals(first.url, expectMostRecentItem().fallbackUrl)
            viewModel.updateMessage("Updated message")
            runCurrent()
            val edited = expectMostRecentItem()
            assertEquals("Updated message", edited.message)
            assertNull(edited.reviewedIssue)
            assertNull(edited.fallbackUrl)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue(first)
                expectNoEvents()
                viewModel.reviewIssue(title)
                runCurrent()
                val current = requireNotNull(viewModel.uiState.value.reviewedIssue)
                viewModel.openSupportIssue(current)
                assertEquals(
                    ReportProblemSideEffect.OpenIssue(useCase("Updated message", title)),
                    awaitItem(),
                )
            }
            runCurrent()
            val retried = expectMostRecentItem()
            assertNull(retried.fallbackUrl)
            assertEquals("Updated message", retried.message)
        }
    }

    @Test
    fun `consumer export should preserve account like text and a long message`() = runTest {
        val message = "1234 5678 9012 3456 " + "🔒&".repeat(3000)
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMessage(message)
            viewModel.reviewIssue(title)
            runCurrent()
            val issue = requireNotNull(expectMostRecentItem().reviewedIssue)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue(issue)
                val exported = (awaitItem() as ReportProblemSideEffect.OpenIssue).issue
                assertEquals("$issuesUrl/new", exported.url)
                assertTrue(exported.body.startsWith(message + "\n\n"))
                assertFalse(exported.body.contains("[account number removed]"))
                assertFalse(exported.body.contains("truncated"))
                assertEquals(message, repository.problemReport.value.description)
            }
        }
    }

    @Test
    fun `leaving the screen should delete collected logs`() = runTest {
        val original = "Unsent description"
        viewModel.updateMessage(original)
        val store = ViewModelStore()
        store.put("report", viewModel)
        store.clear()
        verify(exactly = 1) { repository.deleteLogs() }
        assertEquals(original, repository.problemReport.value.description)
        viewModel = ReportProblemViewModel(repository, useCase)
        viewModel.uiState.test { assertEquals(original, awaitItem().message) }
    }

    @Test
    fun `should open only the visible reviewed support snapshot`() = runTest {
        val original = "  1234 5678 9012 3456\r\nÅ 🦔 &+  "
        viewModel.uiState.test {
            awaitItem()
            viewModel.updateMessage(original)
            viewModel.reviewIssue("A complete title " + "long".repeat(30))
            runCurrent()
            val shown = requireNotNull(expectMostRecentItem().reviewedIssue)
            viewModel.uiSideEffect.test {
                viewModel.openSupportIssue(shown)
                val outgoing = (awaitItem() as ReportProblemSideEffect.OpenIssue).issue
                val fields =
                    outgoing.url.substringAfter('?').split('&').associate {
                        val (key, value) = it.split('=', limit = 2)
                        key to URLDecoder.decode(value, "UTF-8")
                    }
                assertTrue(outgoing === shown)
                assertEquals(shown.title, fields["title"])
                assertEquals(shown.body, fields["body"])
                assertEquals(useCase(original, shown.title).body, shown.body)
                viewModel.copySupportIssue(shown)
                val copied = (awaitItem() as ReportProblemSideEffect.CopyIssue).issue
                assertTrue(copied === shown)
                assertEquals(fields["body"], copied.body)
                assertEquals(original, repository.problemReport.value.description)
                viewModel.updateMessage(original + "edited")
                runCurrent()
                assertExportRejected(shown)
                viewModel.openSupportIssue(shown)
                viewModel.copySupportIssue(shown)
                expectNoEvents()
                // Another screen/repository setter cannot leave an old visible export usable.
                viewModel.reviewIssue(title)
                runCurrent()
                val latest = requireNotNull(viewModel.uiState.value.reviewedIssue)
                val reviewedText = repository.problemReport.value.description
                repository.setDescription("An intermediate edit that collectors may conflate")
                repository.setDescription(reviewedText)
                assertExportRejected(latest)
                viewModel.openSupportIssue(latest)
                expectNoEvents()
                repository.setDescription("Changed by a new screen")
                assertExportRejected(latest)
                viewModel.openSupportIssue(latest)
                expectNoEvents()
            }
            runCurrent()
            assertNull(expectMostRecentItem().reviewedIssue)
        }
        coVerify(exactly = 0) { repository.readLogs() }
        verify(exactly = 0) { repository.setDescription("") }
    }

    @Test
    fun `should preserve draft and export when browser is unavailable`() = runTest {
        for (message in listOf("  A short 🦔 report  ", "Long & 中文🦔".repeat(3000))) {
            viewModel.uiState.test {
                awaitItem()
                viewModel.updateMessage(message)
                viewModel.reviewIssue(title)
                runCurrent()
                val shown = requireNotNull(expectMostRecentItem().reviewedIssue)
                viewModel.uiSideEffect.test {
                    viewModel.openSupportIssue(shown)
                    assertTrue((awaitItem() as ReportProblemSideEffect.OpenIssue).issue === shown)
                    viewModel.onBrowserUnavailable(shown)
                    runCurrent()
                    assertEquals(shown.url, viewModel.uiState.value.fallbackUrl)
                    assertEquals(shown, viewModel.uiState.value.reviewedIssue)
                    viewModel.copySupportIssue(shown)
                    assertEquals(
                        shown.body,
                        (awaitItem() as ReportProblemSideEffect.CopyIssue).issue.body,
                    )
                    assertEquals(useCase(message, title).body, shown.body)
                    assertEquals(message, repository.problemReport.value.description)
                }
                cancelAndIgnoreRemainingEvents()
            }
            val store = ViewModelStore()
            store.put("report", viewModel)
            store.clear()
            viewModel = ReportProblemViewModel(repository, useCase)
            viewModel.uiState.test {
                val recreated = awaitItem()
                assertEquals(message, recreated.message)
                assertNull(recreated.reviewedIssue)
                assertNull(recreated.fallbackUrl)
            }
        }
    }

    @Test
    fun `should copy only the current reviewed fallback link`() = runTest {
        for (message in
            listOf("  A short reviewed 🦔 report  ", "A complete 中文🦔 report & ".repeat(500))) {
            viewModel.uiState.test {
                awaitItem()
                viewModel.updateMessage(message)
                viewModel.reviewIssue(title)
                runCurrent()
                val shown = requireNotNull(expectMostRecentItem().reviewedIssue)
                viewModel.onBrowserUnavailable(shown)
                runCurrent()
                val displayedLink = requireNotNull(expectMostRecentItem().fallbackUrl)
                val capturedCopy = { viewModel.copyFallbackLink(shown) }
                viewModel.uiSideEffect.test {
                    capturedCopy()
                    val firstCopy = (awaitItem() as ReportProblemSideEffect.CopyIssueLink).issue
                    assertTrue(firstCopy === shown)
                    assertEquals(displayedLink, firstCopy.url)
                    viewModel.updateMessage(message + "edited")
                    capturedCopy()
                    expectNoEvents()
                    viewModel.updateMessage(message)
                    capturedCopy()
                    expectNoEvents()
                    assertExportRejected(shown)
                    viewModel.reviewIssue(title)
                    runCurrent()
                    val fresh = requireNotNull(viewModel.uiState.value.reviewedIssue)
                    viewModel.onBrowserUnavailable(fresh)
                    runCurrent()
                    val freshDisplayedLink = requireNotNull(viewModel.uiState.value.fallbackUrl)
                    capturedCopy()
                    expectNoEvents()
                    viewModel.copyFallbackLink(fresh)
                    val copied = (awaitItem() as ReportProblemSideEffect.CopyIssueLink).issue
                    assertTrue(copied === fresh)
                    var exportedLink: String? = null
                    viewModel.consumeExport(ReportProblemSideEffect.CopyIssueLink(copied)) {
                        exportedLink = it.url
                    }
                    assertEquals(freshDisplayedLink, exportedLink)
                    assertEquals(message, repository.problemReport.value.description)
                    // The screen's consumer also rejects an already queued copy after an edit.
                    viewModel.copyFallbackLink(fresh)
                    viewModel.updateMessage(message + "later edit")
                    val queued = awaitItem() as ReportProblemSideEffect.CopyIssueLink
                    var staleExport: String? = null
                    viewModel.consumeExport(queued) { staleExport = it.url }
                    assertNull(staleExport)
                }
                cancelAndIgnoreRemainingEvents()
            }
        }
    }

    private fun assertExportRejected(issue: SupportIssueExport) {
        var exported = false
        viewModel.consumeExport(ReportProblemSideEffect.OpenIssue(issue)) { exported = true }
        assertFalse(exported, "Edited or replaced reviews must not reach the export consumer")
    }
}
