package net.mullvad.mullvadvpn.lib.repository

import android.content.Context
import app.cash.turbine.test
import io.mockk.every
import io.mockk.mockk
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotSame
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class ProblemReportRepositoryTest {
    @Test
    fun `should retain the complete support draft for repository lifetime`() = runTest {
        val context = mockk<Context>()
        every { context.filesDir } returns
            File(requireNotNull(System.getenv("TMPDIR")), "support-draft-test")
        val repository = ProblemReportRepository(context, "logs", mockk())
        val original = "  1234 5678 9012 3456\r\n" + "中文🦔&".repeat(8000) + "  "
        repository.problemReport.test {
            assertEquals("", awaitItem().description)
            repository.setDescription(original)
            assertEquals(original, awaitItem().description)
        }
        // A new screen subscribes to the same repository, not to a ViewModel's saved copy.
        repository.problemReport.test { assertEquals(original, awaitItem().description) }
        val beforeEdit = repository.problemReport.value
        repository.setDescription(original)
        assertNotSame(beforeEdit, repository.problemReport.value)
        repository.deleteLogs()
        assertEquals(original, repository.problemReport.value.description)
        val newProcessRepository = ProblemReportRepository(context, "logs", mockk())
        assertEquals("", newProcessRepository.problemReport.value.description)
        assertEquals(original, repository.problemReport.value.description)
    }
}
