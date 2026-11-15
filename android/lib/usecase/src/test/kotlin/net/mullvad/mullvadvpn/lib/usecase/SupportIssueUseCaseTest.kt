package net.mullvad.mullvadvpn.lib.usecase

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import net.mullvad.mullvadvpn.lib.model.BuildVersion
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SupportIssueUseCaseTest {
    private val issuesUrl = "https://example.test/issues"
    private val useCase =
        SupportIssueUseCase(
            issuesUrl,
            BuildVersion("2026.12-dev-abcdef", 1),
            "16",
            36,
            "Example",
            "Phone",
        )
    private val details =
        "App version: 2026.12-dev-abcdef\nAndroid: 16 (SDK 36)\nManufacturer: Example\nModel: Phone"

    @Test
    fun `issue link should encode title and optional message without adding query parameters`() {
        val issue = useCase(message = "Wi-Fi & DNS? 中文\nline + two", title = "API & unreachable?")
        assertTrue(issue.url.startsWith("$issuesUrl/new?title="))
        val fields = query(issue.url)
        assertEquals(setOf("title", "body"), fields.keys)
        assertEquals(issue.title, fields["title"])
        assertEquals("Wi-Fi & DNS? 中文\nline + two\n\n$details", fields["body"])
        assertEquals(issue.body, fields["body"])
    }

    @Test
    fun `empty message should contain only basic device details and no logs or account number`() {
        val body = useCase("", "Report a problem").body
        assertEquals(details, body)
        assertFalse(body.contains("daemon.log"))
        assertFalse(Regex("[0-9]{16}").containsMatchIn(body))
        assertFalse(body.contains("device ID"))
    }

    @Test
    fun `account like text should remain exactly as reviewed before encoding`() {
        val message = "Account 1234567890123456 or 1234 5678 9012 3456 or 1234-5678-9012-3456"
        val issue = useCase(message, "1234567890123456")
        assertEquals("1234567890123456", query(issue.url)["title"])
        assertEquals("$message\n\n$details", query(issue.url)["body"])
        assertFalse(issue.body.contains("[account number removed]"))
    }

    @Test
    fun `large unicode message should use complete copy rather than a shortened link`() {
        val message = "🦔 & 中文\n".repeat(2000)
        val issue = useCase(message, "Report a problem")
        assertNull(issue.prefilledUrl)
        assertEquals("$issuesUrl/new", issue.url)
        assertEquals("$message\n\n$details", issue.body)
        assertFalse(issue.body.contains("truncated"))
        assertFalse(issue.body.contains('\uFFFD'))
    }

    @Test
    fun `short message should remain intact without truncation notice`() {
        val issue = useCase("Please help", "Report a problem")
        assertEquals("Please help\n\n$details", query(issue.url)["body"])
        assertFalse(issue.body.contains("truncated"))
    }

    @Test
    fun `should export complete reviewed text without hidden adaptation`() {
        val longDetail = " 測試🦔1234567890123456 &+\n".repeat(30)
        val fullDetails =
            SupportIssueUseCase(
                issuesUrl,
                BuildVersion(longDetail, 1),
                longDetail,
                36,
                longDetail,
                longDetail,
            )
        for (message in listOf("  \r\nÅ🦔 & 中文  ", "1234 5678 9012 3456", "& 🦔".repeat(2000))) {
            for (title in listOf("Report & test? 🦔", "title".repeat(100))) {
                val issue = useCase(message, title)
                assertEquals(title, issue.title)
                assertEquals("$message\n\n$details", issue.body)
                if (issue.prefilledUrl != null) {
                    assertEquals(title, query(issue.url)["title"])
                    assertEquals(issue.body, query(issue.url)["body"])
                    assertTrue(issue.url.length <= 4096)
                } else {
                    assertEquals("$issuesUrl/new", issue.url)
                    assertFalse(issue.url.contains('?'))
                }
                val deviceIssue = fullDetails(message, title)
                assertEquals(
                    "$message\n\nApp version: $longDetail\nAndroid: $longDetail (SDK 36)\nManufacturer: $longDetail\nModel: $longDetail",
                    deviceIssue.body,
                )
                assertEquals(title, deviceIssue.title)
                assertNull(deviceIssue.prefilledUrl)
            }
        }
        // The existing 4096-character bound selects transport, not content admission.
        val prefix = SupportIssueExport("", "", "$issuesUrl/new").url.length
        val atBound = SupportIssueExport("", "a".repeat(4096 - prefix), "$issuesUrl/new")
        val aboveBound = SupportIssueExport("", atBound.body + "a", "$issuesUrl/new")
        assertEquals(4096, atBound.prefilledUrl?.length)
        assertNull(aboveBound.prefilledUrl)
        assertEquals(atBound.body + "a", aboveBound.body)
        // UTF-8 cannot represent isolated UTF-16 surrogates. Copy preserves them without
        // letting URLEncoder silently replace them in an apparently complete prefill.
        for (text in listOf("isolated \uD800", "isolated \uDC00")) {
            val bodyIssue = useCase(text, "Report a problem")
            assertNull(bodyIssue.prefilledUrl)
            assertEquals("$text\n\n$details", bodyIssue.body)
            val titleIssue = useCase("message", text)
            assertNull(titleIssue.prefilledUrl)
            assertEquals(text, titleIssue.title)
        }
    }

    private fun query(url: String): Map<String, String> =
        url.substringAfter('?').split('&').associate { field ->
            val (key, value) = field.split('=', limit = 2)
            key to URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }
}
