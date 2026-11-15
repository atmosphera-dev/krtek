package net.mullvad.mullvadvpn.lib.usecase

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import net.mullvad.mullvadvpn.lib.model.BuildVersion

/** Complete outgoing text. The review, browser and clipboard all consume this same value. */
data class SupportIssueExport(val title: String, val body: String, val issuePageUrl: String) {
    val prefilledUrl: String? =
        if (
            StandardCharsets.UTF_8.newEncoder().canEncode(title) &&
                StandardCharsets.UTF_8.newEncoder().canEncode(body)
        ) {
            "$issuePageUrl?title=${title.encode()}&body=${body.encode()}"
                .takeIf { it.length <= MAX_URL_LENGTH }
        } else null

    val url: String
        get() = prefilledUrl ?: issuePageUrl

    companion object {
        // This is a transport selection, never a limit on the draft or any of its fields.
        private const val MAX_URL_LENGTH = 4096
    }
}

class SupportIssueUseCase(
    val issuesUrl: String,
    private val buildVersion: BuildVersion,
    private val androidRelease: String,
    private val androidSdk: Int,
    private val manufacturer: String,
    private val model: String,
) {
    operator fun invoke(message: String, title: String): SupportIssueExport =
        SupportIssueExport(
            title = title,
            body =
                buildString {
                    append(message)
                    if (isNotEmpty()) append("\n\n")
                    append("App version: ${buildVersion.name}\n")
                    append("Android: $androidRelease (SDK $androidSdk)\n")
                    append("Manufacturer: $manufacturer\n")
                    append("Model: $model")
                },
            issuePageUrl = "$issuesUrl/new",
        )
}

private fun String.encode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.name())
