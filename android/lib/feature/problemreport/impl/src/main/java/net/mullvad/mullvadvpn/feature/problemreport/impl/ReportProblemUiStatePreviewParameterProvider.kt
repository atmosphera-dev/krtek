package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.compose.ui.tooling.preview.PreviewParameterProvider
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueExport

class ReportProblemUiStatePreviewParameterProvider :
    PreviewParameterProvider<ReportProblemUiState> {
    override val values: Sequence<ReportProblemUiState>
        get() =
            sequenceOf(
                ReportProblemUiState(),
                ReportProblemUiState(logCollectingState = LogCollectingState.Success),
                ReportProblemUiState(logCollectingState = LogCollectingState.Failed),
                ReportProblemUiState(
                    message = "Unable to connect",
                    reviewedIssue =
                        SupportIssueExport(
                            "Report a problem",
                            "Unable to connect\n\nApp version: test\n" +
                                "Android: 16 (SDK 36)\nManufacturer: Example\nModel: Phone",
                            "https://example.test/issues/new",
                        ),
                    fallbackUrl = "https://example.test/issues/new",
                    logCollectingState = LogCollectingState.Success,
                ),
            )
}
