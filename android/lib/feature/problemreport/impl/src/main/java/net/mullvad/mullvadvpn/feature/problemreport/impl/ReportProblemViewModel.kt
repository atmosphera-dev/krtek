package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.repository.ProblemReportDraft
import net.mullvad.mullvadvpn.lib.repository.ProblemReportRepository
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueExport
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueUseCase

data class ReportProblemUiState(
    val message: String = "",
    val descriptionError: DescriptionError? = null,
    val reviewedIssue: SupportIssueExport? = null,
    val fallbackUrl: String? = null,
    val logCollectingState: LogCollectingState = LogCollectingState.Loading,
)

sealed interface DescriptionError {
    data object Empty : DescriptionError
}

sealed interface LogCollectingState {
    data object Loading : LogCollectingState

    data object Success : LogCollectingState

    data object Failed : LogCollectingState
}

sealed interface ReportProblemSideEffect {
    val issue: SupportIssueExport

    data class OpenIssue(override val issue: SupportIssueExport) : ReportProblemSideEffect

    data class CopyIssue(override val issue: SupportIssueExport) : ReportProblemSideEffect

    data class CopyIssueLink(override val issue: SupportIssueExport) : ReportProblemSideEffect
}

class ReportProblemViewModel(
    private val problemReportRepository: ProblemReportRepository,
    private val supportIssueUseCase: SupportIssueUseCase,
) : ViewModel() {
    private data class Review(val draft: ProblemReportDraft, val issue: SupportIssueExport)

    private val review = MutableStateFlow<Review?>(null)
    private val descriptionError = MutableStateFlow<DescriptionError?>(null)
    private val fallbackUrl = MutableStateFlow<String?>(null)
    private val logCollectingState =
        MutableStateFlow<LogCollectingState>(LogCollectingState.Loading)

    val uiState =
        combine(
                problemReportRepository.problemReport,
                review,
                descriptionError,
                fallbackUrl,
                logCollectingState,
            ) { draft, review, error, fallback, logs ->
                val current = review?.takeIf { it.draft === draft }?.issue
                ReportProblemUiState(
                    draft.description,
                    error,
                    current,
                    fallback.takeIf { current != null },
                    logs,
                )
            }
            .stateIn(
                viewModelScope,
                SharingStarted.WhileSubscribed(VIEW_MODEL_STOP_TIMEOUT),
                ReportProblemUiState(
                    message = problemReportRepository.problemReport.value.description
                ),
            )

    private val _uiSideEffect = Channel<ReportProblemSideEffect>(Channel.BUFFERED)
    val uiSideEffect = _uiSideEffect.receiveAsFlow()

    fun updateMessage(value: String) {
        review.value = null
        fallbackUrl.value = null
        problemReportRepository.setDescription(value)
        descriptionError.value = null
    }

    fun reviewIssue(title: String) {
        val draft = problemReportRepository.problemReport.value
        val message = draft.description
        if (message.isBlank()) {
            descriptionError.value = DescriptionError.Empty
            return
        }
        review.value = Review(draft, supportIssueUseCase(message, title))
        fallbackUrl.value = null
    }

    // A stale rendered button cannot export an edited or replaced review.
    private fun isCurrentReview(issue: SupportIssueExport): Boolean =
        review.value?.let {
            it.issue === issue && it.draft === problemReportRepository.problemReport.value
        } == true

    fun consumeExport(effect: ReportProblemSideEffect, export: (SupportIssueExport) -> Unit) {
        if (isCurrentReview(effect.issue)) export(effect.issue)
    }

    fun openSupportIssue(issue: SupportIssueExport) {
        if (!isCurrentReview(issue)) return
        fallbackUrl.value = null
        viewModelScope.launch { _uiSideEffect.send(ReportProblemSideEffect.OpenIssue(issue)) }
    }

    fun copySupportIssue(issue: SupportIssueExport) {
        if (!isCurrentReview(issue)) return
        viewModelScope.launch { _uiSideEffect.send(ReportProblemSideEffect.CopyIssue(issue)) }
    }

    fun copyFallbackLink(issue: SupportIssueExport) {
        if (!isCurrentReview(issue) || fallbackUrl.value != issue.url) return
        viewModelScope.launch { _uiSideEffect.send(ReportProblemSideEffect.CopyIssueLink(issue)) }
    }

    fun onBrowserUnavailable(issue: SupportIssueExport) {
        if (isCurrentReview(issue)) fallbackUrl.value = issue.url
    }

    init {
        viewModelScope.launch {
            logCollectingState.emit(
                if (problemReportRepository.collectLogs()) LogCollectingState.Success
                else LogCollectingState.Failed
            )
        }
    }

    override fun onCleared() {
        // Collected files and the in-process message have separate lifetimes.
        problemReportRepository.deleteLogs()
    }
}
