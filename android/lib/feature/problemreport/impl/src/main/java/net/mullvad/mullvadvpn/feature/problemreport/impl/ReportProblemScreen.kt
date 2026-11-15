package net.mullvad.mullvadvpn.feature.problemreport.impl

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewParameter
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.feature.problemreport.api.ViewLogsNavKey
import net.mullvad.mullvadvpn.lib.common.compose.CollectSideEffectWithLifecycle
import net.mullvad.mullvadvpn.lib.common.compose.createCopyToClipboardHandle
import net.mullvad.mullvadvpn.lib.common.compose.isTv
import net.mullvad.mullvadvpn.lib.common.compose.unlessIsDetail
import net.mullvad.mullvadvpn.lib.ui.component.CopyableLink
import net.mullvad.mullvadvpn.lib.ui.component.ScaffoldWithSmallTopBar
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateBackIconButton
import net.mullvad.mullvadvpn.lib.ui.component.drawVerticalScrollbar
import net.mullvad.mullvadvpn.lib.ui.component.textfield.ErrorSupportingText
import net.mullvad.mullvadvpn.lib.ui.component.textfield.mullvadDarkTextFieldColors
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.VariantButton
import net.mullvad.mullvadvpn.lib.ui.resource.R
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import net.mullvad.mullvadvpn.lib.ui.theme.color.AlphaScrollbar
import net.mullvad.mullvadvpn.lib.usecase.SupportIssueExport
import org.koin.androidx.compose.koinViewModel

@Preview("Loading|Ready|LogsUnavailable|BrowserUnavailable")
@Composable
private fun PreviewReportProblemScreen(
    @PreviewParameter(ReportProblemUiStatePreviewParameterProvider::class)
    state: ReportProblemUiState
) {
    AppTheme {
        ReportProblemScreen(
            state = state,
            onReviewIssue = {},
            onOpenIssue = {},
            onCopyIssue = {},
            onCopyIssueLink = {},
            onNavigateToViewLogs = {},
            onMessageChanged = {},
            onBackClick = {},
        )
    }
}

@Composable
fun ReportProblem(navigator: Navigator) {
    val vm = koinViewModel<ReportProblemViewModel>()
    val state by vm.uiState.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val browserUnavailable = stringResource(R.string.browser_unavailable)
    val issueTitle = stringResource(R.string.report_a_problem)
    val copyToClipboard = createCopyToClipboardHandle(isSensitive = true)

    CollectSideEffectWithLifecycle(vm.uiSideEffect) { sideEffect ->
        vm.consumeExport(sideEffect) { issue ->
            when (sideEffect) {
                is ReportProblemSideEffect.OpenIssue -> {
                    try {
                        uriHandler.openUri(issue.url)
                    } catch (_: IllegalArgumentException) {
                        // Unlike the generic URI helper, never log the user's report query.
                        vm.onBrowserUnavailable(issue)
                        scope.launch { snackbarHostState.showSnackbar(browserUnavailable) }
                    }
                }
                is ReportProblemSideEffect.CopyIssue -> copyToClipboard(issue.body, null)
                is ReportProblemSideEffect.CopyIssueLink -> copyToClipboard(issue.url, null)
            }
        }
    }

    ReportProblemScreen(
        state = state,
        onReviewIssue = { vm.reviewIssue(issueTitle) },
        onOpenIssue = vm::openSupportIssue,
        onCopyIssue = vm::copySupportIssue,
        onCopyIssueLink = vm::copyFallbackLink,
        onNavigateToViewLogs = dropUnlessResumed { navigator.navigate(ViewLogsNavKey) },
        onMessageChanged = vm::updateMessage,
        onBackClick = dropUnlessResumed { navigator.goBack() },
        snackbarHostState = snackbarHostState,
    )
}

@Composable
private fun ReportProblemScreen(
    state: ReportProblemUiState,
    onReviewIssue: () -> Unit,
    onOpenIssue: (SupportIssueExport) -> Unit,
    onCopyIssue: (SupportIssueExport) -> Unit,
    onCopyIssueLink: (SupportIssueExport) -> Unit,
    onNavigateToViewLogs: () -> Unit,
    onMessageChanged: (String) -> Unit,
    onBackClick: () -> Unit,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    ScaffoldWithSmallTopBar(
        appBarTitle = stringResource(id = R.string.report_a_problem),
        navigationIcon = {
            unlessIsDetail { NavigateBackIconButton(onNavigateBack = onBackClick) }
        },
        snackbarHostState = snackbarHostState,
    ) { modifier ->
        val scrollState = rememberScrollState()
        Column(
            modifier =
                Modifier.imePadding() // imePadding needs to be applied before the parent modifier.
                    .then(modifier)
                    .drawVerticalScrollbar(
                        state = scrollState,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = AlphaScrollbar),
                    )
                    .verticalScroll(state = scrollState)
                    .padding(
                        start = Dimens.sideMargin,
                        end = Dimens.sideMargin,
                        bottom = Dimens.screenBottomMargin,
                    ),
            verticalArrangement = Arrangement.spacedBy(Dimens.mediumPadding),
        ) {
            Text(
                text =
                    stringResource(
                        R.string.problem_report_github_description,
                        stringResource(R.string.app_name),
                    ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelLarge,
            )
            ProblemMessageTextField(
                value = state.message,
                isError = state.descriptionError != null,
                onDescriptionChanged = onMessageChanged,
            )
            PrimaryButton(
                onClick = onReviewIssue,
                text = stringResource(R.string.problem_report_review),
            )
            state.reviewedIssue?.let { issue ->
                SupportIssueReview(
                    issue = issue,
                    fallbackUrl = state.fallbackUrl,
                    onCopyIssue = onCopyIssue,
                    onOpenIssue = onOpenIssue,
                    onCopyIssueLink = onCopyIssueLink,
                )
            }
            if (state.logCollectingState == LogCollectingState.Success) {
                VariantButton(
                    onClick = onNavigateToViewLogs,
                    text = stringResource(R.string.view_logs),
                )
            }
            Text(
                text = stringResource(R.string.problem_report_public_logs_notice),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun SupportIssueReview(
    issue: SupportIssueExport,
    fallbackUrl: String?,
    onCopyIssue: (SupportIssueExport) -> Unit,
    onOpenIssue: (SupportIssueExport) -> Unit,
    onCopyIssueLink: (SupportIssueExport) -> Unit,
) {
    Text(
        text = stringResource(R.string.problem_report_review_title),
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface,
    )
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.onPrimary)) {
        SelectionContainer {
            Column(
                modifier = Modifier.fillMaxWidth().padding(Dimens.mediumPadding),
                verticalArrangement = Arrangement.spacedBy(Dimens.mediumPadding),
            ) {
                Text(
                    issue.title,
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    issue.body,
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
    if (issue.prefilledUrl == null) {
        Text(
            stringResource(R.string.problem_report_copy_fallback),
            color = MaterialTheme.colorScheme.onSurface,
        )
        SelectionContainer { Text(issue.issuePageUrl, color = MaterialTheme.colorScheme.onSurface) }
    }
    VariantButton(
        onClick = { onCopyIssue(issue) },
        text = stringResource(R.string.problem_report_copy),
    )
    PrimaryButton(
        onClick = { onOpenIssue(issue) },
        text = stringResource(R.string.open_github_issue),
    )
    fallbackUrl?.let { CopyableLink(url = it, onCopy = { onCopyIssueLink(issue) }) }
}

// Upstream's editor and localized validation, without email or account attachments.
@Composable
private fun ProblemMessageTextField(
    value: String,
    isError: Boolean,
    onDescriptionChanged: (String) -> Unit,
) {
    TextField(
        modifier =
            Modifier.fillMaxWidth()
                .defaultMinSize(minHeight = Dimens.problemReportTextFieldMinHeight),
        value = value,
        onValueChange = onDescriptionChanged,
        placeholder = { Text(stringResource(R.string.problem_report_message_hint)) },
        isError = isError,
        supportingText =
            if (isError) {
                { ErrorSupportingText(stringResource(R.string.report_problem_message_is_empty)) }
            } else null,
        colors = mullvadDarkTextFieldColors(),
        keyboardOptions =
            KeyboardOptions(
                capitalization = KeyboardCapitalization.Sentences,
                keyboardType = KeyboardType.Text,
                imeAction = if (isTv()) ImeAction.Next else ImeAction.Unspecified,
            ),
    )
}
