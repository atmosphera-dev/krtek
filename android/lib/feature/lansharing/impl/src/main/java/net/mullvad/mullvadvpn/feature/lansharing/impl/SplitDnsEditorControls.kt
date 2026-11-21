package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import java.util.UUID
import net.mullvad.mullvadvpn.lib.ui.component.textfield.CustomTextField
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryTextButton
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens

internal data class SplitDnsEditorUiState(
    val draft: SplitDnsDraft,
    val homeNetworkLabel: String,
    val saving: Boolean = false,
    val error: Int? = null,
) {
    override fun toString(): String = "SplitDnsEditorUiState(saving=$saving)"
}

internal data class SplitDnsEditorActions(
    val onUpdate: ((SplitDnsDraft) -> SplitDnsDraft) -> Unit,
    val onChooseHomeNetwork: () -> Unit,
    val onSave: () -> Unit,
    val onCancel: () -> Unit,
    val onPrivateDnsSettings: () -> Unit,
)

/** Callback-only editor, not yet selected by the Local settings screen. */
@Composable
internal fun SplitDnsEditorControls(
    state: SplitDnsEditorUiState,
    actions: SplitDnsEditorActions,
) {
    Column(
        Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(Dimens.smallPadding),
    ) {
        Text(
            stringResource(R.string.split_dns_title),
            style = MaterialTheme.typography.titleMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        state.draft.domains.forEachIndexed { index, row ->
            key(row.id) { SplitDnsDomainField(row, index, !state.saving, actions.onUpdate) }
        }
        PrimaryTextButton(
            text = stringResource(R.string.split_dns_add_domain),
            isEnabled = !state.saving,
            onClick = {
                actions.onUpdate {
                    it.copy(
                        domains = it.domains + SplitDnsDomainDraft(UUID.randomUUID().toString(), "")
                    )
                }
            },
        )
        SplitDnsHomeFields(state, actions)
        SplitDnsNotes(actions.onPrivateDnsSettings)
        state.error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
        PrimaryButton(
            text = stringResource(R.string.local_access_save),
            isEnabled = !state.saving,
            onClick = actions.onSave,
        )
        PrimaryTextButton(
            text = stringResource(android.R.string.cancel),
            isEnabled = !state.saving,
            onClick = actions.onCancel,
        )
    }
}

@Composable
private fun SplitDnsDomainField(
    row: SplitDnsDomainDraft,
    index: Int,
    enabled: Boolean,
    onUpdate: ((SplitDnsDraft) -> SplitDnsDraft) -> Unit,
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CustomTextField(
                value = row.text,
                labelText = stringResource(R.string.split_dns_domain),
                modifier = Modifier.weight(1f).testTag("split_dns_domain_$index"),
                keyboardType = KeyboardType.Text,
                isEnabled = enabled,
                isValidValue = row.text.isEmpty() || row.canonical() != null,
                isDigitsOnlyAllowed = false,
                onValueChanged = { value ->
                    onUpdate { draft ->
                        draft.copy(
                            domains =
                                draft.domains.map {
                                    if (it.id == row.id) it.copy(text = value) else it
                                }
                        )
                    }
                },
                onSubmit = {},
            )
            IconButton(
                enabled = enabled,
                modifier = Modifier.testTag("split_dns_remove_$index"),
                onClick = {
                    onUpdate { draft ->
                        draft.copy(domains = draft.domains.filterNot { it.id == row.id })
                    }
                },
            ) {
                Icon(
                    Icons.Rounded.Delete,
                    contentDescription = stringResource(R.string.split_dns_remove_domain),
                )
            }
        }
        row.preview()?.let {
            Text(
                stringResource(R.string.split_dns_domain_preview, it),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun SplitDnsHomeFields(state: SplitDnsEditorUiState, actions: SplitDnsEditorActions) {
    CustomTextField(
        value = state.draft.homeResolver,
        labelText = stringResource(R.string.split_dns_home_ip),
        modifier = Modifier.testTag("split_dns_home_ip"),
        keyboardType = KeyboardType.Text,
        isEnabled = !state.saving,
        isValidValue = true,
        isDigitsOnlyAllowed = false,
        onValueChanged = { value -> actions.onUpdate { it.copy(homeResolver = value) } },
        onSubmit = {},
    )
    Text(
        stringResource(R.string.split_dns_home_ip_help),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.split_dns_home_network),
        style = MaterialTheme.typography.titleSmall,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
    PrimaryTextButton(
        text = state.homeNetworkLabel,
        isEnabled = !state.saving,
        onClick = actions.onChooseHomeNetwork,
    )
}

@Composable
private fun SplitDnsNotes(onPrivateDnsSettings: () -> Unit) {
    Text(
        stringResource(R.string.split_dns_no_fallback),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(stringResource(R.string.split_dns_route_help), style = MaterialTheme.typography.bodyMedium)
    Text(
        stringResource(R.string.split_dns_private_dns),
        style = MaterialTheme.typography.bodyMedium,
    )
    PrimaryTextButton(
        text = stringResource(R.string.split_dns_open_private_dns),
        onClick = onPrivateDnsSettings,
    )
}
