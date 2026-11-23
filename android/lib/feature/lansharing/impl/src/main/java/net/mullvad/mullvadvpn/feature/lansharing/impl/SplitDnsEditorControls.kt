package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
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
import java.util.UUID
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.component.textfield.CustomTextField
import net.mullvad.mullvadvpn.lib.ui.component.textfield.mullvadDarkTextFieldColors
import net.mullvad.mullvadvpn.lib.ui.designsystem.MullvadExposedDropdownMenuBox
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryButton
import net.mullvad.mullvadvpn.lib.ui.designsystem.PrimaryTextButton
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import net.mullvad.mullvadvpn.lib.ui.theme.color.menuItemColors

/** Saved split DNS summary below the Local rules. Callbacks decide what each control does. */
@Composable
internal fun SplitDnsSection(
    state: LocalNetworkSharingUiState,
    actions: SplitDnsActions,
    sdkInt: Int,
) {
    val split = state.policy.splitDns
    val rule = state.policy.rules.find { it.id == split.localRuleId }
    HorizontalDivider()
    Text(stringResource(R.string.split_dns_title), style = MaterialTheme.typography.titleMedium)
    if (state.splitDnsRepairable) {
        Text(
            stringResource(R.string.split_dns_policy_invalid),
            color = MaterialTheme.colorScheme.error,
        )
    }
    SwitchListItem(
        title = stringResource(R.string.split_dns_enable),
        isToggled = split.enabled,
        isEnabled = state.policyEditable,
        testTag = "split_dns_enabled",
        onCellClicked = actions.onEnabled,
    )
    if (split.enabled && rule != null) {
        Text(rule.usedOn(), style = MaterialTheme.typography.bodyMedium)
    }
    if (sdkInt == Build.VERSION_CODES.P) {
        Text(
            stringResource(R.string.split_dns_android_9_pause),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    split.homeResolver?.let {
        SplitDnsSummaryValue(R.string.split_dns_home_ip, listOf(it.numericAddress))
    }
    rule?.let { SplitDnsSummaryValue(R.string.split_dns_home_network, listOf(it.networkLabel())) }
    if (split.suffixes.isNotEmpty()) {
        SplitDnsSummaryValue(
            R.string.split_dns_domains,
            split.suffixes.map { SplitDnsDomainDraft.from(it).text },
        )
    }
    PrimaryButton(
        modifier = Modifier.testTag("split_dns_edit"),
        text = stringResource(R.string.split_dns_edit),
        onClick = actions.onEdit,
    )
    Text(
        stringResource(R.string.split_dns_no_fallback),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(stringResource(R.string.split_dns_route_help), style = MaterialTheme.typography.bodyMedium)
    HorizontalDivider()
    Text(
        stringResource(R.string.split_dns_private_dns),
        style = MaterialTheme.typography.bodyMedium,
    )
    PrimaryTextButton(
        modifier = Modifier.testTag("split_dns_private_dns_settings"),
        text = stringResource(R.string.split_dns_open_private_dns),
        onClick = actions.onPrivateDnsSettings,
    )
}

@Composable
private fun SplitDnsSummaryValue(label: Int, values: List<String>) {
    Text(stringResource(label), style = MaterialTheme.typography.titleSmall)
    values.forEach { Text(it, style = MaterialTheme.typography.bodyLarge) }
}

/** Callback-only editor body; Save and Cancel live in the screen's editor action bar. */
@Composable
internal fun SplitDnsEditorControls(
    draft: SplitDnsDraft,
    rules: List<LocalBypassRule>,
    enabled: Boolean,
    onUpdate: ((SplitDnsDraft) -> SplitDnsDraft) -> Unit,
) {
    Column(
        Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(Dimens.smallPadding),
    ) {
        Text(stringResource(R.string.split_dns_edit), style = MaterialTheme.typography.titleMedium)
        draft.domains.forEachIndexed { index, row ->
            key(row.id) { SplitDnsDomainField(row, index, enabled, onUpdate) }
        }
        PrimaryButton(
            modifier = Modifier.testTag("split_dns_add_domain"),
            text = stringResource(R.string.split_dns_add_domain),
            isEnabled = enabled,
            onClick = {
                onUpdate {
                    it.copy(
                        domains = it.domains + SplitDnsDomainDraft(UUID.randomUUID().toString(), "")
                    )
                }
            },
        )
        CustomTextField(
            value = draft.homeResolver,
            labelText = stringResource(R.string.split_dns_home_ip),
            modifier = Modifier.testTag("split_dns_home_ip"),
            keyboardType = KeyboardType.Uri,
            isEnabled = enabled,
            isValidValue =
                draft.homeResolver.isEmpty() || HomeDnsResolver.parse(draft.homeResolver) != null,
            isDigitsOnlyAllowed = false,
            onValueChanged = { value -> onUpdate { it.copy(homeResolver = value) } },
            onSubmit = {},
        )
        Text(
            stringResource(R.string.split_dns_home_ip_help),
            style = MaterialTheme.typography.bodyMedium,
        )
        SplitDnsHomeNetworkPicker(draft.localRuleId, rules) { id ->
            onUpdate { it.copy(localRuleId = id) }
        }
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
                keyboardType = KeyboardType.Uri,
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

/** Lists the existing Local rules only; choosing one never edits or enables that rule. */
@Composable
private fun SplitDnsHomeNetworkPicker(
    selectedId: String?,
    rules: List<LocalBypassRule>,
    onSelect: (String) -> Unit,
) {
    val selected = rules.find { it.id.toString() == selectedId }
    MullvadExposedDropdownMenuBox(
        modifier = Modifier.testTag("split_dns_home_network"),
        label = stringResource(R.string.split_dns_home_network),
        title = selected?.networkLabel() ?: stringResource(R.string.split_dns_choose_home_network),
        colors = mullvadDarkTextFieldColors(),
    ) { close ->
        rules.forEach { rule ->
            DropdownMenuItem(
                modifier = Modifier.testTag("split_dns_home_network_${rule.id}"),
                colors = menuItemColors,
                text = { Text(rule.networkLabel(), style = MaterialTheme.typography.bodyLarge) },
                onClick = {
                    close()
                    onSelect(rule.id.toString())
                },
            )
        }
    }
}

@Composable
private fun LocalBypassRule.networkText(): String? =
    ssidIds
        .takeIf { it.isNotEmpty() }
        ?.let { ids ->
            stringResource(R.string.local_access_wifi, ids.joinToString(", ") { it.displayText() })
        }

/** The rule as the Local rules list shows it: its name and the network it applies to. */
@Composable
internal fun LocalBypassRule.networkLabel(): String =
    stringResource(
        R.string.split_dns_rule_network,
        name.ifEmpty { stringResource(R.string.local_access_unnamed) },
        networkText() ?: stringResource(R.string.local_access_any_network),
    )

@Composable
private fun LocalBypassRule.usedOn(): String =
    networkText()?.let { stringResource(R.string.split_dns_used_on, it) }
        ?: stringResource(R.string.split_dns_used_on_any_network)
