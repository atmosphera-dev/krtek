package net.mullvad.mullvadvpn.feature.lansharing.impl

import java.util.UUID
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule

/** Callbacks are supplied by the consumer; controls never access repositories or navigation. */
data class LocalPolicyActions(
    val onEnabled: (Boolean) -> Unit = {},
    val onExcludedAppsSkipLocalRules: (Boolean) -> Unit = {},
    val onEdit: (LocalBypassRule?) -> Unit = {},
    val onUpdate: ((LocalRuleDraft) -> LocalRuleDraft) -> Unit = {},
    val onSave: () -> Unit = {},
    val onClose: () -> Unit = {},
    val onDiscard: () -> Unit = {},
    val onKeep: () -> Unit = {},
    val onDelete: (UUID) -> Unit = {},
    val onRequestDelete: (LocalBypassRule) -> Unit = {},
    val onCancelDelete: () -> Unit = {},
    val onConnectedWifi: () -> Unit = {},
    val onRequestAccess: (Boolean) -> Unit = {},
    val splitDns: SplitDnsActions = SplitDnsActions(),
)

/** Split DNS callbacks; the section never reaches the repository or Android settings itself. */
data class SplitDnsActions(
    val onEnabled: (Boolean) -> Unit = {},
    val onEdit: () -> Unit = {},
    val onUpdate: ((SplitDnsDraft) -> SplitDnsDraft) -> Unit = {},
    val onSave: () -> Unit = {},
    val onClose: () -> Unit = {},
    val onDiscard: () -> Unit = {},
    val onKeep: () -> Unit = {},
    val onPrivateDnsSettings: () -> Unit = {},
)
