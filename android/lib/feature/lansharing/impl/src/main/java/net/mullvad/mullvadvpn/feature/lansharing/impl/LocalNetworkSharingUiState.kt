package net.mullvad.mullvadvpn.feature.lansharing.impl

import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalNetworkStatus
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy

data class LocalNetworkSharingUiState(
    val lanSharingEnabled: Boolean,
    val isModal: Boolean = false,
    val policy: LocalNetworkAccess = LocalNetworkAccess(),
    val policyReadable: Boolean = true,
    val status: LocalNetworkStatus? = null,
    val editor: LocalEditorState = LocalEditorState(),
    val saving: Boolean = false,
    val error: Int? = null,
    val deleteTarget: LocalRuleDeleteTarget? = null,
    val splitDnsEditor: SplitDnsEditorState = SplitDnsEditorState(),
) {
    val editing: Boolean
        get() = editor.draft != null || splitDnsEditor.draft != null

    val policyEditable: Boolean
        get() = policyReadable && policy.validationError() == null

    /** Only the DNS part is invalid: its editor may repair it, nothing else is invented. */
    val splitDnsRepairable: Boolean
        get() =
            policyReadable &&
                policy.validationError() != null &&
                policy.copy(splitDns = SplitDnsPolicy()).validationError() == null
}
