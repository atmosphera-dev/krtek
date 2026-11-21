package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.compose.ui.tooling.preview.PreviewParameterProvider
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.toLc
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess

class LocalNetworkSharingUiStatePreviewParameterProvider :
    PreviewParameterProvider<Lc<Boolean, LocalNetworkSharingUiState>> {
    override val values: Sequence<Lc<Boolean, LocalNetworkSharingUiState>> =
        sequenceOf(
            Lc.Loading(true),
            LocalNetworkSharingUiState(lanSharingEnabled = true, isModal = false).toLc(),
            LocalNetworkSharingUiState(lanSharingEnabled = true, isModal = true).toLc(),
            LocalNetworkSharingUiState(
                    lanSharingEnabled = false,
                    policy =
                        LocalNetworkAccess(enabled = true, skipLocalRulesForExcludedApps = false),
                )
                .toLc(),
        )
}
