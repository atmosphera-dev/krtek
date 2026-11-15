package net.mullvad.mullvadvpn.lib.model

import arrow.optics.optics

@optics
data class Settings(
    val relaySettings: RelaySettings,
    val obfuscationSettings: ObfuscationSettings,
    val customLists: List<CustomList>,
    val allowLan: Boolean,
    val tunnelOptions: TunnelOptions,
    val relayOverrides: List<RelayOverride>,
    val showBetaReleases: Boolean,
    val splitTunnelSettings: SplitTunnelSettings,
    val apiAccessMethodSettings: List<ApiAccessMethodSetting>,
    val recents: Recents,
    // Null means the Local wire policy could not be represented, never OFF/empty.
    val localNetworkAccess: LocalNetworkAccess? = LocalNetworkAccess(),
) {
    companion object
}
