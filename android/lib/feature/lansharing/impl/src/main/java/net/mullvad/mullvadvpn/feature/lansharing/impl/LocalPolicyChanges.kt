package net.mullvad.mullvadvpn.feature.lansharing.impl

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository

/** One guarded whole-policy transaction for switches, rule saves and deletion. */
internal class LocalPolicyChanges(
    private val settingsRepository: SettingsRepository,
    private val scope: CoroutineScope,
    private val saving: MutableStateFlow<Boolean>,
    private val error: MutableStateFlow<Int?>,
    private val editorOpen: () -> Boolean,
    private val onSaved: suspend (closeEditor: Boolean, requestWifi: Boolean?) -> Unit,
) {
    fun change(
        closeEditor: Boolean = false,
        requestWifi: Boolean? = null,
        update: (LocalNetworkAccess) -> LocalNetworkAccess,
    ) {
        val current = settingsRepository.settingsUpdates.value?.localNetworkAccess
        if (saving.value || current == null) return
        // Only an explicit editor replacement may repair a representable invalid policy.
        // Switches cannot turn an unreadable/invalid policy into an editable default.
        if (!closeEditor && (editorOpen() || current.validationError() != null)) return

        val replacement = update(current)
        if (replacement.validationError() != null) {
            error.value = R.string.local_access_invalid_rule
        } else {
            saving.value = true
            error.value = null
            scope.launch {
                try {
                    settingsRepository
                        .setLocalNetworkAccess(replacement, expected = current)
                        .fold({ error.value = it.message() }, { onSaved(closeEditor, requestWifi) })
                } finally {
                    saving.value = false
                }
            }
        }
    }
}
