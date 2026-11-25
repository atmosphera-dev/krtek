package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.flow.MutableStateFlow
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository

/** What the split DNS section asks for; the screen's ViewModel forwards each one here. */
sealed interface SplitDnsAction {
    data class Enabled(val enabled: Boolean) : SplitDnsAction

    data object Edit : SplitDnsAction

    class Update(val update: (SplitDnsDraft) -> SplitDnsDraft) : SplitDnsAction

    data object Save : SplitDnsAction

    data object Close : SplitDnsAction

    data object Discard : SplitDnsAction

    data object Keep : SplitDnsAction
}

/** Owns the DNS draft; persistence shares the Local screen's one whole-policy transaction. */
internal class SplitDnsSettings(
    private val repository: SettingsRepository,
    private val savedState: SavedStateHandle,
    private val saving: MutableStateFlow<Boolean>,
    private val error: MutableStateFlow<Int?>,
    private val otherEditorOpen: () -> Boolean,
    private val changes: LocalPolicyChanges,
) {
    private val editor = savedState.getStateFlow(SPLIT_DNS_EDITOR_KEY, SplitDnsEditorState())

    fun handle(action: SplitDnsAction) {
        when (action) {
            is SplitDnsAction.Enabled -> enabled(action.enabled)
            SplitDnsAction.Edit -> edit()
            is SplitDnsAction.Update -> update(action.update)
            SplitDnsAction.Save -> save()
            SplitDnsAction.Close -> close()
            SplitDnsAction.Discard -> discard()
            SplitDnsAction.Keep -> keep()
        }
    }

    private fun edit() {
        val policy = repository.settingsUpdates.value?.localNetworkAccess ?: return
        // Allow repair of DNS-invalid represented reads, never invent missing Local settings.
        val repairable = policy.copy(splitDns = SplitDnsPolicy()).validationError() == null
        if (saving.value || otherEditorOpen() || editor.value.draft != null || !repairable) return
        val draft = SplitDnsDraft.from(policy.splitDns)
        setEditor(SplitDnsEditorState(draft, draft))
        error.value = null
    }

    private fun update(update: (SplitDnsDraft) -> SplitDnsDraft) {
        if (saving.value) return
        editor.value.draft?.let { setEditor(editor.value.copy(draft = update(it))) }
        error.value = null
    }

    /** Turning on an incomplete policy opens its editor; nothing is saved until Save. */
    private fun enabled(enabled: Boolean) {
        val policy = repository.settingsUpdates.value?.localNetworkAccess ?: return
        if (enabled && policy.splitDns.copy(enabled = true).validationError(policy.rules) != null) {
            edit()
            update { it.copy(enabled = true) }
        } else {
            changes.change { it.copy(splitDns = it.splitDns.copy(enabled = enabled)) }
        }
    }

    private fun save() {
        val current = repository.settingsUpdates.value?.localNetworkAccess
        val state = editor.value
        val draft = state.draft
        if (current == null || draft == null || saving.value) return
        val stored = SplitDnsDraft.from(current.splitDns)
        val problem = draft.problem(current.rules)
        val replacement = draft.replacement(current)
        when {
            state.baseline != null && !stored.sameContent(state.baseline) -> {
                // Saved DNS changed behind this draft: keep the draft; a second Save decides.
                setEditor(state.copy(baseline = stored))
                error.value = R.string.local_access_conflict
            }
            problem != null || replacement == null ->
                error.value = problem ?: R.string.split_dns_invalid
            else -> changes.change(closeEditor = true, current = current) { replacement }
        }
    }

    private fun close() {
        if (!saving.value) {
            setEditor(editor.value.requestClose())
            error.value = null
        }
    }

    private fun discard() {
        if (!saving.value) setEditor(SplitDnsEditorState())
    }

    private fun keep() = setEditor(editor.value.copy(confirmDiscard = false))

    private fun setEditor(value: SplitDnsEditorState) {
        savedState[SPLIT_DNS_EDITOR_KEY] = value
    }
}

internal const val SPLIT_DNS_EDITOR_KEY = "split-dns-editor"
