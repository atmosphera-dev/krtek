package net.mullvad.mullvadvpn.feature.lansharing.impl

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.util.UUID
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.WhileSubscribed
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.lib.common.Lc
import net.mullvad.mullvadvpn.lib.common.constant.VIEW_MODEL_STOP_TIMEOUT
import net.mullvad.mullvadvpn.lib.common.toLc
import net.mullvad.mullvadvpn.lib.model.ConnectedWifi
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SetLocalNetworkAccessError
import net.mullvad.mullvadvpn.lib.model.WifiUnknownReason
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository

class LocalNetworkSharingViewModel(
    private val isModal: Boolean,
    private val settingsRepository: SettingsRepository,
    private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val editor = savedStateHandle.getStateFlow("local-rule-editor", LocalEditorState())
    private val deleteTarget =
        savedStateHandle.getStateFlow<LocalRuleDeleteTarget?>("local-rule-delete", null)
    private val saving = MutableStateFlow(false)
    private val error = MutableStateFlow<Int?>(null)
    private val effects = Channel<LocalNetworkSharingSideEffect>(Channel.BUFFERED)
    val uiSideEffect = effects.receiveAsFlow()
    private var wifiRequests = 0L
    private val policyChanges =
        LocalPolicyChanges(settingsRepository, viewModelScope, saving, error, editor) {
            closeEditor,
            requestWifi ->
            if (closeEditor) setEditor(LocalEditorState())
            requestWifi?.let { effects.send(LocalNetworkSharingSideEffect(it)) }
        }

    init {
        viewModelScope.launch {
            editor
                .map { it.draft != null }
                .distinctUntilChanged()
                .collectLatest { open ->
                    if (open) settingsRepository.observeLocalNetworkForEditor()
                }
        }
        viewModelScope.launch {
            // One deadline per waiting request. Closing or replacing the draft, a manual Wi-Fi
            // edit or an answer ends the wait and cancels it. Expiry only explains the delay:
            // the request stays, so a later fresh name still fills this draft.
            editor
                .map { if (it.waitingForWifi) it.wifiRequest else null }
                .distinctUntilChanged()
                .collectLatest { request ->
                    // A null request still arrives here, so ending the wait cancels the delay.
                    if (request != null) {
                        delay(WIFI_ANSWER_DEADLINE)
                        val edit = editor.value
                        val wifi = settingsRepository.localNetworkStatus.value?.currentWifi
                        val pending =
                            wifi == null ||
                                (wifi as? ConnectedWifi.Unknown)?.reason ==
                                    WifiUnknownReason.Pending
                        if (edit.waitingForWifi && edit.wifiRequest == request && pending)
                            setEditor(
                                edit.copy(wifiMessage = R.string.local_access_wifi_not_available)
                            )
                    }
                }
        }
        viewModelScope.launch {
            combine(settingsRepository.localNetworkStatus, editor) { status, edit ->
                    status?.currentWifi to edit.waitingForWifi
                }
                .collect { (wifi, waiting) ->
                    // A request made while Wi-Fi was pending or not permitted completes from the
                    // next fresh status. The flag lives in this draft's editor state, so a new,
                    // closed or edited draft never takes the answer.
                    val edit = editor.value
                    if (!waiting || !edit.waitingForWifi || edit.draft == null) return@collect
                    when {
                        wifi is ConnectedWifi.Known -> fillConnectedWifi(wifi)
                        wifi is ConnectedWifi.Unknown && !wifi.reason.awaitsWifi() ->
                            setEditor(
                                edit.copy(
                                    waitingForWifi = false,
                                    wifiMessage = wifi.reason.message(),
                                )
                            )
                    }
                }
        }
    }

    val uiState =
        combine(
                settingsRepository.settingsUpdates.filterNotNull(),
                settingsRepository.localNetworkStatus,
                combine(editor, deleteTarget) { edit, target -> edit to target },
                saving,
                error,
            ) { settings, status, (edit, target), busy, failure ->
                LocalNetworkSharingUiState(
                        lanSharingEnabled = settings.allowLan,
                        isModal = isModal,
                        policy = settings.localNetworkAccess ?: LocalNetworkAccess(),
                        policyReadable = settings.localNetworkAccess != null,
                        status = status,
                        editor = edit,
                        saving = busy,
                        error = failure,
                        deleteTarget = target,
                    )
                    .toLc<Boolean, LocalNetworkSharingUiState>()
            }
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(VIEW_MODEL_STOP_TIMEOUT),
                initialValue = Lc.Loading(isModal),
            )

    fun setLocalNetworkSharingEnabled(enable: Boolean) {
        viewModelScope.launch { settingsRepository.setLocalNetworkSharing(enable) }
    }

    fun edit(rule: LocalBypassRule?) {
        val policy = settingsRepository.settingsUpdates.value?.localNetworkAccess
        if (
            saving.value ||
                editor.value.draft != null ||
                policy == null ||
                policy.validationError() != null
        )
            return
        val draft = rule?.let(LocalRuleDraft::from) ?: LocalRuleDraft(UUID.randomUUID().toString())
        setEditor(LocalEditorState(draft, draft))
        error.value = null
    }

    fun updateDraft(update: (LocalRuleDraft) -> LocalRuleDraft) {
        if (saving.value) return
        editor.value.draft?.let {
            val next = update(it)
            // Only editing the Wi-Fi names supersedes a pending "Use connected Wi-Fi" request.
            setEditor(
                if (next.wifiNames == it.wifiNames) editor.value.copy(draft = next)
                else editor.value.copy(draft = next, waitingForWifi = false, wifiMessage = null)
            )
        }
        error.value = null
    }

    fun closeEditor() {
        if (!saving.value) {
            setEditor(
                if (editor.value.dirty) editor.value.copy(confirmDiscard = true)
                else LocalEditorState()
            )
            error.value = null
        }
    }

    fun discard() = setEditor(LocalEditorState())

    fun keepEditing() = setEditor(editor.value.copy(confirmDiscard = false))

    fun save() {
        val rule = editor.value.draft?.rule()
        if (rule == null) {
            error.value = R.string.local_access_invalid_rule
            return
        }
        policyChanges.change(closeEditor = true, requestWifi = rule.ssidIds.isNotEmpty()) { current
            ->
            current.copy(
                rules =
                    if (current.rules.any { it.id == rule.id })
                        current.rules.map { if (it.id == rule.id) rule else it }
                    else current.rules + rule
            )
        }
    }

    fun setPolicyEnabled(enabled: Boolean) = policyChanges.change { it.copy(enabled = enabled) }

    fun setExcludedAppsSkipLocalRules(skip: Boolean) = policyChanges.change {
        it.copy(skipLocalRulesForExcludedApps = skip)
    }

    fun requestDelete(rule: LocalBypassRule?) {
        if (saving.value || editor.value.draft != null) return
        val current =
            settingsRepository.settingsUpdates.value?.localNetworkAccess?.rules?.find {
                it.id == rule?.id
            }
        savedStateHandle["local-rule-delete"] = current?.let {
            LocalRuleDeleteTarget(it.id.toString(), it.name)
        }
    }

    fun delete(id: UUID) = policyChanges.change {
        requestDelete(null)
        it.copy(rules = it.rules.filterNot { rule -> rule.id == id })
    }

    private fun setEditor(value: LocalEditorState) {
        savedStateHandle["local-rule-editor"] = value
    }

    fun useConnectedWifi() {
        val wifi = settingsRepository.localNetworkStatus.value?.currentWifi
        if (wifi is ConnectedWifi.Known) fillConnectedWifi(wifi)
        else {
            val edit = editor.value
            val draft = edit.draft ?: return
            val reason = (wifi as? ConnectedWifi.Unknown)?.reason ?: WifiUnknownReason.Pending
            val missing = reason == WifiUnknownReason.PermissionMissing
            setEditor(
                edit.copy(
                    draft =
                        if (draft.wifiNames.isEmpty())
                            draft.copy(wifiNames = listOf(LocalWifiDraft("")))
                        else draft,
                    waitingForWifi = reason.awaitsWifi(),
                    wifiMessage = reason.message(),
                    wifiRequest = ++wifiRequests,
                )
            )
            if (missing) viewModelScope.launch { effects.send(LocalNetworkSharingSideEffect(true)) }
        }
    }

    private fun fillConnectedWifi(wifi: ConnectedWifi.Known) {
        val edit = editor.value
        val draft = edit.draft ?: return
        val names = draft.wifiNames.toMutableList()
        val blank = names.indexOfFirst { it.text.isEmpty() }
        when {
            names.any { it.identity() == wifi.ssid } -> Unit
            blank >= 0 -> names[blank] = LocalWifiDraft.from(wifi.ssid)
            names.size < LocalNetworkAccess.MAX_SSIDS_PER_RULE ->
                names.add(LocalWifiDraft.from(wifi.ssid))
            else -> {
                setEditor(
                    edit.copy(
                        waitingForWifi = false,
                        wifiMessage = R.string.local_access_wifi_limit,
                    )
                )
                return
            }
        }
        setEditor(
            edit.copy(
                draft = draft.copy(wifiNames = names),
                waitingForWifi = false,
                wifiMessage = null,
            )
        )
    }
}

/**
 * Android reports current networks right after registration (milliseconds; about a second on a
 * loaded emulator). Five seconds leaves headroom for a slow binder or emulator while still telling
 * the user soon that the name can be typed in.
 */
private val WIFI_ANSWER_DEADLINE = 5.seconds

/** Observation that has not answered yet, or awaits access the user is being asked for. */
private fun WifiUnknownReason.awaitsWifi() =
    this == WifiUnknownReason.Pending || this == WifiUnknownReason.PermissionMissing

internal fun WifiUnknownReason.message(): Int =
    when (this) {
        WifiUnknownReason.PermissionMissing -> R.string.local_access_fine_missing
        WifiUnknownReason.LocationOff -> R.string.local_access_wifi_location_off
        WifiUnknownReason.NotOnWifi -> R.string.local_access_not_on_wifi
        WifiUnknownReason.MultipleWifi -> R.string.local_access_multiple_wifi
        WifiUnknownReason.Pending -> R.string.local_access_waiting_wifi
    }

internal fun SetLocalNetworkAccessError.message(): Int =
    when (this) {
        SetLocalNetworkAccessError.Conflict -> R.string.local_access_conflict
        SetLocalNetworkAccessError.Invalid -> R.string.local_access_invalid_rule
        is SetLocalNetworkAccessError.Unknown -> R.string.local_access_save_failed
    }
