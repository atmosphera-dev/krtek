package net.mullvad.mullvadvpn.feature.lansharing.impl

import android.os.Parcelable
import java.util.UUID
import kotlinx.parcelize.Parcelize
import net.mullvad.mullvadvpn.lib.model.HomeDnsResolver
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SplitDnsDomain
import net.mullvad.mullvadvpn.lib.model.SplitDnsPolicy

/** Stable row identity prevents a removal from transferring field focus to another domain. */
@Parcelize
data class SplitDnsDomainDraft(val id: String, val text: String) : Parcelable {
    fun canonical(): String? = SplitDnsDomain.normalize(text)

    fun preview(): String? = canonical()?.removeSuffix(".")

    override fun toString(): String = "SplitDnsDomainDraft(redacted)"

    companion object {
        fun from(value: String): SplitDnsDomainDraft =
            SplitDnsDomainDraft(
                UUID.randomUUID().toString(),
                // Invalid represented values remain exact and repairable. Only
                // already canonical values lose the root dot for presentation.
                if (SplitDnsDomain.normalize(value) == value) value.removeSuffix(".") else value,
            )
    }
}

/** Presentation only: no preference store, network lookup or Local-rule mutation. */
@Parcelize
data class SplitDnsDraft(
    val enabled: Boolean = false,
    val domains: List<SplitDnsDomainDraft> = emptyList(),
    val homeResolver: String = "",
    val localRuleId: String? = null,
) : Parcelable {
    fun policy(rules: List<LocalBypassRule>): SplitDnsPolicy? {
        val suffixes = domains.map { it.canonical() }
        val resolver = HomeDnsResolver.parse(homeResolver)
        val association = localRuleId?.let { runCatching { UUID.fromString(it) }.getOrNull() }
        val invalid =
            suffixes.any { it == null } ||
                (homeResolver.isNotEmpty() && resolver == null) ||
                (localRuleId != null && association == null)
        if (invalid) return null
        return SplitDnsPolicy(enabled, suffixes.filterNotNull().distinct(), resolver, association)
            .takeIf {
                it.validationError(rules) == null
            }
    }

    fun replacement(current: LocalNetworkAccess): LocalNetworkAccess? =
        policy(current.rules)?.let { split ->
            current.copy(splitDns = split).takeIf { it.validationError() == null }
        }

    override fun toString(): String = "SplitDnsDraft(redacted)"

    companion object {
        fun from(policy: SplitDnsPolicy): SplitDnsDraft =
            SplitDnsDraft(
                policy.enabled,
                policy.suffixes.map(SplitDnsDomainDraft::from),
                policy.homeResolver?.numericAddress.orEmpty(),
                policy.localRuleId?.toString(),
            )
    }
}

@Parcelize
data class SplitDnsEditorState(
    val draft: SplitDnsDraft? = null,
    val baseline: SplitDnsDraft? = null,
    val confirmDiscard: Boolean = false,
) : Parcelable {
    val dirty: Boolean
        get() = draft != null && draft != baseline

    fun requestClose(): SplitDnsEditorState =
        if (dirty) copy(confirmDiscard = true) else SplitDnsEditorState()

    override fun toString(): String = "SplitDnsEditorState(dirty=$dirty)"
}
