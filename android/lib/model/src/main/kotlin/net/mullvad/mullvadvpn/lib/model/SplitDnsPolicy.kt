package net.mullvad.mullvadvpn.lib.model

import java.util.UUID

/** Raw representable drafts stay lossless until an accepted atomic replacement. */
data class SplitDnsPolicy(
    val enabled: Boolean = false,
    val suffixes: List<String> = emptyList(),
    val homeResolver: HomeDnsResolver? = null,
    val localRuleId: UUID? = null,
) {
    fun validationError(rules: List<LocalBypassRule>): SplitDnsPolicyError? =
        when {
            suffixes.any { SplitDnsDomain.normalize(it) == null } ->
                SplitDnsPolicyError.InvalidDomain
            !enabled -> null
            suffixes.isEmpty() -> SplitDnsPolicyError.MissingSuffix
            homeResolver == null -> SplitDnsPolicyError.MissingResolver
            localRuleId == null -> SplitDnsPolicyError.MissingAssociation
            else -> associationError(rules, homeResolver, localRuleId)
        }

    private fun associationError(
        rules: List<LocalBypassRule>,
        resolver: HomeDnsResolver,
        id: UUID,
    ): SplitDnsPolicyError? {
        val rule = rules.find { it.id == id }
        // Saving DNS never enables the Local master/rule or changes its coverage.
        return when {
            rule == null -> SplitDnsPolicyError.UnknownAssociation
            rule.cidrs.none { it.contains(resolver.addressBytes()) } ->
                SplitDnsPolicyError.ResolverNotCovered
            else -> null
        }
    }

    override fun toString(): String =
        "SplitDnsPolicy(enabled=$enabled suffix-count=${suffixes.size} " +
            "has-resolver=${homeResolver != null} has-association=${localRuleId != null})"
}

enum class SplitDnsPolicyError {
    InvalidDomain,
    MissingSuffix,
    MissingResolver,
    MissingAssociation,
    UnknownAssociation,
    ResolverNotCovered,
}
