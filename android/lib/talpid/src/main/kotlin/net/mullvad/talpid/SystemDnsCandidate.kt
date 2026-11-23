package net.mullvad.talpid

/** One complete, eligible passive Internet observation. */
internal data class SystemDnsCandidate(
    val handle: Long,
    val validated: Boolean,
    val local: Boolean,
)

/** Select an observed network, never an arbitrary arrival-order or resolver fallback. */
internal fun selectSystemDnsNetwork(
    candidates: List<SystemDnsCandidate>,
    localHandle: Long?,
): Long? {
    val preferred = candidates.singleOrNull { it.handle == localHandle }
    val validated = candidates.filter { it.validated }.ifEmpty { candidates }
    val physical = validated.filter { it.local }.ifEmpty { validated }
    return preferred?.handle ?: physical.singleOrNull()?.handle
}
