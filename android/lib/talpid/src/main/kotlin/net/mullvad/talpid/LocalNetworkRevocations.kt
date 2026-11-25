package net.mullvad.talpid

import net.mullvad.talpid.model.LocalNetworkSnapshot
import net.mullvad.talpid.model.LocalPhysicalNetwork

/**
 * The watcher serializes this writer with its event lock. It owns only the monotone witness fence,
 * never the watcher's mutable map, status or grants.
 */
internal class LocalNetworkRevocations(
    private val source: LocalNetworkSource,
    private val publication: LocalNetworkPublication,
) {
    var revision = 0L
        private set

    /**
     * Rust may only revoke from this possibly incomplete map. A complete status publication at this
     * fence is required before it admits new work.
     */
    fun revalidate(
        registration: Long,
        sequence: Long,
        running: Boolean,
        access: LocalIdentityAccess,
        networks: List<LocalPhysicalNetwork>,
    ) {
        revision = Math.addExact(revision, 1L)
        if (registration == 0L) return
        val witness =
            try {
                val fresh = if (running) source.readAccess() else access
                val observed =
                    if (running) source.withLegacyIdentity(networks, fresh.identity)
                    else emptyList()
                LocalNetworkSnapshot(
                    sequence,
                    running,
                    fresh.local,
                    fresh.fine,
                    fresh.background,
                    fresh.location,
                    fresh.operations,
                    ArrayList(observed.map { if (fresh.identity) it else it.copy(ssidHex = null) }),
                    revision,
                )
            } catch (_: RuntimeException) {
                LocalNetworkSnapshot(
                    sequence,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    arrayListOf(),
                    revision,
                )
            }
        publication.revalidate(registration, witness)
    }
}
