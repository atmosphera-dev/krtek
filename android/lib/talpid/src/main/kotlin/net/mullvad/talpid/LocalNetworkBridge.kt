package net.mullvad.talpid

import net.mullvad.talpid.model.LocalNetworkSnapshot

object LocalNetworkBridge {
    @JvmStatic external fun published(registration: Long, snapshot: LocalNetworkSnapshot)

    /** Revocation-only JNI: never calls back into the platform or grants work. */
    @JvmStatic external fun revalidate(registration: Long, snapshot: LocalNetworkSnapshot)
}

/** Injected publication boundary. Lambdas are coalesced-status-only test doubles. */
internal fun interface LocalNetworkPublication {
    fun published(registration: Long, snapshot: LocalNetworkSnapshot)

    fun revalidate(registration: Long, snapshot: LocalNetworkSnapshot) = Unit
}

internal object NativeLocalNetworkPublication : LocalNetworkPublication {
    override fun published(registration: Long, snapshot: LocalNetworkSnapshot) =
        LocalNetworkBridge.published(registration, snapshot)

    override fun revalidate(registration: Long, snapshot: LocalNetworkSnapshot) =
        LocalNetworkBridge.revalidate(registration, snapshot)
}
