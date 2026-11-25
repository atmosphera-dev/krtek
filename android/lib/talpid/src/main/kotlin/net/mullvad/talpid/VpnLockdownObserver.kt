package net.mullvad.talpid

import android.content.ContentResolver
import android.database.ContentObserver
import android.os.Handler
import android.provider.Settings
import co.touchlab.kermit.Logger

/** Owns OS configuration observation, independently of physical-network eligibility. */
internal class VpnLockdownObserver(
    private val resolver: ContentResolver,
    handler: Handler,
    private val read: () -> Boolean,
    private val publish: (Boolean) -> Unit,
) : ContentObserver(handler) {
    private var closed = false
    private var registered = false

    @Synchronized
    fun start() {
        check(!closed)
        if (registered) return
        try {
            resolver.registerContentObserver(
                Settings.Secure.getUriFor("always_on_vpn_lockdown"),
                false,
                this,
            )
            resolver.registerContentObserver(
                Settings.Secure.getUriFor("always_on_vpn_app"),
                false,
                this,
            )
            registered = true
        } catch (_: RuntimeException) {
            Logger.w("VPN lockdown observation unavailable; retaining blocking DNS coverage")
        }
        refresh()
    }

    override fun onChange(selfChange: Boolean) = refresh()

    /** Settings and successful capture establishment both change the usable OS view. */
    @Synchronized
    fun refresh() {
        if (!closed) publish(!registered || runCatching(read).getOrDefault(true))
    }

    @Synchronized
    fun close() {
        closed = true
        resolver.unregisterContentObserver(this)
    }
}
