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

    @Synchronized
    fun start() {
        check(!closed)
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
            onChange(false)
        } catch (_: RuntimeException) {
            Logger.w("VPN lockdown observation unavailable; retaining blocking DNS coverage")
            publish(true)
        }
    }

    @Synchronized
    override fun onChange(selfChange: Boolean) {
        if (!closed) publish(runCatching(read).getOrDefault(true))
    }

    @Synchronized
    fun close() {
        closed = true
        resolver.unregisterContentObserver(this)
    }
}
