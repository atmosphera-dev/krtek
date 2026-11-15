package net.mullvad.talpid

import android.net.Network
import co.touchlab.kermit.Logger
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import net.mullvad.talpid.model.LocalNetworkSnapshot
import net.mullvad.talpid.model.LocalPhysicalNetwork

/** One writer, one coalesced delivery worker. Native calls never run under [lock]. */
internal class LocalNetworkWatcher(
    private val source: LocalNetworkSource,
    private val scope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val publish: (Long, LocalNetworkSnapshot) -> Unit = LocalNetworkBridge::published,
) {
    private val lock = Any()
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val networks = linkedMapOf<Long, LocalPhysicalNetwork>()
    // Networks present at registration whose first capabilities have not arrived yet.
    private val initial = mutableSetOf<Long>()
    private var access = LocalIdentityAccess(false, false, false, false, false)
    private var running = false
    private var registration = 0L
    private var epoch = 0L
    private var sequence = 0L
    private var pending = false
    private var published: LocalNetworkSnapshot? = null
    private var worker: Job? = null

    fun registered(value: Long): Boolean = synchronized(lock) { value > 0 && registration == value }

    fun start(): Unit =
        synchronized(lock) {
            if (running) return
            running = true
            try {
                access = source.readAccess()
                subscribe()
                ensureWorker()
                changed()
            } catch (_: RuntimeException) {
                unavailable()
            }
        }

    fun stop() {
        val revoked =
            synchronized(lock) {
                if (!running) return
                running = false
                epoch++
                networks.clear()
                initial.clear()
                published = null
                pending = false
                Triple(epoch, registration, inactiveSnapshot())
            }
        // Registration survives observation suspension. Revoke published physical
        // authority before stopping the source; old callbacks retain the old epoch.
        if (revoked.second != 0L) publish(revoked.second, revoked.third)
        synchronized(lock) { if (epoch == revoked.first) stopSource() }
    }

    private fun ensureWorker() {
        if (worker != null) return
        worker =
            scope.launch(ioDispatcher) {
                for (ignored in changes) {
                    changes.tryReceive()
                    deliver()
                }
            }
    }

    fun attach(value: Long): Boolean =
        synchronized(lock) {
            if (value <= 0 || registration != 0L) return false
            registration = value
            ensureWorker()
            changed()
            true
        }

    fun detach(value: Long): Boolean =
        synchronized(lock) {
            if (value != registration || value == 0L) return false
            registration = 0
            true
        }

    private fun subscribe() {
        val current = ++epoch
        networks.clear()
        initial.clear()
        source.start(
            access.fine,
            { event ->
                synchronized(lock) {
                    if (running && current == epoch) {
                        event.applyTo(networks)
                        if (event is LocalNetworkEvent.Lost) initial.remove(event.handle)
                        initial.removeAll { networks[it]?.capabilitiesFresh == true }
                        changed()
                    }
                }
            },
            { synchronized(lock) { if (running && current == epoch) changed() } },
        )
        // Callbacks are already registered, so every listed network reports itself; callbacks
        // wait for this lock, so none can be missed between registration and this read.
        initial += source.currentNetworks()
    }

    private fun changed() {
        pending = true
        changes.trySend(Unit)
    }

    /** The decision and the framework protect/bind action share this one lock hold. */
    fun withCurrentNetwork(
        handle: Long,
        sequence: Long,
        needsWifiName: Boolean,
        action: (Network) -> Int,
    ): Int =
        synchronized(lock) {
            if (!running || registration == 0L) return LocalSocketPreparation.INACTIVE
            val record = published
            if (pending || sequence != this.sequence || record == null)
                return LocalSocketPreparation.STALE
            val network =
                record.networks.singleOrNull { it.networkHandle == handle && !it.blocked }
                    ?: return LocalSocketPreparation.STALE
            try {
                if (source.readAccess() != access) {
                    changed()
                    return LocalSocketPreparation.STALE
                }
                if (!access.local || (needsWifiName && network.ssidHex == null))
                    return LocalSocketPreparation.STALE
                val current = source.network(handle) ?: return LocalSocketPreparation.STALE
                action(current)
            } catch (_: RuntimeException) {
                changed()
                LocalSocketPreparation.STALE
            }
        }

    private fun unavailable() {
        running = false
        epoch++
        networks.clear()
        initial.clear()
        published = null
        stopSource()
        Logger.w("Local network watcher unavailable")
    }

    private fun stopSource() {
        try {
            source.stop()
        } catch (_: RuntimeException) {
            Logger.w("Local network source cleanup unavailable")
        }
    }

    private fun deliver() {
        val delivery =
            synchronized(lock) {
                // Null while the initial networks are still reporting: stay pending (STALE for
                // sockets) and publish once their callbacks complete the set.
                val snapshot = (if (running) observation() else inactiveSnapshot()) ?: return
                published = snapshot
                pending = false
                if (registration == 0L) null else registration to snapshot
            }
        delivery?.let { publish(it.first, it.second) }
    }

    private fun inactiveSnapshot() =
        LocalNetworkSnapshot(
            ++sequence,
            false,
            false,
            false,
            false,
            false,
            false,
            arrayListOf(),
        )

    private fun observation(): LocalNetworkSnapshot? =
        try {
            val fresh = source.readAccess()
            if (fresh != access) {
                access = fresh
                source.stop()
                subscribe()
            }
            access = fresh
            // A network that left before its callbacks can no longer complete the initial set.
            if (initial.isNotEmpty()) initial.retainAll(source.currentNetworks())
            // Until the networks present at registration have reported, an empty or partial set
            // would read as "not on Wi-Fi". Publish nothing (the daemon keeps Pending), and revoke
            // a record from an earlier subscription rather than leave its authority in place.
            if (initial.isNotEmpty()) {
                if (published?.observerRunning == true) inactiveSnapshot() else null
            } else {
                val observed = source.withLegacyIdentity(networks.values.toList(), access.identity)
                LocalNetworkSnapshot(
                    ++sequence,
                    running,
                    access.local,
                    access.fine,
                    access.background,
                    access.location,
                    access.operations,
                    ArrayList(
                        observed.map {
                            if (access.identity && it.transport == WIFI) it
                            else it.copy(ssidHex = null)
                        }
                    ),
                )
            }
        } catch (_: RuntimeException) {
            unavailable()
            LocalNetworkSnapshot(
                ++sequence,
                false,
                false,
                false,
                false,
                false,
                false,
                arrayListOf(),
            )
        }

    companion object {
        const val WIFI = 1
        const val ETHERNET = 2
    }
}

/** Serialize the two independent owners; neither can cancel the other's demand. */
internal class LocalNetworkDemand(private val apply: (Boolean) -> Unit) {
    private var policy = false
    private var editor = false
    private var wanted = false

    @Synchronized
    fun policy(value: Boolean) {
        policy = value
        reconcile()
    }

    @Synchronized
    fun editor(value: Boolean) {
        editor = value
        reconcile()
    }

    private fun reconcile() {
        val next = policy || editor
        if (next != wanted) {
            wanted = next
            apply(next)
        }
    }
}

internal interface LocalNetworkSource {
    fun readAccess(): LocalIdentityAccess

    fun network(handle: Long): Network?

    fun start(
        includeLocation: Boolean,
        onEvent: (LocalNetworkEvent) -> Unit,
        onAccessChanged: () -> Unit,
    )

    /** Handles of the physical networks the started callback reports, as present right now. */
    fun currentNetworks(): Set<Long>

    fun stop()

    fun withLegacyIdentity(
        networks: List<LocalPhysicalNetwork>,
        allowed: Boolean,
    ): List<LocalPhysicalNetwork>
}

/** Callback values are already owned records; only the watcher owns the mutable map. */
internal sealed interface LocalNetworkEvent {
    fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>)

    data class Available(val handle: Long, val blocked: Boolean) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks[handle] = LocalPhysicalNetwork(handle, blocked = blocked)
        }
    }

    data class Update(
        val handle: Long,
        val update: (LocalPhysicalNetwork) -> LocalPhysicalNetwork,
    ) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks[handle]?.let { networks[handle] = update(it) }
        }
    }

    data class Lost(val handle: Long) : LocalNetworkEvent {
        override fun applyTo(networks: MutableMap<Long, LocalPhysicalNetwork>) {
            networks.remove(handle)
        }
    }
}
