package net.mullvad.talpid

import android.net.Network
import java.lang.reflect.Modifier
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.mullvad.talpid.model.LocalNetworkSnapshot
import net.mullvad.talpid.model.LocalPhysicalNetwork
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Producer-only reproduction: no new JNI hook or product correction. */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalNetworkPublicationTest {
    @Test
    fun `should fence a full publication overtaken outside the event lock`() = runTest {
        val source = Source()
        val pushes = mutableListOf<LocalNetworkSnapshot>()
        val witnesses = mutableListOf<LocalNetworkSnapshot>()
        val overtaken = mutableListOf<LocalNetworkSnapshot>()
        var blockOnDelivery = false
        val publication =
            object : LocalNetworkPublication {
                override fun published(registration: Long, snapshot: LocalNetworkSnapshot) {
                    if (blockOnDelivery) {
                        blockOnDelivery = false
                        overtaken += snapshot
                        source.emit(LocalNetworkEvent.Update(9) { it.copy(blocked = true) })
                    }
                    pushes += snapshot
                }

                override fun revalidate(registration: Long, snapshot: LocalNetworkSnapshot) {
                    witnesses += snapshot
                }
            }
        val watcher =
            LocalNetworkWatcher(
                source,
                backgroundScope,
                StandardTestDispatcher(testScheduler),
                publication,
            )
        watcher.attach(7)
        watcher.start()
        source.emit(LocalNetworkEvent.Available(9, false))
        runCurrent()
        blockOnDelivery = true
        source.emit(LocalNetworkEvent.Update(9) { it.copy(linksFresh = true) })
        runCurrent()
        assertTrue(
            overtaken.single().authorityRevision < witnesses.last().authorityRevision,
            "late full sample retains its old fence rather than borrowing the successor's",
        )
        assertEquals(witnesses.last().authorityRevision, pushes.last().authorityRevision)
        assertTrue(pushes.last().networks.single().blocked)
        assertTrue(
            witnesses.zipWithNext().all { (old, next) ->
                old.authorityRevision < next.authorityRevision
            }
        )
        watcher.stop()
    }

    @Test
    fun `should preserve the one way native witness ABI and snapshot fence getter`() {
        val method =
            LocalNetworkBridge::class
                .java
                .getDeclaredMethod(
                    "revalidate",
                    Long::class.javaPrimitiveType,
                    LocalNetworkSnapshot::class.java,
                )
        assertTrue(Modifier.isNative(method.modifiers))
        assertTrue(Modifier.isStatic(method.modifiers))
        assertEquals(Void.TYPE, method.returnType)
        assertEquals(
            Long::class.javaPrimitiveType,
            LocalNetworkSnapshot::class.java.getDeclaredMethod("getAuthorityRevision").returnType,
        )
    }

    @Test
    fun `should retain a published network loss when return is coalesced`() = runTest {
        val source = Source()
        val pushes = mutableListOf<LocalNetworkSnapshot>()
        val witnesses = mutableListOf<LocalNetworkSnapshot>()
        val watcher =
            LocalNetworkWatcher(
                source,
                backgroundScope,
                StandardTestDispatcher(testScheduler),
                recording(pushes, witnesses),
            )
        watcher.attach(7)
        watcher.start()
        source.emit(LocalNetworkEvent.Available(9, false))
        source.emit(
            LocalNetworkEvent.Update(9) {
                it.copy(
                    transport = LocalNetworkWatcher.WIFI,
                    capabilitiesFresh = true,
                    linksFresh = true,
                )
            }
        )
        runCurrent()
        assertEquals(9L, pushes.last().networks.single().networkHandle)
        val before = witnesses.size
        source.emit(LocalNetworkEvent.Lost(9))
        source.emit(LocalNetworkEvent.Available(9, false))
        source.emit(
            LocalNetworkEvent.Update(9) {
                it.copy(
                    transport = LocalNetworkWatcher.WIFI,
                    capabilitiesFresh = true,
                    linksFresh = true,
                )
            }
        )
        val lostPublished =
            witnesses.drop(before).any {
                !it.observerRunning || it.networks.none { network -> network.networkHandle == 9L }
            }
        runCurrent()
        assertEquals(
            9L,
            pushes.last().networks.single().networkHandle,
            "control: physical return was published",
        )
        watcher.stop()
        assertTrue(
            lostPublished,
            "No loss crossed the existing publication interface before the same-looking return",
        )
    }

    @Test
    fun `should retain a published block when unblock is coalesced`() = runTest {
        val source = Source()
        val pushes = mutableListOf<LocalNetworkSnapshot>()
        val witnesses = mutableListOf<LocalNetworkSnapshot>()
        val watcher =
            LocalNetworkWatcher(
                source,
                backgroundScope,
                StandardTestDispatcher(testScheduler),
                recording(pushes, witnesses),
            )
        watcher.attach(7)
        watcher.start()
        source.emit(LocalNetworkEvent.Available(9, false))
        source.emit(
            LocalNetworkEvent.Update(9) {
                it.copy(
                    transport = LocalNetworkWatcher.WIFI,
                    capabilitiesFresh = true,
                    linksFresh = true,
                )
            }
        )
        runCurrent()
        assertEquals(false, pushes.last().networks.single().blocked)
        val before = witnesses.size
        source.emit(LocalNetworkEvent.Update(9) { it.copy(blocked = true) })
        source.emit(LocalNetworkEvent.Update(9) { it.copy(blocked = false) })
        val blockedPublished =
            witnesses.drop(before).any {
                !it.observerRunning ||
                    it.networks.any { network -> network.networkHandle == 9L && network.blocked }
            }
        runCurrent()
        assertEquals(
            false,
            pushes.last().networks.single().blocked,
            "control: unblock was published",
        )
        watcher.stop()
        assertTrue(
            blockedPublished,
            "No blocking state crossed the existing publication interface before unblock",
        )
    }

    private fun recording(
        pushes: MutableList<LocalNetworkSnapshot>,
        witnesses: MutableList<LocalNetworkSnapshot>,
    ) =
        object : LocalNetworkPublication {
            override fun published(registration: Long, snapshot: LocalNetworkSnapshot) {
                pushes += snapshot
            }

            override fun revalidate(registration: Long, snapshot: LocalNetworkSnapshot) {
                witnesses += snapshot
            }
        }

    private class Source : LocalNetworkSource {
        private var callback: (LocalNetworkEvent) -> Unit = {}

        override fun readAccess() = LocalIdentityAccess(true, true, true, true, true)

        override fun network(handle: Long): Network? = null

        override fun start(
            includeLocation: Boolean,
            onEvent: (LocalNetworkEvent) -> Unit,
            onAccessChanged: () -> Unit,
        ) {
            callback = onEvent
        }

        override fun currentNetworks() = emptySet<Long>()

        override fun stop() = Unit

        override fun withLegacyIdentity(networks: List<LocalPhysicalNetwork>, allowed: Boolean) =
            networks

        fun emit(event: LocalNetworkEvent) = callback(event)
    }
}
