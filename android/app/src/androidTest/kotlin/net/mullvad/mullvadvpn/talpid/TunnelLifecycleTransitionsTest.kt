package net.mullvad.mullvadvpn.talpid

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class TunnelLifecycleTransitionsTest {
    private data class Event(val state: String, val details: String = "")

    private fun transitions(events: List<Event>, start: Int) =
        TunnelLifecycleTransitions.since(events, start) { it.state }

    @Test
    fun connectedFeatureUpdateDoesNotCompleteTheSavedMtuReconnect() {
        val events =
            listOf(
                Event("Connected"),
                Event("Connected", "CUSTOM_MTU"),
                Event("Disconnecting", "RECONNECT"),
            )
        assertEquals(listOf("Connected", "Disconnecting"), events.drop(1).map { it.state })
        assertEquals(listOf("Disconnecting"), transitions(events, 1).map { it.state })
        assertFalse(transitions(events, 1).any { it.state == "Connected" })
        val finished = events + Event("Connecting") + Event("Connected", "CUSTOM_MTU")
        assertEquals(
            listOf("Disconnecting", "Connecting", "Connected"),
            transitions(finished, 1).map { it.state },
        )
    }

    @Test
    fun metadataAloneCannotSatisfyAReconnect() {
        val events = listOf(Event("Connected"), Event("Connected", "CUSTOM_MTU"))
        assertTrue(transitions(events, 1).isEmpty())
        assertEquals(2, events.size, "Raw evidence is retained")
    }

    @Test
    fun repeatedConnectingMetadataKeepsTheFirstLifecycleTransition() {
        val events =
            listOf(
                Event("Connected"),
                Event("Disconnecting"),
                Event("Connecting"),
                Event("Connecting", "new location"),
                Event("Connected"),
                Event("Connected", "exit IP"),
            )
        assertEquals(
            listOf("Disconnecting", "Connecting", "Connected"),
            transitions(events, 1).map { it.state },
        )
        assertEquals(6, events.size)
    }

    @Test
    fun errorAndDisconnectedCannotBeHiddenByMetadataUpdates() {
        for (unexpected in listOf("Error", "Disconnected")) {
            val events =
                listOf(
                    Event("Connected"),
                    Event("Connected", "metadata"),
                    Event("Disconnecting"),
                    Event(unexpected),
                    Event("Connecting"),
                    Event("Connected"),
                )
            assertTrue(transitions(events, 1).any { it.state == unexpected })
        }
    }

    @Test
    fun connectingBeforeTheCommandCursorIsNotFreshConnecting() {
        val events = listOf(Event("Connected"), Event("Connecting"), Event("Connected"))
        assertEquals(listOf("Connected"), transitions(events, 2).map { it.state })
        assertFalse(transitions(events, 2).any { it.state == "Connecting" })
    }

    @Test
    fun cursorAtStartOrEndPreservesItsBoundary() {
        val events = listOf(Event("Connecting"), Event("Connected"))
        assertEquals(events, transitions(events, 0))
        assertTrue(transitions(events, events.size).isEmpty())
        assertTrue(transitions(emptyList(), 0).isEmpty())
    }

    @Test
    fun invalidCursorIsRejected() {
        assertFailsWith<IllegalArgumentException> { transitions(emptyList(), -1) }
        assertFailsWith<IllegalArgumentException> { transitions(emptyList(), 1) }
    }
}
