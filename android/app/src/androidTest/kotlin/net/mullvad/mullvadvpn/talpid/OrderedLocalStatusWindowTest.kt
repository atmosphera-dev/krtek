package net.mullvad.mullvadvpn.talpid

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class OrderedLocalStatusWindowTest {
    @Test
    fun stableRuleNeedsNoArtificialEvent() {
        assertTrue(OrderedLocalStatusWindow.Window().processedThrough(7u, 7u))
    }

    @Test
    fun finishWaitsForAlreadyPublishedEvents() {
        val window = OrderedLocalStatusWindow.Window()
        assertFalse(window.processedThrough(7u, 9u))
        window.append(8u, true)
        assertFalse(window.processedThrough(7u, 9u))
        window.append(9u, true)
        assertTrue(window.processedThrough(7u, 9u))
    }

    @Test
    fun transientEligibilityCannotConflateAway() {
        val window = OrderedLocalStatusWindow.Window()
        window.append(8u, false)
        window.append(9u, true)
        val error = assertThrows<IllegalStateException> { window.processedThrough(7u, 9u) }
        assertEquals("Local rule eligibility changed during UDP probe", error.message)
    }

    @Test
    fun missingEventFailsRatherThanLookingStable() {
        val window = OrderedLocalStatusWindow.Window()
        window.append(9u, true)
        val error = assertThrows<IllegalStateException> { window.processedThrough(7u, 9u) }
        assertEquals("Gap or reordered Local status evidence", error.message)
    }

    @Test
    fun daemonRevisionResetFails() {
        val error =
            assertThrows<IllegalStateException> {
                OrderedLocalStatusWindow.Window().processedThrough(7u, 6u)
            }
        assertEquals("Daemon status revision reset during probe", error.message)
    }
}
