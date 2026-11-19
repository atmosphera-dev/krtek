package net.mullvad.mullvadvpn.talpid

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OrderedLocalStatusWindowTest {
    @Test
    fun stableRuleNeedsNoArtificialEvent() {
        assertTrue(OrderedLocalStatusWindow().processedThrough(7u, 7u))
    }

    @Test
    fun finishWaitsForAlreadyPublishedEvents() {
        val window = OrderedLocalStatusWindow()
        assertFalse(window.processedThrough(7u, 9u))
        window.append(8u, true)
        assertFalse(window.processedThrough(7u, 9u))
        window.append(9u, true)
        assertTrue(window.processedThrough(7u, 9u))
    }

    @Test(expected = IllegalStateException::class)
    fun transientEligibilityCannotConflateAway() {
        val window = OrderedLocalStatusWindow()
        window.append(8u, false)
        window.append(9u, true)
        window.processedThrough(7u, 9u)
    }

    @Test(expected = IllegalStateException::class)
    fun missingEventFailsRatherThanLookingStable() {
        val window = OrderedLocalStatusWindow()
        window.append(9u, true)
        window.processedThrough(7u, 9u)
    }

    @Test(expected = IllegalStateException::class)
    fun daemonRevisionResetFails() {
        OrderedLocalStatusWindow().processedThrough(7u, 6u)
    }
}
