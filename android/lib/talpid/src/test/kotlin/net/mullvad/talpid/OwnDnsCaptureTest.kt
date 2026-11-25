package net.mullvad.talpid

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OwnDnsCaptureTest {
    @Test
    fun `should require an exact idle incarnation for stock DNS`() {
        val owner = LocalFrontendOwnership()
        val idle = owner.ownDnsCaptureEpoch
        assertTrue(idle > 0)
        assertTrue(owner.tryFrontend(1))
        assertTrue(owner.ownDnsCaptureEpoch < 0)
        owner.frontendFinished(1)
        assertTrue(owner.ownDnsCaptureEpoch > 0)
        assertNotEquals(idle, owner.ownDnsCaptureEpoch)
    }

    @Test
    fun `should prevent stock DNS for outstanding handover obligations`() {
        val owner = LocalFrontendOwnership()
        assertTrue(owner.tryFrontend(1))
        val first = owner.ownDnsCaptureEpoch
        assertTrue(owner.tryHandover(1, 2))
        val handover = owner.ownDnsCaptureEpoch
        assertTrue(handover < 0)
        assertNotEquals(first, handover)
        owner.establishing(2)
        owner.establishmentFailed(2)
        owner.frontendFinished(2)
        assertTrue(owner.ownDnsCaptureEpoch < 0)
        owner.frontendFinished(1)
        assertTrue(owner.ownDnsCaptureEpoch > 0)
    }

    @Test
    fun `should prove interface absence on revoke without releasing descriptor obligations`() {
        val owner = LocalFrontendOwnership()
        assertTrue(owner.tryFrontend(1))
        owner.revoke()
        val revoked = owner.ownDnsCaptureEpoch
        assertTrue(revoked > 0)
        assertTrue(owner.owns(1))
        owner.frontendFinished(1)
        assertEquals(revoked, owner.ownDnsCaptureEpoch)
        assertTrue(owner.tryUpstream())
        assertTrue(owner.ownDnsCaptureEpoch < 0)
        owner.upstreamClosed()
        assertNotEquals(revoked, owner.ownDnsCaptureEpoch)
    }
}
