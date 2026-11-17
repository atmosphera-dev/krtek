package net.mullvad.mullvadvpn.talpid

import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class ClipboardRestoreContractTest {
    @Test
    fun contentUriAuthorityMustNotBeDestroyedByAClipboardTest() {
        assertTrue(ClipboardRestoreContract.restorable(emptyList()))
        assertTrue(ClipboardRestoreContract.restorable(listOf(null to null, "https" to "file")))
        for (scheme in listOf("content", "CONTENT")) {
            assertFalse(ClipboardRestoreContract.restorable(listOf(scheme to null)))
            assertFalse(ClipboardRestoreContract.restorable(listOf(null to scheme)))
            assertFalse(ClipboardRestoreContract.restorable(listOf(null to null, scheme to null)))
        }
    }
}
