package net.mullvad.talpid

import android.content.ContentResolver
import android.net.Uri
import android.os.Handler
import android.provider.Settings
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class VpnLockdownObserverTest {
    private val resolver = mockk<ContentResolver>(relaxed = true)
    private val values = mutableListOf<Boolean>()

    @AfterEach fun cleanup() = unmockkAll()

    private fun observer(read: () -> Boolean): VpnLockdownObserver {
        mockkStatic(Settings.Secure::class)
        every { Settings.Secure.getUriFor(any()) } answers { mockk<Uri>() }
        return VpnLockdownObserver(resolver, mockk<Handler>(), read, values::add)
    }

    @Test
    fun `should register before initial read and publish every live change`() {
        var enabled = false
        val observer = observer {
            verify(exactly = 2) { resolver.registerContentObserver(any(), false, any()) }
            enabled
        }
        observer.start()
        enabled = true
        observer.onChange(false)
        enabled = false
        observer.onChange(false)
        assertEquals(listOf(false, true, false), values)
        observer.close()
        observer.onChange(false)
        assertEquals(listOf(false, true, false), values)
        verify(exactly = 1) { resolver.unregisterContentObserver(observer) }
    }

    @Test
    fun `should retain blocking coverage on unavailable OS state`() {
        val observer = observer { error("OS read unavailable") }
        observer.start()
        assertEquals(listOf(true), values)
        observer.close()
    }

    @Test
    fun `should retain blocking coverage on registration failure until registration succeeds`() {
        every { resolver.registerContentObserver(any(), false, any()) } throws
            IllegalStateException("registration unavailable")
        val observer = observer { false }
        observer.start()
        assertEquals(listOf(true), values)
        observer.onChange(false)
        assertEquals(listOf(true, true), values)
        every { resolver.registerContentObserver(any(), false, any()) } returns Unit
        observer.start()
        assertEquals(listOf(true, true, false), values)
        observer.close()
        observer.onChange(false)
        assertEquals(listOf(true, true, false), values)
    }
}
