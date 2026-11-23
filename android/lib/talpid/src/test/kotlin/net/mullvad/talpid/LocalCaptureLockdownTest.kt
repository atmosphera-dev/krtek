package net.mullvad.talpid

import android.content.ContentResolver
import android.net.Uri
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.Settings
import arrow.core.right
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import java.net.InetAddress
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.Prepared
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class LocalCaptureLockdownTest {
    private lateinit var service: TalpidVpnService
    private lateinit var observer: VpnLockdownObserver
    private var established = false
    private var lockdown = true
    private val published = mutableListOf<Boolean>()

    @BeforeEach
    fun setup() {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk()
        mockkStatic(Settings.Secure::class)
        every { Settings.Secure.getUriFor(any()) } returns mockk<Uri>()
        mockkStatic("net.mullvad.mullvadvpn.lib.common.util.VpnServiceUtilsKt")
        service = spyk(TalpidVpnService())
        service.connectivityListener = mockk(relaxed = true)
        every { service.prepareVpnSafe() } returns Prepared.right()
        mockkConstructor(VpnService.Builder::class)
        val builder = mockk<VpnService.Builder>(relaxed = true)
        every { anyConstructed<VpnService.Builder>().setMtu(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setBlocking(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().setMetered(any()) } returns builder
        every { anyConstructed<VpnService.Builder>().addAddress(any<String>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addRoute(any<InetAddress>(), any()) } returns
            builder
        every { anyConstructed<VpnService.Builder>().addDnsServer(any<InetAddress>()) } returns
            builder
        val descriptor = mockk<ParcelFileDescriptor>(relaxed = true)
        every { descriptor.fd } returns 7
        every { anyConstructed<VpnService.Builder>().establish() } answers
            {
                established = true
                descriptor
            }
        // Android's caller-scoped getter returns false without an established VPN,
        // even when the OS lockdown setting is already ON.
        observer =
            VpnLockdownObserver(
                mockk<ContentResolver>(relaxed = true),
                mockk<Handler>(),
                { established && lockdown },
                published::add,
            )
        TalpidVpnService::class.java.getDeclaredField("lockdownObserver").apply {
            isAccessible = true
            set(service, observer)
        }
        observer.start()
        assertEquals(listOf(false), published)
    }

    @AfterEach fun cleanup() = unmockkAll()

    private fun open(generation: Long) =
        service.openLocalFrontend(
            generation,
            arrayOf("10.77.10.1/32"),
            dnsServers = arrayListOf(InetAddress.getByName("10.77.10.54")),
        )

    @Test
    fun `should publish lockdown after first Partial establish without a settings event`() {
        assertTrue(open(1).isOpen)
        assertEquals(listOf(false, true), published)
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should observe lockdown switched on while Partial is running`() {
        lockdown = false
        assertTrue(open(1).isOpen)
        assertEquals(listOf(false, false), published)
        lockdown = true
        observer.onChange(false)
        assertEquals(listOf(false, false, true), published)
        lockdown = false
        observer.onChange(false)
        assertEquals(listOf(false, false, true, false), published)
        service.finishLocalFrontend(1)
    }

    @Test
    fun `should resample on successful handover but not failed establish`() {
        assertTrue(open(1).isOpen)
        lockdown = false
        assertTrue(service.handoverLocalFrontend(1, 2, arrayOf("10.77.10.1/32")).result.isOpen)
        assertEquals(listOf(false, true, false), published)
        service.finishLocalFrontend(1)
        every { anyConstructed<VpnService.Builder>().establish() } returns null
        service.handoverLocalFrontend(2, 3, arrayOf("10.77.10.1/32"))
        assertEquals(listOf(false, true, false), published)
        service.finishLocalFrontend(2)
        service.finishLocalFrontend(3)
    }
}
