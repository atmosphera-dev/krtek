package net.mullvad.talpid

import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class LocalFrontendLockdownTest {
    @Test
    fun `should accept default capture routes only with DNS demand`() {
        val routes = arrayOf("0.0.0.0/0", "::/0")
        val dns = listOf(InetAddress.getByName("10.77.10.54"))
        assertNotNull(LocalFrontendConfig.parse(routes, dns))
        assertEquals(dns, LocalFrontendConfig.parse(routes, dns)?.dnsServers)
        assertNull(LocalFrontendConfig.parse(routes))
    }

    @Test
    fun `should retain strict Local prefixes and reject other public coverage`() {
        val dns = listOf(InetAddress.getByName("10.77.10.54"))
        assertNotNull(LocalFrontendConfig.parse(arrayOf("10.77.10.53/32"), dns))
        assertNull(LocalFrontendConfig.parse(arrayOf("8.8.8.8/32"), dns))
        assertNull(LocalFrontendConfig.parse(arrayOf("2000::/3"), dns))
        assertNull(LocalFrontendConfig.parse(arrayOf("10.77.10.53/24"), dns))
    }
}
