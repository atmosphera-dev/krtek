package net.mullvad.mullvadvpn.test.publicdns

import java.io.IOException
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir

class PrivateDnsBytesTest {
    @TempDir lateinit var directory: Path

    @Test
    fun `should keep temporary files under the configured JVM scratch root`() {
        val root = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath()
        assertTrue(directory.toAbsolutePath().startsWith(root))
        System.getenv("TMPDIR")?.let { assertEquals(Path.of(it).toAbsolutePath(), root) }
    }

    @Test
    fun `should save complete rejected response bytes with exact metadata`() {
        val bytes = ByteArray(65535) { (it % 251).toByte() }
        val saved = PrivateDnsBytes(directory.toFile()).save("response-000.bin", bytes)
        assertContentEquals(bytes, Path.of(saved.path).toFile().readBytes())
        assertEquals(bytes.size, saved.size)
        assertEquals(PrivateDnsBytes.digest(bytes), saved.sha256)
        assertEquals(64, saved.sha256.length)
        assertTrue(saved.path.startsWith(directory.toString()))
    }

    @Test
    fun `should refuse overwriting evidence and preserve original bytes`() {
        val owner = PrivateDnsBytes(directory.toFile())
        val original = byteArrayOf(0, 1, 2)
        val saved = owner.save("query.bin", original)
        assertThrows<IOException> { owner.save("query.bin", byteArrayOf(3)) }
        assertContentEquals(original, Path.of(saved.path).toFile().readBytes())
    }

    @Test
    fun `should isolate attempt directories`() {
        val first = PrivateDnsBytes(directory.toFile())
        val second = PrivateDnsBytes(directory.toFile())
        assertNotEquals(first.directory, second.directory)
        assertEquals(first.directory.parentFile, second.directory.parentFile)
    }

    @Test
    fun `should reject paths outside the private attempt`() {
        val owner = PrivateDnsBytes(directory.toFile())
        listOf("../query.bin", "/query.bin", "query/part.bin", "query.txt").forEach { name ->
            assertThrows<IllegalArgumentException> { owner.save(name, byteArrayOf(1)) }
        }
        assertEquals(0, owner.directory.listFiles()!!.size)
    }
}
