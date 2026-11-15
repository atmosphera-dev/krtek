package net.mullvad.mullvadvpn.lib.grpc

import co.touchlab.kermit.LogWriter
import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import co.touchlab.kermit.StaticConfig
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import mullvad_daemon.management_interface.AccessMethodSetting
import mullvad_daemon.management_interface.AppVersionInfo
import mullvad_daemon.management_interface.DaemonEvent
import mullvad_daemon.management_interface.DeviceEvent
import mullvad_daemon.management_interface.DeviceState
import mullvad_daemon.management_interface.LeakInfo
import mullvad_daemon.management_interface.LocalBypassRule
import mullvad_daemon.management_interface.LocalNetworkAccess
import mullvad_daemon.management_interface.RelayList
import mullvad_daemon.management_interface.RelayListCountry
import mullvad_daemon.management_interface.RemoveDeviceEvent
import mullvad_daemon.management_interface.Settings
import mullvad_daemon.management_interface.TunnelState
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import org.junit.jupiter.api.Test

class SafeEventLogSummaryTest {
    @Test
    fun `should remove Local values and unknown fields before formatting`() {
        val ssid = "wifi-Ł船-marker"
        val name = "private-rule-marker"
        val cidr = "192.168.240.0/28"
        val bytes = ssid.encodeUtf8()
        // unknownFields contains encoded fields, not arbitrary payload bytes:
        // field 99, length-delimited, with this short synthetic SSID as payload.
        val unknownFields =
            Buffer()
                .writeByte(0x9a)
                .writeByte(0x06)
                .writeByte(bytes.size)
                .write(bytes)
                .readByteString()
        val event =
            DaemonEvent(
                event =
                    DaemonEvent.Event.Settings(
                        Settings(
                            local_network_access =
                                LocalNetworkAccess(
                                    enabled = true,
                                    rules =
                                        listOf(
                                            LocalBypassRule(
                                                id = "00000000-0000-0000-0000-000000000001",
                                                name = name,
                                                enabled = true,
                                                cidrs = listOf(cidr),
                                                ssid_ids = listOf(bytes),
                                            )
                                        ),
                                )
                        )
                    )
            )
        val decoded = DaemonEvent.ADAPTER.decode(DaemonEvent.ADAPTER.encode(event))
        assertTrue(decoded.toString().contains(name))
        val messages = mutableListOf<String>()
        val writer =
            object : LogWriter() {
                override fun log(
                    severity: Severity,
                    message: String,
                    tag: String,
                    throwable: Throwable?,
                ) {
                    assertEquals(Severity.Verbose, severity)
                    assertEquals(null, throwable)
                    messages.add(message)
                }
            }
        val logger =
            Logger(StaticConfig(minSeverity = Severity.Verbose, logWriterList = listOf(writer)))
        decoded.logSafeEventSummary(logger)
        DaemonEvent(unknownFields = unknownFields).logSafeEventSummary(logger)
        val status =
            mullvad_daemon.management_interface.LocalNetworkStatus(
                current_wifi =
                    mullvad_daemon.management_interface.ConnectedWifi(
                        identity =
                            mullvad_daemon.management_interface.ConnectedWifi.Identity.Ssid(bytes)
                    ),
                unknownFields = unknownFields,
            )
        val statusEvent = DaemonEvent(event = DaemonEvent.Event.LocalNetworkStatus(status))
        DaemonEvent.ADAPTER.decode(DaemonEvent.ADAPTER.encode(statusEvent))
            .logSafeEventSummary(logger)
        assertEquals(
            "Event: ${DaemonEvent(event = DaemonEvent.Event.Settings(Settings()))}",
            messages[0],
        )
        assertEquals("Event: ${DaemonEvent()}", messages[1])
        assertEquals("Event: Event(type=local-network-status)", messages[2])
        val output = messages.joinToString("\n")
        for (secret in
            listOf(
                ssid,
                name,
                cidr,
                bytes.hex(),
                Base64.getEncoder().encodeToString(bytes.toByteArray()),
            )) {
            assertFalse(output.contains(secret))
        }
    }

    @Test
    fun `should retain upstream event detail except Local sensitive fields`() {
        val secret = "Local-secret-Ł船-marker"
        val bytes = secret.encodeUtf8()
        val unknown =
            Buffer()
                .writeByte(0x9a)
                .writeByte(0x06)
                .writeByte(bytes.size)
                .write(bytes)
                .readByteString()
        val nonLocal =
            listOf(
                DaemonEvent.Event.TunnelState(
                    TunnelState(
                        state =
                            TunnelState.State.Disconnected(
                                TunnelState.Disconnected(locked_down = true)
                            )
                    )
                ),
                DaemonEvent.Event.Device(
                    DeviceEvent(
                        cause = DeviceEvent.Cause.ROTATED_KEY,
                        new_state = DeviceState(state = DeviceState.State.REVOKED),
                    )
                ),
                DaemonEvent.Event.NewAccessMethod(
                    AccessMethodSetting(name = "ordinary-method-detail", enabled = true)
                ),
                DaemonEvent.Event.RelayList(
                    RelayList(
                        countries =
                            listOf(RelayListCountry(name = "ordinary-country-detail", code = "xy"))
                    )
                ),
                DaemonEvent.Event.VersionInfo(AppVersionInfo(supported = true)),
                DaemonEvent.Event.RemoveDevice(
                    RemoveDeviceEvent(account_number = "ordinary-private-diagnostic-detail")
                ),
                DaemonEvent.Event.LeakInfo(LeakInfo(ip_addrs = listOf("203.0.113.4"))),
            )
        for (event in nonLocal) {
            val original = DaemonEvent(event = event)
            // Existing payload diagnostics are byte-for-byte upstream formatting.
            assertEquals(original.toString(), original.safeEventLogSummary())
            val unknownEnvelope = original.copy(unknownFields = unknown)
            assertEquals(original.toString(), unknownEnvelope.safeEventLogSummary())
            assertEquals(unknown, unknownEnvelope.unknownFields)
        }
        val policy =
            LocalNetworkAccess(
                enabled = true,
                rules =
                    listOf(
                        LocalBypassRule(
                            id = secret,
                            name = secret,
                            enabled = true,
                            cidrs = listOf("192.168.240.0/28"),
                            ssid_ids = listOf(bytes),
                            unknownFields = unknown,
                        )
                    ),
                unknownFields = unknown,
            )
        val settings =
            Settings(
                allow_lan = true,
                auto_connect = true,
                local_network_access = policy,
                unknownFields = unknown,
            )
        val event =
            DaemonEvent(event = DaemonEvent.Event.Settings(settings), unknownFields = unknown)
        val wire = DaemonEvent.ADAPTER.encode(event)
        val decoded = DaemonEvent.ADAPTER.decode(wire)
        val expected =
            DaemonEvent(
                event =
                    DaemonEvent.Event.Settings(
                        settings.copy(local_network_access = null, unknownFields = ByteString.EMPTY)
                    )
            )
        assertEquals(expected.toString(), decoded.safeEventLogSummary())
        assertTrue(decoded.safeEventLogSummary().contains("allow_lan=true"))
        assertTrue(decoded.safeEventLogSummary().contains("auto_connect=true"))
        assertTrue(
            wire.contentEquals(DaemonEvent.ADAPTER.encode(decoded)),
            "logging does not mutate subscribers",
        )
        val outputs =
            listOf(
                decoded.safeEventLogSummary(),
                DaemonEvent(unknownFields = unknown).safeEventLogSummary(),
                DaemonEvent(
                        event =
                            DaemonEvent.Event.LocalNetworkStatus(
                                mullvad_daemon.management_interface.LocalNetworkStatus(
                                    unknownFields = unknown
                                )
                            )
                    )
                    .safeEventLogSummary(),
            )
        for (output in outputs) {
            for (value in
                listOf(secret, bytes.hex(), bytes.base64(), "192.168.240.0/28")) assertFalse(
                output.contains(value)
            )
        }
    }
}
