package net.mullvad.mullvadvpn.lib.grpc

import co.touchlab.kermit.Logger
import mullvad_daemon.management_interface.DaemonEvent
import okio.ByteString

internal fun DaemonEvent.logSafeEventSummary(logger: Logger = Logger) {
    logger.v("Event: ${safeEventLogSummary()}")
}

/** Project Local fields out before formatting; the live subscriber value is never changed. */
internal fun DaemonEvent.safeEventLogSummary(): String =
    when (val event = event) {
        is DaemonEvent.Event.Settings ->
            copy(
                    event =
                        DaemonEvent.Event.Settings(
                            event.value.copy(
                                local_network_access = null,
                                unknownFields = ByteString.EMPTY,
                            )
                        ),
                    unknownFields = ByteString.EMPTY,
                )
                .toString()
        is DaemonEvent.Event.LocalNetworkStatus -> "Event(type=local-network-status)"
        // Unknown envelope fields may contain a newer Local payload. Never format those bytes.
        else -> copy(unknownFields = ByteString.EMPTY).toString()
    }
