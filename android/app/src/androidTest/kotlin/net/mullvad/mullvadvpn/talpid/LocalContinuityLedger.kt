package net.mullvad.mullvadvpn.talpid

import java.io.IOException

/** Test-only ledger classification: intentional retirement is not a continuity-gap waiver. */
internal object LocalContinuityLedger {
    data class UdpSendFailure(
        val expectedScheduled: Long,
        val scheduled: Long,
        val start: Long,
        val send: Long,
        val returned: Long,
        val errorClass: String,
        val ioException: String,
    ) {
        init {
            check(scheduled == expectedScheduled)
            val deadline = scheduled + 5_000_000_000L
            check(start in scheduled..send && start - scheduled < 250_000_000L)
            check(send <= deadline && returned in send..deadline)
            // The neutral consumer catches IOException, not arbitrary harness failures.
            val type = Class.forName(errorClass, false, IOException::class.java.classLoader)
            check(IOException::class.java.isAssignableFrom(type))
            check(ioException == errorClass || ioException.startsWith("$errorClass: "))
        }
    }

    fun retirementOutcome(
        transport: String,
        outcome: String,
        scheduled: Long,
        revokedAt: Long?,
        sendFailure: UdpSendFailure? = null,
    ): Boolean {
        if (outcome == "udp-send-error") {
            check(transport == "udp")
            checkNotNull(sendFailure)
            check(sendFailure.scheduled == scheduled)
            return revokedAt != null && sendFailure.returned >= revokedAt
        }
        if (revokedAt == null || scheduled + 5_000_000_000L < revokedAt || outcome == "reply")
            return false
        // Preserve the existing in-flight cancellation/missing-reply retirement handling.
        check(outcome in setOf("error", "cancelled", "udp-reply-missing"))
        return true
    }

    /**
     * Run-05 item-4-answer-r02: an app-list change rebuilds the interface and Android closes
     * connections open at that moment. Only the session's pre-existing UDP socket, sending at or
     * after the measured change, may fail that way. Earlier sends, other sockets and sessions
     * without a measured app-list change still fail.
     */
    fun appListSocketDrop(
        transport: String,
        failure: UdpSendFailure,
        appListChangeAt: Long?,
        socketId: Int,
        preExistingSocketId: Int,
    ): Boolean {
        check(transport == "udp")
        return appListChangeAt != null &&
            socketId == preExistingSocketId &&
            failure.send >= appListChangeAt
    }

    /** Any other tolerated UDP failure needs its recovery reply; the last sample has none. */
    fun recoveryIndex(index: Int, sampleCount: Int): Int {
        check(index in 0 until sampleCount)
        if (index + 1 >= sampleCount)
            throw AssertionError(
                "UDP failure at tick $index is the session's last sample: no recovery reply"
            )
        return index + 1
    }
}
