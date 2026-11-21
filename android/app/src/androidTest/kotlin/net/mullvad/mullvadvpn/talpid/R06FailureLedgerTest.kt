package net.mullvad.mullvadvpn.talpid

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class R06FailureLedgerTest {
    @Test
    fun bodyFailureSurvivesSuccessfulRestoration() {
        val original = AssertionError("body")
        val phases = mutableListOf<String>()
        val ledger = R06FailureLedger.Ledger { phase, _ -> phases += phase }
        var restored = false
        val actual =
            assertThrows(AssertionError::class.java) {
                ledger.run({ throw original }, { restored = true })
            }
        assertSame(original, actual)
        assertTrue(restored)
        assertEquals(listOf("body"), phases)
    }

    @Test
    fun restorationOnlyFailureIsNotReportedAsBodyFailure() {
        val original = IllegalStateException("restoration")
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        val actual =
            assertThrows(IllegalStateException::class.java) {
                ledger.run({}, { throw original })
            }
        assertSame(original, actual)
        assertEquals(listOf("settings-restoration"), ledger.failures.map { it.phase })
    }

    @Test
    fun bodyAndFinallyErrorsAreBothRetainedWithBodyPrimary() {
        val body = AssertionError("body")
        val restoration = IllegalStateException("restoration")
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        val actual =
            assertThrows(AssertionError::class.java) {
                ledger.run({ throw body }, { throw restoration })
            }
        assertSame(body, actual)
        assertEquals(listOf(restoration), actual.suppressed.toList())
        assertEquals(listOf("body", "settings-restoration"), ledger.failures.map { it.phase })
    }

    @Test
    fun outerFinallyCannotEraseAnAlreadyRecordedBodyError() {
        val body = AssertionError("body")
        val outer = IllegalStateException("outer restoration")
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        ledger.record("body", body)
        ledger.record("outer-restoration", outer)
        val actual = assertThrows(AssertionError::class.java) { ledger.throwIfFailed() }
        assertSame(body, actual)
        assertSame(outer, actual.suppressed.single())
    }

    @Test
    fun persistenceFailureIsVisibleWithoutMaskingOriginalFailure() {
        val body = AssertionError("body")
        val disk = IllegalStateException("evidence write")
        val ledger = R06FailureLedger.Ledger { _, _ -> throw disk }
        val actual = assertThrows(AssertionError::class.java) { ledger.run({ throw body }, {}) }
        assertSame(body, actual)
        assertSame(disk, actual.suppressed.single())
        assertEquals(listOf("body", "evidence-write"), ledger.failures.map { it.phase })
    }

    @Test
    fun propagatedOriginalIsNotDuplicatedOrSelfSuppressed() {
        val body = AssertionError("body")
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        ledger.record("body", body)
        ledger.record("outer", body)
        val actual = assertThrows(AssertionError::class.java) { ledger.throwIfFailed() }
        assertSame(body, actual)
        assertTrue(actual.suppressed.isEmpty())
        assertEquals(1, ledger.failures.size)
    }

    @Test
    fun independentRestorationContinuesAfterFailureWithoutRunningFinalProof() {
        val original = AssertionError("include app")
        val attempted = mutableListOf<String>()
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        val restored =
            ledger.attemptAll(
                "include-app" to
                    {
                        attempted += "include"
                        throw original
                    },
                "split-enabled" to { attempted += "split" },
                "allow-lan" to { attempted += "lan" },
            )
        if (restored) attempted += "final-proof"
        assertEquals(listOf("include", "split", "lan"), attempted)
        assertEquals(listOf("include-app"), ledger.failures.map { it.phase })
        assertSame(original, assertThrows(AssertionError::class.java) { ledger.throwIfFailed() })
    }

    @Test
    fun independentRestorationRetainsEveryErrorAndBodyPrimary() {
        val body = AssertionError("body")
        val split = IllegalStateException("split")
        val lan = IllegalStateException("lan")
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        ledger.record("body", body)
        assertEquals(false, ledger.attemptAll("split" to { throw split }, "lan" to { throw lan }))
        assertSame(body, assertThrows(AssertionError::class.java) { ledger.throwIfFailed() })
        assertEquals(listOf(split, lan), body.suppressed.toList())
    }

    @Test
    fun successfulIndependentRestorationAllowsFinalProofDespitePriorBodyFailure() {
        val ledger = R06FailureLedger.Ledger { _, _ -> }
        ledger.record("body", AssertionError("body"))
        assertTrue(ledger.attemptAll("split" to {}, "lan" to {}))
        assertEquals(listOf("body"), ledger.failures.map { it.phase })
    }
}
