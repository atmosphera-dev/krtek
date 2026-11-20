package net.mullvad.mullvadvpn.talpid

/** Test-only failure custody. A finally error never replaces an earlier body error. */
internal object R06FailureLedger {
    class Ledger(private val persist: (String, Throwable) -> Unit) {
        data class Failure(val phase: String, val error: Throwable)

        private val recorded = mutableListOf<Failure>()
        val failures: List<Failure>
            get() = recorded.toList()

        fun record(phase: String, error: Throwable) {
            // A propagated primary can be caught by the outer fixture after its own
            // finally. Retain the phase-specific original, not a duplicate exception.
            if (recorded.any { it.error === error }) return
            recorded += Failure(phase, error)
            try {
                persist(phase, error)
            } catch (storageError: Throwable) {
                if (recorded.none { it.error === storageError }) {
                    recorded += Failure("evidence-write", storageError)
                }
            }
        }

        fun run(body: () -> Unit, restoration: () -> Unit) {
            try {
                body()
            } catch (error: Throwable) {
                record("body", error)
            } finally {
                try {
                    restoration()
                } catch (error: Throwable) {
                    record("settings-restoration", error)
                }
            }
            throwIfFailed()
        }

        fun throwIfFailed() {
            val primary = recorded.firstOrNull()?.error ?: return
            recorded.drop(1).forEach { failure ->
                if (primary.suppressed.none { it === failure.error }) {
                    primary.addSuppressed(failure.error)
                }
            }
            throw primary
        }
    }
}
