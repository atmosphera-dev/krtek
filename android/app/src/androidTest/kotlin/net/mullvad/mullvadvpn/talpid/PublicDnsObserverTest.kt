package net.mullvad.mullvadvpn.talpid

/** Opt-in diagnostic lifetime fence, never a socket, tunnel or timing correction. */
class PublicDnsObserverTest {
    private var owner: String? = null

    fun observe(phase: String): String {
        check(phase in setOf("start", "finish"))
        val expected = if (phase == "start") "" else checkNotNull(owner)
        val actual = barrier(expected)
        check(actual.isNotEmpty() && (expected.isEmpty() || actual == expected)) {
            "Observation gap: native owner changed"
        }
        owner = actual
        return actual
    }

    private external fun barrier(expected: String): String
}
