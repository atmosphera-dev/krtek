package net.mullvad.mullvadvpn.talpid

/** Lifecycle transitions, without losing raw same-state metadata updates at the caller. */
internal object TunnelLifecycleTransitions {
    fun <T> since(records: List<T>, start: Int, kind: (T) -> Any): List<T> {
        require(start in 0..records.size)
        var previous = records.getOrNull(start - 1)?.let(kind)
        return buildList {
            for (index in start until records.size) {
                val state = records[index]
                val current = kind(state)
                if (current != previous) add(state)
                previous = current
            }
        }
    }
}
