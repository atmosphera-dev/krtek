package net.mullvad.mullvadvpn.talpid

/** Test-only revision evidence from one raw, non-conflating daemon subscription. */
internal class OrderedLocalStatusWindow {
    private val samples = mutableListOf<Pair<ULong, Boolean>>()

    @Synchronized
    fun append(revision: ULong, eligible: Boolean) {
        samples.add(revision to eligible)
    }

    /** A status RPC at probe end is a publication fence, not a new event. */
    @Synchronized
    fun processedThrough(start: ULong, finish: ULong): Boolean {
        check(finish >= start) { "Daemon status revision reset during probe" }
        var last = start
        for ((revision, eligible) in samples) {
            if (revision <= start || revision > finish) continue
            check(revision == last + 1u) { "Gap or reordered Local status evidence" }
            check(eligible) { "Local rule eligibility changed during UDP probe" }
            last = revision
        }
        return last == finish
    }
}
