package net.mullvad.mullvadvpn.talpid

/** Clipboard replacement revokes URI grants; copied values do not retain that authority. */
internal object ClipboardRestoreContract {
    fun restorable(schemes: List<Pair<String?, String?>>): Boolean =
        schemes.none { (item, intent) ->
            item.equals("content", ignoreCase = true) || intent.equals("content", ignoreCase = true)
        }
}
