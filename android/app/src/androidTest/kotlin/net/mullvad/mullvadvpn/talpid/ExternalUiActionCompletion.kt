package net.mullvad.mullvadvpn.talpid

/** Accessibility dispatch does not advance Compose's controlled composition scheduler. */
internal object ExternalUiActionCompletion {
    fun settle(androidIdle: () -> Unit, composeIdle: () -> Unit) {
        androidIdle()
        composeIdle()
    }
}
