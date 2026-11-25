package net.mullvad.talpid

import net.mullvad.talpid.model.CaptureNetworkObservation

internal object LocalCaptureNetworkBridge {
    @JvmStatic external fun lockdownChanged(registration: Long, enabled: Boolean)

    @JvmStatic
    external fun published(
        registration: Long,
        generation: Long,
        observation: CaptureNetworkObservation,
    )
}
