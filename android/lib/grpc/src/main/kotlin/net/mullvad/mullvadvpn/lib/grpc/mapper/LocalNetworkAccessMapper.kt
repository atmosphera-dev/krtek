package net.mullvad.mullvadvpn.lib.grpc.mapper

import java.util.UUID
import mullvad_daemon.management_interface.LocalBypassRule
import mullvad_daemon.management_interface.LocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.LocalBypassRule as ModelLocalBypassRule
import net.mullvad.mullvadvpn.lib.model.LocalCidr
import net.mullvad.mullvadvpn.lib.model.LocalNetworkAccess as ModelLocalNetworkAccess
import net.mullvad.mullvadvpn.lib.model.SsidIdentity
import okio.ByteString.Companion.toByteString

internal fun LocalNetworkAccess.toDomain(): ModelLocalNetworkAccess {
    // Reads preserve stored values, including semantic errors, for the editor.
    // Only mutation serialization validates and normalizes policy.
    return ModelLocalNetworkAccess(enabled, rules.map { it.toDomain() })
}

private fun LocalBypassRule.toDomain(): ModelLocalBypassRule {
    return ModelLocalBypassRule(
        id = localRuleId(id),
        name = name,
        enabled = enabled,
        cidrs =
            cidrs.map {
                LocalCidr.parse(it).getOrNull()
                    ?: throw IllegalArgumentException("Invalid local prefix")
            },
        ssidIds =
            ssid_ids.map {
                SsidIdentity.fromBytes(it.toByteArray())
                    ?: throw IllegalArgumentException("Invalid SSID byte identity")
            },
    )
}

internal fun localRuleId(text: String): UUID {
    val uuid =
        try {
            UUID.fromString(text)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid local rule identifier")
        }
    // UUID.fromString also accepts abbreviated groups; require the full wire form.
    require(uuid.toString().equals(text, ignoreCase = true)) { "Invalid local rule identifier" }
    return uuid
}

internal fun ModelLocalNetworkAccess.fromDomain(): LocalNetworkAccess {
    require(validationError() == null) { "Invalid local network policy" }
    return asExpected()
}

/** A read snapshot is an exact comparison token, never replacement input. */
internal fun ModelLocalNetworkAccess.asExpected(): LocalNetworkAccess {
    return LocalNetworkAccess(
        enabled = enabled,
        rules =
            rules.map { rule ->
                LocalBypassRule(
                    id = rule.id.toString(),
                    name = rule.name,
                    enabled = rule.enabled,
                    cidrs = rule.cidrs.map { it.toString() },
                    ssid_ids = rule.ssidIds.map { it.bytes().toByteString() },
                )
            },
    )
}
