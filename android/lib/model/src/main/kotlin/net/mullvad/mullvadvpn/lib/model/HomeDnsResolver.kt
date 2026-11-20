package net.mullvad.mullvadvpn.lib.model

/** Numeric-only and family-preserving. No hostname lookup or mapped-v6 collapse. */
class HomeDnsResolver
private constructor(
    val numericAddress: String,
    private val octets: ByteArray,
) {
    fun addressBytes(): ByteArray = octets.copyOf()

    override fun equals(other: Any?): Boolean =
        other is HomeDnsResolver && octets.contentEquals(other.octets)

    override fun hashCode(): Int = octets.contentHashCode()

    override fun toString(): String = "HomeDnsResolver(redacted)"

    companion object {
        fun parse(text: String): HomeDnsResolver? =
            LocalCidr.parseAddress(text)?.let { HomeDnsResolver(LocalCidr.formatAddress(it), it) }
    }
}
