package net.mullvad.mullvadvpn.lib.model

import android.icu.text.IDNA

/** Advisory editor normalization. Rust validates every replacement authoritatively. */
object SplitDnsDomain {
    private val idna by lazy {
        IDNA.getUTS46Instance(
            IDNA.USE_STD3_RULES or
                IDNA.CHECK_BIDI or
                IDNA.CHECK_CONTEXTJ or
                IDNA.NONTRANSITIONAL_TO_ASCII or
                IDNA.NONTRANSITIONAL_TO_UNICODE
        )
    }

    fun normalize(input: String): String? {
        val text = input.trim().removePrefix(".").removeSuffix(".")
        if (text.isEmpty() || LocalCidr.parseAddress(text) != null || text.any { it in "*/\\:@[]" })
            return null
        return canonicalAscii(text)
    }

    private fun canonicalAscii(text: String): String? {
        val asciiInfo = IDNA.Info()
        val ascii = idna.nameToASCII(text, StringBuilder(), asciiInfo).toString()
        if (
            asciiInfo.hasErrors() ||
                ascii.isEmpty() ||
                ascii.endsWith('.') ||
                LocalCidr.parseAddress(ascii) != null
        )
            return null
        return "$ascii.".takeIf { roundTrips(ascii) }
    }

    private fun roundTrips(ascii: String): Boolean {
        val unicodeInfo = IDNA.Info()
        val unicode = idna.nameToUnicode(ascii, StringBuilder(), unicodeInfo)
        if (unicodeInfo.hasErrors()) return false
        val roundTripInfo = IDNA.Info()
        val roundTrip = idna.nameToASCII(unicode, StringBuilder(), roundTripInfo).toString()
        return !roundTripInfo.hasErrors() && roundTrip == ascii
    }
}
