package com.firewalldns.engine.core

import java.net.IDN
import java.util.Locale

/** Canonicalizes a hostname; DNS wire-format parsing belongs in the DNS adapter. */
object DomainNormalizer {
    fun normalize(hostname: String): String? {
        val input = hostname.trim().removeSuffix(".")
        if (input.isEmpty() || input.length > 253 || input.any { it.isWhitespace() }) return null
        val ascii = try {
            IDN.toASCII(input, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) { return null }
        if (ascii.length > 253) return null
        val labels = ascii.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > 63 || label.first() == '-' || label.last() == '-' ||
                    label.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-') }
            }) return null
        return ascii
    }
}
