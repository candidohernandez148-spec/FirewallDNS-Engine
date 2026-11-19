package com.firewalldns.engine.core

import java.net.IDN
import java.util.Locale

/** Canonicalizes DNS names, including service labels such as _sip._tcp. */
object DomainNormalizer {
    fun normalize(hostname: String): String? {
        val input = hostname.trim().removeSuffix(".")
        if (input.isEmpty() || input.length > 253 || input.any { it.isWhitespace() }) return null

        val labels = input.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return null
        val asciiLabels = labels.map { label ->
            val lower = label.lowercase(Locale.ROOT)
            // Underscores are valid in common DNS service labels (for example _sip._tcp).
            if ('_' in lower) {
                if (lower.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_') }) return null
                lower
            } else {
                try {
                    IDN.toASCII(label, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
                } catch (_: IllegalArgumentException) {
                    return null
                }
            }
        }
        if (asciiLabels.any { label ->
                label.isEmpty() || label.length > 63 || label.first() == '-' || label.last() == '-' ||
                    label.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_') }
            }) return null
        return asciiLabels.joinToString(".").takeIf { it.length <= 253 }
    }
}
