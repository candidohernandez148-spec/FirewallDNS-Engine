package com.firewalldns.engine.threat

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * Deterministic canonical signing and verification for updatable threat feeds
 * using SHA256withECDSA (available across JVM and Android API 26+).
 */
object ThreatFeedVerifier {
    private const val FEED_MAGIC = "FWDNS_THREAT_FEED_V1"
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    fun canonicalPayload(feed: SignedThreatFeed): ByteArray {
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { out ->
            out.writeUTF(FEED_MAGIC)
            out.writeLong(feed.version)
            out.writeLong(feed.publishedAtEpochMillis)
            out.writeLong(feed.expiresAtEpochMillis)

            val sortedIndicators = feed.indicators.sortedBy { it.id }
            out.writeInt(sortedIndicators.size)
            for (ind in sortedIndicators) {
                out.writeUTF(ind.id)
                out.writeUTF(ind.domain)
                out.writeBoolean(ind.includeSubdomains)
                out.writeUTF(ind.category.name)
                out.writeInt(ind.confidence)
                out.writeUTF(ind.action.name)
                out.writeUTF(ind.source.name)
                out.writeUTF(ind.reason)
            }

            val sortedSafe = feed.safeDomains.sorted()
            out.writeInt(sortedSafe.size)
            for (safe in sortedSafe) {
                out.writeUTF(safe)
            }
        }
        return baos.toByteArray()
    }

    fun sign(
        version: Long,
        publishedAtEpochMillis: Long,
        expiresAtEpochMillis: Long,
        indicators: List<ThreatIndicator>,
        safeDomains: List<String>,
        privateKey: PrivateKey,
    ): SignedThreatFeed {
        val unsigned = SignedThreatFeed(
            version = version,
            publishedAtEpochMillis = publishedAtEpochMillis,
            expiresAtEpochMillis = expiresAtEpochMillis,
            indicators = indicators,
            safeDomains = safeDomains,
            signatureBase64 = "",
        )
        val signatureBytes = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(canonicalPayload(unsigned))
            sign()
        }
        return unsigned.copy(signatureBase64 = encodeBase64(signatureBytes))
    }

    fun verify(
        feed: SignedThreatFeed,
        trustedPublicKey: PublicKey,
        currentFeedVersion: Long,
        nowEpochMillis: Long,
    ): String? {
        if (feed.version <= 0L) return "threat_feed_version_invalid"
        if (feed.version <= currentFeedVersion) return "threat_feed_version_not_newer"
        if (feed.expiresAtEpochMillis <= feed.publishedAtEpochMillis) return "threat_feed_expiry_before_publish"
        if (feed.expiresAtEpochMillis <= nowEpochMillis) return "threat_feed_expired"
        val signatureBytes = decodeBase64(feed.signatureBase64) ?: return "threat_feed_signature_malformed"
        if (signatureBytes.isEmpty()) return "threat_feed_signature_empty"

        val verified = runCatching {
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(trustedPublicKey)
                update(canonicalPayload(feed))
                verify(signatureBytes)
            }
        }.getOrDefault(false)
        return if (verified) null else "threat_feed_signature_invalid"
    }

    private const val B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    internal fun encodeBase64(data: ByteArray): String {
        val out = StringBuilder(((data.size + 2) / 3) * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xff
            val hasB1 = i + 1 < data.size
            val b1 = if (hasB1) data[i + 1].toInt() and 0xff else 0
            val hasB2 = i + 2 < data.size
            val b2 = if (hasB2) data[i + 2].toInt() and 0xff else 0

            val triple = (b0 shl 16) or (b1 shl 8) or b2
            out.append(B64_ALPHABET[(triple ushr 18) and 0x3f])
            out.append(B64_ALPHABET[(triple ushr 12) and 0x3f])
            out.append(if (hasB1) B64_ALPHABET[(triple ushr 6) and 0x3f] else '=')
            out.append(if (hasB2) B64_ALPHABET[triple and 0x3f] else '=')
            i += 3
        }
        return out.toString()
    }

    internal fun decodeBase64(input: String): ByteArray? {
        val clean = input.trim()
        if (clean.isEmpty() || clean.length % 4 != 0) return null
        val bytes = ByteArrayOutputStream((clean.length / 4) * 3)
        var i = 0
        while (i < clean.length) {
            val c0 = decodeChar(clean[i])
            val c1 = decodeChar(clean[i + 1])
            val c2Char = clean[i + 2]
            val c3Char = clean[i + 3]
            if (c0 < 0 || c1 < 0) return null

            val pad2 = c2Char == '='
            val pad3 = c3Char == '='
            if (pad2 && !pad3) return null
            if ((pad2 || pad3) && i + 4 != clean.length) return null

            val c2 = if (pad2) 0 else decodeChar(c2Char)
            val c3 = if (pad3) 0 else decodeChar(c3Char)
            if (c2 < 0 || c3 < 0) return null

            val triple = (c0 shl 18) or (c1 shl 12) or (c2 shl 6) or c3
            bytes.write((triple ushr 16) and 0xff)
            if (!pad2) bytes.write((triple ushr 8) and 0xff)
            if (!pad3) bytes.write(triple and 0xff)
            i += 4
        }
        return bytes.toByteArray()
    }

    private fun decodeChar(c: Char): Int = when (c) {
        in 'A'..'Z' -> c.code - 'A'.code
        in 'a'..'z' -> c.code - 'a'.code + 26
        in '0'..'9' -> c.code - '0'.code + 52
        '+' -> 62
        '/' -> 63
        else -> -1
    }
}
