package com.firewalldns.engine.dns

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Bounded in-memory cache for validated upstream DNS messages.
 *
 * Keys include the upstream endpoint and the complete query wire image, except
 * transaction ID and RD bit; CD remains part of the key. This avoids sharing
 * answers across EDNS options, client subnets, cookies, question casing, or other
 * query variants. Storage is bounded by entry count and total response bytes.
 * Expiration uses a monotonic nanosecond clock; no disk or network I/O occurs here.
 */
class DnsResponseCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val maxBytes: Int = DEFAULT_MAX_BYTES,
    private val maxTtlSeconds: Long = DEFAULT_MAX_TTL_SECONDS,
) {
    private data class Entry(val response: ByteArray, val insertedAtNanos: Long, val ttlNanos: Long)

    /** Content-based key avoids java.util.Base64, unavailable on Android API 24–25. */
    private class CacheKey(val upstream: String, query: ByteArray) {
        private val wireQuery = query.copyOf()

        override fun equals(other: Any?): Boolean =
            other is CacheKey && upstream == other.upstream && wireQuery.contentEquals(other.wireQuery)

        override fun hashCode(): Int = 31 * upstream.hashCode() + wireQuery.contentHashCode()
    }

    private val entries = ConcurrentHashMap<CacheKey, Entry>()
    private val writeLock = ReentrantLock()
    private var currentBytes: Int = 0

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(maxBytes in 1..MAX_BYTES_LIMIT) { "maxBytes is out of range" }
        require(maxTtlSeconds in 1..(Long.MAX_VALUE / NANOS_PER_SECOND)) { "maxTtlSeconds is out of range" }
    }

    fun get(upstream: String, query: ByteArray, nowNanos: Long): DnsUpstreamResponse? {
        val parsed = DnsMessageParser.parse(query) as? DnsParseResult.Valid ?: return null
        val cacheEntry = entries[key(upstream, query)] ?: return null
        val elapsedNanos = nowNanos - cacheEntry.insertedAtNanos
        if (elapsedNanos < 0L || elapsedNanos >= cacheEntry.ttlNanos) return null
        val remainingNanos = cacheEntry.ttlNanos - elapsedNanos
        val remainingSeconds = ((remainingNanos - 1L) / NANOS_PER_SECOND) + 1L
        val response = cacheEntry.response.copyOf()
        putU16(response, 0, parsed.question.id)
        val flags = u16(response, 2)
        putU16(response, 2, (flags and RD_MASK.inv()) or
            (parsed.question.requestFlags and RD_MASK))
        parsed.question.wireQuestion.copyInto(response, DNS_HEADER_SIZE)
        if (!rewriteRemainingTtls(response, remainingSeconds)) return null
        return DnsUpstreamResponse(response, DnsUpstreamTransport.CACHE)
    }

    fun put(
        upstream: String,
        query: ByteArray,
        response: ByteArray,
        nowNanos: Long,
    ): Boolean {
        val parsed = DnsMessageParser.parse(query) as? DnsParseResult.Valid ?: return false
        if (response.size < DNS_HEADER_SIZE || u16(response, 0) != parsed.question.id) return false
        if ((u16(response, 2) and OPCODE_MASK) != (parsed.question.requestFlags and OPCODE_MASK)) return false
        val ttlSeconds = responseTtlSeconds(response, parsed.question.wireQuestion) ?: return false
        if (ttlSeconds <= 0L) return false
        val boundedTtl = minOf(ttlSeconds, maxTtlSeconds)
        val ttlNanos = boundedTtl * NANOS_PER_SECOND
        val stored = response.copyOf()
        if (stored.size > maxBytes) return false
        val cacheKey = key(upstream, query)
        writeLock.withLock {
            removeExpiredEntries(nowNanos)
            entries.remove(cacheKey)?.let { currentBytes -= it.response.size }
            while (entries.isNotEmpty() &&
                (entries.size >= maxEntries || currentBytes + stored.size > maxBytes)
            ) {
                val victim = entries.entries.firstOrNull() ?: break
                if (entries.remove(victim.key, victim.value)) currentBytes -= victim.value.response.size
            }
            entries[cacheKey] = Entry(stored, nowNanos, ttlNanos)
            currentBytes += stored.size
        }
        return true
    }

    fun clear() {
        writeLock.withLock {
            entries.clear()
            currentBytes = 0
        }
    }

    val size: Int get() = entries.size

    private fun isExpired(entry: Entry, nowNanos: Long): Boolean {
        val elapsedNanos = nowNanos - entry.insertedAtNanos
        return elapsedNanos < 0L || elapsedNanos >= entry.ttlNanos
    }

    private fun removeExpiredEntries(nowNanos: Long) {
        entries.entries.toList().forEach { (key, entry) ->
            if (isExpired(entry, nowNanos) && entries.remove(key, entry)) {
                currentBytes -= entry.response.size
            }
        }
    }

    private fun key(upstream: String, query: ByteArray): CacheKey {
        val canonical = query.copyOf()
        canonical[0] = 0
        canonical[1] = 0
        putU16(canonical, 2, u16(canonical, 2) and RD_MASK.inv())
        return CacheKey(upstream, canonical)
    }

    /**
     * Positive answers use the lowest answer RR TTL. NXDOMAIN and NODATA require
     * an authority SOA and use min(SOA RR TTL, SOA.MINIMUM), per RFC 2308.
     * Truncated, malformed, TTL=0 and non-cacheable response codes are misses.
     */
    private fun responseTtlSeconds(message: ByteArray, expectedQuestion: ByteArray): Long? {
        if (message.size < DNS_HEADER_SIZE || message.size > MAX_DNS_MESSAGE_SIZE) return null
        val flags = u16(message, 2)
        if (flags and QR_MASK == 0 || flags and TC_MASK != 0) return null
        val rcode = flags and RCODE_MASK
        if (rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN) return null
        if (u16(message, 4) != 1) return null

        val questionNameEnd = skipName(message, DNS_HEADER_SIZE) ?: return null
        if (questionNameEnd + 4 > message.size) return null
        val questionEnd = questionNameEnd + 4
        if (!message.copyOfRange(DNS_HEADER_SIZE, questionEnd).contentEquals(expectedQuestion)) return null
        var offset = questionEnd

        val answerCount = u16(message, 6)
        val authorityCount = u16(message, 8)
        val additionalCount = u16(message, 10)
        if (answerCount + authorityCount + additionalCount > MAX_RECORDS) return null
        var positiveTtl: Long? = null
        var negativeTtl: Long? = null

        val totalRecords = answerCount + authorityCount + additionalCount
        for (index in 0 until totalRecords) {
            val section = when {
                index < answerCount -> SECTION_ANSWER
                index < answerCount + authorityCount -> SECTION_AUTHORITY
                else -> SECTION_ADDITIONAL
            }
            val nameEnd = skipName(message, offset) ?: return null
            if (nameEnd + RR_FIXED_SIZE > message.size) return null
            val type = u16(message, nameEnd)
            val ttl = u32(message, nameEnd + 4)
            val rdLength = u16(message, nameEnd + 8)
            val rdataStart = nameEnd + RR_FIXED_SIZE
            val rdataEnd = rdataStart + rdLength
            if (rdataEnd < rdataStart || rdataEnd > message.size) return null

            if (section == SECTION_ANSWER && type != TYPE_OPT) {
                positiveTtl = positiveTtl?.let { minOf(it, ttl) } ?: ttl
            } else if (section == SECTION_AUTHORITY && type == TYPE_SOA) {
                val minimum = soaMinimum(message, rdataStart, rdataEnd) ?: return null
                val candidate = minOf(ttl, minimum)
                negativeTtl = negativeTtl?.let { minOf(it, candidate) } ?: candidate
            }
            offset = rdataEnd
        }
        if (offset != message.size) return null
        val selected = when {
            rcode == RCODE_NXDOMAIN && negativeTtl != null && positiveTtl != null ->
                minOf(negativeTtl, positiveTtl)
            rcode == RCODE_NXDOMAIN -> negativeTtl
            answerCount == 0 -> negativeTtl
            else -> positiveTtl
        }
        return selected?.takeIf { it > 0L }
    }

    private fun rewriteRemainingTtls(message: ByteArray, remainingSeconds: Long): Boolean {
        if (message.size < DNS_HEADER_SIZE) return false
        var offset = skipName(message, DNS_HEADER_SIZE) ?: return false
        if (offset + 4 > message.size) return false
        offset += 4
        val total = u16(message, 6) + u16(message, 8) + u16(message, 10)
        if (total > MAX_RECORDS) return false
        repeat(total) {
            val nameEnd = skipName(message, offset) ?: return false
            if (nameEnd + RR_FIXED_SIZE > message.size) return false
            val type = u16(message, nameEnd)
            val rdataLength = u16(message, nameEnd + 8)
            val rdataStart = nameEnd + RR_FIXED_SIZE
            val rdataEnd = rdataStart + rdataLength
            if (rdataEnd < rdataStart || rdataEnd > message.size) return false
            // OPT's TTL field contains extended RCODE/version/flags, not a TTL.
            if (type != TYPE_OPT) putU32(message, nameEnd + 4, minOf(u32(message, nameEnd + 4), remainingSeconds))
            offset = rdataEnd
        }
        return offset == message.size
    }

    private fun soaMinimum(message: ByteArray, start: Int, end: Int): Long? {
        val firstNameEnd = skipName(message, start) ?: return null
        if (firstNameEnd > end) return null
        val secondNameEnd = skipName(message, firstNameEnd) ?: return null
        if (secondNameEnd + 20 != end) return null
        return u32(message, secondNameEnd + 16)
    }

    /** Skip a possibly compressed DNS name and return the first byte after its encoding. */
    private fun skipName(message: ByteArray, start: Int): Int? {
        if (start !in message.indices) return null
        var cursor = start
        var jumped = false
        var consumed = -1
        var steps = 0
        while (steps++ < MAX_NAME_STEPS) {
            if (cursor !in message.indices) return null
            val length = message[cursor].toInt() and 0xff
            when {
                length == 0 -> return if (jumped) consumed else cursor + 1
                length and 0xc0 == 0xc0 -> {
                    if (cursor + 1 >= message.size) return null
                    val pointer = ((length and 0x3f) shl 8) or (message[cursor + 1].toInt() and 0xff)
                    if (pointer >= message.size) return null
                    if (!jumped) consumed = cursor + 2
                    jumped = true
                    cursor = pointer
                }
                length and 0xc0 != 0 || length > 63 -> return null
                else -> {
                    if (cursor + 1 + length > message.size) return null
                    cursor += length + 1
                }
            }
        }
        return null
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun u32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xff) shl 24) or
            ((bytes[offset + 1].toLong() and 0xff) shl 16) or
            ((bytes[offset + 2].toLong() and 0xff) shl 8) or
            (bytes[offset + 3].toLong() and 0xff)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Long) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 2_048
        const val DEFAULT_MAX_BYTES = 4 * 1024 * 1024
        const val MAX_BYTES_LIMIT = 64 * 1024 * 1024
        const val DEFAULT_MAX_TTL_SECONDS = 86_400L
        const val NANOS_PER_SECOND = 1_000_000_000L
        const val DNS_HEADER_SIZE = 12
        const val RR_FIXED_SIZE = 10
        const val MAX_DNS_MESSAGE_SIZE = 65_535
        const val MAX_RECORDS = 4_096
        const val MAX_NAME_STEPS = 256
        const val RD_MASK = 0x0100
        const val QR_MASK = 0x8000
        const val OPCODE_MASK = 0x7800
        const val TC_MASK = 0x0200
        const val RCODE_MASK = 0x000f
        const val RCODE_NOERROR = 0
        const val RCODE_NXDOMAIN = 3
        const val TYPE_SOA = 6
        const val TYPE_OPT = 41
        const val SECTION_ANSWER = 0
        const val SECTION_AUTHORITY = 1
        const val SECTION_ADDITIONAL = 2
    }
}
