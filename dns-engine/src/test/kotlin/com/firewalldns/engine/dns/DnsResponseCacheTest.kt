package com.firewalldns.engine.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsResponseCacheTest {
    @Test fun positiveAnswerExpiresAtLowestAnswerTtlRewritesIdAndDecrementsTtl() {
        val cache = DnsResponseCache()
        val original = query("example.com", id = 0x1111)
        assertTrue(cache.put("1.1.1.1:53", original, positiveResponse(original, ttl = 30), 1_000))

        val secondQuery = query("example.com", id = 0x2222)
        val hit = assertNotNull(cache.get("1.1.1.1:53", secondQuery, 1_000_001_000))
        assertEquals(DnsUpstreamTransport.CACHE, hit.transport)
        assertEquals(0x2222, u16(hit.message, 0))
        assertEquals(0x0100, u16(hit.message, 2) and 0x0110)
        assertEquals(29L, u32(hit.message, hit.message.size - 10))
        assertEquals(1, cache.size)
        assertNull(cache.get("1.1.1.1:53", secondQuery, 30_000_001_000))
    }

    @Test fun negativeNxdomainUsesMinimumOfSoaTtlAndMinimumField() {
        val cache = DnsResponseCache()
        val request = query("missing.example")
        assertTrue(cache.put("9.9.9.9:53", request, negativeResponse(request, 120, 45), 0))
        assertNotNull(cache.get("9.9.9.9:53", request, 44_000_000_000))
        assertNull(cache.get("9.9.9.9:53", request, 45_000_000_000))
    }

    @Test fun nodataUsesAuthoritySoaForNegativeCaching() {
        val cache = DnsResponseCache()
        val request = query("no-record.example")
        val nodata = negativeResponse(request, 90, 30).also { it[3] = 0x80.toByte() }
        assertTrue(cache.put("upstream", request, nodata, 0))
        assertNotNull(cache.get("upstream", request, 29_000_000_000))
        assertNull(cache.get("upstream", request, 30_000_000_000))
    }

    @Test fun doesNotCacheTtlZeroServfailTruncatedOrMalformedResponses() {
        val cache = DnsResponseCache()
        val request = query("example.com")
        assertFalse(cache.put("upstream", request, positiveResponse(request, 0), 0))
        assertFalse(cache.put("upstream", request, positiveResponse(request, 30).also { it[3] = 2 }, 0))
        assertFalse(cache.put("upstream", request, positiveResponse(request, 30).also { it[2] = 0x83.toByte() }, 0))
        assertFalse(cache.put("upstream", request, byteArrayOf(1, 2, 3), 0))
        assertEquals(0, cache.size)
    }

    @Test fun queryEdnsOptionsAndUpstreamAreIsolated() {
        val cache = DnsResponseCache()
        val request = query("example.com")
        assertTrue(cache.put("1.1.1.1:53", request, positiveResponse(request, 60), 0))
        assertNull(cache.get("8.8.8.8:53", request, 0))
        val checkingDisabled = request.copyOf().also { it[3] = 0x10 }
        assertNull(cache.get("1.1.1.1:53", checkingDisabled, 0))
        val changed = request.copyOf(request.size + 11)
        changed[11] = 1
        changed[request.size + 2] = 41
        changed[request.size + 3] = 0x04
        changed[request.size + 4] = 0xd0.toByte()
        assertNull(cache.get("1.1.1.1:53", changed, 0))
    }

    @Test fun refusesResponsesWithForwardCompressionPointers() {
        val cache = DnsResponseCache()
        val request = query("example.com")
        val malformed = positiveResponse(request, 60).also {
            val answerOffset = request.size
            // A forward pointer into the RR TYPE field is invalid DNS compression.
            it[answerOffset] = 0xc0.toByte()
            it[answerOffset + 1] = (answerOffset + 2).toByte()
        }
        assertFalse(cache.put("upstream", request, malformed, 0))
        assertEquals(0, cache.size)
    }

    @Test fun refusesEntriesLargerThanConfiguredByteBudget() {
        val cache = DnsResponseCache(maxBytes = 1)
        val request = query("large.example")
        assertFalse(cache.put("upstream", request, positiveResponse(request, 60), 0))
        assertEquals(0, cache.size)
    }

    @Test fun respectsEntryBoundAndClear() {
        val cache = DnsResponseCache(maxEntries = 1)
        val first = query("one.example")
        val second = query("two.example")
        assertTrue(cache.put("upstream", first, positiveResponse(first, 20), 0))
        assertTrue(cache.put("upstream", second, positiveResponse(second, 20), 1))
        assertEquals(1, cache.size)
        cache.clear()
        assertEquals(0, cache.size)
    }

    private fun positiveResponse(query: ByteArray, ttl: Int): ByteArray {
        val response = ByteArray(query.size + 16)
        query.copyInto(response)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[7] = 1
        val offset = query.size
        response[offset] = 0xc0.toByte()
        response[offset + 1] = 0x0c
        putU16(response, offset + 2, 1)
        putU16(response, offset + 4, 1)
        putU32(response, offset + 6, ttl.toLong())
        putU16(response, offset + 10, 4)
        response[offset + 12] = 192.toByte()
        response[offset + 13] = 0
        response[offset + 14] = 2
        response[offset + 15] = 1
        return response
    }

    private fun negativeResponse(query: ByteArray, soaTtl: Int, soaMinimum: Int): ByteArray {
        val soaOwner = byteArrayOf(0xc0.toByte(), 0x0c)
        val mname = byteArrayOf(2, 'n'.code.toByte(), 's'.code.toByte(), 0xc0.toByte(), 0x0c)
        val rname = byteArrayOf(10) + "hostmaster".toByteArray() + byteArrayOf(0xc0.toByte(), 0x0c)
        val fields = ByteArray(20)
        putU32(fields, 0, 1)
        putU32(fields, 4, 3600)
        putU32(fields, 8, 600)
        putU32(fields, 12, 86400)
        putU32(fields, 16, soaMinimum.toLong())
        val rdata = mname + rname + fields
        val response = ByteArray(query.size + soaOwner.size + 10 + rdata.size)
        query.copyInto(response)
        response[2] = 0x81.toByte()
        response[3] = 0x83.toByte()
        response[9] = 1
        val offset = query.size
        soaOwner.copyInto(response, offset)
        putU16(response, offset + 2, 6)
        putU16(response, offset + 4, 1)
        putU32(response, offset + 6, soaTtl.toLong())
        putU16(response, offset + 10, rdata.size)
        rdata.copyInto(response, offset + 12)
        return response
    }

    private fun query(domain: String, id: Int = 0x1234): ByteArray {
        val labels = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray().toList()
        } + 0.toByte()
        val question = labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            putU16(it, 0, id)
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun u16(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    private fun u32(bytes: ByteArray, offset: Int) =
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
}
