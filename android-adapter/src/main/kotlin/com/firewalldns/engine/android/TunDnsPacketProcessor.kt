package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.runtime.EngineRuntime

/**
 * DNS-only TUN data-plane adapter.
 *
 * The VPN host must route only its virtual DNS addresses to the TUN. This adapter
 * deliberately does not pretend to forward arbitrary IP traffic or implement TCP.
 * Upstream exchanges are synchronous and MUST be invoked on a bounded I/O worker,
 * never on the TUN reader thread.
 */
class TunDnsPacketProcessor(
    private val engine: EngineRuntime,
    private val exchangeUpstream: (ByteArray) -> DnsUpstreamResult,
    private val maxDnsPayloadBytes: Int = 1232,
) {
    init {
        require(maxDnsPayloadBytes in 512..4096)
    }

    /** Returns a complete IP/UDP response packet, or null for unsupported/invalid input. */
    fun process(packet: ByteArray, length: Int = packet.size): ByteArray? {
        val request = decode(packet, length) ?: return null
        val evaluation = engine.evaluateDns(request.dns)
        val response = when (evaluation) {
            is DnsEvaluation.Blocked -> evaluation.response
            is DnsEvaluation.Forward -> when (val upstream = exchangeUpstream(request.dns)) {
                is DnsUpstreamResult.Success -> upstream.response.message
                is DnsUpstreamResult.Failure -> servfail(evaluation.question)
                DnsUpstreamResult.Cancelled -> return null
            }
            is DnsEvaluation.Rejected -> return null
        }
        val bounded = if (response.size > maxDnsPayloadBytes) {
            truncated(evaluation, response)
        } else {
            response
        }
        return encodeResponse(request, bounded)
    }

    private data class Request(
        val ipv6: Boolean,
        val ipHeaderLength: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val dns: ByteArray,
        val originalHeader: ByteArray,
    )

    private fun decode(packet: ByteArray, length: Int): Request? {
        if (length <= 0 || length > packet.size) return null
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> decodeIpv4(packet, length)
            6 -> decodeIpv6(packet, length)
            else -> null
        }
    }

    private fun decodeIpv4(packet: ByteArray, length: Int): Request? {
        if (length < 28) return null
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < 20 || headerLength + 8 > length) return null
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength + 8 || totalLength > length) return null
        if ((packet[9].toInt() and 0xff) != IPPROTO_UDP) return null
        if ((u16(packet, 6) and 0x3fff) != 0) return null // no fragments
        val udpLength = u16(packet, headerLength + 4)
        if (udpLength < 8 || headerLength + udpLength != totalLength) return null
        val sourcePort = u16(packet, headerLength)
        val destinationPort = u16(packet, headerLength + 2)
        if (destinationPort != DNS_PORT || udpLength == 8) return null
        return Request(
            ipv6 = false,
            ipHeaderLength = headerLength,
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dns = packet.copyOfRange(headerLength + 8, headerLength + udpLength),
            originalHeader = packet.copyOfRange(0, headerLength),
        )
    }

    private fun decodeIpv6(packet: ByteArray, length: Int): Request? {
        if (length < 48) return null
        val payloadLength = u16(packet, 4)
        if (payloadLength < 8 || 40 + payloadLength > length) return null
        // Extension headers and jumbograms are intentionally rejected, not misparsed.
        if ((packet[6].toInt() and 0xff) != IPPROTO_UDP) return null
        val udpLength = u16(packet, 44)
        if (udpLength < 8 || udpLength != payloadLength) return null
        val sourcePort = u16(packet, 40)
        val destinationPort = u16(packet, 42)
        if (destinationPort != DNS_PORT || udpLength == 8) return null
        return Request(
            ipv6 = true,
            ipHeaderLength = 40,
            sourceAddress = packet.copyOfRange(8, 24),
            destinationAddress = packet.copyOfRange(24, 40),
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dns = packet.copyOfRange(48, 40 + udpLength),
            originalHeader = packet.copyOfRange(0, 40),
        )
    }

    private fun encodeResponse(request: Request, dns: ByteArray): ByteArray? {
        val udpLength = 8 + dns.size
        val ipLength = request.ipHeaderLength + udpLength
        if (ipLength > 65_535 || (!request.ipv6 && ipLength > 65_535)) return null
        val output = ByteArray(ipLength)
        request.originalHeader.copyInto(output)
        if (request.ipv6) {
            request.destinationAddress.copyInto(output, 8)
            request.sourceAddress.copyInto(output, 24)
            putU16(output, 4, udpLength)
            output[7] = 64
        } else {
            request.destinationAddress.copyInto(output, 12)
            request.sourceAddress.copyInto(output, 16)
            putU16(output, 2, ipLength)
            output[8] = 64
            putU16(output, 10, 0)
        }
        val udpOffset = request.ipHeaderLength
        putU16(output, udpOffset, request.destinationPort)
        putU16(output, udpOffset + 2, request.sourcePort)
        putU16(output, udpOffset + 4, udpLength)
        putU16(output, udpOffset + 6, 0)
        dns.copyInto(output, udpOffset + 8)
        val checksum = udpChecksum(
            request.ipv6,
            request.destinationAddress,
            request.sourceAddress,
            output,
            udpOffset,
            udpLength,
        )
        putU16(output, udpOffset + 6, if (checksum == 0) 0xffff else checksum)
        if (!request.ipv6) {
            val headerLength = request.ipHeaderLength
            putU16(output, 10, internetChecksum(output, 0, headerLength))
        }
        return output
    }

    private fun truncated(evaluation: DnsEvaluation, fullResponse: ByteArray): ByteArray {
        val question = when (evaluation) {
            is DnsEvaluation.Blocked -> evaluation.question
            is DnsEvaluation.Forward -> evaluation.question
            is DnsEvaluation.Rejected -> return fullResponse.copyOf(maxDnsPayloadBytes)
        }
        val wire = question.wireQuestion
        val response = ByteArray(12 + wire.size)
        putU16(response, 0, question.id)
        val flags = 0x8000 or 0x0200 or (question.requestFlags and 0x0110) or 0x0080
        putU16(response, 2, flags)
        putU16(response, 4, 1)
        wire.copyInto(response, 12)
        return response
    }

    private fun servfail(question: com.firewalldns.engine.dns.DnsQuestion): ByteArray {
        val response = ByteArray(12 + question.wireQuestion.size)
        putU16(response, 0, question.id)
        putU16(response, 2, 0x8000 or 0x0080 or (question.requestFlags and 0x0110) or 0x0002)
        putU16(response, 4, 1)
        question.wireQuestion.copyInto(response, 12)
        return response
    }

    private fun udpChecksum(
        ipv6: Boolean,
        source: ByteArray,
        destination: ByteArray,
        packet: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        fun add(data: ByteArray, start: Int, count: Int) {
            var i = start
            val end = start + count
            while (i + 1 < end) {
                sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
                i += 2
            }
            if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        }
        add(source, 0, source.size)
        add(destination, 0, destination.size)
        if (ipv6) {
            sum += ((length ushr 16) and 0xffff).toLong()
            sum += (length and 0xffff).toLong()
            sum += IPPROTO_UDP.toLong()
        } else {
            sum += IPPROTO_UDP.toLong()
            sum += length.toLong()
        }
        add(packet, offset, length)
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private companion object {
        const val DNS_PORT = 53
        const val IPPROTO_UDP = 17
    }
}
