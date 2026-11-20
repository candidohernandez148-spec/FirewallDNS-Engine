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
    private val maxDnsPayloadBytes: Int = 1232,
    private val exchangeUpstream: (ByteArray) -> DnsUpstreamResult,
) {
    init {
        require(maxDnsPayloadBytes in 512..4096)
    }

    sealed interface PacketResult {
        data class Response(val packet: ByteArray, val outcome: String) : PacketResult
        data class NoResponse(val reason: String) : PacketResult
    }

    /** Compatibility API. Detailed callers should use processDetailed() to retain the terminal reason. */
    fun process(packet: ByteArray, length: Int = packet.size): ByteArray? =
        (processDetailed(packet, length) as? PacketResult.Response)?.packet

    /** Returns a payload-free terminal reason when the packet cannot be answered. */
    fun processDetailed(packet: ByteArray, length: Int = packet.size): PacketResult {
        val decoded = decodeDetailed(packet, length)
        val request = when (decoded) {
            is DecodeResult.Valid -> decoded.request
            is DecodeResult.Invalid -> return PacketResult.NoResponse(decoded.reason)
        }
        val evaluation = engine.evaluateDns(request.dns)
        val response: ByteArray
        val responseOutcome: String
        when (evaluation) {
            is DnsEvaluation.Blocked -> {
                response = evaluation.response
                responseOutcome = "dns_blocked_response"
            }
            is DnsEvaluation.Forward -> when (val upstream = exchangeUpstream(request.dns)) {
                is DnsUpstreamResult.Success -> {
                    response = upstream.response.message
                    responseOutcome = "dns_forwarded_response"
                }
                is DnsUpstreamResult.Failure -> {
                    response = servfail(evaluation.question)
                    responseOutcome = "upstream_failure_servfail"
                }
                DnsUpstreamResult.Cancelled -> return PacketResult.NoResponse("upstream_cancelled")
            }
            is DnsEvaluation.Rejected -> return PacketResult.NoResponse("dns_rejected")
        }
        val bounded = if (response.size > maxDnsPayloadBytes) truncated(evaluation, response) else response
        val encoded = encodeResponse(request, bounded)
            ?: return PacketResult.NoResponse("response_encoding_failed")
        return PacketResult.Response(encoded, responseOutcome)
    }

    private sealed interface DecodeResult {
        data class Valid(val request: Request) : DecodeResult
        data class Invalid(val reason: String) : DecodeResult
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

    private fun decodeDetailed(packet: ByteArray, length: Int): DecodeResult {
        if (length <= 0 || length > packet.size) return DecodeResult.Invalid("invalid_packet_length")
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> decodeIpv4(packet, length)
            6 -> decodeIpv6(packet, length)
            else -> DecodeResult.Invalid("unsupported_ip_version")
        }
    }

    private fun decodeIpv4(packet: ByteArray, length: Int): DecodeResult {
        if (length < 20) return DecodeResult.Invalid("ipv4_header_truncated")
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < 20 || headerLength > length) return DecodeResult.Invalid("ipv4_header_length_invalid")
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength || totalLength > length) return DecodeResult.Invalid("ipv4_total_length_invalid")
        val protocol = packet[9].toInt() and 0xff
        if (protocol != IPPROTO_UDP) {
            return DecodeResult.Invalid(if (protocol == IPPROTO_TCP) "unsupported_transport_tcp" else "unsupported_transport_other")
        }
        if ((u16(packet, 6) and 0x3fff) != 0) return DecodeResult.Invalid("ipv4_fragment_unsupported")
        if (headerLength + 8 > totalLength) return DecodeResult.Invalid("udp_header_truncated")
        return decodeUdp(packet, length, false, headerLength, totalLength,
            packet.copyOfRange(12, 16), packet.copyOfRange(16, 20))
    }

    private fun decodeIpv6(packet: ByteArray, length: Int): DecodeResult {
        if (length < 40) return DecodeResult.Invalid("ipv6_header_truncated")
        val payloadLength = u16(packet, 4)
        if (payloadLength == 0 || 40 + payloadLength > length) return DecodeResult.Invalid("ipv6_payload_length_invalid")
        val nextHeader = packet[6].toInt() and 0xff
        if (nextHeader != IPPROTO_UDP) {
            val reason = when (nextHeader) {
                IPPROTO_TCP -> "unsupported_transport_tcp"
                44 -> "ipv6_fragment_unsupported"
                0, 43, 51, 60 -> "ipv6_extension_header_unsupported"
                else -> "unsupported_transport_other"
            }
            return DecodeResult.Invalid(reason)
        }
        if (payloadLength < 8) return DecodeResult.Invalid("udp_header_truncated")
        return decodeUdp(packet, length, true, 40, 40 + payloadLength,
            packet.copyOfRange(8, 24), packet.copyOfRange(24, 40))
    }

    private fun decodeUdp(
        packet: ByteArray,
        length: Int,
        ipv6: Boolean,
        ipHeaderLength: Int,
        packetEnd: Int,
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
    ): DecodeResult {
        if (ipHeaderLength + 8 > packetEnd) return DecodeResult.Invalid("udp_header_truncated")
        val udpLength = u16(packet, ipHeaderLength + 4)
        if (udpLength < 8 || ipHeaderLength + udpLength != packetEnd || packetEnd > length) {
            return DecodeResult.Invalid("udp_length_invalid")
        }
        val sourcePort = u16(packet, ipHeaderLength)
        val destinationPort = u16(packet, ipHeaderLength + 2)
        if (destinationPort != DNS_PORT) return DecodeResult.Invalid("non_dns_udp_packet")
        if (udpLength < 8 + 12) return DecodeResult.Invalid("dns_payload_too_short")
        return DecodeResult.Valid(
            Request(
                ipv6 = ipv6,
                ipHeaderLength = ipHeaderLength,
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                dns = packet.copyOfRange(ipHeaderLength + 8, ipHeaderLength + udpLength),
                originalHeader = packet.copyOfRange(0, ipHeaderLength),
            ),
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
        const val IPPROTO_TCP = 6
    }
}
