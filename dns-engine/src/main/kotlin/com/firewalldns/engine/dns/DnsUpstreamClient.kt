package com.firewalldns.engine.dns

import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Socket protection hook implemented by the Android VpnService adapter. */
interface DnsSocketProtector {
    fun protect(socket: DatagramSocket): Boolean = true
    fun protect(socket: Socket): Boolean = true
}

object NoOpDnsSocketProtector : DnsSocketProtector

data class DnsUpstreamConfig(
    val host: String,
    val port: Int = 53,
    val timeoutMillis: Int = 2_000,
    val udpBufferBytes: Int = 4_096,
) {
    init {
        require(host.isNotBlank()) { "DNS upstream host must not be blank" }
        require(port in 1..65_535) { "DNS upstream port is invalid" }
        require(timeoutMillis > 0) { "DNS timeout must be positive" }
        require(udpBufferBytes in 512..65_535) { "DNS UDP buffer size is invalid" }
    }
}

enum class DnsUpstreamTransport { UDP, TCP }

data class DnsUpstreamResponse(
    val message: ByteArray,
    val transport: DnsUpstreamTransport,
)

sealed interface DnsUpstreamResult {
    data class Success(val response: DnsUpstreamResponse) : DnsUpstreamResult
    data class Failure(val reason: String) : DnsUpstreamResult
}

/**
 * Bounded synchronous DNS upstream exchange. Call from an I/O dispatcher, never
 * from the packet/policy hot path. UDP truncation is retried over DNS-over-TCP.
 * The protector must exclude both socket types from the local VPN to prevent loops.
 */
class DnsUpstreamClient(
    private val config: DnsUpstreamConfig,
    private val socketProtector: DnsSocketProtector = NoOpDnsSocketProtector,
) {
    private sealed interface UdpAttempt {
        data class Response(val bytes: ByteArray, val truncated: Boolean) : UdpAttempt
        data class Failure(val reason: String) : UdpAttempt
    }

    fun exchange(query: ByteArray): DnsUpstreamResult {
        val question = when (val parsed = DnsMessageParser.parse(query)) {
            is DnsParseResult.Valid -> parsed.question
            is DnsParseResult.Invalid -> return DnsUpstreamResult.Failure(parsed.reason)
        }
        if (question.dnsClass != 1) {
            return DnsUpstreamResult.Failure("dns_upstream_query_class_unsupported")
        }

        return when (val udp = exchangeUdp(query, question)) {
            is UdpAttempt.Failure -> DnsUpstreamResult.Failure(udp.reason)
            is UdpAttempt.Response -> if (udp.truncated) {
                exchangeTcp(query, question)
            } else {
                DnsUpstreamResult.Success(DnsUpstreamResponse(udp.bytes, DnsUpstreamTransport.UDP))
            }
        }
    }

    private fun exchangeUdp(query: ByteArray, question: DnsQuestion): UdpAttempt = try {
        DatagramSocket().use { socket ->
            socket.soTimeout = config.timeoutMillis
            if (!socketProtector.protect(socket)) {
                return UdpAttempt.Failure("dns_upstream_udp_socket_protection_failed")
            }
            socket.connect(InetSocketAddress(config.host, config.port))
            socket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(config.udpBufferBytes)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val response = buffer.copyOf(packet.length)
            val invalidReason = validateResponse(query, question, response)
            if (invalidReason != null) return UdpAttempt.Failure(invalidReason)
            UdpAttempt.Response(response, flags(response) and FLAG_TRUNCATED != 0)
        }
    } catch (_: SocketTimeoutException) {
        UdpAttempt.Failure("dns_upstream_udp_timeout")
    } catch (_: SecurityException) {
        UdpAttempt.Failure("dns_upstream_udp_security_error")
    } catch (_: IOException) {
        UdpAttempt.Failure("dns_upstream_udp_io_error")
    } catch (_: IllegalArgumentException) {
        UdpAttempt.Failure("dns_upstream_udp_endpoint_invalid")
    }

    private fun exchangeTcp(query: ByteArray, question: DnsQuestion): DnsUpstreamResult = try {
        Socket().use { socket ->
            if (!socketProtector.protect(socket)) {
                return DnsUpstreamResult.Failure("dns_upstream_tcp_socket_protection_failed")
            }
            socket.connect(InetSocketAddress(config.host, config.port), config.timeoutMillis)
            socket.soTimeout = config.timeoutMillis
            socket.getOutputStream().apply {
                write(DnsTcpFrameCodec.encode(query))
                flush()
            }
            val input = DataInputStream(socket.getInputStream())
            val frameLength = input.readUnsignedShort()
            if (frameLength < DNS_HEADER_SIZE) {
                return DnsUpstreamResult.Failure("dns_upstream_tcp_frame_too_short")
            }
            val response = ByteArray(frameLength)
            input.readFully(response)
            val invalidReason = validateResponse(query, question, response)
            if (invalidReason != null) return DnsUpstreamResult.Failure(invalidReason)
            if (flags(response) and FLAG_TRUNCATED != 0) {
                return DnsUpstreamResult.Failure("dns_upstream_tcp_response_truncated")
            }
            DnsUpstreamResult.Success(DnsUpstreamResponse(response, DnsUpstreamTransport.TCP))
        }
    } catch (_: SocketTimeoutException) {
        DnsUpstreamResult.Failure("dns_upstream_tcp_timeout")
    } catch (_: EOFException) {
        DnsUpstreamResult.Failure("dns_upstream_tcp_response_incomplete")
    } catch (_: SecurityException) {
        DnsUpstreamResult.Failure("dns_upstream_tcp_security_error")
    } catch (_: IOException) {
        DnsUpstreamResult.Failure("dns_upstream_tcp_io_error")
    } catch (_: IllegalArgumentException) {
        DnsUpstreamResult.Failure("dns_upstream_tcp_endpoint_invalid")
    }

    private fun validateResponse(query: ByteArray, question: DnsQuestion, response: ByteArray): String? {
        if (response.size < DNS_HEADER_SIZE) return "dns_upstream_response_header_truncated"
        if (u16(response, 0) != question.id) return "dns_upstream_transaction_id_mismatch"
        val responseFlags = flags(response)
        if (responseFlags and FLAG_RESPONSE == 0) return "dns_upstream_packet_is_not_response"
        if ((responseFlags and OPCODE_MASK) != (question.requestFlags and OPCODE_MASK)) {
            return "dns_upstream_opcode_mismatch"
        }
        if (u16(response, 4) != 1) return "dns_upstream_question_count_unsupported"
        val questionEnd = DNS_HEADER_SIZE + question.wireQuestion.size
        if (response.size < questionEnd) return "dns_upstream_response_question_truncated"
        if (!response.copyOfRange(DNS_HEADER_SIZE, questionEnd).contentEquals(question.wireQuestion)) {
            return "dns_upstream_question_mismatch"
        }
        // The original query is validated before this method; retain this check to
        // make accidental use with a different query/question pair fail closed.
        if (u16(query, 0) != question.id) return "dns_upstream_query_mismatch"
        return null
    }

    private fun flags(message: ByteArray): Int = u16(message, 2)

    private fun u16(message: ByteArray, offset: Int): Int =
        ((message[offset].toInt() and 0xff) shl 8) or (message[offset + 1].toInt() and 0xff)

    private companion object {
        const val DNS_HEADER_SIZE = 12
        const val FLAG_RESPONSE = 0x8000
        const val FLAG_TRUNCATED = 0x0200
        const val OPCODE_MASK = 0x7800
    }
}
