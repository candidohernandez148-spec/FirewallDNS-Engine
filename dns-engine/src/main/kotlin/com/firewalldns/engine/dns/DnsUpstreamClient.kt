package com.firewalldns.engine.dns

import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Socket protection hook implemented by the Android VpnService adapter. */
interface DnsSocketProtector {
    fun protect(socket: DatagramSocket): Boolean
    fun protect(socket: Socket): Boolean
}

data class DnsUpstreamConfig(
    val host: String,
    val port: Int = 53,
    val timeoutMillis: Int = 2_000,
    val udpBufferBytes: Int = 4_096,
) {
    init {
        require(isNumericAddress(host)) { "DNS upstream host must be a numeric IPv4 or IPv6 address" }
        require(port in 1..65_535) { "DNS upstream port is invalid" }
        require(timeoutMillis > 0) { "DNS timeout must be positive" }
        require(udpBufferBytes in 512..65_535) { "DNS UDP buffer size is invalid" }
    }

    private fun isNumericAddress(value: String): Boolean {
        if (value.contains(':')) {
            if (!value.matches(Regex("[0-9A-Fa-f:.]+"))) return false
            return runCatching { InetAddress.getByName(value) is Inet6Address }.getOrDefault(false)
        }
        val octets = value.split('.')
        return octets.size == 4 && octets.all { octet ->
            octet.isNotEmpty() && (octet == "0" || !octet.startsWith('0')) &&
                octet.toIntOrNull()?.let { it in 0..255 } == true
        }
    }
}

enum class DnsUpstreamTransport { UDP, TCP, CACHE }

data class DnsUpstreamResponse(
    val message: ByteArray,
    val transport: DnsUpstreamTransport,
)

sealed interface DnsUpstreamResult {
    data class Success(val response: DnsUpstreamResponse) : DnsUpstreamResult
    data class Failure(val reason: String) : DnsUpstreamResult
    data object Cancelled : DnsUpstreamResult
}

class DnsUpstreamClient(
    private val config: DnsUpstreamConfig,
    private val socketProtector: DnsSocketProtector,
    private val responseCache: DnsResponseCache = DnsResponseCache(),
    private val monotonicClockNanos: () -> Long = System::nanoTime,
) {
    private sealed interface UdpAttempt {
        data class Response(val bytes: ByteArray, val truncated: Boolean) : UdpAttempt
        data class Failure(val reason: String) : UdpAttempt
        data object Cancelled : UdpAttempt
    }

    fun exchange(query: ByteArray): DnsUpstreamResult = exchange(query, DnsExchangeCancellation())

    fun exchange(query: ByteArray, cancellation: DnsExchangeCancellation): DnsUpstreamResult {
        if (cancellation.isCancelled) return DnsUpstreamResult.Cancelled
        val question = when (val parsed = DnsMessageParser.parse(query)) {
            is DnsParseResult.Valid -> parsed.question
            is DnsParseResult.Invalid -> return DnsUpstreamResult.Failure(parsed.reason)
        }
        val upstreamIdentity = "${config.host}:${config.port}"
        responseCache.get(upstreamIdentity, query, monotonicClockNanos())?.let {
            return DnsUpstreamResult.Success(it)
        }
        val result = when (val udp = exchangeUdp(query, question, cancellation)) {
            is UdpAttempt.Failure -> DnsUpstreamResult.Failure(udp.reason)
            UdpAttempt.Cancelled -> DnsUpstreamResult.Cancelled
            is UdpAttempt.Response -> if (cancellation.isCancelled) {
                DnsUpstreamResult.Cancelled
            } else if (udp.truncated) {
                exchangeTcp(query, question, cancellation)
            } else {
                DnsUpstreamResult.Success(DnsUpstreamResponse(udp.bytes, DnsUpstreamTransport.UDP))
            }
        }
        if (result is DnsUpstreamResult.Success) {
            responseCache.put(upstreamIdentity, query, result.response.message, monotonicClockNanos())
        }
        return result
    }

    private fun exchangeUdp(query: ByteArray, question: DnsQuestion, cancellation: DnsExchangeCancellation): UdpAttempt = try {
        DatagramSocket().use { socket ->
            if (!cancellation.register(socket)) return UdpAttempt.Cancelled
            try {
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
            } finally {
                cancellation.unregister(socket)
            }
        }
    } catch (_: SocketTimeoutException) {
        if (cancellation.isCancelled) UdpAttempt.Cancelled else UdpAttempt.Failure("dns_upstream_udp_timeout")
    } catch (_: SecurityException) {
        if (cancellation.isCancelled) UdpAttempt.Cancelled else UdpAttempt.Failure("dns_upstream_udp_security_error")
    } catch (_: IOException) {
        if (cancellation.isCancelled) UdpAttempt.Cancelled else UdpAttempt.Failure("dns_upstream_udp_io_error")
    } catch (_: IllegalArgumentException) {
        UdpAttempt.Failure("dns_upstream_udp_endpoint_invalid")
    }

    private fun exchangeTcp(query: ByteArray, question: DnsQuestion, cancellation: DnsExchangeCancellation): DnsUpstreamResult = try {
        Socket().use { socket ->
            if (!cancellation.register(socket)) return DnsUpstreamResult.Cancelled
            try {
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
            } finally {
                cancellation.unregister(socket)
            }
        }
    } catch (_: SocketTimeoutException) {
        if (cancellation.isCancelled) DnsUpstreamResult.Cancelled else DnsUpstreamResult.Failure("dns_upstream_tcp_timeout")
    } catch (_: EOFException) {
        if (cancellation.isCancelled) DnsUpstreamResult.Cancelled else DnsUpstreamResult.Failure("dns_upstream_tcp_response_incomplete")
    } catch (_: SecurityException) {
        if (cancellation.isCancelled) DnsUpstreamResult.Cancelled else DnsUpstreamResult.Failure("dns_upstream_tcp_security_error")
    } catch (_: IOException) {
        if (cancellation.isCancelled) DnsUpstreamResult.Cancelled else DnsUpstreamResult.Failure("dns_upstream_tcp_io_error")
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
        if (u16(query, 0) != question.id) return "dns_upstream_query_mismatch"
        return DnsUpstreamResponseValidator.validate(response, question.wireQuestion)
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
