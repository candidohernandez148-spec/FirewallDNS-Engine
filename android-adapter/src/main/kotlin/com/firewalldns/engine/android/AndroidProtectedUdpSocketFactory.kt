package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsSocketProtector
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetSocketAddress

/**
 * Creates one connected UDP socket for one transport flow.
 *
 * The socket is always excluded from the active VPN before connect() is called.
 * The caller owns the returned socket and must close it when its flow ends.
 * This factory does not create threads, queues, retries, or a second packet stack.
 */
class AndroidProtectedUdpSocketFactory(
    private val socketProtector: DnsSocketProtector,
    private val socketProvider: () -> DatagramSocket = { DatagramSocket(null) },
) {
    /**
     * Opens a protected UDP socket to a numeric, already-resolved endpoint.
     *
     * @throws IllegalArgumentException for unresolved endpoints or invalid limits.
     * @throws IOException when Android refuses protection or socket setup fails.
     */
    @Throws(IOException::class)
    fun open(
        remote: InetSocketAddress,
        timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
        receiveBufferBytes: Int = DEFAULT_BUFFER_BYTES,
    ): DatagramSocket {
        require(!remote.isUnresolved) { "UDP endpoint must already be resolved" }
        require(remote.port in 1..65_535) { "UDP endpoint port is invalid" }
        require(timeoutMillis in 1..MAX_TIMEOUT_MILLIS) { "UDP timeout is outside the allowed range" }
        require(receiveBufferBytes in MIN_BUFFER_BYTES..MAX_BUFFER_BYTES) {
            "UDP receive buffer is outside the allowed range"
        }

        val socket = socketProvider()
        try {
            socket.soTimeout = timeoutMillis
            socket.receiveBufferSize = receiveBufferBytes
            if (!socketProtector.protect(socket)) {
                throw IOException("firewalldns_udp_socket_protection_failed")
            }
            // Never move connect() above protect(): that would risk routing this
            // socket back into the VPN whose TUN is carrying the original flow.
            socket.connect(remote)
            return socket
        } catch (failure: Throwable) {
            runCatching { socket.close() }
            throw failure
        }
    }

    private companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 5_000
        const val MAX_TIMEOUT_MILLIS = 120_000
        const val DEFAULT_BUFFER_BYTES = 8_192
        const val MIN_BUFFER_BYTES = 512
        const val MAX_BUFFER_BYTES = 65_507
    }
}
