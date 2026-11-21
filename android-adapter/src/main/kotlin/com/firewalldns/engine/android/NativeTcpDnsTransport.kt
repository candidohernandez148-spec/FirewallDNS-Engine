package com.firewalldns.engine.android

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean

sealed interface NativeTcpDnsEvent {
    data class SessionOpened(
        val sessionId: Long,
        val clientAddress: ByteArray,
        val clientPort: Int,
        val serverAddress: ByteArray,
        val serverPort: Int,
    ) : NativeTcpDnsEvent

    data class Data(val sessionId: Long, val bytes: ByteArray) : NativeTcpDnsEvent
    data class PeerHalfClosed(val sessionId: Long) : NativeTcpDnsEvent
    data class SessionClosed(val sessionId: Long) : NativeTcpDnsEvent
}

/**
 * JNI facade for the single-owner smoltcp TCP/53 transport.
 *
 * enqueuePacket is safe from the TUN reader thread: native code only appends
 * to a separate bounded ingress queue. All other native calls must be made
 * by the same dedicated owner thread that first calls poll().
 */
class NativeTcpDnsTransport private constructor(
    private val handle: Long,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)

    fun enqueuePacket(packet: ByteArray): Int {
        if (closed.get()) return ERROR_CLOSED
        return nativeEnqueuePacket(handle, packet, packet.size)
    }

    fun poll(nowElapsedMillis: Long, maxIngressPackets: Int = 32): Int {
        if (closed.get()) return ERROR_CLOSED
        return nativePoll(handle, nowElapsedMillis, maxIngressPackets)
    }

    fun takePacket(): ByteArray? {
        if (closed.get()) return null
        return nativeTakePacket(handle).takeUnless { it.isEmpty() }
    }

    fun takeEvent(): NativeTcpDnsEvent? {
        if (closed.get()) return null
        val bytes = nativeTakeEvent(handle)
        if (bytes.isEmpty()) return null
        return decodeEvent(bytes)
    }

    /** Queues one complete framed DNS response; call only on the owner thread. */
    fun queueResponse(sessionId: Long, framedDnsResponse: ByteArray): Int {
        if (closed.get()) return ERROR_CLOSED
        return nativeQueueResponse(handle, sessionId, framedDnsResponse)
    }

    /** Requests graceful FIN or immediate RST; call only on the owner thread. */
    fun closeSession(sessionId: Long, abort: Boolean = false): Boolean {
        if (closed.get()) return false
        return nativeCloseSession(handle, sessionId, if (abort) 1 else 0) == RESULT_OK
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) nativeDestroy(handle)
    }

    private fun decodeEvent(bytes: ByteArray): NativeTcpDnsEvent? = runCatching {
        val input = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        when (input.get().toInt() and 0xff) {
            EVENT_SESSION_OPENED -> {
                val sessionId = input.long
                val clientAddress = readAddress(input)
                val clientPort = input.short.toInt() and 0xffff
                val serverAddress = readAddress(input)
                val serverPort = input.short.toInt() and 0xffff
                require(!input.hasRemaining())
                NativeTcpDnsEvent.SessionOpened(
                    sessionId,
                    clientAddress,
                    clientPort,
                    serverAddress,
                    serverPort,
                )
            }
            EVENT_DATA -> {
                val sessionId = input.long
                val length = input.int
                require(length >= 0 && length == input.remaining())
                val payload = ByteArray(length)
                input.get(payload)
                NativeTcpDnsEvent.Data(sessionId, payload)
            }
            EVENT_PEER_HALF_CLOSED -> {
                val sessionId = input.long
                require(!input.hasRemaining())
                NativeTcpDnsEvent.PeerHalfClosed(sessionId)
            }
            EVENT_SESSION_CLOSED -> {
                val sessionId = input.long
                require(!input.hasRemaining())
                NativeTcpDnsEvent.SessionClosed(sessionId)
            }
            else -> null
        }
    }.getOrNull()

    private fun readAddress(input: ByteBuffer): ByteArray {
        val family = input.get().toInt() and 0xff
        val length = when (family) {
            4 -> 4
            6 -> 16
            else -> error("Unsupported IP address family")
        }
        require(input.remaining() >= length + 2)
        return ByteArray(length).also { input.get(it) }
    }

    companion object {
        const val RESULT_OK = 1
        private const val ERROR_CLOSED = -100
        private const val EVENT_SESSION_OPENED = 1
        private const val EVENT_DATA = 2
        private const val EVENT_PEER_HALF_CLOSED = 3
        private const val EVENT_SESSION_CLOSED = 4

        init {
            System.loadLibrary("firewalldns_native")
        }

        fun create(
            mtu: Int,
            tunClientIpv4: ByteArray,
            tunClientIpv6: ByteArray,
            maxSessions: Int = 64,
        ): NativeTcpDnsTransport? {
            require(tunClientIpv4.size == 4)
            require(tunClientIpv6.size == 16)
            val factory = NativeTcpDnsTransport(0L)
            val handle = factory.nativeCreate(mtu, tunClientIpv4, tunClientIpv6, maxSessions)
            return handle.takeIf { it > 0L }?.let(::NativeTcpDnsTransport)
        }
    }

    private external fun nativeCreate(
        mtu: Int,
        tunClientIpv4: ByteArray,
        tunClientIpv6: ByteArray,
        maxSessions: Int,
    ): Long
    private external fun nativeEnqueuePacket(handle: Long, packet: ByteArray, length: Int): Int
    private external fun nativePoll(handle: Long, nowMillis: Long, maxIngressPackets: Int): Int
    private external fun nativeTakePacket(handle: Long): ByteArray
    private external fun nativeTakeEvent(handle: Long): ByteArray
    private external fun nativeQueueResponse(handle: Long, sessionId: Long, response: ByteArray): Int
    private external fun nativeCloseSession(handle: Long, sessionId: Long, abort: Int): Int
    private external fun nativeDestroy(handle: Long)
}
