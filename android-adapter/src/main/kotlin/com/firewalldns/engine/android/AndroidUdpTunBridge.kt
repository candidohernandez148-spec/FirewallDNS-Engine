package com.firewalldns.engine.android

import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/** Result of inspecting one packet read from the Android TUN descriptor. */
enum class UdpTunPacketResult {
    QUEUED,
    DNS_BYPASS,
    UNSUPPORTED,
    REJECTED,
}

/**
 * Experimental non-DNS UDP bridge for an isolated diagnostic TUN.
 *
 * It extracts complete UDP datagrams, sends payloads through Android protected
 * UDP sockets, and reconstructs IP/UDP responses for the TUN writer. The
 * optional endpoint mapper exists only for deterministic loopback diagnostics.
 * This class is not connected to the production VPN service.
 */
class AndroidUdpTunBridge(
    private val flowManager: AndroidUdpFlowManager,
    private val writeTunPacket: (ByteArray) -> Unit,
    private val mapRemoteEndpoint: (InetSocketAddress) -> InetSocketAddress = { it },
) : AutoCloseable {
    private data class FlowKey(
        val sourceAddress: String,
        val destinationAddress: String,
        val sourcePort: Int,
        val destinationPort: Int,
    )

    private val lock = Any()
    private val closed = AtomicBoolean(false)
    private val flows = ConcurrentHashMap<FlowKey, AndroidUdpFlow>()

    val activeFlowCount: Int get() = flows.size

    fun process(packet: ByteArray): UdpTunPacketResult {
        if (closed.get()) return UdpTunPacketResult.REJECTED
        val datagram = UdpTunPacketCodec.parse(packet) ?: return UdpTunPacketResult.UNSUPPORTED
        // DNS remains exclusively on the existing DNS processor path.
        if (datagram.destinationPort == DNS_PORT) return UdpTunPacketResult.DNS_BYPASS
        if (datagram.payload.isEmpty()) return UdpTunPacketResult.REJECTED

        val key = FlowKey(
            datagram.sourceAddress.hostAddress,
            datagram.destinationAddress.hostAddress,
            datagram.sourcePort,
            datagram.destinationPort,
        )
        val flow = try {
            synchronized(lock) {
                if (closed.get()) return UdpTunPacketResult.REJECTED
                flows[key] ?: openFlow(key, datagram).also { flows[key] = it }
            }
        } catch (_: IOException) {
            return UdpTunPacketResult.REJECTED
        } catch (_: RuntimeException) {
            return UdpTunPacketResult.REJECTED
        }

        return if (flow.send(datagram.payload)) UdpTunPacketResult.QUEUED
        else UdpTunPacketResult.REJECTED
    }

    private fun openFlow(key: FlowKey, request: UdpTunDatagram): AndroidUdpFlow {
        val remote = InetSocketAddress(request.destinationAddress, request.destinationPort)
        val mappedRemote = mapRemoteEndpoint(remote)
        require(!mappedRemote.isUnresolved) { "firewalldns_udp_remote_unresolved" }
        return flowManager.open(mappedRemote, object : AndroidUdpFlowListener {
            override fun onDatagram(datagram: ByteArray) {
                if (closed.get()) return
                val response = UdpTunPacketCodec.buildResponse(request, datagram) ?: return
                runCatching { writeTunPacket(response) }
            }

            override fun onFailure(cause: IOException) {
                removeFlow(key)
            }

            override fun onIdleTimeout() {
                removeFlow(key)
            }
        })
    }

    private fun removeFlow(key: FlowKey) {
        val removed = synchronized(lock) { flows.remove(key) }
        removed?.close()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        val snapshot = synchronized(lock) {
            flows.values.toList().also { flows.clear() }
        }
        snapshot.forEach { it.close() }
        flowManager.close()
    }

    private companion object {
        const val DNS_PORT = 53
    }
}
