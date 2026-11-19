package com.firewalldns.engine.android

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Receives one datagram at a time on the flow worker. Implementations must return quickly. */
interface AndroidUdpFlowListener {
    fun onDatagram(datagram: ByteArray)
    fun onFailure(cause: IOException) = Unit
}

/** A single remote UDP association. The manager owns its socket and worker lifecycle. */
interface AndroidUdpFlow : AutoCloseable {
    val id: Long

    /** Enqueues a copy; false means the flow is closed or its bounded queue is full. */
    fun send(datagram: ByteArray): Boolean

    override fun close()
}

/**
 * Experimental, bounded UDP flow manager.
 *
 * Each flow has one worker that alternates bounded outbound sends with timed receives.
 * All sockets come from AndroidProtectedUdpSocketFactory, so protect() precedes connect().
 * This is not a TUN/smoltcp bridge and must not be used as a production packet path yet.
 */
class AndroidUdpFlowManager(
    private val socketFactory: AndroidProtectedUdpSocketFactory,
    maxFlows: Int = DEFAULT_MAX_FLOWS,
    maxQueuedDatagramsPerFlow: Int = DEFAULT_QUEUE_CAPACITY,
    maxDatagramBytes: Int = DEFAULT_MAX_DATAGRAM_BYTES,
    receivePollTimeoutMillis: Int = DEFAULT_RECEIVE_POLL_TIMEOUT_MILLIS,
) : AutoCloseable {
    private val flowLimit = maxFlows.also { require(it in 1..MAX_ALLOWED_FLOWS) }
    private val queueLimit = maxQueuedDatagramsPerFlow.also { require(it in 1..MAX_ALLOWED_QUEUE_CAPACITY) }
    private val datagramLimit = maxDatagramBytes.also { require(it in 1..MAX_ALLOWED_DATAGRAM_BYTES) }
    private val pollTimeout = receivePollTimeoutMillis.also { require(it in 10..1_000) }

    init {
        require(flowLimit.toLong() * queueLimit.toLong() * datagramLimit.toLong() <= MAX_QUEUED_BYTES) {
            "firewalldns_udp_queue_memory_limit_exceeded"
        }
    }

    private val lock = Any()
    private val closed = AtomicBoolean(false)
    private val nextId = AtomicLong(1)
    private val sent = AtomicLong()
    private val received = AtomicLong()
    private val rejected = AtomicLong()
    private val flows = ConcurrentHashMap<Long, Flow>()
    private val executor = Executors.newFixedThreadPool(flowLimit, FlowThreadFactory())

    val activeFlowCount: Int get() = flows.size
    val sentDatagramCount: Long get() = sent.get()
    val receivedDatagramCount: Long get() = received.get()
    val rejectedDatagramCount: Long get() = rejected.get()

    /** Opens a protected flow or fails without exceeding the configured flow limit. */
    @Throws(IOException::class)
    fun open(remote: InetSocketAddress, listener: AndroidUdpFlowListener): AndroidUdpFlow {
        synchronized(lock) {
            check(!closed.get()) { "firewalldns_udp_manager_closed" }
            check(flows.size < flowLimit) { "firewalldns_udp_flow_limit_reached" }

            val socket = socketFactory.open(
                remote = remote,
                timeoutMillis = pollTimeout,
                receiveBufferBytes = maxOf(MIN_RECEIVE_BUFFER_BYTES, datagramLimit),
            )
            val id = nextId.getAndIncrement()
            val flow = Flow(id, socket, listener)
            flows[id] = flow
            try {
                executor.execute(flow)
            } catch (failure: RejectedExecutionException) {
                flows.remove(id, flow)
                flow.closeSocket()
                throw IOException("firewalldns_udp_worker_unavailable", failure)
            }
            return flow
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        val snapshot = synchronized(lock) { flows.values.toList() }
        snapshot.forEach { it.close() }
        executor.shutdownNow()
        flows.clear()
    }

    private inner class Flow(
        override val id: Long,
        private val socket: DatagramSocket,
        private val listener: AndroidUdpFlowListener,
    ) : AndroidUdpFlow, Runnable {
        private val active = AtomicBoolean(true)
        private val outbound = ArrayBlockingQueue<ByteArray>(queueLimit)

        override fun send(datagram: ByteArray): Boolean {
            if (datagram.isEmpty() || datagram.size > datagramLimit || !active.get()) {
                rejected.incrementAndGet()
                return false
            }
            val accepted = outbound.offer(datagram.copyOf())
            if (!accepted || !active.get()) {
                rejected.incrementAndGet()
                if (!active.get()) outbound.clear()
                return false
            }
            return true
        }

        override fun close() {
            if (!active.compareAndSet(true, false)) return
            outbound.clear()
            closeSocket()
        }

        fun closeSocket() {
            runCatching { socket.close() }
        }

        override fun run() {
            val receiveBuffer = ByteArray(datagramLimit)
            try {
                while (active.get() && !closed.get()) {
                    while (true) {
                        val pending = outbound.poll() ?: break
                        socket.send(DatagramPacket(pending, pending.size))
                        sent.incrementAndGet()
                    }

                    try {
                        val packet = DatagramPacket(receiveBuffer, receiveBuffer.size)
                        socket.receive(packet)
                        if (active.get() && packet.length > 0) {
                            received.incrementAndGet()
                            listener.onDatagram(receiveBuffer.copyOfRange(packet.offset, packet.offset + packet.length))
                        }
                    } catch (_: SocketTimeoutException) {
                        // Timed receive lets the worker service its outbound queue and observe shutdown.
                    }
                }
            } catch (failure: IOException) {
                if (active.get() && !closed.get()) {
                    runCatching { listener.onFailure(failure) }
                }
            } catch (failure: RuntimeException) {
                if (active.get() && !closed.get()) {
                    runCatching { listener.onFailure(IOException("firewalldns_udp_listener_failed", failure)) }
                }
            } finally {
                active.set(false)
                outbound.clear()
                closeSocket()
                flows.remove(id, this)
            }
        }
    }

    private class FlowThreadFactory : ThreadFactory {
        private val sequence = AtomicLong()
        override fun newThread(runnable: Runnable): Thread =
            Thread(runnable, "FirewallDNS-UDP-${sequence.incrementAndGet()}").apply {
                isDaemon = true
            }
    }

    private companion object {
        const val DEFAULT_MAX_FLOWS = 32
        const val MAX_ALLOWED_FLOWS = 128
        const val DEFAULT_QUEUE_CAPACITY = 64
        const val MAX_ALLOWED_QUEUE_CAPACITY = 256
        const val DEFAULT_MAX_DATAGRAM_BYTES = 1_500
        const val MAX_ALLOWED_DATAGRAM_BYTES = 65_507
        const val MAX_QUEUED_BYTES = 16L * 1024L * 1024L
        const val DEFAULT_RECEIVE_POLL_TIMEOUT_MILLIS = 100
        const val MIN_RECEIVE_BUFFER_BYTES = 512
    }
}
