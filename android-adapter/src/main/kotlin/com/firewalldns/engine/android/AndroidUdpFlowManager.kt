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
    /** Called once when a flow has received/sent no datagrams for its configured idle period. */
    fun onIdleTimeout() = Unit
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
 * Idle flows expire automatically, releasing their socket, worker and flow-limit slot.
 * This is not a production packet path.
 */
class AndroidUdpFlowManager(
    private val socketFactory: AndroidProtectedUdpSocketFactory,
    maxFlows: Int = DEFAULT_MAX_FLOWS,
    maxQueuedDatagramsPerFlow: Int = DEFAULT_QUEUE_CAPACITY,
    maxDatagramBytes: Int = DEFAULT_MAX_DATAGRAM_BYTES,
    maxQueuedBytesPerFlow: Int = DEFAULT_MAX_QUEUED_BYTES_PER_FLOW,
    receivePollTimeoutMillis: Int = DEFAULT_RECEIVE_POLL_TIMEOUT_MILLIS,
    idleTimeoutMillis: Int = DEFAULT_IDLE_TIMEOUT_MILLIS,
) : AutoCloseable {
    private val flowLimit = maxFlows.also { require(it in 1..MAX_ALLOWED_FLOWS) }
    private val queueLimit = maxQueuedDatagramsPerFlow.also { require(it in 1..MAX_ALLOWED_QUEUE_CAPACITY) }
    private val datagramLimit = maxDatagramBytes.also { require(it in 1..MAX_ALLOWED_DATAGRAM_BYTES) }
    private val byteQueueLimit = maxQueuedBytesPerFlow.also { require(it in datagramLimit..MAX_ALLOWED_QUEUED_BYTES_PER_FLOW) }
    private val pollTimeout = receivePollTimeoutMillis.also { require(it in 10..1_000) }
    private val idleTimeout = idleTimeoutMillis.also { require(it in pollTimeout..MAX_IDLE_TIMEOUT_MILLIS) }

    init {
        require(flowLimit.toLong() * byteQueueLimit.toLong() <= MAX_QUEUED_BYTES) {
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
        // Flow workers remove themselves from the registry in finally. Use the
        // same lock for snapshot/removal so close() cannot race a weakly
        // consistent ConcurrentHashMap traversal while capacity is released.
        val snapshot = synchronized(lock) { flows.values.toList() }
        snapshot.forEach { it.close() }
        executor.shutdownNow()
        synchronized(lock) { flows.clear() }
    }

    private inner class Flow(
        override val id: Long,
        private val socket: DatagramSocket,
        private val listener: AndroidUdpFlowListener,
    ) : AndroidUdpFlow, Runnable {
        private val active = AtomicBoolean(true)
        private val lastActivityNanos = AtomicLong(System.nanoTime())
        private val outbound = ArrayBlockingQueue<ByteArray>(queueLimit)
        private val outboundLock = Any()
        private var outboundBytes = 0

        override fun send(datagram: ByteArray): Boolean {
            if (datagram.isEmpty() || datagram.size > datagramLimit || !active.get()) {
                rejected.incrementAndGet()
                return false
            }
            synchronized(outboundLock) {
                if (!active.get() || outbound.size >= queueLimit || datagram.size > byteQueueLimit - outboundBytes) {
                    rejected.incrementAndGet()
                    return false
                }
                if (!outbound.offer(datagram.copyOf())) {
                    rejected.incrementAndGet()
                    return false
                }
                outboundBytes += datagram.size
                lastActivityNanos.set(System.nanoTime())
                return true
            }
        }

        override fun close() {
            if (!active.compareAndSet(true, false)) return
            synchronized(outboundLock) {
                outbound.clear()
                outboundBytes = 0
            }
            closeSocket()
        }

        fun closeSocket() {
            runCatching { socket.close() }
        }

        override fun run() {
            val receiveBuffer = ByteArray(datagramLimit + 1)
            try {
                while (active.get() && !closed.get()) {
                    while (true) {
                        val pending = synchronized(outboundLock) {
                            outbound.poll()?.also { outboundBytes = (outboundBytes - it.size).coerceAtLeast(0) }
                        } ?: break
                        socket.send(DatagramPacket(pending, pending.size))
                        sent.incrementAndGet()
                        lastActivityNanos.set(System.nanoTime())
                    }

                    try {
                        val packet = DatagramPacket(receiveBuffer, receiveBuffer.size)
                        socket.receive(packet)
                        if (active.get() && packet.length > datagramLimit) {
                            rejected.incrementAndGet()
                        } else if (active.get() && packet.length > 0) {
                            lastActivityNanos.set(System.nanoTime())
                            received.incrementAndGet()
                            listener.onDatagram(receiveBuffer.copyOfRange(packet.offset, packet.offset + packet.length))
                        }
                    } catch (_: SocketTimeoutException) {
                        if (idleDurationReached()) {
                            runCatching { listener.onIdleTimeout() }
                            break
                        }
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
                synchronized(outboundLock) {
                    outbound.clear()
                    outboundBytes = 0
                }
                closeSocket()
                synchronized(lock) { flows.remove(id, this) }
            }
        }

        private fun idleDurationReached(): Boolean =
            System.nanoTime() - lastActivityNanos.get() >= idleTimeout.toLong() * NANOS_PER_MILLI
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
        const val DEFAULT_MAX_QUEUED_BYTES_PER_FLOW = 256 * 1024
        const val MAX_ALLOWED_QUEUED_BYTES_PER_FLOW = 256 * 1024
        const val DEFAULT_RECEIVE_POLL_TIMEOUT_MILLIS = 100
        const val DEFAULT_IDLE_TIMEOUT_MILLIS = 60_000
        const val MAX_IDLE_TIMEOUT_MILLIS = 300_000
        const val NANOS_PER_MILLI = 1_000_000L
        const val MIN_RECEIVE_BUFFER_BYTES = 512
    }
}
