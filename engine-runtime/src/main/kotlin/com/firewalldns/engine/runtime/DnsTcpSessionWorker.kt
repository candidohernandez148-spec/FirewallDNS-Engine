package com.firewalldns.engine.runtime

import com.firewalldns.engine.dns.DnsTcpSessionProcessor
import java.util.ArrayDeque
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Runs DNS policy and upstream work away from the smoltcp owner thread.
 * The transport owner only offers ordered stream bytes and drains framed
 * response bytes; this worker never touches a TCP socket.
 */
class DnsTcpSessionWorker(
    private val processor: DnsTcpSessionProcessor,
    private val cancelUpstream: () -> Unit,
    private val onResponsesAvailable: () -> Unit = {},
    private val maxQueuedInputBytes: Int = DEFAULT_MAX_QUEUED_INPUT_BYTES,
    private val maxQueuedInputChunks: Int = DEFAULT_MAX_QUEUED_INPUT_CHUNKS,
    private val maxQueuedResponseBytes: Int = DEFAULT_MAX_QUEUED_RESPONSE_BYTES,
    private val maxQueuedResponseFrames: Int = DEFAULT_MAX_QUEUED_RESPONSE_FRAMES,
) : AutoCloseable {
    sealed interface OfferResult {
        data object Accepted : OfferResult
        data class Closed(val reason: String) : OfferResult
    }

    private val closed = AtomicBoolean(false)
    private val inputLock = Any()
    private val input = ArrayBlockingQueue<ByteArray>(maxQueuedInputChunks)
    private val inputBytes = AtomicInteger(0)
    private val outputLock = Any()
    private val output = ArrayDeque<ByteArray>()
    private var outputBytes = 0
    @Volatile private var terminalReason: String? = null

    private val worker: Thread

    init {
        require(maxQueuedInputBytes > 0)
        require(maxQueuedInputChunks > 0)
        require(maxQueuedResponseBytes > 0)
        require(maxQueuedResponseFrames > 0)
        worker = Thread(::runWorker, "FirewallDNS-DNS-TCP-session").apply {
            isDaemon = true
            start()
        }
    }

    val isClosed: Boolean get() = closed.get()
    val closeReason: String? get() = terminalReason
    val queuedInputBytes: Int get() = inputBytes.get()
    val queuedResponseBytes: Int
        get() = synchronized(outputLock) { outputBytes }

    /** Losing any TCP stream bytes is terminal because DNS framing would desynchronize. */
    fun offer(bytes: ByteArray, length: Int = bytes.size): OfferResult {
        if (length <= 0 || length > bytes.size) return closeWith("dns_tcp_worker_input_length_invalid")
        synchronized(inputLock) {
            terminalReason?.let { return OfferResult.Closed(it) }
            if (closed.get()) return OfferResult.Closed(terminalReason ?: "dns_tcp_worker_closed")
            val currentBytes = inputBytes.get()
            val nextBytes = currentBytes + length
            if (nextBytes < currentBytes || nextBytes > maxQueuedInputBytes) {
                closeLocked("dns_tcp_worker_input_limit_exceeded")
                return OfferResult.Closed(terminalReason!!)
            }
            inputBytes.set(nextBytes)
            if (!input.offer(bytes.copyOf(length))) {
                inputBytes.addAndGet(-length)
                closeLocked("dns_tcp_worker_queue_full")
                return OfferResult.Closed(terminalReason!!)
            }
        }
        return OfferResult.Accepted
    }

    /** Called only by the smoltcp owner thread; byte chunks remain FIFO ordered. */
    fun drainResponses(maxFrames: Int = DEFAULT_DRAIN_BATCH): List<ByteArray> {
        require(maxFrames in 1..MAX_DRAIN_BATCH)
        synchronized(outputLock) {
            val drained = ArrayList<ByteArray>(minOf(maxFrames, output.size))
            repeat(minOf(maxFrames, output.size)) {
                val frame = output.removeFirst()
                outputBytes -= frame.size
                drained += frame
            }
            return drained
        }
    }

    override fun close() {
        closeWith("dns_tcp_worker_closed")
    }

    private fun closeWith(reason: String): OfferResult.Closed {
        synchronized(inputLock) {
            closeLocked(reason)
            return OfferResult.Closed(terminalReason!!)
        }
    }

    private fun closeLocked(reason: String) {
        if (!closed.compareAndSet(false, true)) return
        terminalReason = reason.ifBlank { "dns_tcp_worker_closed" }
        input.clear()
        inputBytes.set(0)
        synchronized(outputLock) {
            output.clear()
            outputBytes = 0
        }
        runCatching(cancelUpstream)
        worker.interrupt()
    }

    private fun runWorker() {
        try {
            while (!closed.get()) {
                val chunk = try {
                    input.take()
                } catch (_: InterruptedException) {
                    break
                }
                val stopAfterTake = synchronized(inputLock) {
                    if (closed.get()) true else {
                        inputBytes.addAndGet(-chunk.size)
                        false
                    }
                }
                if (stopAfterTake || closed.get()) break

                var result = processor.onIncomingBytes(chunk)
                while (!closed.get()) {
                    when (result) {
                        is DnsTcpSessionProcessor.ProcessResult.Processed -> {
                            val bytes = processor.pollOutbound(processor.maxPendingOutboundBytes)
                            if (!enqueueFramedResponses(bytes)) return
                            if (!result.hasMoreWork) break
                            result = processor.processPendingFrames()
                        }
                        DnsTcpSessionProcessor.ProcessResult.Backpressure -> {
                            closeWith("dns_tcp_worker_processor_backpressure")
                            return
                        }
                        DnsTcpSessionProcessor.ProcessResult.Closed -> {
                            closeWith("dns_tcp_processor_closed")
                            return
                        }
                        is DnsTcpSessionProcessor.ProcessResult.TerminalError -> {
                            closeWith(result.reason)
                            return
                        }
                    }
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: Exception) {
            closeWith("dns_tcp_worker_processing_failed")
        } finally {
            processor.close()
        }
    }

    /** Splits the processor's concatenated RFC 1035 frames without changing their bytes. */
    private fun enqueueFramedResponses(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return true
        val frames = ArrayList<ByteArray>()
        var offset = 0
        while (offset < bytes.size) {
            if (bytes.size - offset < 2) {
                closeWith("dns_tcp_worker_invalid_outbound_framing")
                return false
            }
            val length = ((bytes[offset].toInt() and 0xff) shl 8) or
                (bytes[offset + 1].toInt() and 0xff)
            val frameSize = 2 + length
            if (length < 12 || frameSize > bytes.size - offset) {
                closeWith("dns_tcp_worker_invalid_outbound_framing")
                return false
            }
            frames += bytes.copyOfRange(offset, offset + frameSize)
            offset += frameSize
        }
        return enqueueResponses(frames)
    }

    private fun enqueueResponses(frames: List<ByteArray>): Boolean {
        if (frames.isEmpty()) return true
        val added = synchronized(outputLock) {
            val additionalBytes = frames.sumOf { it.size.toLong() }
            if (output.size + frames.size > maxQueuedResponseFrames ||
                additionalBytes + outputBytes > maxQueuedResponseBytes
            ) {
                false
            } else {
                frames.forEach { output.addLast(it.copyOf()) }
                outputBytes += additionalBytes.toInt()
                true
            }
        }
        if (!added) {
            closeWith("dns_tcp_worker_response_limit_exceeded")
            return false
        }
        runCatching(onResponsesAvailable)
        return true
    }

    private companion object {
        const val DEFAULT_MAX_QUEUED_INPUT_BYTES = 256 * 1024
        const val DEFAULT_MAX_QUEUED_INPUT_CHUNKS = 32
        const val DEFAULT_MAX_QUEUED_RESPONSE_BYTES = 256 * 1024
        const val DEFAULT_MAX_QUEUED_RESPONSE_FRAMES = 128
        const val DEFAULT_DRAIN_BATCH = 16
        const val MAX_DRAIN_BATCH = 64
    }
}
