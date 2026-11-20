package com.firewalldns.engine.runtime

import java.util.ArrayDeque
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Moves ordered TCP stream chunks through [DnsTcpSessionProcessor] on one bounded
 * I/O worker. The smoltcp poll thread only calls [offer] and [drainResponses];
 * it never performs DNS policy evaluation or upstream network I/O.
 *
 * The host must call [close] when the TCP socket closes and provide
 * [cancelUpstream] that closes the active protected upstream socket. Response
 * frames are drained by the owner of the smoltcp SocketSet, never written to a
 * smoltcp socket from this worker.
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

    /**
     * Offers one ordered TCP receive chunk. Any rejected chunk closes the
     * logical session: continuing after losing stream bytes would desynchronize
     * DNS framing and is therefore unsafe.
     */
    fun offer(bytes: ByteArray, length: Int = bytes.size): OfferResult {
        if (length <= 0 || length > bytes.size) {
            return closeWith("dns_tcp_worker_input_length_invalid")
        }
        synchronized(inputLock) {
            terminalReason?.let { return OfferResult.Closed(it) }
            if (closed.get()) return OfferResult.Closed(terminalReason ?: "dns_tcp_worker_closed")
            val nextBytes = inputBytes.get() + length
            if (nextBytes < inputBytes.get() || nextBytes > maxQueuedInputBytes) {
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

    /** Called by the smoltcp owner thread to move completed DNS frames to its TCP socket. */
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
        try {
            cancelUpstream()
        } catch (_: Exception) {
            // Cancellation is best-effort; the worker is still interrupted below.
        }
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
                inputBytes.addAndGet(-chunk.size)
                var result = processor.accept(chunk)
                while (true) {
                    when (result) {
                        is DnsTcpSessionProcessor.Result.Closed -> {
                            closeWith(result.reason)
                            return
                        }
                        is DnsTcpSessionProcessor.Result.Batch -> {
                            if (!enqueueResponses(result.framedResponses)) return
                            if (!result.hasBufferedData) break
                            result = processor.accept(byteArrayOf())
                        }
                    }
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: Exception) {
            closeWith("dns_tcp_worker_processing_failed")
        } finally {
            processor.close(terminalReason ?: "dns_tcp_worker_stopped")
        }
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
        try {
            onResponsesAvailable()
        } catch (_: Exception) {
            // A wake-up callback must never affect DNS processing or socket state.
        }
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
