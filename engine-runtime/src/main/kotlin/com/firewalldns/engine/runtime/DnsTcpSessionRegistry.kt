package com.firewalldns.engine.runtime

import java.util.concurrent.atomic.AtomicLong

/**
 * Owns the bounded lifecycle of DNS/TCP workers, one per accepted TCP flow.
 *
 * The transport owner (for example, the smoltcp SocketSet thread) supplies a
 * stable session id, forwards ordered receive chunks with [offer], drains
 * completed DNS frames with [drainResponses], and closes sessions on FIN/RST.
 * This registry never owns or accesses TCP sockets.
 *
 * [onResponsesAvailable] must only wake the transport owner. It must not poll,
 * mutate sockets, or perform network I/O from the worker thread.
 */
class DnsTcpSessionRegistry(
    private val processorFactory: (sessionId: Long) -> DnsTcpSessionProcessor,
    private val cancelUpstream: (sessionId: Long) -> Unit,
    private val onResponsesAvailable: (sessionId: Long) -> Unit,
    private val maxSessions: Int = DEFAULT_MAX_SESSIONS,
    private val idleTimeoutNanos: Long = DEFAULT_IDLE_TIMEOUT_NANOS,
    private val nowNanos: () -> Long = System::nanoTime,
) : AutoCloseable {
    sealed interface OpenResult {
        data object Opened : OpenResult
        data object AlreadyExists : OpenResult
        data object CapacityReached : OpenResult
        data object Closed : OpenResult
    }

    sealed interface OfferResult {
        data object MissingSession : OfferResult
        data class WorkerResult(val result: DnsTcpSessionWorker.OfferResult) : OfferResult
    }

    private class Entry(
        val worker: DnsTcpSessionWorker,
        initialActivityNanos: Long,
    ) {
        val lastActivityNanos = AtomicLong(initialActivityNanos)
    }

    private val lock = Any()
    private val sessions = LinkedHashMap<Long, Entry>()
    @Volatile private var closed = false

    init {
        require(maxSessions > 0)
        require(idleTimeoutNanos > 0)
    }

    val activeSessionCount: Int
        get() {
            synchronized(lock) {
                removeClosedLocked()
                return sessions.size
            }
        }

    /** Creates a worker for a newly established TCP flow. Duplicate ids are rejected. */
    fun openSession(sessionId: Long): OpenResult {
        synchronized(lock) {
            if (closed) return OpenResult.Closed
            removeClosedLocked()
            if (sessions.containsKey(sessionId)) return OpenResult.AlreadyExists
            if (sessions.size >= maxSessions) return OpenResult.CapacityReached

            val worker = DnsTcpSessionWorker(
                processor = processorFactory(sessionId),
                cancelUpstream = { cancelUpstream(sessionId) },
                onResponsesAvailable = { onResponsesAvailable(sessionId) },
            )
            sessions[sessionId] = Entry(worker, nowNanos())
            return OpenResult.Opened
        }
    }

    /** Copies and queues an ordered TCP receive chunk without doing DNS or network work here. */
    fun offer(sessionId: Long, bytes: ByteArray, length: Int = bytes.size): OfferResult {
        return synchronized(lock) {
            if (closed) return@synchronized OfferResult.MissingSession
            val entry = sessions[sessionId] ?: return@synchronized OfferResult.MissingSession
            val result = entry.worker.offer(bytes, length)
            if (result == DnsTcpSessionWorker.OfferResult.Accepted) {
                entry.lastActivityNanos.set(nowNanos())
            } else if (sessions[sessionId] === entry) {
                sessions.remove(sessionId)
            }
            OfferResult.WorkerResult(result)
        }
    }

    /** Called only by the TCP socket owner; returned frames remain in FIFO order. */
    fun drainResponses(sessionId: Long, maxFrames: Int = DEFAULT_DRAIN_BATCH): List<ByteArray> {
        val entry = synchronized(lock) { sessions[sessionId] } ?: return emptyList()
        val frames = entry.worker.drainResponses(maxFrames)
        if (entry.worker.isClosed) removeEntry(sessionId, entry, closeWorker = false)
        return frames
    }

    /** FIN, RST, or transport teardown must close the matching session. */
    fun closeSession(sessionId: Long): Boolean {
        val entry = synchronized(lock) { sessions.remove(sessionId) } ?: return false
        entry.worker.close()
        return true
    }

    /**
     * Expires idle sessions using a monotonic clock. Call from the transport
     * owner's existing maintenance/poll cycle; this class creates no timer.
     */
    fun expireIdleSessions(now: Long = nowNanos()): List<Long> {
        val expired = synchronized(lock) {
            val ids = sessions.entries
                .filter { (_, entry) -> now - entry.lastActivityNanos.get() >= idleTimeoutNanos }
                .map { it.key }
            ids.mapNotNull { id -> sessions.remove(id)?.let { id to it } }
        }
        expired.forEach { (_, entry) -> entry.worker.close() }
        return expired.map { it.first }
    }

    override fun close() {
        val workers = synchronized(lock) {
            if (closed) return
            closed = true
            sessions.values.map { it.worker }.also { sessions.clear() }
        }
        workers.forEach(DnsTcpSessionWorker::close)
    }

    private fun removeEntry(sessionId: Long, expected: Entry) {
        // The worker is already terminal when this method is called.
        synchronized(lock) {
            if (sessions[sessionId] === expected) sessions.remove(sessionId)
        }
    }

    private fun removeClosedLocked() {
        val iterator = sessions.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value.worker.isClosed) iterator.remove()
        }
    }

    private companion object {
        const val DEFAULT_MAX_SESSIONS = 64
        const val DEFAULT_IDLE_TIMEOUT_NANOS = 60_000_000_000L
        const val DEFAULT_DRAIN_BATCH = 16
    }
}
