package com.firewalldns.engine.dns

import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Per-exchange cancellation scope. Cancelling closes the active socket to unblock
 * UDP receive and TCP connect/read. Create one instance per exchange.
 */
class DnsExchangeCancellation {
    private val cancelled = AtomicBoolean(false)
    private val activeSocket = AtomicReference<Closeable?>(null)

    val isCancelled: Boolean get() = cancelled.get()

    fun cancel() {
        if (cancelled.compareAndSet(false, true)) {
            runCatching { activeSocket.getAndSet(null)?.close() }
        }
    }

    internal fun register(socket: Closeable): Boolean {
        if (cancelled.get()) return false
        activeSocket.set(socket)
        if (cancelled.get() && activeSocket.compareAndSet(socket, null)) {
            runCatching { socket.close() }
            return false
        }
        return !cancelled.get()
    }

    internal fun unregister(socket: Closeable) {
        activeSocket.compareAndSet(socket, null)
    }
}
