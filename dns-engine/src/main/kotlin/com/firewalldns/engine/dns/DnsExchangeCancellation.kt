package com.firewalldns.engine.dns

import java.io.Closeable
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

/** Cooperative per-exchange cancellation scope that closes active sockets immediately. */
class DnsExchangeCancellation {
    private val cancelled = AtomicBoolean(false)
    private val activeResources: MutableSet<Closeable> =
        Collections.synchronizedSet(linkedSetOf())

    val isCancelled: Boolean
        get() = cancelled.get()

    fun register(resource: Closeable): Boolean {
        if (cancelled.get()) {
            runCatching { resource.close() }
            return false
        }
        activeResources.add(resource)
        if (cancelled.get()) {
            activeResources.remove(resource)
            runCatching { resource.close() }
            return false
        }
        return true
    }

    fun unregister(resource: Closeable) {
        activeResources.remove(resource)
    }

    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        val snapshot = synchronized(activeResources) {
            activeResources.toList().also { activeResources.clear() }
        }
        snapshot.forEach { runCatching { it.close() } }
    }
}
