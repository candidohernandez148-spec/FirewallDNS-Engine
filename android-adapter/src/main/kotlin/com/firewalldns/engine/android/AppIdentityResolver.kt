package com.firewalldns.engine.android

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicLong

data class AppIdentityMetricsSnapshot(
    val lookupAttempts: Long,
    val resolved: Long,
    val degradedUnavailable: Long,
    val cacheHits: Long,
)

/**
 * Resolves the owning Android application package for a TUN DNS flow.
 * Implementations must degrade explicitly to null when OS APIs or permissions
 * do not expose socket ownership so global policy rules remain active.
 */
fun interface AppIdentityResolver {
    fun resolveAppPackage(
        protocol: Int,
        sourceAddress: ByteArray,
        sourcePort: Int,
        destinationAddress: ByteArray,
        destinationPort: Int,
    ): String?

    fun metrics(): AppIdentityMetricsSnapshot = AppIdentityMetricsSnapshot(0L, 0L, 0L, 0L)
}

object NoopAppIdentityResolver : AppIdentityResolver {
    override fun resolveAppPackage(
        protocol: Int,
        sourceAddress: ByteArray,
        sourcePort: Int,
        destinationAddress: ByteArray,
        destinationPort: Int,
    ): String? = null
}

/**
 * Android API 29+ connection-owner UID/package resolver backed by
 * [ConnectivityManager.getConnectionOwnerUid] with a bounded monotonic TTL cache
 * and explicit degradation to null on older OS versions or missing permissions.
 */
class AndroidAppIdentityResolver(
    context: Context,
    private val cacheMaxEntries: Int = 512,
    cacheTtlMillis: Long = 5_000L,
    private val clockNanos: () -> Long = System::nanoTime,
) : AppIdentityResolver {
    private val appContext = context.applicationContext
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val packageManager = appContext.packageManager
    private val cacheTtlNanos = cacheTtlMillis * 1_000_000L

    private data class FlowKey(
        val protocol: Int,
        val sourceAddress: ByteArray,
        val sourcePort: Int,
        val destinationAddress: ByteArray,
        val destinationPort: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is FlowKey) return false
            return protocol == other.protocol &&
                sourcePort == other.sourcePort &&
                destinationPort == other.destinationPort &&
                sourceAddress.contentEquals(other.sourceAddress) &&
                destinationAddress.contentEquals(other.destinationAddress)
        }

        override fun hashCode(): Int {
            var h = protocol
            h = 31 * h + sourceAddress.contentHashCode()
            h = 31 * h + sourcePort
            h = 31 * h + destinationAddress.contentHashCode()
            h = 31 * h + destinationPort
            return h
        }
    }

    private class CacheEntry(val appPackage: String?, val expiresAtNanos: Long)

    private val lock = Any()
    private val cache = object : LinkedHashMap<FlowKey, CacheEntry>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, CacheEntry>?): Boolean =
            size > cacheMaxEntries
    }

    private val attempts = AtomicLong()
    private val resolved = AtomicLong()
    private val degradedUnavailable = AtomicLong()
    private val cacheHits = AtomicLong()

    init {
        require(cacheMaxEntries in 16..8192)
        require(cacheTtlMillis >= 0L)
    }

    override fun resolveAppPackage(
        protocol: Int,
        sourceAddress: ByteArray,
        sourcePort: Int,
        destinationAddress: ByteArray,
        destinationPort: Int,
    ): String? {
        attempts.incrementAndGet()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || connectivityManager == null) {
            degradedUnavailable.incrementAndGet()
            return null
        }

        val now = clockNanos()
        val key = FlowKey(
            protocol = protocol,
            sourceAddress = sourceAddress.copyOf(),
            sourcePort = sourcePort,
            destinationAddress = destinationAddress.copyOf(),
            destinationPort = destinationPort,
        )
        if (cacheTtlNanos > 0L) {
            synchronized(lock) {
                val cached = cache[key]
                if (cached != null && now - cached.expiresAtNanos < 0L) {
                    cacheHits.incrementAndGet()
                    if (cached.appPackage != null) resolved.incrementAndGet() else degradedUnavailable.incrementAndGet()
                    return cached.appPackage
                }
            }
        }

        val pkg = lookupOwnerPackageApi29(protocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
        if (pkg != null) resolved.incrementAndGet() else degradedUnavailable.incrementAndGet()

        if (cacheTtlNanos > 0L) {
            synchronized(lock) {
                cache[key] = CacheEntry(pkg, now + cacheTtlNanos)
            }
        }
        return pkg
    }

    override fun metrics(): AppIdentityMetricsSnapshot = AppIdentityMetricsSnapshot(
        lookupAttempts = attempts.get(),
        resolved = resolved.get(),
        degradedUnavailable = degradedUnavailable.get(),
        cacheHits = cacheHits.get(),
    )

    private fun lookupOwnerPackageApi29(
        protocol: Int,
        sourceAddress: ByteArray,
        sourcePort: Int,
        destinationAddress: ByteArray,
        destinationPort: Int,
    ): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val cm = connectivityManager ?: return null
        return runCatching {
            val local = InetSocketAddress(InetAddress.getByAddress(sourceAddress), sourcePort)
            val remote = InetSocketAddress(InetAddress.getByAddress(destinationAddress), destinationPort)
            val uid = cm.getConnectionOwnerUid(protocol, local, remote)
            if (uid == Process.INVALID_UID || uid < 0) return null
            packageManager.getPackagesForUid(uid)?.firstOrNull()?.takeIf { it.isNotBlank() }
        }.getOrNull()
    }
}
