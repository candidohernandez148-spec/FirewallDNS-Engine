package com.firewalldns.engine.android

/**
 * Optional JNI access to the experimental Rust packet preflight.
 *
 * The Kotlin packet processor remains authoritative. This bridge is used by
 * the on-device comparison harness only; it must not be placed on the production
 * packet path until parity and end-to-end performance are demonstrated.
 */
internal object NativePacketCore {
    @Volatile
    private var loadResult: Boolean? = null

    /**
     * Returns 4 for supported IPv4/UDP/DNS, 6 for supported IPv6/UDP/DNS,
     * 0 for invalid/unsupported packets, or null when the native library is absent.
     */
    fun validateDnsUdpPacket(packet: ByteArray, length: Int = packet.size): Int? {
        if (length < 0 || length > packet.size || !ensureLoaded()) return null
        return try {
            nativeValidateDnsUdpPacket(packet, length)
        } catch (_: LinkageError) {
            null
        }
    }

    @Synchronized
    private fun ensureLoaded(): Boolean {
        loadResult?.let { return it }
        val loaded = try {
            System.loadLibrary("firewalldns_native")
            true
        } catch (_: LinkageError) {
            false
        } catch (_: SecurityException) {
            false
        }
        loadResult = loaded
        return loaded
    }

    private external fun nativeValidateDnsUdpPacket(packet: ByteArray, length: Int): Int
}
