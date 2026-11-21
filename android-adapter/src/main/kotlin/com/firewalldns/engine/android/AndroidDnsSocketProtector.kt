package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsSocketProtector
import java.net.DatagramSocket
import java.net.Socket

/** Delegates socket protection directly to Android's active VpnService. */
enum class DnsSocketProtectionProtocol { UDP, TCP }

class AndroidDnsSocketProtector(
    private val vpnService: VpnService,
    private val onProtectionResult: (DnsSocketProtectionProtocol, Boolean) -> Unit = { _, _ -> },
) : DnsSocketProtector {
    override fun protect(socket: DatagramSocket): Boolean =
        protectAndRecord(DnsSocketProtectionProtocol.UDP) { vpnService.protect(socket) }

    override fun protect(socket: Socket): Boolean =
        protectAndRecord(DnsSocketProtectionProtocol.TCP) { vpnService.protect(socket) }

    private inline fun protectAndRecord(
        protocol: DnsSocketProtectionProtocol,
        protect: () -> Boolean,
    ): Boolean = try {
        protect().also { result -> runCatching { onProtectionResult(protocol, result) } }
    } catch (error: Throwable) {
        runCatching { onProtectionResult(protocol, false) }
        throw error
    }
}