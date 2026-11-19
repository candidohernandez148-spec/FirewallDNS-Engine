package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsSocketProtector
import java.net.DatagramSocket
import java.net.Socket

/**
 * Android boundary for excluding DNS upstream sockets from the active VPN.
 *
 * DnsUpstreamClient invokes this protector before connecting either socket.
 * Keep the VpnService instance tied to the active service lifecycle.
 */
class AndroidDnsSocketProtector(
    private val vpnService: VpnService,
) : DnsSocketProtector {

    override fun protect(socket: DatagramSocket): Boolean =
        vpnService.protect(socket)

    override fun protect(socket: Socket): Boolean =
        vpnService.protect(socket)
}
