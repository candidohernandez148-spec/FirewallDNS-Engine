package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsSocketProtector
import java.net.DatagramSocket
import java.net.Socket

/** Delegates socket protection directly to Android's active VpnService. */
class AndroidDnsSocketProtector(private val vpnService: VpnService) : DnsSocketProtector {
    override fun protect(socket: DatagramSocket): Boolean = vpnService.protect(socket)
    override fun protect(socket: Socket): Boolean = vpnService.protect(socket)
}
