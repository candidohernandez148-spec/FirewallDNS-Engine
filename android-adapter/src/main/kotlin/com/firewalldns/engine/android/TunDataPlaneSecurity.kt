package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamConfig
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

data class SocketProtectionAuditSnapshot(
    val udpAttempts: Long,
    val udpSuccesses: Long,
    val udpFailures: Long,
    val tcpAttempts: Long,
    val tcpSuccesses: Long,
    val tcpFailures: Long,
) {
    val totalFailures: Long get() = udpFailures + tcpFailures
}

/**
 * Auditing [DnsSocketProtector] wrapper ensuring every upstream UDP/TCP socket protection attempt
 * is counted and surfaced for fail-closed runtime monitoring.
 */
class AuditedDnsSocketProtector(
    private val delegate: DnsSocketProtector,
) : DnsSocketProtector {
    private val udpAttempts = AtomicLong()
    private val udpSuccesses = AtomicLong()
    private val udpFailures = AtomicLong()
    private val tcpAttempts = AtomicLong()
    private val tcpSuccesses = AtomicLong()
    private val tcpFailures = AtomicLong()

    override fun protect(socket: DatagramSocket): Boolean {
        udpAttempts.incrementAndGet()
        val ok = runCatching { delegate.protect(socket) }.getOrDefault(false)
        if (ok) udpSuccesses.incrementAndGet() else udpFailures.incrementAndGet()
        return ok
    }

    override fun protect(socket: Socket): Boolean {
        tcpAttempts.incrementAndGet()
        val ok = runCatching { delegate.protect(socket) }.getOrDefault(false)
        if (ok) tcpSuccesses.incrementAndGet() else tcpFailures.incrementAndGet()
        return ok
    }

    fun hasFailures(): Boolean = udpFailures.get() > 0L || tcpFailures.get() > 0L

    fun snapshot(): SocketProtectionAuditSnapshot = SocketProtectionAuditSnapshot(
        udpAttempts = udpAttempts.get(),
        udpSuccesses = udpSuccesses.get(),
        udpFailures = udpFailures.get(),
        tcpAttempts = tcpAttempts.get(),
        tcpSuccesses = tcpSuccesses.get(),
        tcpFailures = tcpFailures.get(),
    )
}

data class TunDataPlaneSecurityConfig(
    val tunIpv4Address: String = DEFAULT_TUN_IPV4_ADDRESS,
    val tunIpv4DnsServer: String = DEFAULT_TUN_IPV4_DNS,
    val tunIpv6Address: String = DEFAULT_TUN_IPV6_ADDRESS,
    val tunIpv6DnsServer: String = DEFAULT_TUN_IPV6_DNS,
    val upstreamConfigs: List<DnsUpstreamConfig>,
    val interceptedRoutesIpv4: List<String> = DEFAULT_INTERCEPTED_IPV4_ROUTES,
    val interceptedRoutesIpv6: List<String> = DEFAULT_INTERCEPTED_IPV6_ROUTES,
    val appPackageName: String,
    val disallowedPackages: Set<String> = setOf(appPackageName),
    val allowBypass: Boolean = false,
    val blockExternalDotPort853: Boolean = true,
    val allowLoopbackUpstreamsForTesting: Boolean = false,
) {
    companion object {
        const val DEFAULT_TUN_IPV4_ADDRESS = "10.77.0.2"
        const val DEFAULT_TUN_IPV4_DNS = "10.77.0.1"
        const val DEFAULT_TUN_IPV6_ADDRESS = "fd77::2"
        const val DEFAULT_TUN_IPV6_DNS = "fd77::1"

        val DEFAULT_INTERCEPTED_IPV4_ROUTES = listOf(
            "10.77.0.1/32",
            "1.1.1.1/32",
            "1.0.0.1/32",
            "8.8.8.8/32",
            "8.8.4.4/32",
            "9.9.9.9/32",
        )

        val DEFAULT_INTERCEPTED_IPV6_ROUTES = listOf(
            "fd77::1/128",
            "2606:4700:4700::1111/128",
            "2606:4700:4700::1001/128",
            "2001:4860:4860::8888/128",
            "2001:4860:4860::8844/128",
            "2620:fe::fe/128",
        )
    }
}

data class SecurityCheckDetail(
    val name: String,
    val passed: Boolean,
    val detail: String,
)

data class TunDataPlaneValidationResult(
    val passed: Boolean,
    val protectVerified: Boolean,
    val loopFreeVerified: Boolean,
    val zeroDnsLeaksVerified: Boolean,
    val checks: List<SecurityCheckDetail>,
    val failureReasons: List<String>,
)

/**
 * Preflight validator gating production data-plane activation on:
 * 1. Verified [android.net.VpnService.protect] for UDP and TCP sockets.
 * 2. Loop-free routing & own-app exclusion invariants.
 * 3. Zero-DNS-leak dual-stack routing & anti-bypass invariants.
 */
object TunDataPlaneSecurityValidator {
    fun validatePreflight(
        config: TunDataPlaneSecurityConfig,
        protector: DnsSocketProtector,
    ): TunDataPlaneValidationResult {
        val checks = ArrayList<SecurityCheckDetail>()
        val failures = ArrayList<String>()

        // 1. VpnService.protect() verification (UDP + TCP real sockets)
        val udpProtected = runCatching {
            DatagramSocket().use { socket -> protector.protect(socket) }
        }.getOrDefault(false)
        val tcpProtected = runCatching {
            Socket().use { socket -> protector.protect(socket) }
        }.getOrDefault(false)
        val protectVerified = udpProtected && tcpProtected
        checks += SecurityCheckDetail(
            name = "vpn_service_protect_udp",
            passed = udpProtected,
            detail = if (udpProtected) "DatagramSocket protected" else "DatagramSocket protect() returned false",
        )
        checks += SecurityCheckDetail(
            name = "vpn_service_protect_tcp",
            passed = tcpProtected,
            detail = if (tcpProtected) "Socket protected" else "Socket protect() returned false",
        )
        if (!udpProtected) failures += "protect_udp_failed"
        if (!tcpProtected) failures += "protect_tcp_failed"

        // 2. Loop-free validation
        val loopChecks = validateLoopFreedom(config, protectVerified)
        checks += loopChecks
        val loopFreeVerified = loopChecks.all { it.passed }
        loopChecks.filterNot { it.passed }.forEach { failures += it.name }

        // 3. Zero DNS leaks validation
        val leakChecks = validateZeroDnsLeaks(config)
        checks += leakChecks
        val zeroDnsLeaksVerified = leakChecks.all { it.passed }
        leakChecks.filterNot { it.passed }.forEach { failures += it.name }

        return TunDataPlaneValidationResult(
            passed = protectVerified && loopFreeVerified && zeroDnsLeaksVerified,
            protectVerified = protectVerified,
            loopFreeVerified = loopFreeVerified,
            zeroDnsLeaksVerified = zeroDnsLeaksVerified,
            checks = checks,
            failureReasons = failures,
        )
    }

    private fun validateLoopFreedom(
        config: TunDataPlaneSecurityConfig,
        protectVerified: Boolean,
    ): List<SecurityCheckDetail> {
        val checks = ArrayList<SecurityCheckDetail>()

        val hasSelfExclusion = config.appPackageName.isNotBlank() &&
            config.disallowedPackages.contains(config.appPackageName)
        checks += SecurityCheckDetail(
            name = "loop_self_package_excluded",
            passed = hasSelfExclusion,
            detail = if (hasSelfExclusion) {
                "Own package excluded from VPN routing"
            } else {
                "Own package missing from disallowedPackages"
            },
        )

        val hasUpstreams = config.upstreamConfigs.isNotEmpty()
        checks += SecurityCheckDetail(
            name = "loop_upstreams_configured",
            passed = hasUpstreams,
            detail = if (hasUpstreams) "${config.upstreamConfigs.size} numeric upstreams" else "No upstream resolvers configured",
        )

        val tunV4Addr = parseIpv4(config.tunIpv4Address)
        val tunV4Dns = parseIpv4(config.tunIpv4DnsServer)
        val tunV6Addr = parseIpv6(config.tunIpv6Address)
        val tunV6Dns = parseIpv6(config.tunIpv6DnsServer)

        var upstreamSafe = hasUpstreams
        var upstreamFailDetail = "All upstreams outside virtual TUN addresses"
        for (upstream in config.upstreamConfigs) {
            val addr = runCatching { InetAddress.getByName(upstream.host) }.getOrNull()
            if (addr == null) {
                upstreamSafe = false
                upstreamFailDetail = "Invalid upstream address: ${upstream.host}"
                break
            }
            if (addr.isAnyLocalAddress || addr.isMulticastAddress) {
                upstreamSafe = false
                upstreamFailDetail = "Upstream cannot be unspecified/multicast: ${upstream.host}"
                break
            }
            if (addr.isLoopbackAddress && !config.allowLoopbackUpstreamsForTesting) {
                upstreamSafe = false
                upstreamFailDetail = "Loopback upstream disallowed in production: ${upstream.host}"
                break
            }
            val bytes = addr.address
            if (addr is Inet4Address) {
                if ((tunV4Addr != null && bytes.contentEquals(tunV4Addr)) ||
                    (tunV4Dns != null && bytes.contentEquals(tunV4Dns)) ||
                    inIpv4Cidr(bytes, "10.77.0.0/24")
                ) {
                    upstreamSafe = false
                    upstreamFailDetail = "Upstream collides with virtual IPv4 TUN subnet: ${upstream.host}"
                    break
                }
            } else if (addr is Inet6Address) {
                if ((tunV6Addr != null && bytes.contentEquals(tunV6Addr)) ||
                    (tunV6Dns != null && bytes.contentEquals(tunV6Dns)) ||
                    inIpv6Cidr(bytes, "fd77::/64")
                ) {
                    upstreamSafe = false
                    upstreamFailDetail = "Upstream collides with virtual IPv6 TUN subnet: ${upstream.host}"
                    break
                }
            }
        }
        checks += SecurityCheckDetail(
            name = "loop_upstream_disjoint_from_tun",
            passed = upstreamSafe,
            detail = upstreamFailDetail,
        )

        val protectedForwardingSafe = protectVerified && hasSelfExclusion
        checks += SecurityCheckDetail(
            name = "loop_protected_bypass_guaranteed",
            passed = protectedForwardingSafe,
            detail = if (protectedForwardingSafe) {
                "Both protect() and disallowedApplication active for upstream sockets"
            } else {
                "Cannot guarantee upstream sockets bypass TUN without protect() and self-exclusion"
            },
        )
        return checks
    }

    private fun validateZeroDnsLeaks(config: TunDataPlaneSecurityConfig): List<SecurityCheckDetail> {
        val checks = ArrayList<SecurityCheckDetail>()

        val noBypass = !config.allowBypass
        checks += SecurityCheckDetail(
            name = "leak_allow_bypass_disabled",
            passed = noBypass,
            detail = if (noBypass) "VPN bypass disabled" else "allowBypass must be false",
        )

        val dotBlocked = config.blockExternalDotPort853
        checks += SecurityCheckDetail(
            name = "leak_external_dot_853_blocked",
            passed = dotBlocked,
            detail = if (dotBlocked) "External DoT (port 853) blocked/reset" else "External DoT unblocked",
        )

        val v4Dns = parseIpv4(config.tunIpv4DnsServer)
        val v6Dns = parseIpv6(config.tunIpv6DnsServer)
        val v4Covered = v4Dns != null && config.interceptedRoutesIpv4.any { inIpv4Cidr(v4Dns, it) }
        val v6Covered = v6Dns != null && config.interceptedRoutesIpv6.any { inIpv6Cidr(v6Dns, it) }
        checks += SecurityCheckDetail(
            name = "leak_dual_stack_dns_routes_active",
            passed = v4Covered && v6Covered,
            detail = if (v4Covered && v6Covered) {
                "Dual-stack IPv4 and IPv6 virtual DNS routes active"
            } else {
                "Missing IPv4 or IPv6 virtual DNS capture route"
            },
        )

        var externalUpstreamsCovered = true
        var uncoveredHost = ""
        for (upstream in config.upstreamConfigs) {
            val addr = runCatching { InetAddress.getByName(upstream.host) }.getOrNull() ?: continue
            if (addr.isLoopbackAddress) continue
            val covered = when (addr) {
                is Inet4Address -> config.interceptedRoutesIpv4.any { inIpv4Cidr(addr.address, it) }
                is Inet6Address -> config.interceptedRoutesIpv6.any { inIpv6Cidr(addr.address, it) }
                else -> false
            }
            if (!covered) {
                externalUpstreamsCovered = false
                uncoveredHost = upstream.host
                break
            }
        }
        checks += SecurityCheckDetail(
            name = "leak_hardcoded_upstream_routes_captured",
            passed = externalUpstreamsCovered,
            detail = if (externalUpstreamsCovered) {
                "All public DNS upstream endpoints intercepted for non-VPN apps"
            } else {
                "Public upstream $uncoveredHost not covered by TUN capture routes"
            },
        )

        return checks
    }

    internal fun parseIpv4(ip: String): ByteArray? {
        val parts = ip.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0..3) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            out[i] = v.toByte()
        }
        return out
    }

    internal fun parseIpv6(ip: String): ByteArray? = runCatching {
        val addr = InetAddress.getByName(ip)
        if (addr is Inet6Address) addr.address else null
    }.getOrNull()

    internal fun inIpv4Cidr(address: ByteArray, cidr: String): Boolean {
        val parts = cidr.split('/')
        if (parts.size != 2 || address.size != 4) return false
        val net = parseIpv4(parts[0]) ?: return false
        val prefix = parts[1].toIntOrNull() ?: return false
        if (prefix !in 0..32) return false
        return matchesPrefix(address, net, prefix)
    }

    internal fun inIpv6Cidr(address: ByteArray, cidr: String): Boolean {
        val parts = cidr.split('/')
        if (parts.size != 2 || address.size != 16) return false
        val net = parseIpv6(parts[0]) ?: return false
        val prefix = parts[1].toIntOrNull() ?: return false
        if (prefix !in 0..128) return false
        return matchesPrefix(address, net, prefix)
    }

    private fun matchesPrefix(a: ByteArray, b: ByteArray, prefixBits: Int): Boolean {
        val fullBytes = prefixBits / 8
        for (i in 0 until fullBytes) {
            if (a[i] != b[i]) return false
        }
        val rem = prefixBits % 8
        if (rem != 0) {
            val mask = (0xff shl (8 - rem)) and 0xff
            if ((a[fullBytes].toInt() and mask) != (b[fullBytes].toInt() and mask)) return false
        }
        return true
    }
}

/**
 * Per-packet runtime guard against TUN routing loops and DoT (853) DNS leaks.
 */
internal class LoopAndLeakGuard(
    config: TunDataPlaneSecurityConfig,
) {
    private val virtualDnsV4 = TunDataPlaneSecurityValidator.parseIpv4(config.tunIpv4DnsServer)
    private val virtualDnsV6 = TunDataPlaneSecurityValidator.parseIpv6(config.tunIpv6DnsServer)
    private val blockExternalDot = config.blockExternalDotPort853

    sealed interface Decision {
        data object Allow : Decision
        data class LoopBlocked(val reason: String) : Decision
        data class LeakBlocked(val reason: String, val responsePacket: ByteArray? = null) : Decision
    }

    fun inspect(packet: ByteArray, length: Int): Decision {
        if (length < 20 || length > packet.size) return Decision.Allow
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> inspectIpv4(packet, length)
            6 -> inspectIpv6(packet, length)
            else -> Decision.Allow
        }
    }

    private fun inspectIpv4(packet: ByteArray, length: Int): Decision {
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || ihl > length) return Decision.Allow
        val totalLen = u16(packet, 2)
        if (totalLen < ihl || totalLen > length) return Decision.Allow
        val src = packet.copyOfRange(12, 16)
        val dst = packet.copyOfRange(16, 20)
        if (src.contentEquals(dst)) {
            return Decision.LoopBlocked("loop_identical_endpoints_v4")
        }
        if (virtualDnsV4 != null && src.contentEquals(virtualDnsV4)) {
            return Decision.LoopBlocked("loop_virtual_dns_source_v4")
        }
        val proto = packet[9].toInt() and 0xff
        return inspectL4(ipv6 = false, src = src, dst = dst, proto = proto, packet = packet, l4Offset = ihl, end = totalLen)
    }

    private fun inspectIpv6(packet: ByteArray, length: Int): Decision {
        if (length < 40) return Decision.Allow
        val payloadLen = u16(packet, 4)
        val end = 40 + payloadLen
        if (payloadLen == 0 || end > length) return Decision.Allow
        val src = packet.copyOfRange(8, 24)
        val dst = packet.copyOfRange(24, 40)
        if (src.contentEquals(dst)) {
            return Decision.LoopBlocked("loop_identical_endpoints_v6")
        }
        if (virtualDnsV6 != null && src.contentEquals(virtualDnsV6)) {
            return Decision.LoopBlocked("loop_virtual_dns_source_v6")
        }
        var next = packet[6].toInt() and 0xff
        var offset = 40
        var extensions = 0
        while (next in IPV6_EXTENSION_HEADERS) {
            if (++extensions > 8 || offset + 2 > end) return Decision.Allow
            if (next == 44) {
                if (offset + 8 > end) return Decision.Allow
                next = packet[offset].toInt() and 0xff
                offset += 8
                continue
            }
            val following = packet[offset].toInt() and 0xff
            val extLen = if (next == 51) ((packet[offset + 1].toInt() and 0xff) + 2) * 4
            else ((packet[offset + 1].toInt() and 0xff) + 1) * 8
            if (extLen < 8 || offset + extLen > end) return Decision.Allow
            next = following
            offset += extLen
        }
        return inspectL4(ipv6 = true, src = src, dst = dst, proto = next, packet = packet, l4Offset = offset, end = end)
    }

    private fun inspectL4(
        ipv6: Boolean,
        src: ByteArray,
        dst: ByteArray,
        proto: Int,
        packet: ByteArray,
        l4Offset: Int,
        end: Int,
    ): Decision {
        if (proto == 17) {
            if (l4Offset + 8 > end) return Decision.Allow
            val srcPort = u16(packet, l4Offset)
            val dstPort = u16(packet, l4Offset + 2)
            if (srcPort == 53) return Decision.LoopBlocked("loop_dns_udp_source_port_53")
            if (blockExternalDot && dstPort == 853) {
                return Decision.LeakBlocked("dns_leak_dot_udp_853_blocked")
            }
        } else if (proto == 6) {
            if (l4Offset + 20 > end) return Decision.Allow
            val srcPort = u16(packet, l4Offset)
            val dstPort = u16(packet, l4Offset + 2)
            if (srcPort == 53) return Decision.LoopBlocked("loop_dns_tcp_source_port_53")
            if (blockExternalDot && dstPort == 853) {
                val decoded = TunTcpSegmentCodec.decode(packet, end)
                val rst = if (decoded is TunTcpSegmentCodec.DecodeResult.Valid && !decoded.packet.isRst) {
                    val d = decoded.packet
                    val rstFlags = if (d.isAck) TunTcpSegmentCodec.FLAG_RST
                    else TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK
                    val seq = if (d.isAck) d.ackNumber else 0L
                    val segLen = d.payload.size.toLong() +
                        (if (d.isSyn) 1L else 0L) +
                        (if (d.isFin) 1L else 0L)
                    val ack = if (d.isAck) 0L else (d.sequenceNumber + segLen) and 0xFFFF_FFFFL
                    TunTcpSegmentCodec.encode(
                        ipv6 = ipv6,
                        sourceAddress = dst,
                        destinationAddress = src,
                        sourcePort = dstPort,
                        destinationPort = srcPort,
                        sequenceNumber = seq,
                        ackNumber = ack,
                        flags = rstFlags,
                        windowSize = 0,
                    )
                } else {
                    null
                }
                return Decision.LeakBlocked("dns_leak_dot_tcp_853_blocked", rst)
            }
        }
        return Decision.Allow
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private companion object {
        val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)
    }
}
