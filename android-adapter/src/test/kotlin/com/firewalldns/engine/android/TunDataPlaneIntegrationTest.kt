package com.firewalldns.engine.android

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpStreamDecoder
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.runtime.EngineRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class TunDataPlaneIntegrationTest {

    @Test
    fun preflightGateRefusesActivationWhenProtectLoopOrLeakChecksFail() {
        val baseConfig = TunDataPlaneSecurityConfig(
            upstreamConfigs = listOf(DnsUpstreamConfig("1.1.1.1", 53, 1_000)),
            appPackageName = "com.firewalldns.diagnostics",
        )

        // 1. Reject when protect() fails
        val failingProtector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean = false
            override fun protect(socket: Socket): Boolean = true
        }
        val rejectProtect = TunDataPlaneCoordinator.createValidated(
            engine = EngineRuntime(),
            rawProtector = failingProtector,
            securityConfig = baseConfig,
        )
        assertTrue(rejectProtect is TunDataPlaneCoordinator.ActivationResult.Rejected)
        val protectVal = (rejectProtect as TunDataPlaneCoordinator.ActivationResult.Rejected).validation
        assertFalse(protectVal.passed)
        assertFalse(protectVal.protectVerified)
        assertTrue(protectVal.failureReasons.contains("protect_udp_failed"))

        // 2. Reject when upstream collides with TUN virtual DNS (loop risk) or self package not excluded
        val okProtector = RecordingSocketProtector()
        val loopConfig = baseConfig.copy(
            upstreamConfigs = listOf(DnsUpstreamConfig("10.77.0.1", 53, 1_000)),
            disallowedPackages = emptySet(),
        )
        val rejectLoop = TunDataPlaneCoordinator.createValidated(
            engine = EngineRuntime(),
            rawProtector = okProtector,
            securityConfig = loopConfig,
        )
        val loopVal = (rejectLoop as TunDataPlaneCoordinator.ActivationResult.Rejected).validation
        assertFalse(loopVal.passed)
        assertFalse(loopVal.loopFreeVerified)
        assertTrue(loopVal.failureReasons.contains("loop_self_package_excluded"))
        assertTrue(loopVal.failureReasons.contains("loop_upstream_disjoint_from_tun"))

        // 3. Reject when bypass is allowed or IPv6 route or DoT block missing (DNS leak risk)
        val leakConfig = baseConfig.copy(
            allowBypass = true,
            blockExternalDotPort853 = false,
            interceptedRoutesIpv6 = emptyList(),
        )
        val rejectLeak = TunDataPlaneCoordinator.createValidated(
            engine = EngineRuntime(),
            rawProtector = okProtector,
            securityConfig = leakConfig,
        )
        val leakVal = (rejectLeak as TunDataPlaneCoordinator.ActivationResult.Rejected).validation
        assertFalse(leakVal.passed)
        assertFalse(leakVal.zeroDnsLeaksVerified)
        assertTrue(leakVal.failureReasons.contains("leak_allow_bypass_disabled"))
        assertTrue(leakVal.failureReasons.contains("leak_external_dot_853_blocked"))
        assertTrue(leakVal.failureReasons.contains("leak_dual_stack_dns_routes_active"))
    }

    @Test
    fun validatedProductionCoordinatorEnforcesProtectZeroLoopsAndZeroDnsLeaksEndToEnd() {
        val upstreamQueriesReceived = AtomicInteger(0)
        val stopServer = AtomicBoolean(false)
        val udpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val responderThread = thread(name = "test-dns-loopback-upstream") {
            val buf = ByteArray(1024)
            udpServer.soTimeout = 200
            while (!stopServer.get() && !udpServer.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    udpServer.receive(pkt)
                    upstreamQueriesReceived.incrementAndGet()
                    val query = pkt.data.copyOf(pkt.length)
                    val resp = positiveResponse(query)
                    udpServer.send(DatagramPacket(resp, resp.size, pkt.socketAddress))
                } catch (_: Throwable) {
                    // Timeout or closed
                }
            }
        }

        try {
            val protector = RecordingSocketProtector()
            val clock = AtomicLong(1_000_000L)
            val engine = EngineRuntime(
                initialRules = listOf(
                    PolicyRule(
                        id = "block-ads",
                        domain = "ads.blocked.example",
                        action = PolicyAction.BLOCK,
                        source = RuleSource.USER,
                        reason = "user_block_rule",
                    ),
                ),
            )
            val secConfig = TunDataPlaneSecurityConfig(
                upstreamConfigs = listOf(DnsUpstreamConfig("127.0.0.1", udpServer.localPort, 1_500)),
                appPackageName = "com.firewalldns.diagnostics",
                allowLoopbackUpstreamsForTesting = true,
            )
            val activation = TunDataPlaneCoordinator.createValidated(
                engine = engine,
                rawProtector = protector,
                securityConfig = secConfig,
                clockNanos = { clock.get() },
            )
            assertTrue(activation is TunDataPlaneCoordinator.ActivationResult.Activated)
            val coordinator = (activation as TunDataPlaneCoordinator.ActivationResult.Activated).coordinator
            assertTrue(coordinator.validation.passed)

            val clientV4 = InetAddress.getByName("10.77.0.2").address
            val dnsV4 = InetAddress.getByName("10.77.0.1").address
            val hardcodedV4 = InetAddress.getByName("1.1.1.1").address
            val clientV6 = InetAddress.getByName("fd77::2").address
            val dnsV6 = InetAddress.getByName("fd77::1").address

            // A. Hardcoded external DNS (1.1.1.1:53) split into IPv4 fragments -> forwarded through protected socket
            val allowedQuery = dnsQuery("allowed.example.com", 101)
            val udpAllowedPkt = buildIpv4UdpPacket(clientV4, hardcodedV4, 41_001, 53, allowedQuery)
            val splitAt = 28 // inside UDP payload (aligned to 8 bytes after 20-byte IP header)
            val frag1 = buildIpv4Fragment(clientV4, hardcodedV4, 17, 0x3333, 0, true, udpAllowedPkt.copyOfRange(20, splitAt))
            val frag2 = buildIpv4Fragment(clientV4, hardcodedV4, 17, 0x3333, splitAt - 20, false, udpAllowedPkt.copyOfRange(splitAt, udpAllowedPkt.size))
            assertTrue(coordinator.onPacket(frag1) is TunDataPlaneCoordinator.PacketHandlingResult.Consumed)
            val udpRes = coordinator.onPacket(frag2) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            assertEquals(1, udpRes.packets.size)
            val udpRespPayload = extractIpv4UdpPayload(udpRes.packets.first())
            assertEquals(0, udpRespPayload[3].toInt() and 0x0f) // NOERROR
            assertEquals(1, upstreamQueriesReceived.get())
            assertTrue(protector.udpProtectCalls.get() >= 2) // preflight + runtime query

            // B. IPv6 UDP/53 with Hop-by-Hop extension header + BLOCK rule -> NXDOMAIN without upstream
            val blockedQuery = dnsQuery("ads.blocked.example", 202)
            val ipv6ExtBlocked = buildIpv6HopByHopUdpPacket(clientV6, dnsV6, 42_002, 53, blockedQuery)
            val blockedRes = coordinator.onPacket(ipv6ExtBlocked) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            val blockedDns = extractIpv6UdpPayload(blockedRes.packets.first())
            assertEquals(3, blockedDns[3].toInt() and 0x0f) // NXDOMAIN
            assertEquals(1, upstreamQueriesReceived.get()) // upstream NOT contacted

            // C. IPv4 TCP/53 session -> handshake + query forwarded through protected upstream + FIN
            val clientIsn = 50_000L
            val syn = TunTcpSegmentCodec.encode(false, clientV4, hardcodedV4, 43_003, 53, clientIsn, 0L, TunTcpSegmentCodec.FLAG_SYN, 65_535, 1460)
            val synAckRes = coordinator.onPacket(syn) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            val synAck = (TunTcpSegmentCodec.decode(synAckRes.packets.first()) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            val ack = TunTcpSegmentCodec.encode(false, clientV4, hardcodedV4, 43_003, 53, clientIsn + 1, synAck.sequenceNumber + 1, TunTcpSegmentCodec.FLAG_ACK, 65_535)
            coordinator.onPacket(ack)
            val tcpDnsFrame = DnsTcpFrameCodec.encode(dnsQuery("tcp-allowed.example.com", 303))
            val psh = TunTcpSegmentCodec.encode(false, clientV4, hardcodedV4, 43_003, 53, clientIsn + 1, synAck.sequenceNumber + 1, TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 65_535, payload = tcpDnsFrame)
            val tcpDataRes = coordinator.onPacket(psh) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            val tcpSeg = (TunTcpSegmentCodec.decode(tcpDataRes.packets.first()) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            val tcpDecoder = DnsTcpStreamDecoder()
            tcpDecoder.feed(tcpSeg.payload)
            val tcpDnsResp = (tcpDecoder.drainFrame() as DnsTcpStreamDecoder.DrainResult.Frame).message
            assertEquals(0, tcpDnsResp[3].toInt() and 0x0f)
            assertEquals(2, upstreamQueriesReceived.get())

            // D. Loop prevention: virtual DNS source, identical endpoints, and sourcePort == 53 are blocked
            val loop1 = buildIpv4UdpPacket(dnsV4, clientV4, 44_001, 53, allowedQuery)
            val loop2 = buildIpv4UdpPacket(clientV4, clientV4, 44_002, 53, allowedQuery)
            val loop3 = buildIpv4UdpPacket(clientV4, hardcodedV4, 53, 44_003, allowedQuery)
            assertEquals("loop_virtual_dns_source_v4", (coordinator.onPacket(loop1) as TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped).outcome)
            assertEquals("loop_identical_endpoints_v4", (coordinator.onPacket(loop2) as TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped).outcome)
            assertEquals("loop_dns_udp_source_port_53", (coordinator.onPacket(loop3) as TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped).outcome)

            // E. Zero DNS leaks: TCP/853 DoT receives RST, UDP/853 dropped
            val dotTcpSyn = TunTcpSegmentCodec.encode(false, clientV4, hardcodedV4, 45_001, 853, 999L, 0L, TunTcpSegmentCodec.FLAG_SYN, 65_535)
            val dotTcpRes = coordinator.onPacket(dotTcpSyn) as TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped
            assertEquals("dns_leak_dot_tcp_853_blocked", dotTcpRes.outcome)
            assertEquals(1, dotTcpRes.responsePackets.size)
            val rstPkt = (TunTcpSegmentCodec.decode(dotTcpRes.responsePackets.first()) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            assertTrue(rstPkt.isRst)

            val dotUdp = buildIpv4UdpPacket(clientV4, hardcodedV4, 45_002, 853, allowedQuery)
            val dotUdpRes = coordinator.onPacket(dotUdp) as TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped
            assertEquals("dns_leak_dot_udp_853_blocked", dotUdpRes.outcome)

            // F. Fail-closed if runtime protect() ever fails: refuses forwarding & emits SERVFAIL
            protector.failRuntimeProtect.set(true)
            val newAllowed = buildIpv4UdpPacket(clientV4, hardcodedV4, 46_001, 53, dnsQuery("uncached-failclosed.example.com", 404))
            val failClosedRes = coordinator.onPacket(newAllowed) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            assertEquals("upstream_failure_servfail", failClosedRes.outcome)
            val servfailPayload = extractIpv4UdpPayload(failClosedRes.packets.first())
            assertEquals(2, servfailPayload[3].toInt() and 0x0f) // SERVFAIL
            assertEquals(2, upstreamQueriesReceived.get()) // upstream NOT reached without protect()

            val metrics = coordinator.metrics()
            assertEquals(3L, metrics.loopsBlocked)
            assertEquals(2L, metrics.dnsLeaksBlocked)
            assertTrue(metrics.runtimeProtectFailClosedBlocked >= 1L)
            assertTrue(metrics.fragmentReassembly.packetsReassembled >= 1L)

            coordinator.close()
        } finally {
            stopServer.set(true)
            udpServer.close()
            responderThread.join(2_000)
        }
    }

    private class RecordingSocketProtector : DnsSocketProtector {
        val udpProtectCalls = AtomicInteger(0)
        val tcpProtectCalls = AtomicInteger(0)
        val failRuntimeProtect = AtomicBoolean(false)

        override fun protect(socket: DatagramSocket): Boolean {
            val count = udpProtectCalls.incrementAndGet()
            return !(failRuntimeProtect.get() && count > 1)
        }

        override fun protect(socket: Socket): Boolean {
            val count = tcpProtectCalls.incrementAndGet()
            return !(failRuntimeProtect.get() && count > 1)
        }
    }

    private fun dnsQuery(domain: String, id: Int): ByteArray {
        val labels = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray().toList()
        } + 0.toByte()
        val question = labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = (id ushr 8).toByte()
            it[1] = id.toByte()
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun positiveResponse(query: ByteArray): ByteArray {
        val response = ByteArray(query.size + 16)
        query.copyInto(response)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[7] = 1
        val offset = query.size
        response[offset] = 0xc0.toByte()
        response[offset + 1] = 0x0c
        response[offset + 3] = 1
        response[offset + 5] = 1
        response[offset + 9] = 60
        response[offset + 11] = 4
        response[offset + 12] = 93.toByte()
        response[offset + 13] = 184.toByte()
        response[offset + 14] = 216.toByte()
        response[offset + 15] = 34
        return response
    }

    private fun buildIpv4UdpPacket(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        putU16(pkt, 2, total)
        pkt[8] = 64
        pkt[9] = 17
        src.copyInto(pkt, 12)
        dst.copyInto(pkt, 16)
        putU16(pkt, 10, internetChecksum(pkt, 0, 20))
        putU16(pkt, 20, srcPort)
        putU16(pkt, 22, dstPort)
        putU16(pkt, 24, udpLen)
        payload.copyInto(pkt, 28)
        val csum = udpChecksum(ipv6 = false, src = src, dst = dst, packet = pkt, offset = 20, length = udpLen)
        putU16(pkt, 26, if (csum == 0) 0xffff else csum)
        return pkt
    }

    private fun buildIpv4Fragment(
        src: ByteArray,
        dst: ByteArray,
        protocol: Int,
        ident: Int,
        offsetBytes: Int,
        moreFragments: Boolean,
        data: ByteArray,
    ): ByteArray {
        val total = 20 + data.size
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        putU16(pkt, 2, total)
        putU16(pkt, 4, ident)
        putU16(pkt, 6, (offsetBytes / 8) or (if (moreFragments) 0x2000 else 0))
        pkt[8] = 64
        pkt[9] = protocol.toByte()
        src.copyInto(pkt, 12)
        dst.copyInto(pkt, 16)
        putU16(pkt, 10, internetChecksum(pkt, 0, 20))
        data.copyInto(pkt, 20)
        return pkt
    }

    private fun buildIpv6HopByHopUdpPacket(
        src: ByteArray,
        dst: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalPayload = 8 + udpLen
        val pkt = ByteArray(40 + totalPayload)
        pkt[0] = 0x60
        putU16(pkt, 4, totalPayload)
        pkt[6] = 0 // Hop-by-Hop
        pkt[7] = 64
        src.copyInto(pkt, 8)
        dst.copyInto(pkt, 24)
        pkt[40] = 17 // UDP
        pkt[41] = 0 // 8 bytes
        putU16(pkt, 48, srcPort)
        putU16(pkt, 50, dstPort)
        putU16(pkt, 52, udpLen)
        payload.copyInto(pkt, 56)
        val csum = udpChecksum(ipv6 = true, src = src, dst = dst, packet = pkt, offset = 48, length = udpLen)
        putU16(pkt, 54, if (csum == 0) 0xffff else csum)
        return pkt
    }

    private fun extractIpv4UdpPayload(pkt: ByteArray): ByteArray {
        val ihl = (pkt[0].toInt() and 0x0f) * 4
        return pkt.copyOfRange(ihl + 8, pkt.size)
    }

    private fun extractIpv6UdpPayload(pkt: ByteArray): ByteArray =
        pkt.copyOfRange(48, pkt.size)

    private fun udpChecksum(
        ipv6: Boolean,
        src: ByteArray,
        dst: ByteArray,
        packet: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        fun add(data: ByteArray, start: Int, count: Int) {
            var i = start
            val end = start + count
            while (i + 1 < end) {
                sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
                i += 2
            }
            if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        }
        add(src, 0, src.size)
        add(dst, 0, dst.size)
        if (ipv6) {
            sum += ((length ushr 16) and 0xffff).toLong()
            sum += (length and 0xffff).toLong()
            sum += 17L
        } else {
            sum += 17L
            sum += length.toLong()
        }
        add(packet, offset, length)
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
