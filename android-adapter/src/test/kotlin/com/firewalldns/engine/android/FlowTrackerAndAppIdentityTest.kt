package com.firewalldns.engine.android

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.runtime.EngineRuntime
import com.firewalldns.engine.threat.FeedUpdateResult
import com.firewalldns.engine.threat.ThreatCategory
import com.firewalldns.engine.threat.ThreatFeedVerifier
import com.firewalldns.engine.threat.ThreatIndicator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class FlowTrackerAndAppIdentityTest {

    @Test
    fun flowTrackerEnforcesCapacityEvictionIdleTtlAndCloseReasons() {
        val nowNanos = AtomicLong(1_000_000_000L)
        val tracker = TunFlowTracker(
            config = TunFlowTrackerConfig(maxActiveFlows = 8, idleTimeoutMillis = 1_000L),
            clockNanos = { nowNanos.get() },
        )
        val client = InetAddress.getByName("10.77.0.2").address
        val server = InetAddress.getByName("10.77.0.1").address

        repeat(10) { i ->
            tracker.recordPacket(
                key = TunFlowTracker.FlowKey(17, false, client, 40_000 + i, server, 53),
                inBytes = 60,
                outBytes = 90,
            )
        }
        var snap = tracker.snapshot()
        assertEquals(8, snap.activeFlows)
        assertEquals(2L, snap.closedEvictedCapacity)
        assertEquals(10L, snap.totalOpened)

        tracker.closeFlow(TunFlowTracker.FlowKey(17, false, client, 40_009, server, 53), FlowCloseReason.POLICY_BLOCKED)
        nowNanos.addAndGet(1_500_000_000L)
        val expired = tracker.evictExpired()
        assertEquals(7, expired)

        snap = tracker.snapshot()
        assertEquals(0, snap.activeFlows)
        assertEquals(1L, snap.closedPolicyBlocked)
        assertEquals(7L, snap.closedIdleTimeout)
    }

    @Test
    fun appIdentityAttributionEnforcesPerAppRulesAndDegradesExplicitlyWhenNull() {
        val udpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val serverThread = thread(name = "app-identity-test-dns") {
            val buf = ByteArray(1024)
            udpServer.soTimeout = 200
            while (!udpServer.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    udpServer.receive(pkt)
                    val q = pkt.data.copyOf(pkt.length)
                    val r = positiveResponse(q)
                    udpServer.send(DatagramPacket(r, r.size, pkt.socketAddress))
                } catch (_: Throwable) {
                }
            }
        }

        try {
            val engine = EngineRuntime(
                initialRules = listOf(
                    PolicyRule(
                        id = "block-social-for-browser",
                        domain = "social.example.com",
                        appPackage = "com.example.browser",
                        action = PolicyAction.BLOCK,
                        source = RuleSource.USER,
                        reason = "app_blocked_browser",
                    ),
                ),
            )
            var currentPkg: String? = "com.example.browser"
            val resolver = AppIdentityResolver { _, _, _, _, _ -> currentPkg }
            val protector = object : DnsSocketProtector {
                override fun protect(socket: DatagramSocket): Boolean = true
                override fun protect(socket: Socket): Boolean = true
            }
            val activation = TunDataPlaneCoordinator.createValidated(
                engine = engine,
                rawProtector = protector,
                securityConfig = TunDataPlaneSecurityConfig(
                    upstreamConfigs = listOf(DnsUpstreamConfig("127.0.0.1", udpServer.localPort, 1_500)),
                    appPackageName = "com.firewalldns.diagnostics",
                    allowLoopbackUpstreamsForTesting = true,
                ),
                appIdentityResolver = resolver,
            )
            val coordinator = (activation as TunDataPlaneCoordinator.ActivationResult.Activated).coordinator
            val client = InetAddress.getByName("10.77.0.2").address
            val dns = InetAddress.getByName("10.77.0.1").address

            // 1. Matching appPackage -> blocked with NXDOMAIN
            val pktBrowser = buildIpv4UdpPacket(client, dns, 41_111, 53, dnsQuery("social.example.com", 10))
            val resBrowser = coordinator.onPacket(pktBrowser) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            assertEquals("dns_blocked_response", resBrowser.outcome)

            // 2. App identity unavailable (null) -> explicitly degrades to global rules (ALLOW -> forwarded)
            currentPkg = null
            val pktUnknown = buildIpv4UdpPacket(client, dns, 41_112, 53, dnsQuery("social.example.com", 11))
            val resUnknown = coordinator.onPacket(pktUnknown) as TunDataPlaneCoordinator.PacketHandlingResult.Responses
            assertEquals("dns_forwarded_response", resUnknown.outcome)

            val metrics = coordinator.metrics()
            assertTrue(metrics.flows.totalOpened >= 2L)
            assertEquals(1L, metrics.flows.closedPolicyBlocked)

            coordinator.close()
            assertEquals(0, coordinator.metrics().flows.activeFlows)
        } finally {
            udpServer.close()
            serverThread.join(2_000)
        }
    }

    @Test
    fun runtimeThreatFeedUpdateInvalidatesDecisionCacheImmediately() {
        val engine = EngineRuntime()
        val query = dnsQuery("new-malware.example", 77)
        val first = engine.evaluateDns(query)
        assertTrue(first is DnsEvaluation.Forward)

        // Cached ALLOW at threatRevision 0 -> now publish signed feed blocking new-malware.example
        val kp = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val now = 1_700_000_000_000L
        val feed = ThreatFeedVerifier.sign(
            version = 1L,
            publishedAtEpochMillis = now - 1_000L,
            expiresAtEpochMillis = now + 60_000L,
            indicators = listOf(
                ThreatIndicator(
                    id = "mal-new",
                    domain = "new-malware.example",
                    category = ThreatCategory.MALWARE,
                    confidence = 99,
                    action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED,
                    reason = "signed_malware_block",
                ),
            ),
            safeDomains = emptyList(),
            privateKey = kp.private,
        )
        val update = engine.replaceThreatFeed(feed, kp.public, now)
        assertTrue(update is FeedUpdateResult.Applied)
        assertEquals(1L, engine.threatRevision)

        val afterUpdate = engine.evaluateDns(query, nowEpochMillis = now)
        assertTrue(afterUpdate is DnsEvaluation.Blocked)
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
        val csum = udpChecksumIpv4(src, dst, pkt, 20, udpLen)
        putU16(pkt, 26, if (csum == 0) 0xffff else csum)
        return pkt
    }

    private fun udpChecksumIpv4(src: ByteArray, dst: ByteArray, packet: ByteArray, offset: Int, length: Int): Int {
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
        sum += 17L
        sum += length.toLong()
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
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
