package com.firewalldns.engine.android

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpStreamDecoder
import com.firewalldns.engine.dns.DnsUpstreamResponse
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import com.firewalldns.engine.runtime.EngineRuntime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

class TunTcpStackLoadTest {

    @Test
    fun ipv4AndIpv6HandshakeSplitDnsQueryAndGracefulFinLifecycle() {
        val clock = AtomicLong(1_000_000L)
        val engine = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "block-tracker",
                    domain = "tracker.example.com",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "test_user_block",
                ),
            ),
        )
        val stack = TunTcpStack(
            engine = engine,
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            config = TunTcpStackConfig(timeWaitMillis = 500L),
            clockNanos = { clock.get() },
            isnProvider = { 10_000L },
        )

        // IPv4 blocked query split across two TCP segments
        runSingleSession(
            stack = stack,
            clock = clock,
            ipv6 = false,
            clientIp = InetAddress.getByName("10.77.0.2").address,
            serverIp = InetAddress.getByName("10.77.0.1").address,
            clientPort = 51_001,
            queries = listOf(dnsQuery("tracker.example.com", 77)),
            expectedRcodes = listOf(3),
        )

        // IPv6 allowed query
        runSingleSession(
            stack = stack,
            clock = clock,
            ipv6 = true,
            clientIp = InetAddress.getByName("fd77::2").address,
            serverIp = InetAddress.getByName("fd77::1").address,
            clientPort = 51_002,
            queries = listOf(dnsQuery("allowed.example.com", 88)),
            expectedRcodes = listOf(0),
        )

        // Advance past TIME_WAIT and tick to release both sessions
        clock.addAndGet(600_000_000L)
        stack.tick()

        val m = stack.metrics()
        assertEquals(0, m.activeSessions)
        assertEquals(2L, m.totalAccepted)
        assertEquals(2L, m.totalClosedGracefully)
        assertEquals(0L, m.totalReset)
        assertEquals(2L, m.dnsQueriesProcessed)
        assertEquals(0L, m.badChecksumDropped)
    }

    @Test
    fun retransmitsDroppedSynAckAndFastRetransmitsLostDataUnderDupAcks() {
        val clock = AtomicLong(1_000_000L)
        val engine = EngineRuntime()
        val stack = TunTcpStack(
            engine = engine,
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            config = TunTcpStackConfig(initialRtoMillis = 100L, maxRtoMillis = 800L, maxRetransmissions = 4, timeWaitMillis = 0L),
            clockNanos = { clock.get() },
            isnProvider = { 50_000L },
        )

        val clientIp = InetAddress.getByName("10.77.0.2").address
        val serverIp = InetAddress.getByName("10.77.0.1").address
        var clientSeq = 1_000L

        // 1. Send SYN, drop first SYN+ACK
        val syn = TunTcpSegmentCodec.encode(
            ipv6 = false, clientIp, serverIp, 42_000, 53,
            clientSeq, 0L, TunTcpSegmentCodec.FLAG_SYN, 4096, mssOption = 1460,
        )
        val firstSynAck = stack.onPacket(syn)
        assertEquals(1, firstSynAck.size)
        // Drop firstSynAck! Advance clock past RTO (100 ms)
        clock.addAndGet(110_000_000L)
        val retransmitted = stack.tick()
        assertEquals(1, retransmitted.size)
        val synAckDec = (TunTcpSegmentCodec.decode(retransmitted[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        assertTrue(synAckDec.isSyn && synAckDec.isAck)
        clientSeq++

        // Complete handshake
        var serverExpectedAck = (synAckDec.sequenceNumber + 1L) and 0xFFFF_FFFFL
        stack.onPacket(
            TunTcpSegmentCodec.encode(
                false, clientIp, serverIp, 42_000, 53,
                clientSeq, serverExpectedAck, TunTcpSegmentCodec.FLAG_ACK, 4096,
            ),
        )

        // 2. Send 2 pipelined queries in small segments so server produces multiple response bytes
        val q = dnsQuery("retransmit.example.com", 901)
        val framed = DnsTcpFrameCodec.encode(q)
        val dataOut = stack.onPacket(
            TunTcpSegmentCodec.encode(
                false, clientIp, serverIp, 42_000, 53,
                clientSeq, serverExpectedAck, TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 4096,
                payload = framed,
            ),
        )
        clientSeq += framed.size
        assertTrue(dataOut.isNotEmpty())
        val expectedResp = DnsTcpFrameCodec.encode(positiveResponse(q))

        // Drop the server response and send 3 duplicate ACKs with unchanged window -> triggers fast retransmit!
        var fastRetransSeg: TunTcpSegmentCodec.DecodedTcpPacket? = null
        repeat(3) {
            val res = stack.onPacket(
                TunTcpSegmentCodec.encode(
                    false, clientIp, serverIp, 42_000, 53,
                    clientSeq, serverExpectedAck, TunTcpSegmentCodec.FLAG_ACK, 4096,
                ),
            )
            if (res.isNotEmpty()) {
                fastRetransSeg = (TunTcpSegmentCodec.decode(res[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            }
        }
        assertTrue(fastRetransSeg != null)
        assertArrayEquals(expectedResp, fastRetransSeg!!.payload)
        serverExpectedAck += expectedResp.size

        // ACK the fast-retransmitted data & close cleanly
        stack.onPacket(
            TunTcpSegmentCodec.encode(
                false, clientIp, serverIp, 42_000, 53,
                clientSeq, serverExpectedAck, TunTcpSegmentCodec.FLAG_FIN or TunTcpSegmentCodec.FLAG_ACK, 4096,
            ),
        )
        // Client sends final ACK for server FIN
        stack.onPacket(
            TunTcpSegmentCodec.encode(
                false, clientIp, serverIp, 42_000, 53,
                clientSeq + 1L, serverExpectedAck + 1L, TunTcpSegmentCodec.FLAG_ACK, 4096,
            ),
        )

        val m = stack.metrics()
        assertEquals(2L, m.retransmissions) // 1 SYN+ACK RTO + 1 Fast Retransmit
        assertEquals(1L, m.fastRetransmissions)
        assertEquals(1L, m.totalClosedGracefully)
        assertEquals(0, m.activeSessions)
    }

    @Test
    fun enforcesPeerSlidingWindowAndZeroWindowBackpressure() {
        val clock = AtomicLong(1_000_000L)
        val stack = TunTcpStack(
            engine = EngineRuntime(),
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            config = TunTcpStackConfig(initialRtoMillis = 50L, timeWaitMillis = 0L),
            clockNanos = { clock.get() },
            isnProvider = { 20_000L },
        )

        val clientIp = InetAddress.getByName("10.77.0.2").address
        val serverIp = InetAddress.getByName("10.77.0.1").address
        var clientSeq = 5_000L

        val synAckPkts = stack.onPacket(
            TunTcpSegmentCodec.encode(false, clientIp, serverIp, 43_000, 53, clientSeq++, 0L, TunTcpSegmentCodec.FLAG_SYN, 16, mssOption = 1460),
        )
        val synAck = (TunTcpSegmentCodec.decode(synAckPkts[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        var ackNum = synAck.sequenceNumber + 1L

        stack.onPacket(
            TunTcpSegmentCodec.encode(false, clientIp, serverIp, 43_000, 53, clientSeq, ackNum, TunTcpSegmentCodec.FLAG_ACK, 16),
        )

        // Send query with peerWindow = 16 bytes: response (~54 bytes) must be capped at 16 bytes in-flight!
        val q = dnsQuery("window.example.com", 404)
        val framed = DnsTcpFrameCodec.encode(q)
        val expectedResp = DnsTcpFrameCodec.encode(positiveResponse(q))
        assertTrue(expectedResp.size > 32)

        val out1 = stack.onPacket(
            TunTcpSegmentCodec.encode(
                false, clientIp, serverIp, 43_000, 53, clientSeq, ackNum,
                TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 16, payload = framed,
            ),
        )
        clientSeq += framed.size
        assertEquals(1, out1.size)
        val seg1 = (TunTcpSegmentCodec.decode(out1[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        assertEquals(16, seg1.payload.size)
        ackNum += 16

        val received = ByteArrayOutputStream()
        received.write(seg1.payload)

        // Advertise zero window: server must hold remaining bytes and emit zero-window probe on tick
        val outZero = stack.onPacket(
            TunTcpSegmentCodec.encode(false, clientIp, serverIp, 43_000, 53, clientSeq, ackNum, TunTcpSegmentCodec.FLAG_ACK, 0),
        )
        assertTrue(outZero.isEmpty())
        clock.addAndGet(60_000_000L)
        val probe = stack.tick()
        assertEquals(1, probe.size)
        val probeSeg = (TunTcpSegmentCodec.decode(probe[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        assertEquals(0, probeSeg.payload.size)

        // Re-open window to 1024 -> remaining bytes flush immediately!
        val outRest = stack.onPacket(
            TunTcpSegmentCodec.encode(false, clientIp, serverIp, 43_000, 53, clientSeq, ackNum, TunTcpSegmentCodec.FLAG_ACK, 1024),
        )
        assertTrue(outRest.isNotEmpty())
        for (p in outRest) {
            val s = (TunTcpSegmentCodec.decode(p) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            received.write(s.payload)
            ackNum += s.payload.size
        }
        assertArrayEquals(expectedResp, received.toByteArray())
        assertTrue(stack.metrics().zeroWindowEvents > 0)
    }

    @Test
    fun abortsTimedOutSessionWithRstWhenMaxRetransmissionsExceeded() {
        val clock = AtomicLong(1_000_000L)
        val stack = TunTcpStack(
            engine = EngineRuntime(),
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            config = TunTcpStackConfig(initialRtoMillis = 50L, maxRtoMillis = 400L, maxRetransmissions = 2),
            clockNanos = { clock.get() },
        )

        val clientIp = InetAddress.getByName("10.77.0.2").address
        val serverIp = InetAddress.getByName("10.77.0.1").address
        stack.onPacket(
            TunTcpSegmentCodec.encode(false, clientIp, serverIp, 44_000, 53, 1L, 0L, TunTcpSegmentCodec.FLAG_SYN, 4096),
        )
        assertEquals(1, stack.metrics().activeSessions)

        // Retry 1 (50ms), Retry 2 (100ms), Exceeded -> RST (200ms)
        clock.addAndGet(60_000_000L)
        assertEquals(1, stack.tick().size)
        clock.addAndGet(110_000_000L)
        assertEquals(1, stack.tick().size)
        clock.addAndGet(210_000_000L)
        val rstPkts = stack.tick()
        assertEquals(1, rstPkts.size)
        val rst = (TunTcpSegmentCodec.decode(rstPkts[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        assertTrue(rst.isRst)
        assertEquals(0, stack.metrics().activeSessions)
        assertEquals(1L, stack.metrics().totalReset)
    }

    @Test
    fun stressLoadWithConcurrentSessionsOutOfOrderPacketLossAndSessionLimit() {
        val clock = AtomicLong(1_000_000L)
        val engine = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "block-ads",
                    domain = "ads.load.example",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.BUILTIN,
                    reason = "test_builtin_block",
                ),
            ),
        )
        val maxSessions = 24
        val stack = TunTcpStack(
            engine = engine,
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            config = TunTcpStackConfig(
                maxSessions = maxSessions,
                initialRtoMillis = 40L,
                maxRtoMillis = 320L,
                maxRetransmissions = 5,
                timeWaitMillis = 200L,
            ),
            clockNanos = { clock.get() },
        )

        val clientIp = InetAddress.getByName("10.77.0.2").address
        val serverIp = InetAddress.getByName("10.77.0.1").address
        val queriesPerSession = 3

        class SimClient(val idx: Int, val port: Int, val ipv6: Boolean) {
            val cAddr = if (ipv6) InetAddress.getByName("fd77::2").address else clientIp
            val sAddr = if (ipv6) InetAddress.getByName("fd77::1").address else serverIp
            var seq = 100_000L + port
            var ack = 0L
            val decoder = DnsTcpStreamDecoder()
            val expectedIds = listOf(
                (idx * 10 + 1) and 0xffff,
                (idx * 10 + 2) and 0xffff,
                (idx * 10 + 3) and 0xffff,
            )
            var ackedFin = false
        }

        val activeClients = (0 until maxSessions).map { idx ->
            SimClient(idx = idx, port = 45_000 + idx, ipv6 = idx % 2 == 1)
        }

        // Handshake all 24 sessions
        for (c in activeClients) {
            val synOut = stack.onPacket(
                TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq++, 0L, TunTcpSegmentCodec.FLAG_SYN, 4096, mssOption = 1400),
            )
            val synAck = (TunTcpSegmentCodec.decode(synOut[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            c.ack = synAck.sequenceNumber + 1L
            stack.onPacket(
                TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_ACK, 4096),
            )
        }
        assertEquals(maxSessions, stack.metrics().activeSessions)

        // 8 extra connections beyond maxSessions must receive RST and increment rejected_limit
        for (extra in 0 until 8) {
            val rstOut = stack.onPacket(
                TunTcpSegmentCodec.encode(false, clientIp, serverIp, 49_000 + extra, 53, 1L, 0L, TunTcpSegmentCodec.FLAG_SYN, 4096),
            )
            assertEquals(1, rstOut.size)
            val rst = (TunTcpSegmentCodec.decode(rstOut[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            assertTrue(rst.isRst)
        }
        assertEquals(8L, stack.metrics().sessionsRejectedLimit)

        // Send 3 pipelined DNS queries per session; intentionally swap segments out-of-order on half of them
        // and drop every 5th server response packet to force retransmissions under load!
        var dropCounter = 0
        for ((idx, c) in activeClients.withIndex()) {
            val q1 = dnsQuery("ads.load.example", c.expectedIds[0])
            val q2 = dnsQuery("svc-$idx.load.example", c.expectedIds[1])
            val q3 = dnsQuery("cdn-$idx.load.example", c.expectedIds[2])
            val stream = DnsTcpFrameCodec.encode(q1) + DnsTcpFrameCodec.encode(q2) + DnsTcpFrameCodec.encode(q3)
            val mid = stream.size / 2
            val part1 = stream.copyOfRange(0, mid)
            val part2 = stream.copyOfRange(mid, stream.size)

            val responses = ArrayList<ByteArray>()
            if (idx % 2 == 0) {
                // Out-of-order delivery: part2 arrives before part1!
                responses += stack.onPacket(
                    TunTcpSegmentCodec.encode(
                        c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq + part1.size, c.ack,
                        TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 4096, payload = part2,
                    ),
                )
                responses += stack.onPacket(
                    TunTcpSegmentCodec.encode(
                        c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack,
                        TunTcpSegmentCodec.FLAG_ACK, 4096, payload = part1,
                    ),
                )
            } else {
                responses += stack.onPacket(
                    TunTcpSegmentCodec.encode(
                        c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack,
                        TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 4096, payload = stream,
                    ),
                )
            }
            c.seq += stream.size

            for (rawOut in responses) {
                val seg = (TunTcpSegmentCodec.decode(rawOut) as TunTcpSegmentCodec.DecodeResult.Valid).packet
                if (seg.payload.isNotEmpty()) {
                    if ((++dropCounter) % 5 == 0) {
                        // Drop server packet! Will recover on tick() RTO retransmission
                        continue
                    }
                    if (seg.sequenceNumber == c.ack) {
                        c.decoder.feed(seg.payload)
                        c.ack += seg.payload.size
                    }
                }
            }
            stack.onPacket(
                TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_ACK, 4096),
            )
        }

        // Run RTO ticks until every dropped packet is retransmitted and acknowledged
        repeat(6) {
            clock.addAndGet(50_000_000L)
            val timerOut = stack.tick()
            for (rawOut in timerOut) {
                val seg = (TunTcpSegmentCodec.decode(rawOut) as TunTcpSegmentCodec.DecodeResult.Valid).packet
                val c = activeClients.first { it.port == seg.destinationPort }
                if (seg.payload.isNotEmpty() && seg.sequenceNumber == c.ack) {
                    c.decoder.feed(seg.payload)
                    c.ack += seg.payload.size
                    stack.onPacket(
                        TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_ACK, 4096),
                    )
                }
            }
        }

        // Verify every client decoded all 3 exact responses, then close cleanly (20 FIN, 4 RST)
        for ((idx, c) in activeClients.withIndex()) {
            val decodedFrames = ArrayList<ByteArray>()
            while (true) {
                when (val d = c.decoder.drainFrame()) {
                    is DnsTcpStreamDecoder.DrainResult.Frame -> decodedFrames += d.message
                    else -> break
                }
            }
            assertEquals("Client $idx missing DNS frames", queriesPerSession, decodedFrames.size)
            assertEquals(c.expectedIds[0], u16(decodedFrames[0], 0))
            assertEquals(3, decodedFrames[0][3].toInt() and 0x0f) // Blocked NXDOMAIN
            assertEquals(c.expectedIds[1], u16(decodedFrames[1], 0))
            assertEquals(0, decodedFrames[1][3].toInt() and 0x0f) // Forwarded NOERROR
            assertEquals(c.expectedIds[2], u16(decodedFrames[2], 0))
            assertEquals(0, decodedFrames[2][3].toInt() and 0x0f) // Forwarded NOERROR

            if (idx < 20) {
                val finOut = stack.onPacket(
                    TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_FIN or TunTcpSegmentCodec.FLAG_ACK, 4096),
                )
                c.seq++
                // Consume server FIN+ACK
                for (rawOut in finOut) {
                    val seg = (TunTcpSegmentCodec.decode(rawOut) as TunTcpSegmentCodec.DecodeResult.Valid).packet
                    if (seg.isFin) {
                        c.ack = seg.sequenceNumber + 1L
                        stack.onPacket(
                            TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_ACK, 4096),
                        )
                        c.ackedFin = true
                    }
                }
                assertTrue(c.ackedFin)
            } else {
                stack.onPacket(
                    TunTcpSegmentCodec.encode(c.ipv6, c.cAddr, c.sAddr, c.port, 53, c.seq, c.ack, TunTcpSegmentCodec.FLAG_RST, 0),
                )
            }
        }

        // Expire TIME_WAIT and verify zero leaked sessions
        clock.addAndGet(250_000_000L)
        stack.tick()

        val metrics = stack.metrics()
        assertEquals(0, metrics.activeSessions)
        assertEquals((maxSessions * queriesPerSession).toLong(), metrics.dnsQueriesProcessed)
        assertEquals(20L, metrics.totalClosedGracefully)
        assertEquals(4L, metrics.totalReset)
        assertTrue(metrics.retransmissions > 0L)
        assertTrue(metrics.outOfOrderBuffered > 0L)
        assertEquals(0L, metrics.badChecksumDropped)
    }

    private fun runSingleSession(
        stack: TunTcpStack,
        clock: AtomicLong,
        ipv6: Boolean,
        clientIp: ByteArray,
        serverIp: ByteArray,
        clientPort: Int,
        queries: List<ByteArray>,
        expectedRcodes: List<Int>,
    ) {
        var clientSeq = 1_000L
        val synOut = stack.onPacket(
            TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq++, 0L, TunTcpSegmentCodec.FLAG_SYN, 4096, mssOption = 1400),
        )
        assertEquals(1, synOut.size)
        val synAck = (TunTcpSegmentCodec.decode(synOut[0]) as TunTcpSegmentCodec.DecodeResult.Valid).packet
        assertTrue(synAck.isSyn && synAck.isAck)
        var serverAck = synAck.sequenceNumber + 1L

        stack.onPacket(
            TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq, serverAck, TunTcpSegmentCodec.FLAG_ACK, 4096),
        )

        val decoder = DnsTcpStreamDecoder()
        for (q in queries) {
            val framed = DnsTcpFrameCodec.encode(q)
            val half = framed.size / 2
            val outA = stack.onPacket(
                TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq, serverAck, TunTcpSegmentCodec.FLAG_ACK, 4096, payload = framed.copyOfRange(0, half)),
            )
            clientSeq += half
            assertEquals(1, outA.size) // Pure ACK for partial frame

            val outB = stack.onPacket(
                TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq, serverAck, TunTcpSegmentCodec.FLAG_PSH or TunTcpSegmentCodec.FLAG_ACK, 4096, payload = framed.copyOfRange(half, framed.size)),
            )
            clientSeq += framed.size - half
            for (raw in outB) {
                val seg = (TunTcpSegmentCodec.decode(raw) as TunTcpSegmentCodec.DecodeResult.Valid).packet
                if (seg.payload.isNotEmpty()) {
                    decoder.feed(seg.payload)
                    serverAck += seg.payload.size
                }
            }
        }

        for (expectedRcode in expectedRcodes) {
            val frame = decoder.drainFrame() as DnsTcpStreamDecoder.DrainResult.Frame
            assertEquals(expectedRcode, frame.message[3].toInt() and 0x0f)
        }

        val finOut = stack.onPacket(
            TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq++, serverAck, TunTcpSegmentCodec.FLAG_FIN or TunTcpSegmentCodec.FLAG_ACK, 4096),
        )
        assertTrue(finOut.any {
            val seg = (TunTcpSegmentCodec.decode(it) as TunTcpSegmentCodec.DecodeResult.Valid).packet
            seg.isFin
        })
        serverAck += 1L
        stack.onPacket(
            TunTcpSegmentCodec.encode(ipv6, clientIp, serverIp, clientPort, 53, clientSeq, serverAck, TunTcpSegmentCodec.FLAG_ACK, 4096),
        )
        clock.addAndGet(1_000_000L)
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
        response[offset + 12] = 192.toByte()
        response[offset + 13] = 0
        response[offset + 14] = 2
        response[offset + 15] = 1
        return response
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
