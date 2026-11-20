package com.firewalldns.engine.runtime

import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpFrameDecode
import com.firewalldns.engine.dns.DnsUpstreamResponse
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsTcpSessionRegistryTest {
    @Test
    fun boundsSessionsRejectsDuplicateIdsAndReleasesCapacityOnClose() {
        val registry = registry(maxSessions = 1)

        try {
            assertEquals(DnsTcpSessionRegistry.OpenResult.Opened, registry.openSession(10))
            assertEquals(DnsTcpSessionRegistry.OpenResult.AlreadyExists, registry.openSession(10))
            assertEquals(DnsTcpSessionRegistry.OpenResult.CapacityReached, registry.openSession(11))
            assertEquals(1, registry.activeSessionCount)

            assertTrue(registry.closeSession(10))
            assertEquals(0, registry.activeSessionCount)
            assertEquals(DnsTcpSessionRegistry.OpenResult.Opened, registry.openSession(11))
        } finally {
            registry.close()
        }
    }

    @Test
    fun forwardsChunksToWorkerAndDrainsResponseOnTransportOwner() {
        val ready = CountDownLatch(1)
        val registry = registry(onReady = { ready.countDown() })
        val query = query("registry.example")
        val expected = response(query)

        try {
            assertEquals(DnsTcpSessionRegistry.OpenResult.Opened, registry.openSession(7))
            assertEquals(
                DnsTcpSessionRegistry.OfferResult.WorkerResult(DnsTcpSessionWorker.OfferResult.Accepted),
                registry.offer(7, DnsTcpFrameCodec.encode(query)),
            )
            assertTrue(ready.await(2, TimeUnit.SECONDS), "session worker should wake transport owner")

            val frames = registry.drainResponses(7)
            assertEquals(1, frames.size)
            val decoded = assertIs<DnsTcpFrameDecode.Complete>(DnsTcpFrameCodec.decode(frames.single()))
            assertContentEquals(expected, decoded.message)
        } finally {
            registry.close()
        }
    }

    @Test
    fun drainingAResponseRefreshesTheIdleDeadline() {
        val clock = AtomicLong(100)
        val ready = CountDownLatch(1)
        val registry = registry(
            idleTimeoutNanos = 10,
            nowNanos = { clock.get() },
            onReady = { ready.countDown() },
        )

        try {
            assertEquals(DnsTcpSessionRegistry.OpenResult.Opened, registry.openSession(8))
            assertEquals(
                DnsTcpSessionRegistry.OfferResult.WorkerResult(DnsTcpSessionWorker.OfferResult.Accepted),
                registry.offer(8, DnsTcpFrameCodec.encode(query("idle-refresh.example"))),
            )
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            clock.set(109)
            assertEquals(1, registry.drainResponses(8).size)
            assertEquals(emptyList(), registry.expireIdleSessions(now = 118))
            assertEquals(listOf(8L), registry.expireIdleSessions(now = 119))
        } finally {
            registry.close()
        }
    }

    @Test
    fun expiresIdleSessionAndCancelsItsUpstream() {
        val clock = AtomicLong(100)
        val cancelled = CountDownLatch(1)
        val registry = registry(
            cancel = { cancelled.countDown() },
            idleTimeoutNanos = 10,
            nowNanos = { clock.get() },
        )

        try {
            assertEquals(DnsTcpSessionRegistry.OpenResult.Opened, registry.openSession(42))
            clock.set(111)
            assertEquals(listOf(42L), registry.expireIdleSessions())
            assertTrue(cancelled.await(2, TimeUnit.SECONDS))
            assertEquals(0, registry.activeSessionCount)
        } finally {
            registry.close()
        }
    }

    @Test
    fun closeAllIsIdempotentAndRejectsFurtherSessions() {
        val registry = registry()
        registry.openSession(1)

        registry.close()
        registry.close()

        assertEquals(0, registry.activeSessionCount)
        assertEquals(DnsTcpSessionRegistry.OpenResult.Closed, registry.openSession(2))
    }

    private fun registry(
        maxSessions: Int = 8,
        idleTimeoutNanos: Long = 60_000_000_000L,
        nowNanos: () -> Long = System::nanoTime,
        cancel: (Long) -> Unit = {},
        onReady: (Long) -> Unit = {},
    ) = DnsTcpSessionRegistry(
        processorFactory = {
            DnsTcpSessionProcessor(
                engine = EngineRuntime(),
                exchangeUpstream = { message ->
                    DnsUpstreamResult.Success(
                        DnsUpstreamResponse(response(message), DnsUpstreamTransport.UDP),
                    )
                },
            )
        },
        cancelUpstream = cancel,
        onResponsesAvailable = onReady,
        maxSessions = maxSessions,
        idleTimeoutNanos = idleTimeoutNanos,
        nowNanos = nowNanos,
    )

    private fun query(domain: String): ByteArray {
        val name = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = name.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun response(query: ByteArray): ByteArray = query.copyOf().also {
        it[2] = 0x81.toByte()
        it[3] = 0x80.toByte()
    }
}
