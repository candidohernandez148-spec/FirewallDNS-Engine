package com.firewalldns.engine.runtime

import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.dns.DnsPolicyAdapter
import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpSessionProcessor
import com.firewalldns.engine.dns.DnsTcpStreamDecoder
import com.firewalldns.engine.dns.DnsUpstreamResponse
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsTcpSessionWorkerTest {
    @Test
    fun processesOnWorkerAndReturnsFramesForSmoltcpOwnerToDrain() {
        val query = query("worker.example")
        val expected = response(query)
        val ready = CountDownLatch(1)
        val processor = DnsTcpSessionProcessor(
            policyAdapter = DnsPolicyAdapter(PolicyEngine(emptyList())),
            exchangeUpstream = { message, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(response(message), DnsUpstreamTransport.TCP))
            },
        )
        val worker = DnsTcpSessionWorker(
            processor = processor,
            cancelUpstream = {},
            onResponsesAvailable = { ready.countDown() },
        )

        try {
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(DnsTcpFrameCodec.encode(query)))
            assertTrue(ready.await(2, TimeUnit.SECONDS), "worker should publish a completed response")
            val drained = worker.drainResponses()
            assertEquals(1, drained.size)
            val decoder = DnsTcpStreamDecoder()
            assertIs<DnsTcpStreamDecoder.FeedResult.Accepted>(decoder.feed(drained.single()))
            val decoded = assertIs<DnsTcpStreamDecoder.DrainResult.Frame>(decoder.drainFrame())
            assertContentEquals(expected, decoded.message)
            assertEquals(0, worker.queuedResponseBytes)
        } finally {
            worker.close()
        }
    }

    @Test
    fun reportsIdleOnlyAfterProcessingAndResponseDrainComplete() {
        val ready = CountDownLatch(1)
        val query = query("idle-worker.example")
        val processor = DnsTcpSessionProcessor(
            policyAdapter = DnsPolicyAdapter(PolicyEngine(emptyList())),
            exchangeUpstream = { message, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(response(message), DnsUpstreamTransport.TCP))
            },
        )
        val worker = DnsTcpSessionWorker(
            processor = processor,
            cancelUpstream = {},
            onResponsesAvailable = { ready.countDown() },
        )

        try {
            assertTrue(worker.isIdle)
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(DnsTcpFrameCodec.encode(query)))
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            assertTrue(!worker.isIdle, "queued responses are still outstanding")
            assertEquals(1, worker.drainResponses().size)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (!worker.isIdle && System.nanoTime() < deadline) {
                Thread.sleep(1)
            }
            assertTrue(worker.isIdle, "worker should become idle after processing and response drain")
        } finally {
            worker.close()
        }
    }

    @Test
    fun closesAndCancelsUpstreamWhenInputQueueWouldLoseStreamBytes() {
        val upstreamStarted = CountDownLatch(1)
        val cancelCalled = CountDownLatch(1)
        val releaseUpstream = CountDownLatch(1)
        val queryFrame = DnsTcpFrameCodec.encode(query("blocked-worker.example"))
        val processor = DnsTcpSessionProcessor(
            policyAdapter = DnsPolicyAdapter(PolicyEngine(emptyList())),
            exchangeUpstream = { _, _ ->
                upstreamStarted.countDown()
                releaseUpstream.await(2, TimeUnit.SECONDS)
                DnsUpstreamResult.Failure("cancelled_test")
            },
        )
        val worker = DnsTcpSessionWorker(
            processor = processor,
            cancelUpstream = {
                cancelCalled.countDown()
                releaseUpstream.countDown()
            },
            maxQueuedInputChunks = 1,
        )

        try {
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(queryFrame))
            assertTrue(upstreamStarted.await(2, TimeUnit.SECONDS), "worker should enter upstream exchange")
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(queryFrame))
            val rejected = assertIs<DnsTcpSessionWorker.OfferResult.Closed>(worker.offer(queryFrame))
            assertEquals("dns_tcp_worker_queue_full", rejected.reason)
            assertTrue(cancelCalled.await(2, TimeUnit.SECONDS), "queue overflow must cancel upstream")
            assertTrue(worker.isClosed)
        } finally {
            releaseUpstream.countDown()
            worker.close()
        }
    }

    @Test
    fun closesWhenResponseQueueCannotRetainWholeBatch() {
        val closed = CountDownLatch(1)
        val queryFrame = DnsTcpFrameCodec.encode(query("response-limit.example"))
        val processor = DnsTcpSessionProcessor(
            policyAdapter = DnsPolicyAdapter(PolicyEngine(emptyList())),
            exchangeUpstream = { message, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(response(message), DnsUpstreamTransport.TCP))
            },
        )
        val worker = DnsTcpSessionWorker(
            processor = processor,
            cancelUpstream = { closed.countDown() },
            maxQueuedResponseBytes = 1,
        )

        try {
            worker.offer(queryFrame)
            assertTrue(closed.await(2, TimeUnit.SECONDS), "response overflow should close the session")
            assertEquals("dns_tcp_worker_response_limit_exceeded", worker.closeReason)
            assertEquals(0, worker.queuedResponseBytes)
        } finally {
            worker.close()
        }
    }

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
