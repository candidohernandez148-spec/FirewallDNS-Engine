package com.firewalldns.engine.runtime

import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpFrameDecode
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
            engine = EngineRuntime(),
            exchangeUpstream = {
                DnsUpstreamResult.Success(DnsUpstreamResponse(expected, DnsUpstreamTransport.UDP))
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
            val decoded = assertIs<DnsTcpFrameDecode.Complete>(DnsTcpFrameCodec.decode(drained.single()))
            assertContentEquals(expected, decoded.message)
            assertEquals(0, worker.queuedResponseBytes)
        } finally {
            worker.close()
        }
    }

    @Test
    fun closesAndCancelsUpstreamWhenInputQueueWouldLoseStreamBytes() {
        val upstreamStarted = CountDownLatch(1)
        val cancelCalled = CountDownLatch(1)
        val releaseUpstream = CountDownLatch(1)
        val query = DnsTcpFrameCodec.encode(query("blocked-worker.example"))
        val worker = DnsTcpSessionWorker(
            processor = DnsTcpSessionProcessor(
                engine = EngineRuntime(),
                exchangeUpstream = {
                    upstreamStarted.countDown()
                    releaseUpstream.await(2, TimeUnit.SECONDS)
                    DnsUpstreamResult.Failure("cancelled_test")
                },
            ),
            cancelUpstream = {
                cancelCalled.countDown()
                releaseUpstream.countDown()
            },
            maxQueuedInputChunks = 1,
        )

        try {
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(query))
            assertTrue(upstreamStarted.await(2, TimeUnit.SECONDS), "worker should enter upstream exchange")
            assertEquals(DnsTcpSessionWorker.OfferResult.Accepted, worker.offer(query))
            val rejected = assertIs<DnsTcpSessionWorker.OfferResult.Closed>(worker.offer(query))
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
        val query = query("response-limit.example")
        val worker = DnsTcpSessionWorker(
            processor = DnsTcpSessionProcessor(
                engine = EngineRuntime(),
                exchangeUpstream = {
                    DnsUpstreamResult.Success(
                        DnsUpstreamResponse(response(it), DnsUpstreamTransport.UDP),
                    )
                },
            ),
            cancelUpstream = { closed.countDown() },
            maxQueuedResponseBytes = 1,
        )

        try {
            worker.offer(DnsTcpFrameCodec.encode(query))
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
