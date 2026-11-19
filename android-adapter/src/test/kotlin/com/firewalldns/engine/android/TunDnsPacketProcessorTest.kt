package com.firewalldns.engine.android

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsUpstreamResponse
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import com.firewalldns.engine.runtime.EngineRuntime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class TunDnsPacketProcessorTest {
    @Test fun forwardsIpv4DnsThroughEngineAndBuildsReversePacket() {
        val query = query("allowed.example")
        val upstreamResponse = response(query)
        val processor = TunDnsPacketProcessor(EngineRuntime()) {
            DnsUpstreamResult.Success(DnsUpstreamResponse(upstreamResponse, DnsUpstreamTransport.UDP))
        }

        val result = processor.process(ipv4Packet(query))

        assertNotNull(result)
        val packet = result!!
        assertEquals(4, packet[0].toInt() ushr 4)
        assertArrayEquals(byteArrayOf(10, 77, 0, 1), packet.copyOfRange(12, 16))
        assertArrayEquals(byteArrayOf(192.toByte(), 0, 2, 10), packet.copyOfRange(16, 20))
        assertEquals(53, u16(packet, 20))
        assertEquals(53000, u16(packet, 22))
        assertArrayEquals(upstreamResponse, packet.copyOfRange(28, packet.size))
        assertEquals(0, checksum(packet, 0, 20))
    }

    @Test fun forwardsIpv6DnsAndBuildsUdpChecksum() {
        val query = query("ipv6.example")
        val upstreamResponse = response(query)
        val processor = TunDnsPacketProcessor(EngineRuntime()) {
            DnsUpstreamResult.Success(DnsUpstreamResponse(upstreamResponse, DnsUpstreamTransport.UDP))
        }

        val result = processor.process(ipv6Packet(query))

        assertNotNull(result)
        val packet = result!!
        assertEquals(6, packet[0].toInt() ushr 4)
        assertArrayEquals(ipv6Destination(), packet.copyOfRange(8, 24))
        assertArrayEquals(ipv6Source(), packet.copyOfRange(24, 40))
        assertEquals(53, u16(packet, 40))
        assertEquals(53001, u16(packet, 42))
        assertNotEqualsZero(u16(packet, 46))
    }

    @Test fun blockDecisionSynthesizesResponseWithoutCallingUpstream() {
        val query = query("blocked.example")
        val runtime = EngineRuntime(
            initialRules = listOf(
                PolicyRule(
                    id = "test-block",
                    domain = "blocked.example",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "test_block",
                ),
            ),
        )
        var upstreamCalls = 0
        val processor = TunDnsPacketProcessor(runtime) {
            upstreamCalls++
            DnsUpstreamResult.Failure("must_not_be_called")
        }

        val result = processor.process(ipv4Packet(query))

        assertNotNull(result)
        assertEquals(0, upstreamCalls)
        assertEquals(3, u16(result!!, 30) and 0x000f)
    }

    @Test fun rejectsTcpAndFragmentedPacketsInsteadOfMisparsingThem() {
        val query = query("unsupported.example")
        val tcp = ipv4Packet(query).also { it[9] = 6 }
        val fragmented = ipv4Packet(query).also { it[6] = 0x20 }
        val processor = TunDnsPacketProcessor(EngineRuntime()) {
            DnsUpstreamResult.Failure("unused")
        }
        assertNull(processor.process(tcp))
        assertNull(processor.process(fragmented))
    }

    private fun query(domain: String): ByteArray {
        val qname = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun response(query: ByteArray): ByteArray =
        query.copyOf().also { it[2] = (it[2].toInt() or 0x80).toByte() }

    private fun ipv4Packet(dns: ByteArray): ByteArray {
        val packet = ByteArray(28 + dns.size)
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        byteArrayOf(192.toByte(), 0, 2, 10).copyInto(packet, 12)
        byteArrayOf(10, 77, 0, 1).copyInto(packet, 16)
        put16(packet, 20, 53000)
        put16(packet, 22, 53)
        put16(packet, 24, 8 + dns.size)
        dns.copyInto(packet, 28)
        return packet
    }

    private fun ipv6Packet(dns: ByteArray): ByteArray {
        val packet = ByteArray(48 + dns.size)
        packet[0] = 0x60
        put16(packet, 4, 8 + dns.size)
        packet[6] = 17
        packet[7] = 64
        ipv6Source().copyInto(packet, 8)
        ipv6Destination().copyInto(packet, 24)
        put16(packet, 40, 53001)
        put16(packet, 42, 53)
        put16(packet, 44, 8 + dns.size)
        dns.copyInto(packet, 48)
        return packet
    }

    private fun ipv6Source() = byteArrayOf(
        0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2,
    )

    private fun ipv6Destination() = byteArrayOf(
        0xfd.toByte(), 0x77, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    )

    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private fun u16(data: ByteArray, offset: Int) =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        while (i + 1 < offset + length) {
            sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun assertNotEqualsZero(value: Int) {
        assertEquals(false, value == 0)
    }
}
