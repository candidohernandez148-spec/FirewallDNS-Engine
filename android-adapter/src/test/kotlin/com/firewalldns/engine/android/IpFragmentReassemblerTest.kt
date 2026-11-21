package com.firewalldns.engine.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

class IpFragmentReassemblerTest {

    @Test
    fun reassemblesOutOfOrderIpv4FragmentsAndRecalculatesHeaderChecksum() {
        val clock = AtomicLong(1_000_000L)
        val reassembler = IpFragmentReassembler(clockNanos = { clock.get() })
        val payload = ByteArray(40) { (it + 1).toByte() }
        val src = InetAddress.getByName("10.77.0.2").address
        val dst = InetAddress.getByName("10.77.0.1").address

        val frag1 = buildIpv4Fragment(src, dst, 17, 0x1234, offsetBytes = 0, moreFragments = true, data = payload.copyOfRange(0, 24))
        val frag2 = buildIpv4Fragment(src, dst, 17, 0x1234, offsetBytes = 24, moreFragments = false, data = payload.copyOfRange(24, 40))

        // Out of order: fragment 2 arrives first
        assertTrue(reassembler.process(frag2) is IpFragmentReassembler.Result.Pending)
        val ready = reassembler.process(frag1)
        assertTrue(ready is IpFragmentReassembler.Result.Ready)
        ready as IpFragmentReassembler.Result.Ready
        assertTrue(ready.wasFragmented)
        assertEquals(20 + payload.size, ready.length)
        assertEquals(0, internetChecksum(ready.packet, 0, 20))
        assertEquals(0, u16(ready.packet, 6) and 0x3fff)
        assertArrayEquals(payload, ready.packet.copyOfRange(20, ready.length))
    }

    @Test
    fun reassemblesIpv6FragmentsWithHopByHopExtensionHeader() {
        val clock = AtomicLong(1_000_000L)
        val reassembler = IpFragmentReassembler(clockNanos = { clock.get() })
        val payload = ByteArray(32) { (0x40 + it).toByte() }
        val src = InetAddress.getByName("fd77::2").address
        val dst = InetAddress.getByName("fd77::1").address

        val frag1 = buildIpv6HopByHopFragment(src, dst, upperProto = 17, ident = 0xCAFEBABEL, offsetBytes = 0, moreFragments = true, data = payload.copyOfRange(0, 16))
        val frag2 = buildIpv6HopByHopFragment(src, dst, upperProto = 17, ident = 0xCAFEBABEL, offsetBytes = 16, moreFragments = false, data = payload.copyOfRange(16, 32))

        assertTrue(reassembler.process(frag2) is IpFragmentReassembler.Result.Pending)
        val ready = reassembler.process(frag1) as IpFragmentReassembler.Result.Ready
        assertTrue(ready.wasFragmented)
        // Base 40-byte IPv6 + 8-byte Hop-by-Hop + 32-byte payload
        assertEquals(40 + 8 + payload.size, ready.length)
        assertEquals(8 + payload.size, u16(ready.packet, 4))
        // Hop-by-Hop nextHeader updated to UDP (17)
        assertEquals(17, ready.packet[40].toInt() and 0xff)
        assertArrayEquals(payload, ready.packet.copyOfRange(48, ready.length))
    }

    @Test
    fun rejectsOverlappingFragmentsAndExpiresStaleAssemblies() {
        val clock = AtomicLong(1_000_000L)
        val reassembler = IpFragmentReassembler(
            config = FragmentReassemblerConfig(fragmentTimeoutMillis = 500L),
            clockNanos = { clock.get() },
        )
        val src = InetAddress.getByName("10.77.0.2").address
        val dst = InetAddress.getByName("10.77.0.1").address

        val frag1 = buildIpv4Fragment(src, dst, 17, 0x0101, offsetBytes = 0, moreFragments = true, data = ByteArray(16))
        val overlap = buildIpv4Fragment(src, dst, 17, 0x0101, offsetBytes = 8, moreFragments = false, data = ByteArray(16))
        assertTrue(reassembler.process(frag1) is IpFragmentReassembler.Result.Pending)
        val dropped = reassembler.process(overlap)
        assertTrue(dropped is IpFragmentReassembler.Result.Dropped)
        assertEquals("fragment_overlap_rejected", (dropped as IpFragmentReassembler.Result.Dropped).reason)

        // TTL expiry test
        val stale = buildIpv4Fragment(src, dst, 17, 0x0202, offsetBytes = 0, moreFragments = true, data = ByteArray(16))
        assertTrue(reassembler.process(stale) is IpFragmentReassembler.Result.Pending)
        assertEquals(1, reassembler.metrics().pendingAssemblies)
        clock.addAndGet(600_000_000L)
        assertEquals(1, reassembler.evictExpired())
        assertEquals(0, reassembler.metrics().pendingAssemblies)
        assertEquals(0, reassembler.metrics().bufferedBytes)
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
        val flagsAndOff = (offsetBytes / 8) or (if (moreFragments) 0x2000 else 0)
        putU16(pkt, 6, flagsAndOff)
        pkt[8] = 64
        pkt[9] = protocol.toByte()
        src.copyInto(pkt, 12)
        dst.copyInto(pkt, 16)
        putU16(pkt, 10, internetChecksum(pkt, 0, 20))
        data.copyInto(pkt, 20)
        return pkt
    }

    private fun buildIpv6HopByHopFragment(
        src: ByteArray,
        dst: ByteArray,
        upperProto: Int,
        ident: Long,
        offsetBytes: Int,
        moreFragments: Boolean,
        data: ByteArray,
    ): ByteArray {
        val payloadLen = 8 + 8 + data.size
        val pkt = ByteArray(40 + payloadLen)
        pkt[0] = 0x60
        putU16(pkt, 4, payloadLen)
        pkt[6] = 0 // Hop-by-Hop
        pkt[7] = 64
        src.copyInto(pkt, 8)
        dst.copyInto(pkt, 24)
        // Hop-by-Hop (8 bytes) -> Fragment Header (44)
        pkt[40] = 44
        pkt[41] = 0
        // Fragment header (8 bytes)
        pkt[48] = upperProto.toByte()
        val fragField = (offsetBytes and 0xfff8) or (if (moreFragments) 1 else 0)
        putU16(pkt, 50, fragField)
        pkt[52] = (ident ushr 24).toByte()
        pkt[53] = (ident ushr 16).toByte()
        pkt[54] = (ident ushr 8).toByte()
        pkt[55] = ident.toByte()
        data.copyInto(pkt, 56)
        return pkt
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

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
