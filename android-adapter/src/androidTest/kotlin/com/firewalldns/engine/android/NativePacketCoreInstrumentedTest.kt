package com.firewalldns.engine.android

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device-side parity and microbenchmark for the experimental Rust preflight.
 *
 * The Kotlin reference deliberately implements the same narrow validation contract
 * as rust-core. This measures packet preflight only, not DNS policy, upstream I/O,
 * VpnService.protect(), or the complete TUN path.
 */
@RunWith(AndroidJUnit4::class)
class NativePacketCoreInstrumentedTest {

    @Test
    fun loadsRustLibraryAndRejectsTruncatedPacket() {
        val result = NativePacketCore.validateDnsUdpPacket(byteArrayOf(0x45), 1)
        assertNotNull("Rust JNI library must be packaged for the target ABI", result)
        assertEquals(0, result)
    }

    @Test
    fun rustAndKotlinReturnTheSameResultForValidIpv4AndIpv6Packets() {
        assertParity(ipv4DnsPacket(), expected = 4)
        assertParity(ipv6DnsPacket(), expected = 6)
    }

    @Test
    fun rustAndKotlinRejectCorruptAndTruncatedPacketsConsistently() {
        val badIpv4Checksum = ipv4DnsPacket().also { it[8] = 63 }
        assertParity(badIpv4Checksum, expected = 0)

        val badIpv6Checksum = ipv6DnsPacket().also { it[47] = 0 }
        assertParity(badIpv6Checksum, expected = 0)

        val truncated = ipv4DnsPacket().copyOf(27)
        assertParity(truncated, expected = 0)

        val badLength = ipv4DnsPacket().also { it[3] = (it[3].toInt() - 1).toByte() }
        // Both implementations reject a UDP length that no longer matches the IP payload.
        assertParity(badLength, expected = 0)
    }

    @Test
    fun reportsRustVersusKotlinPreflightBenchmark() {
        benchmark("ipv4", ipv4DnsPacket())
        benchmark("ipv6", ipv6DnsPacket())
    }

    private fun assertParity(packet: ByteArray, expected: Int) {
        val kotlinResult = kotlinValidateDnsUdpPacket(packet)
        val rustResult = NativePacketCore.validateDnsUdpPacket(packet, packet.size)
        assertNotNull("Rust JNI library must be packaged for the target ABI", rustResult)
        assertEquals("Kotlin reference result", expected, kotlinResult)
        assertEquals("Rust JNI result", kotlinResult, rustResult)
    }

    private fun benchmark(label: String, packet: ByteArray) {
        val warmups = 30
        val samples = 250

        fun measure(name: String, validate: () -> Int): LongArray {
            repeat(warmups) { assertEquals( if (label == "ipv4") 4 else 6, validate()) }
            return LongArray(samples) {
                val start = System.nanoTime()
                val result = validate()
                val elapsed = System.nanoTime() - start
                assertEquals(if (label == "ipv4") 4 else 6, result)
                elapsed
            }
        }

        val kotlinTimes = measure("kotlin") { kotlinValidateDnsUdpPacket(packet) }
        val rustTimes = measure("rust_jni") {
            NativePacketCore.validateDnsUdpPacket(packet, packet.size)
                ?: error("Rust JNI library is unavailable on this device")
        }

        Log.i(
            TAG,
            "NATIVE_PREFLIGHT label=$label samples=$samples " +
                "kotlin_p50_us=${percentileMicros(kotlinTimes, 50)} " +
                "kotlin_p95_us=${percentileMicros(kotlinTimes, 95)} " +
                "kotlin_p99_us=${percentileMicros(kotlinTimes, 99)} " +
                "rust_jni_p50_us=${percentileMicros(rustTimes, 50)} " +
                "rust_jni_p95_us=${percentileMicros(rustTimes, 95)} " +
                "rust_jni_p99_us=${percentileMicros(rustTimes, 99)}"
        )
    }

    private fun percentileMicros(values: LongArray, percentile: Int): Long {
        val sorted = values.sortedArray()
        val index = (((percentile / 100.0) * sorted.size).toInt() - 1)
            .coerceIn(0, sorted.lastIndex)
        return sorted[index] / 1_000L
    }

    /** Test-only Kotlin baseline matching rust-core's current validation contract. */
    private fun kotlinValidateDnsUdpPacket(packet: ByteArray): Int {
        if (packet.isEmpty()) return 0
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> if (validIpv4(packet)) 4 else 0
            6 -> if (validIpv6(packet)) 6 else 0
            else -> 0
        }
    }

    private fun validIpv4(packet: ByteArray): Boolean {
        if (packet.size < 28) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl !in 20..60 || ihl + 20 > packet.size) return false
        if ((packet[9].toInt() and 0xff) != UDP_PROTOCOL) return false
        if (checksum(packet, 0, ihl) != 0) return false

        val totalLength = u16(packet, 2)
        if (totalLength < ihl + 20 || totalLength > packet.size) return false
        if ((u16(packet, 6) and 0x3fff) != 0) return false

        val udpOffset = ihl
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < 20 || udpLength != totalLength - ihl) return false
        if (u16(packet, udpOffset + 2) != DNS_PORT) return false
        return u16(packet, udpOffset + 6) == 0 ||
            checksumIpv4Udp(packet, udpOffset, udpLength) == 0
    }

    private fun validIpv6(packet: ByteArray): Boolean {
        if (packet.size < 60 || (packet[6].toInt() and 0xff) != UDP_PROTOCOL) return false
        val payloadLength = u16(packet, 4)
        if (payloadLength < 20 || 40 + payloadLength > packet.size) return false

        val udpLength = u16(packet, 44)
        if (udpLength < 20 || udpLength != payloadLength) return false
        if (u16(packet, 42) != DNS_PORT || u16(packet, 46) == 0) return false
        return checksumIpv6Udp(packet, 40, udpLength) == 0
    }

    private fun checksumIpv4Udp(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        sum = addWords(sum, packet, 12, 8)
        sum += UDP_PROTOCOL.toLong()
        sum += length.toLong()
        sum = addWords(sum, packet, offset, length)
        return foldChecksum(sum)
    }

    private fun checksumIpv6Udp(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        sum = addWords(sum, packet, 8, 32)
        sum += ((length ushr 16) and 0xffff).toLong()
        sum += (length and 0xffff).toLong()
        sum += UDP_PROTOCOL.toLong()
        sum = addWords(sum, packet, offset, length)
        return foldChecksum(sum)
    }

    private fun checksum(packet: ByteArray, offset: Int, length: Int): Int {
        return foldChecksum(addWords(0L, packet, offset, length))
    }

    private fun addWords(initial: Long, packet: ByteArray, offset: Int, length: Int): Long {
        var sum = initial
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((packet[index].toInt() and 0xff) shl 8) or
                (packet[index + 1].toInt() and 0xff)).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        return sum
    }

    private fun foldChecksum(value: Long): Int {
        var sum = value
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun ipv4DnsPacket(): ByteArray {
        val dns = dnsHeader()
        val packet = ByteArray(20 + 8 + dns.size)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 6, 0x4000) // DF is supported; fragmentation is not.
        packet[8] = 64
        packet[9] = UDP_PROTOCOL.toByte()
        byteArrayOf(10, 0, 0, 2).copyInto(packet, 12)
        byteArrayOf(10, 0, 0, 1).copyInto(packet, 16)
        putU16(packet, 20, 53000)
        putU16(packet, 22, DNS_PORT)
        putU16(packet, 24, 8 + dns.size)
        dns.copyInto(packet, 28)
        putU16(packet, 10, checksum(packet, 0, 20))
        return packet
    }

    private fun ipv6DnsPacket(): ByteArray {
        val dns = dnsHeader()
        val packet = ByteArray(40 + 8 + dns.size)
        packet[0] = 0x60
        putU16(packet, 4, 8 + dns.size)
        packet[6] = UDP_PROTOCOL.toByte()
        packet[7] = 64
        byteArrayOf(
            0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2,
        ).copyInto(packet, 8)
        byteArrayOf(
            0xfd.toByte(), 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ).copyInto(packet, 24)
        putU16(packet, 40, 53000)
        putU16(packet, 42, DNS_PORT)
        putU16(packet, 44, 8 + dns.size)
        dns.copyInto(packet, 48)
        putU16(packet, 46, checksumIpv6Udp(packet, 40, 8 + dns.size))
        return packet
    }

    private fun dnsHeader() = ByteArray(12).also {
        it[0] = 0x12
        it[1] = 0x34
        it[2] = 0x01
        it[5] = 1
    }

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    private fun putU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private companion object {
        const val TAG = "FirewallDNSBenchmark"
        const val DNS_PORT = 53
        const val UDP_PROTOCOL = 17
    }
}
