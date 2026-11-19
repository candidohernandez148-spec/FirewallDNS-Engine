package com.firewalldns.engine.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/** Confirms that the packaged ARM64 Rust JNI library can be loaded on-device. */
@RunWith(AndroidJUnit4::class)
class NativePacketCoreInstrumentedTest {
    @Test
    fun loadsRustLibraryAndRejectsTruncatedPacket() {
        val result = NativePacketCore.validateDnsUdpPacket(byteArrayOf(0x45), 1)
        assertNotNull("Rust JNI library must be packaged for the target ABI", result)
        assertEquals(0, result)
    }
}
