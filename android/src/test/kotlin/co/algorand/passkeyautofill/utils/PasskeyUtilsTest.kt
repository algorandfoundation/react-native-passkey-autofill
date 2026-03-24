package co.algorand.passkeyautofill.utils

import org.junit.Assert.assertEquals
import org.junit.Test

class PasskeyUtilsTest {
    @Test
    fun testNormalizeBase64() {
        // Standard base64
        assertEquals("SGVsbG8", PasskeyUtils.normalizeBase64("SGVsbG8="))
        // URL-safe base64
        assertEquals("a+b/c", PasskeyUtils.normalizeBase64("a-b_c"))
        // URL-safe with padding
        assertEquals("a+b/c", PasskeyUtils.normalizeBase64("a-b_c=="))
    }
}
