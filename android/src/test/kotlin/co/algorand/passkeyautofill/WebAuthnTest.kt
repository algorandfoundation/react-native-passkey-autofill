package co.algorand.passkeyautofill

import android.content.Context
import android.content.res.Resources
import android.util.Base64
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import java.nio.ByteBuffer
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [WebAuthn] — the AAGUID injection / configuration helpers.
 *
 * `android.util.Base64` is stubbed to delegate to `java.util.Base64`. WebAuthn only ever uses the
 * URL_SAFE | NO_WRAP | NO_PADDING combination, which is byte-for-byte equivalent to the URL encoder
 * without padding, so the stub exercises the real parsing/splicing logic without needing a device
 * or Robolectric.
 */
class WebAuthnTest {
    private val base64Flags = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any<ByteArray>(), any<Int>()) } answers {
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }
        every { Base64.decode(any<String>(), any<Int>()) } answers {
            java.util.Base64.getUrlDecoder().decode(firstArg<String>())
        }
    }

    @After
    fun tearDown() {
        unmockkStatic(Base64::class)
    }

    // --- Minimal CBOR builders (definite-length, additional-info < 24 except byte strings) ---

    private fun mapHeader(entries: Int): ByteArray = byteArrayOf((0xA0 or entries).toByte())

    private fun textItem(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size < 24) { "test helper only supports short text strings" }
        return byteArrayOf((0x60 or bytes.size).toByte()) + bytes
    }

    private fun byteStringItem(bytes: ByteArray): ByteArray = when {
        bytes.size < 24 -> byteArrayOf((0x40 or bytes.size).toByte()) + bytes
        bytes.size < 256 -> byteArrayOf(0x58.toByte(), bytes.size.toByte()) + bytes
        else -> throw IllegalArgumentException("test helper only supports byte strings < 256")
    }

    private val emptyMap = byteArrayOf(0xA0.toByte())

    /** A realistic attestationObject map: {"fmt": "none", "attStmt": {}, "authData": <bytes>}. */
    private fun attestationObject(authData: ByteArray): ByteArray =
        mapHeader(3) +
            textItem("fmt") + textItem("none") +
            textItem("attStmt") + emptyMap +
            textItem("authData") + byteStringItem(authData)

    /** authData = rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + 2 trailing bytes. */
    private fun authDataWith(aaguid: ByteArray): ByteArray {
        val data = ByteArray(55) { it.toByte() }
        System.arraycopy(aaguid, 0, data, 37, aaguid.size)
        return data
    }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, base64Flags)

    private fun decode(value: String): ByteArray = Base64.decode(value, base64Flags)

    @Test
    fun injectAaguid_overwritesOnlyTheAaguidRegion() {
        val original = encode(attestationObject(authDataWith(ByteArray(16) { 0x11 })))

        val newAaguid = ByteArray(16) { 0x22 }
        val result = WebAuthn.injectAaguid(original, newAaguid)

        val expected = attestationObject(authDataWith(newAaguid))
        assertArrayEquals(expected, decode(result))
    }

    @Test
    fun injectAaguid_rejectsWrongLengthAaguid() {
        val attObj = encode(attestationObject(authDataWith(ByteArray(16))))
        assertThrows(IllegalArgumentException::class.java) {
            WebAuthn.injectAaguid(attObj, ByteArray(15))
        }
    }

    @Test
    fun injectAaguid_throwsWhenAuthDataKeyMissing() {
        val noAuthData = encode(mapHeader(1) + textItem("fmt") + textItem("none"))
        assertThrows(IllegalArgumentException::class.java) {
            WebAuthn.injectAaguid(noAuthData, ByteArray(16))
        }
    }

    // --- configuredAaguid ---

    private fun contextWithAaguidString(raw: String?): Context {
        val context = mockk<Context>()
        val resources = mockk<Resources>()
        every { context.packageName } returns PACKAGE
        every { context.resources } returns resources
        if (raw == null) {
            every { resources.getIdentifier(AAGUID_RESOURCE, "string", PACKAGE) } returns 0
        } else {
            every { resources.getIdentifier(AAGUID_RESOURCE, "string", PACKAGE) } returns RES_ID
            every { context.getString(RES_ID) } returns raw
        }
        return context
    }

    private fun uuidBytes(uuid: String): ByteArray {
        val parsed = UUID.fromString(uuid)
        return ByteBuffer.allocate(16)
            .putLong(parsed.mostSignificantBits)
            .putLong(parsed.leastSignificantBits)
            .array()
    }

    @Test
    fun configuredAaguid_returnsBytesForValidUuid() {
        val uuid = "1f59713a-c021-4e63-9158-2cc5fdc14e52"
        assertArrayEquals(uuidBytes(uuid), WebAuthn.configuredAaguid(contextWithAaguidString(uuid)))
    }

    @Test
    fun configuredAaguid_trimsWhitespace() {
        val uuid = "1f59713a-c021-4e63-9158-2cc5fdc14e52"
        assertArrayEquals(
            uuidBytes(uuid),
            WebAuthn.configuredAaguid(contextWithAaguidString("  $uuid  ")),
        )
    }

    @Test
    fun configuredAaguid_nullWhenResourceMissing() {
        assertNull(WebAuthn.configuredAaguid(contextWithAaguidString(null)))
    }

    @Test
    fun configuredAaguid_nullWhenBlank() {
        assertNull(WebAuthn.configuredAaguid(contextWithAaguidString("   ")))
    }

    @Test
    fun configuredAaguid_nullWhenAllZero() {
        assertNull(
            WebAuthn.configuredAaguid(contextWithAaguidString("00000000-0000-0000-0000-000000000000")),
        )
    }

    @Test
    fun configuredAaguid_nullWhenMalformed() {
        assertNull(WebAuthn.configuredAaguid(contextWithAaguidString("not-a-uuid")))
    }

    private companion object {
        const val PACKAGE = "co.algorand.test"
        const val AAGUID_RESOURCE = "passkey_autofill_aaguid"
        const val RES_ID = 99
    }
}
