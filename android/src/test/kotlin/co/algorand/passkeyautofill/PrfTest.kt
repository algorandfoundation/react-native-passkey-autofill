package co.algorand.passkeyautofill

import co.algorand.passkeyautofill.credentials.PasskeyDerivation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class PrfTest {
    private val hdRootSecret = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { i -> value.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun matchesTheSharedReferenceVectorForALegacyIdentity() {
        // Pinned in src/__tests__/Prf.test.ts and the iOS tests: a legacy
        // identity is the lowercased label, so it reaches credRandom already
        // folded and the output is unchanged by taking it verbatim.
        val identity = PasskeyDerivation.identity(PasskeyDerivation.VERSION_LEGACY_LABEL, null, "dXNlci0xMjM=")
        assertEquals("dxnlci0xmjm=", identity)
        assertEquals(
            "13837ef05514972d99cef1aae8148908391b79b04a1cb1973a938f739dc54660",
            Prf.credRandom(hdRootSecret, "example.com", identity).toHex(),
        )
    }

    @Test
    fun lowercasesTheRelyingPartyButNotTheIdentity() {
        assertEquals(
            Prf.credRandom(hdRootSecret, "example.com", "user-123").toHex(),
            Prf.credRandom(hdRootSecret, "Example.COM", "user-123").toHex(),
        )
        // user.id is opaque, case-significant base64url: two ids differing only
        // in case are two accounts and must not share a PRF secret.
        assertNotEquals(
            Prf.credRandom(hdRootSecret, "example.com", "AbCd").toHex(),
            Prf.credRandom(hdRootSecret, "example.com", "abcd").toHex(),
        )
    }

    @Test
    fun aCanonicalIdentityIsTheNormalisedUserId() {
        val identity = PasskeyDerivation.identity(PasskeyDerivation.VERSION_CANONICAL_USER_ID, "AbC+/d==", "Alice")
        assertEquals("AbC-_d", identity)
        assertEquals(
            Prf.credRandom(hdRootSecret, "example.com", "AbC-_d").toHex(),
            Prf.credRandom(hdRootSecret, "example.com", identity).toHex(),
        )
    }
}
