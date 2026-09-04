package co.algorand.passkeyautofill.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RelyingPartyTest {
    private val apkOrigin = "android:apk-key-hash:Ab-C_d0EfGhIjKlMnOpQrStUvWxYz0123456789AbC"

    @Test
    fun readsTheRpIdFromEitherRequestShape() {
        assertEquals("example.com", RelyingParty.requestedRpId("""{"rpId":"example.com","challenge":"x"}"""))
        assertEquals("example.com", RelyingParty.requestedRpId("""{"publicKey":{"rpId":"Example.COM."}}"""))
    }

    @Test
    fun aRequestWithoutAnRpIdNamesNoRelyingParty() {
        assertNull(RelyingParty.requestedRpId("""{"challenge":"x"}"""))
        assertNull(RelyingParty.requestedRpId("""{"publicKey":{"rpId":""}}"""))
        assertNull(RelyingParty.requestedRpId("""{"publicKey":{"rpId":"   "}}"""))
        assertNull(RelyingParty.requestedRpId("not json"))
        assertNull(RelyingParty.requestedRpId(null))
    }

    @Test
    fun fallsBackToTheCallingAppOnlyWhenTheRequestNamesNothing() {
        assertEquals("example.com", RelyingParty.effectiveRpId("""{"rpId":"example.com"}""", apkOrigin))
        assertEquals(apkOrigin, RelyingParty.effectiveRpId("""{"challenge":"x"}""", apkOrigin))
        assertNull(RelyingParty.effectiveRpId("""{"challenge":"x"}""", null))
        assertNull(RelyingParty.effectiveRpId(null, null))
    }

    @Test
    fun normalisesWebIdentitiesToTheirHost() {
        assertEquals("example.com", RelyingParty.normalize("example.com"))
        assertEquals("example.com", RelyingParty.normalize("EXAMPLE.com"))
        assertEquals("example.com", RelyingParty.normalize("https://example.com"))
        assertEquals("example.com", RelyingParty.normalize("https://example.com/"))
        assertEquals("example.com", RelyingParty.normalize("https://Example.com:8443/login?next=x#y"))
        assertEquals("example.com", RelyingParty.normalize("example.com."))
        assertEquals("login.example.com", RelyingParty.normalize("login.example.com"))
    }

    @Test
    fun keepsAnApkKeyHashOriginVerbatim() {
        assertEquals(apkOrigin, RelyingParty.normalize(apkOrigin))
        // The hash is base64url: case must survive normalisation.
        assertFalse(RelyingParty.matches(apkOrigin, apkOrigin.lowercase()))
        assertNull(RelyingParty.normalize("android:apk-key-hash:"))
    }

    @Test
    fun rejectsBlankOrMalformedIdentities() {
        assertNull(RelyingParty.normalize(""))
        assertNull(RelyingParty.normalize("   "))
        assertNull(RelyingParty.normalize("exa mple.com"))
        assertNull(RelyingParty.normalize("https://"))
        assertFalse(RelyingParty.matches("", "example.com"))
        assertFalse(RelyingParty.matches("example.com", ""))
    }

    @Test
    fun aCredentialMatchesOnlyItsOwnRelyingParty() {
        assertTrue(RelyingParty.matches("example.com", "example.com"))
        assertTrue(RelyingParty.matches("https://example.com", "EXAMPLE.COM"))
        assertTrue(RelyingParty.matches(apkOrigin, apkOrigin))

        // The finding's reproduction: a.example must never be offered for b.example.
        assertFalse(RelyingParty.matches("a.example", "b.example"))
        // Subdomains are distinct relying parties, in both directions.
        assertFalse(RelyingParty.matches("example.com", "login.example.com"))
        assertFalse(RelyingParty.matches("login.example.com", "example.com"))
        // A web credential is not a native one and vice versa.
        assertFalse(RelyingParty.matches("example.com", apkOrigin))
        assertFalse(RelyingParty.matches(apkOrigin, "example.com"))
    }
}
