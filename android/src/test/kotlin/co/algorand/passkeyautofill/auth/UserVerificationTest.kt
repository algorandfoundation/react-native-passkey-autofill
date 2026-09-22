package co.algorand.passkeyautofill.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UserVerificationTest {
    @Test
    fun uvIsSetOnlyWhenACeremonyActuallyRan() {
        for (requested in listOf("required", "preferred", "discouraged")) {
            assertFalse(UserVerification.outcome(requested, systemVerified = false, manualVerified = false).verified)
            assertTrue(UserVerification.outcome(requested, systemVerified = true, manualVerified = false).verified)
            assertTrue(UserVerification.outcome(requested, systemVerified = false, manualVerified = true).verified)
        }
    }

    @Test
    fun requiredWithoutVerificationFailsTheOperation() {
        // The finding's reproduction: preferred, no system result, no prompt —
        // the operation may proceed, but with UV clear.
        val preferred = UserVerification.outcome("preferred", systemVerified = false, manualVerified = false)
        assertTrue(preferred.satisfiesRequest)
        assertFalse(preferred.verified)

        val discouraged = UserVerification.outcome("discouraged", systemVerified = false, manualVerified = false)
        assertTrue(discouraged.satisfiesRequest)

        val required = UserVerification.outcome("required", systemVerified = false, manualVerified = false)
        assertFalse(required.satisfiesRequest)
        assertTrue(UserVerification.outcome("required", systemVerified = true, manualVerified = false).satisfiesRequest)
        assertTrue(UserVerification.outcome("required", systemVerified = false, manualVerified = true).satisfiesRequest)
    }

    @Test
    fun unknownRequestValuesReadAsPreferred() {
        assertEquals("preferred", UserVerification.normalize(null))
        assertEquals("preferred", UserVerification.normalize(""))
        assertEquals("preferred", UserVerification.normalize("whatever"))
        assertEquals("required", UserVerification.normalize(" Required "))
        assertEquals("discouraged", UserVerification.normalize("DISCOURAGED"))
    }
}
