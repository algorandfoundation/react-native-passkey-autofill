package co.algorand.passkeyautofill.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The identity every deterministic secret of a credential is derived from.
 * Mirrored by `PasskeyDerivation.swift` and by the shared reference vectors in
 * `src/__tests__/Prf.test.ts`; all three must agree.
 */
class PasskeyDerivationTest {

    private fun credential(
        userId: String,
        userHandle: String,
        derivationVersion: Int
    ) = Credential(
        credentialId = "cred-1",
        origin = "example.com",
        userHandle = userHandle,
        userId = userId,
        publicKey = "",
        privateKey = "",
        count = 0,
        derivationVersion = derivationVersion
    )

    @Test
    fun canonicalVersionDerivesFromUserId() {
        assertEquals(
            "dXNlci0xMjM",
            PasskeyDerivation.identity(
                PasskeyDerivation.VERSION_CANONICAL_USER_ID,
                "dXNlci0xMjM",
                "account@example.com"
            )
        )
    }

    @Test
    fun legacyVersionDerivesFromTheLowercasedLabel() {
        // A credential written before the field existed has to keep deriving from
        // exactly what it always did, or its PRF secret moves under it.
        assertEquals(
            "account@example.com",
            PasskeyDerivation.identity(
                PasskeyDerivation.VERSION_LEGACY_LABEL,
                "dXNlci0xMjM",
                "Account@Example.com"
            )
        )
    }

    @Test
    fun theTwoVersionsDisagree() {
        // The reason the version is stored per credential rather than inferred.
        assertNotEquals(
            PasskeyDerivation.identity(PasskeyDerivation.VERSION_LEGACY_LABEL, "dXNlci0xMjM", "dXNlci0xMjM="),
            PasskeyDerivation.identity(PasskeyDerivation.VERSION_CANONICAL_USER_ID, "dXNlci0xMjM", "dXNlci0xMjM=")
        )
    }

    @Test
    fun canonicalIdentityPreservesCase() {
        // `user.id` is opaque RP-owned bytes; base64url is case significant.
        assertEquals(
            "AbCd",
            PasskeyDerivation.identity(PasskeyDerivation.VERSION_CANONICAL_USER_ID, "AbCd", "label")
        )
    }

    @Test
    fun encodingVariantsNormaliseToTheSameIdentity() {
        assertEquals("dXNlci0xMjM", PasskeyDerivation.normalizeUserId("dXNlci0xMjM="))
        assertEquals("a-b_c", PasskeyDerivation.normalizeUserId("a+b/c=="))
        assertEquals("a-b_c", PasskeyDerivation.normalizeUserId("  a-b_c  "))
    }

    @Test
    fun aPlaceholderOrMissingUserIdIsNotDerivable() {
        assertFalse(PasskeyDerivation.isDerivableUserId(""))
        assertFalse(PasskeyDerivation.isDerivableUserId(null))
        assertFalse(PasskeyDerivation.isDerivableUserId("unknown-id"))
        assertTrue(PasskeyDerivation.isDerivableUserId("dXNlci0xMjM"))
    }

    @Test
    fun aRequestWithoutAUserIdStaysOnTheLegacyIdentity() {
        assertEquals(
            PasskeyDerivation.VERSION_LEGACY_LABEL,
            PasskeyDerivation.versionForNewCredential("")
        )
        assertEquals(
            PasskeyDerivation.VERSION_LEGACY_LABEL,
            PasskeyDerivation.versionForNewCredential("unknown-id")
        )
        assertEquals(
            "label",
            PasskeyDerivation.identity(PasskeyDerivation.VERSION_CANONICAL_USER_ID, "unknown-id", "Label")
        )
    }

    @Test
    fun aNewCredentialWithAUserIdIsStampedCanonical() {
        assertEquals(
            PasskeyDerivation.VERSION_CANONICAL_USER_ID,
            PasskeyDerivation.versionForNewCredential("dXNlci0xMjM")
        )
    }

    @Test
    fun storedCredentialResolvesItsOwnIdentity() {
        assertEquals(
            "dXNlci0xMjM",
            PasskeyDerivation.identity(
                credential("dXNlci0xMjM", "Account@Example.com", PasskeyDerivation.VERSION_CANONICAL_USER_ID)
            )
        )
        assertEquals(
            "account@example.com",
            PasskeyDerivation.identity(
                credential("dXNlci0xMjM", "Account@Example.com", PasskeyDerivation.VERSION_LEGACY_LABEL)
            )
        )
    }

    @Test
    fun aCredentialDefaultsToTheLegacyIdentity() {
        // What every record written before this field existed reads back as.
        val legacy = Credential(
            credentialId = "cred-1",
            origin = "example.com",
            userHandle = "Account@Example.com",
            userId = "dXNlci0xMjM",
            publicKey = "",
            privateKey = "",
            count = 0
        )
        assertEquals(PasskeyDerivation.VERSION_LEGACY_LABEL, legacy.derivationVersion)
        assertEquals("account@example.com", PasskeyDerivation.identity(legacy))
    }
}
