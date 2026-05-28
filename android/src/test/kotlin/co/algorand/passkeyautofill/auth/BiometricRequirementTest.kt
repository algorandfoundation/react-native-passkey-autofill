package co.algorand.passkeyautofill.auth

import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager.Authenticators
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BiometricRequirementTest {
    @Test
    fun fromValue_mapsKnownStrings() {
        assertEquals(BiometricRequirement.STRONG, BiometricRequirement.fromValue("strong"))
        assertEquals(
            BiometricRequirement.STRONG_OR_CREDENTIAL,
            BiometricRequirement.fromValue("strongOrCredential"),
        )
        assertEquals(
            BiometricRequirement.WEAK_OR_CREDENTIAL,
            BiometricRequirement.fromValue("weakOrCredential"),
        )
    }

    @Test
    fun fromValue_defaultsToStrongOrCredential_forNullBlankOrUnknown() {
        assertEquals(BiometricRequirement.STRONG_OR_CREDENTIAL, BiometricRequirement.fromValue(null))
        assertEquals(BiometricRequirement.STRONG_OR_CREDENTIAL, BiometricRequirement.fromValue(""))
        assertEquals(BiometricRequirement.STRONG_OR_CREDENTIAL, BiometricRequirement.fromValue("nonsense"))
    }

    @Test
    fun fromValue_trimsWhitespace() {
        assertEquals(BiometricRequirement.STRONG, BiometricRequirement.fromValue("  strong  "))
    }

    @Test
    fun allowedAuthenticators_matchLevel() {
        assertEquals(Authenticators.BIOMETRIC_STRONG, BiometricRequirement.STRONG.allowedAuthenticators)
        assertEquals(
            Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL,
            BiometricRequirement.STRONG_OR_CREDENTIAL.allowedAuthenticators,
        )
        assertEquals(
            Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL,
            BiometricRequirement.WEAK_OR_CREDENTIAL.allowedAuthenticators,
        )
    }

    @Test
    fun deviceCredentialAndCryptoBindingFlags() {
        assertFalse(BiometricRequirement.STRONG.allowsDeviceCredential)
        assertTrue(BiometricRequirement.STRONG_OR_CREDENTIAL.allowsDeviceCredential)
        assertTrue(BiometricRequirement.WEAK_OR_CREDENTIAL.allowsDeviceCredential)

        assertTrue(BiometricRequirement.STRONG.isCryptoBound)
        assertTrue(BiometricRequirement.STRONG_OR_CREDENTIAL.isCryptoBound)
        assertFalse(BiometricRequirement.WEAK_OR_CREDENTIAL.isCryptoBound)
    }

    @Test
    fun keystoreAuthType_matchLevel() {
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, BiometricRequirement.STRONG.keystoreAuthType)
        assertEquals(
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            BiometricRequirement.STRONG_OR_CREDENTIAL.keystoreAuthType,
        )
        assertEquals(0, BiometricRequirement.WEAK_OR_CREDENTIAL.keystoreAuthType)
    }
}
