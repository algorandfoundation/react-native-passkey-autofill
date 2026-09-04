package co.algorand.passkeyautofill.auth

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyProperties
import co.algorand.passkeyautofill.utils.PasskeyLog
import androidx.biometric.BiometricManager.Authenticators

/**
 * The set of authenticators a passkey operation will accept. Configured at build time via the
 * `biometricRequirement` config-plugin prop and read from app `<meta-data>` at runtime.
 */
enum class BiometricRequirement {
    /** Strong biometric only. Crypto-bound key. */
    STRONG,

    /** Strong biometric OR device credential (PIN/pattern/password). Crypto-bound key. Default. */
    STRONG_OR_CREDENTIAL,

    /**
     * Weak biometric OR device credential. NOT crypto-bound: Android cannot gate a Keystore key on
     * weak biometrics, so the key is not user-auth-required and the prompt is a UI-only gate.
     */
    WEAK_OR_CREDENTIAL;

    /** Authenticators to pass to `BiometricPrompt.PromptInfo` / `BiometricPromptData`. */
    val allowedAuthenticators: Int
        get() = when (this) {
            STRONG -> Authenticators.BIOMETRIC_STRONG
            STRONG_OR_CREDENTIAL -> Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
            WEAK_OR_CREDENTIAL -> Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL
        }

    /** True when device credential is accepted; a negative button must NOT be set in that case. */
    val allowsDeviceCredential: Boolean
        get() = when (this) {
            STRONG -> false
            STRONG_OR_CREDENTIAL, WEAK_OR_CREDENTIAL -> true
        }

    /** True when the Keystore key is user-auth-bound and prompts use a `CryptoObject`. */
    val isCryptoBound: Boolean
        get() = when (this) {
            STRONG, STRONG_OR_CREDENTIAL -> true
            WEAK_OR_CREDENTIAL -> false
        }

    /** Auth type for `KeyGenParameterSpec.setUserAuthenticationParameters` (only when [isCryptoBound]). */
    val keystoreAuthType: Int
        get() = when (this) {
            STRONG -> KeyProperties.AUTH_BIOMETRIC_STRONG
            STRONG_OR_CREDENTIAL -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            WEAK_OR_CREDENTIAL -> 0 // no auth binding — key is not user-auth-required
        }

    companion object {
        private const val TAG = "BiometricRequirement"
        const val META_DATA_KEY = "co.algorand.passkeyautofill.BIOMETRIC_REQUIREMENT"

        fun fromValue(value: String?): BiometricRequirement = when (val trimmed = value?.trim()) {
            "strong" -> STRONG
            "strongOrCredential" -> STRONG_OR_CREDENTIAL
            "weakOrCredential" -> WEAK_OR_CREDENTIAL
            else -> {
                if (!trimmed.isNullOrEmpty()) {
                    PasskeyLog.w(TAG, "Unknown biometricRequirement value '$trimmed', using default STRONG_OR_CREDENTIAL")
                }
                STRONG_OR_CREDENTIAL
            }
        }

        /** Reads the build-time configured requirement from app `<meta-data>`; defaults on any failure. */
        fun resolve(context: Context): BiometricRequirement {
            val value = try {
                context.packageManager
                    .getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)
                    .metaData
                    ?.getString(META_DATA_KEY)
            } catch (e: Exception) {
                PasskeyLog.w(TAG, "Failed to read $META_DATA_KEY meta-data, using default", e)
                null
            }
            return fromValue(value)
        }
    }
}
