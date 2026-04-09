package co.algorand.passkeyautofill.utils

import android.util.Log
import javax.crypto.Cipher

object PasskeyUtils {
    private const val TAG = "PasskeyUtils"

    fun normalizeBase64(s: String): String {
        return s.replace("-", "+").replace("_", "/").replace("=", "")
    }

    /**
     * Extracts a Cipher from a BiometricPrompt.AuthenticationResult or similar objects 
     * using reflection. This is necessary because the Credentials library uses 
     * hidden or internal wrappers for platform/androidx biometric results.
     */
    fun extractCipher(authResult: Any?): Cipher? {
        if (authResult == null) return null
        return try {
            Log.i(TAG, "Attempting to extract cipher from: ${authResult.javaClass.name}")
            
            // 1. Try direct getCryptoObject (works for androidx.biometric or platform)
            var cryptoObject = authResult.javaClass.methods.find { it.name == "getCryptoObject" }?.invoke(authResult)
            
            // 2. If not found, check if it's a wrapper like androidx.credentials.provider.AuthenticationResult
            if (cryptoObject == null) {
                val unwrappingMethods = listOf(
                    "getFrameworkAuthenticationResult", 
                    "getBiometricPromptAuthenticationResult",
                    "getAuthenticationResult"
                )
                for (methodName in unwrappingMethods) {
                    try {
                        val method = authResult.javaClass.methods.find { it.name == methodName }
                        if (method != null) {
                            val innerResult = method.invoke(authResult)
                            if (innerResult != null && innerResult !== authResult) {
                                Log.i(TAG, "Unwrapped via $methodName to ${innerResult.javaClass.name}")
                                cryptoObject = innerResult.javaClass.methods.find { it.name == "getCryptoObject" }?.invoke(innerResult)
                                if (cryptoObject != null) break
                            }
                        }
                    } catch (e: Exception) { /* ignore */ }
                }
            }
            
            // 2.5 Try to find hidden fields directly if methods fail
            if (cryptoObject == null) {
                val hiddenFields = listOf("mFrameworkAuthenticationResult", "mBiometricPromptAuthenticationResult")
                for (fieldName in hiddenFields) {
                    try {
                        val field = authResult.javaClass.getDeclaredField(fieldName)
                        field.isAccessible = true
                        val innerResult = field.get(authResult)
                        if (innerResult != null) {
                            Log.i(TAG, "Unwrapped via field $fieldName to ${innerResult.javaClass.name}")
                            cryptoObject = innerResult.javaClass.methods.find { it.name == "getCryptoObject" }?.invoke(innerResult)
                            if (cryptoObject != null) break
                        }
                    } catch (e: Exception) { /* ignore */ }
                }
            }
            
            // 3. Exhaustive search for any method returning something that has getCryptoObject
            if (cryptoObject == null) {
                for (method in authResult.javaClass.methods) {
                    if (method.parameterCount == 0 && method.name.startsWith("get") && method.returnType != Void.TYPE) {
                        try {
                            val candidate = method.invoke(authResult) ?: continue
                            if (candidate === authResult) continue
                            
                            val getCrypto = candidate.javaClass.methods.find { it.name == "getCryptoObject" }
                            if (getCrypto != null) {
                                cryptoObject = getCrypto.invoke(candidate)
                                if (cryptoObject != null) {
                                    Log.i(TAG, "Found cryptoObject via ${method.name} -> ${candidate.javaClass.name}")
                                    break
                                }
                            }
                        } catch (e: Exception) { continue }
                    }
                }
            }

            // 4. Try searching for fields too
            if (cryptoObject == null) {
                for (field in authResult.javaClass.declaredFields) {
                    try {
                        field.isAccessible = true
                        val candidate = field.get(authResult) ?: continue
                        val getCrypto = candidate.javaClass.methods.find { it.name == "getCryptoObject" }
                        if (getCrypto != null) {
                            cryptoObject = getCrypto.invoke(candidate)
                            if (cryptoObject != null) {
                                Log.i(TAG, "Found cryptoObject in field ${field.name}")
                                break
                            }
                        }
                    } catch (e: Exception) { continue }
                }
            }
            
            if (cryptoObject == null) {
                Log.w(TAG, "Could not find CryptoObject in ${authResult.javaClass.name}")
                return null
            }
            
            // 5. Finally extract the Cipher from the CryptoObject
            val getCipher = cryptoObject.javaClass.methods.find { it.name == "getCipher" }
            val cipher = getCipher?.invoke(cryptoObject) as? Cipher
            Log.i(TAG, "Extracted cipher: $cipher")
            cipher
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract cipher via reflection", e)
            null
        }
    }
}
