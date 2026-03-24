package co.algorand.passkeyautofill.utils

object PasskeyUtils {
    fun normalizeBase64(s: String): String {
        return s.replace("-", "+").replace("_", "/").replace("=", "")
    }
}
