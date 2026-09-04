package co.algorand.passkeyautofill.credentials

import org.json.JSONObject

/**
 * Relying-party scoping for stored credentials.
 *
 * A WebAuthn credential is bound to one relying party for life. A stored
 * record's `origin` is the RP ID the credential was created for (`rp.id` at
 * registration) or, for a native caller that named none, the caller's
 * `android:apk-key-hash:` origin. Nothing may be offered to or signed for a
 * relying party other than that one — regardless of what `allowCredentials`
 * says, and even though a signature for the wrong RP would normally fail to
 * verify: offering it still leaks which accounts exist elsewhere, and signing
 * with it turns the provider into an oracle for a foreign credential.
 *
 * Related Origin Requests (a relying party authorising extra origins through
 * `/.well-known/webauthn`) are not supported: the requested RP ID must equal
 * the stored one after normalisation. A request that names no relying party
 * and comes from an unidentifiable caller matches nothing.
 */
object RelyingParty {
    private const val APK_KEY_HASH_PREFIX = "android:apk-key-hash:"
    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*://")

    /**
     * The RP ID a get request names (`rpId`, inside `publicKey` or at the top
     * level), normalised; `null` when the request carries none or it is
     * malformed.
     */
    fun requestedRpId(requestJson: String?): String? {
        if (requestJson.isNullOrBlank()) return null
        val pk = try {
            val json = JSONObject(requestJson)
            if (json.has("publicKey")) json.getJSONObject("publicKey") else json
        } catch (e: Exception) {
            return null
        }
        return normalize(pk.optString("rpId", ""))
    }

    /**
     * The relying party a get request must be authorised against: the RP ID it
     * names, else the calling app's own origin (a native caller that omitted
     * `rpId`), else nothing.
     */
    fun effectiveRpId(requestJson: String?, callingOrigin: String?): String? =
        requestedRpId(requestJson) ?: callingOrigin?.let { normalize(it) }

    /**
     * Whether a credential stored for `storedOrigin` may be used for
     * `requestedRpId`. Both sides are normalised; anything unparseable is a
     * no-match.
     */
    fun matches(storedOrigin: String, requestedRpId: String): Boolean {
        val stored = normalize(storedOrigin) ?: return false
        val requested = normalize(requestedRpId) ?: return false
        return stored == requested
    }

    /**
     * Canonical comparison form of an RP identity. A web origin or URL reduces
     * to its lowercase host (scheme, port, path and trailing dot removed). An
     * `android:apk-key-hash:` origin is kept verbatim — the hash is base64url
     * and case significant. Blank or whitespace-bearing values are `null`.
     */
    fun normalize(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty() || trimmed.any { it.isWhitespace() }) return null
        if (trimmed.startsWith(APK_KEY_HASH_PREFIX, ignoreCase = true)) {
            val hash = trimmed.substring(APK_KEY_HASH_PREFIX.length)
            return if (hash.isEmpty()) null else APK_KEY_HASH_PREFIX + hash
        }
        var host = trimmed.lowercase().replace(SCHEME, "")
        host = host.takeWhile { it != '/' && it != '?' && it != '#' }
        host = host.substringBefore(':')
        host = host.trimEnd('.')
        return host.ifEmpty { null }
    }
}
