package co.algorand.passkeyautofill

import android.util.Base64 as AndroidBase64
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/**
 * WebAuthn PRF (`prf`) extension helpers, backed by the authenticator
 * `hmac-secret` mechanism (CTAP2.1).
 *
 * Output formula per the WebAuthn spec:
 *
 *     output = HMAC-SHA256(credRandom, SHA256("WebAuthn PRF" || 0x00 || salt))
 *
 * `credRandom` is a per-credential 32-byte secret. We derive it
 * deterministically (HKDF-SHA256) from the wallet HD root secret, the
 * relying-party identifier, and the credential's derivation identity — the
 * same inputs that produce the deterministic signing key. This avoids a storage migration
 * and ensures restoring the wallet seed reproduces the same PRF outputs
 * on another device.
 */
object Prf {
  private const val CRED_RANDOM_INFO = "WebAuthn-PRF-credRandom"
  private val SALT_PREFIX: ByteArray = "WebAuthn PRF".toByteArray(Charsets.UTF_8) + byteArrayOf(0x00)

  /**
   * Derive a 32-byte per-credential PRF secret from the HD root secret.
   * Deterministic over `(hdRootSecret, lower(rpId), identity)`.
   *
   * @param identity the credential's derivation identity from
   *   `PasskeyDerivation.identity`, used VERBATIM. A legacy identity arrives
   *   already lowercased, so legacy outputs are unchanged; a canonical one is
   *   the relying party's opaque `user.id`, whose case must survive.
   */
  fun credRandom(
    hdRootSecret: ByteArray,
    relyingPartyIdentifier: String,
    identity: String,
  ): ByteArray {
    val salt = relyingPartyIdentifier.lowercase().toByteArray(Charsets.UTF_8) +
      byteArrayOf(0x00) +
      identity.toByteArray(Charsets.UTF_8)
    return hkdfSha256(
      ikm = hdRootSecret,
      salt = salt,
      info = CRED_RANDOM_INFO.toByteArray(Charsets.UTF_8),
      length = 32,
    )
  }

  /**
   * Evaluate the PRF for a single salt. Returns 32 bytes of output material.
   *
   * Per the WebAuthn spec the value the authenticator HMACs is
   * `SHA-256("WebAuthn PRF" || 0x00 || rpSalt)`. The Chromium-on-Android
   * client manager performs this hashing on behalf of the RP and passes the
   * result through the `prfAlreadyHashed` extension; in that case the
   * `salt` is already the inner hash and we must NOT hash again. Standard
   * `prf` requests send the raw RP salt and require hashing.
   */
  fun evaluate(credRandom: ByteArray, salt: ByteArray, alreadyHashed: Boolean = true): ByteArray {
    val macInput = if (alreadyHashed) {
      salt
    } else {
      MessageDigest.getInstance("SHA-256").digest(SALT_PREFIX + salt)
    }
    val mac = Mac.getInstance("HmacSHA256").apply {
      init(SecretKeySpec(credRandom, "HmacSHA256"))
    }
    return mac.doFinal(macInput)
  }

  /**
   * Parsed PRF inputs from the relying party. Reduced to at most two salts
   * (first + optional second) — already resolved against `evalByCredential`
   * for the credential the user is asserting with.
   *
   * @property alreadyHashed `true` when the salts have already been passed
   *   through `SHA-256("WebAuthn PRF" || 0x00 || ...)` by the platform (the
   *   case for both the Chromium `prfAlreadyHashed` extension on Android
   *   and Apple's `ASAuthorizationPublicKeyCredentialPRFAssertionInput`).
   */
  data class Input(val first: ByteArray, val second: ByteArray?, val alreadyHashed: Boolean)

  /**
   * Parse PRF eval salts out of a WebAuthn request JSON.
   *
   * Recognises:
   *  - `extensions.prf.eval` / `extensions.prf.evalByCredential[<credId>]`
   *    — raw RP-supplied salts that still need to be hashed before HMAC.
   *  - `extensions.prfAlreadyHashed.eval` /
   *    `extensions.prfAlreadyHashed.evalByCredential[<credId>]` — Chromium
   *    on Android emits this when forwarding a `prf` request to a credential
   *    provider so the provider doesn't need to know the spec-mandated hash
   *    prefix. The salts here are already 32-byte SHA-256 outputs and must
   *    not be re-hashed.
   *
   * @param requestJson the inner `publicKey` request JSON object.
   * @param credentialIdB64Url base64url-encoded credentialId we're asserting
   *   with (used to look up the per-credential salts).
   */
  fun parseInput(requestJson: JSONObject, credentialIdB64Url: String?): Input? {
    val extensions = requestJson.optJSONObject("extensions") ?: return null

    // Pre-hashed form wins — when Chromium sends both for compatibility,
    // honour the already-hashed values to match what the browser expects.
    extensions.optJSONObject("prfAlreadyHashed")?.let { node ->
      parseExtensionNode(node, credentialIdB64Url, alreadyHashed = true)?.let { return it }
    }
    extensions.optJSONObject("prf")?.let { node ->
      parseExtensionNode(node, credentialIdB64Url, alreadyHashed = false)?.let { return it }
    }
    return null
  }

  private fun parseExtensionNode(
    node: JSONObject,
    credentialIdB64Url: String?,
    alreadyHashed: Boolean,
  ): Input? {
    // Per-credential salts win over the global `eval` block.
    if (credentialIdB64Url != null) {
      val byCred = node.optJSONObject("evalByCredential")
      if (byCred != null) {
        for (key in byCred.keys()) {
          if (normalizeBase64Url(key) == normalizeBase64Url(credentialIdB64Url)) {
            byCred.optJSONObject(key)?.let { return parseSalts(it, alreadyHashed) }
          }
        }
      }
    }
    return node.optJSONObject("eval")?.let { parseSalts(it, alreadyHashed) }
  }

  private fun parseSalts(obj: JSONObject, alreadyHashed: Boolean): Input? {
    val first = obj.optString("first", "").takeIf { it.isNotEmpty() } ?: return null
    val firstBytes = decodeBase64UrlOrBase64(first)
    val secondBytes = obj.optString("second", "")
      .takeIf { it.isNotEmpty() }
      ?.let { decodeBase64UrlOrBase64(it) }
    return Input(firstBytes, secondBytes, alreadyHashed)
  }

  private fun normalizeBase64Url(value: String): String =
    value.trim().trimEnd('=').replace('+', '-').replace('/', '_')

  private fun decodeBase64UrlOrBase64(value: String): ByteArray {
    val flags = AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING
    return try {
      AndroidBase64.decode(value, flags)
    } catch (e: IllegalArgumentException) {
      AndroidBase64.decode(value, AndroidBase64.NO_WRAP)
    }
  }

  /** Encode a 32-byte PRF output for inclusion in a WebAuthn response JSON. */
  fun encodeOutput(bytes: ByteArray): String =
    AndroidBase64.encodeToString(bytes, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)

  // RFC 5869 HKDF-SHA256.
  private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
    // Extract.
    mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
    val prk = mac.doFinal(ikm)
    // Expand.
    mac.init(SecretKeySpec(prk, "HmacSHA256"))
    val output = ByteArray(length)
    var t = ByteArray(0)
    var offset = 0
    var counter: Byte = 1
    while (offset < length) {
      mac.reset()
      mac.init(SecretKeySpec(prk, "HmacSHA256"))
      mac.update(t)
      mac.update(info)
      mac.update(counter)
      t = mac.doFinal()
      val take = minOf(t.size, length - offset)
      System.arraycopy(t, 0, output, offset, take)
      offset += take
      counter++
    }
    return output
  }
}
