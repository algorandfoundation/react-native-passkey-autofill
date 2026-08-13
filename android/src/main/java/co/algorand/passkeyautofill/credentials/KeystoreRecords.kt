package co.algorand.passkeyautofill.credentials

import android.util.Base64 as AndroidBase64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/**
 * The single owner of the on-disk record format shared with the wallet's
 * `@algorandfoundation/react-native-keystore` MMKV instance
 * ([CredentialRepository.PASSKEYS_MMKV_ID]).
 *
 * The keystore package was refactored to split every key into two MMKV
 * entries (see `wallet-provider-extensions/keystore/react-native/src/storage/driver.ts`):
 *
 * - `k/<id>` — PLAINTEXT JSON metadata (a `Key`, never `KeyData`: no private
 *   material). Every `Uint8Array` field (currently only `publicKey`) is
 *   replaced by a `{"$u8": "<base64>"}` wrapper (`serializeKey`), because
 *   `JSON.stringify` cannot represent raw bytes.
 * - `m/<id>` — the sealed, base64-encoded RAW secret bytes for `id` (whatever
 *   `DriverMaterial.bytes` was for that key — e.g. the 96-byte BIP32-Ed25519
 *   root for an `hd-root-key`, or a signing key's raw private scalar). This is
 *   NOT a JSON document: the sealed plaintext is exactly `base64(bytes)`.
 *
 * Before the split, a key was one flat MMKV entry keyed by the bare id, whose
 * sealed plaintext was `base64url(JSON.stringify(KeyData))` — metadata AND
 * private material together, with every byte field written as a plain JSON
 * number array (`decode`'s legacy branch in `src/storage/state.ts`).
 *
 * The sealing envelope changed too (`sealData`/`openData` in
 * `src/storage/crypto.ts`): the legacy envelope is `{"iv": b64, "tag": b64,
 * "content": b64}` (the GCM tag in its own field, as produced by
 * `react-native-quick-crypto`'s `createCipheriv`); the new envelope is
 * `{"iv": b64, "content": b64}`, where the 16-byte GCM tag is APPENDED to the
 * ciphertext — the WebCrypto `SubtleCrypto.encrypt`/`decrypt` convention, and
 * also `Cipher.doFinal`'s default AES/GCM behaviour on the JVM, so
 * [sealEnvelope] needs no special-casing for the new shape.
 *
 * This object owns both halves of the format (prefixes, metadata (de)serialization,
 * material sealing/opening for both envelopes, legacy flat-record decoding) so
 * [CredentialRepository] never has to hand-roll them again.
 */
object KeystoreRecords {
    /** Prefix for plaintext `Key` metadata records: `k/<id>`. */
    const val METADATA_PREFIX = "k/"

    /**
     * The record type of both roots of the wallet's key hierarchy. The two are
     * told apart by [schemeOf], never by their type — which is why a naive
     * "first record of type `hd-root-key`" lookup picks whichever happens to
     * come first.
     */
    const val TYPE_HD_ROOT_KEY = "hd-root-key"

    /**
     * The deterministic-P256 **main key**: PBKDF2-HMAC-SHA512 over the parent
     * seed's bytes, 64 bytes of material, and the root the passkey hierarchy is
     * actually defined against (`deriveDomainKey` in `keystore/core` refuses any
     * other parent). Preferred for every new credential.
     */
    const val SCHEME_PBKDF2_P256 = "pbkdf2-p256"

    /**
     * The BIP32-Ed25519 extended root (96 bytes), the wallet's *account* root.
     * Passkeys used to be derived from it because it was the only root a wallet
     * exposed; credentials created back then are pinned to it forever, so it
     * stays a supported parent scheme — it is just no longer chosen for new
     * keys.
     */
    const val SCHEME_BIP32_ED25519 = "bip32-ed25519"

    /** Prefix for sealed raw-material records: `m/<id>`. */
    const val MATERIAL_PREFIX = "m/"

    /** GCM IV length in bytes (96-bit, matching the JS `sealData`). */
    private const val IV_LENGTH = 12

    /** GCM authentication tag length in bits. */
    private const val GCM_TAG_BITS = 128

    /** The MMKV key under which `id`'s metadata is stored. */
    fun metadataKey(id: String): String = METADATA_PREFIX + id

    /** The MMKV key under which `id`'s sealed material is stored. */
    fun materialKey(id: String): String = MATERIAL_PREFIX + id

    /**
     * Wraps `bytes` the same way `serializeKey`'s `JSON.stringify` replacer
     * does, producing the `{"$u8": "<base64>"}` shape used for every
     * `Uint8Array` field of a plaintext `k/` metadata record.
     */
    fun wrapBytes(bytes: ByteArray): JSONObject =
        JSONObject().put("\$u8", AndroidBase64.encodeToString(bytes, AndroidBase64.NO_WRAP))

    /**
     * Reverses [wrapBytes]. Returns `null` when `value` is not a `{"$u8": …}`
     * wrapper (e.g. absent, or a legacy plain JSON array — callers that must
     * also tolerate the legacy shape handle that separately).
     */
    fun unwrapBytes(value: Any?): ByteArray? {
        val obj = value as? JSONObject ?: return null
        if (!obj.has("\$u8") || obj.isNull("\$u8")) return null
        return AndroidBase64.decode(obj.getString("\$u8"), AndroidBase64.DEFAULT)
    }

    /**
     * Seals `plaintext` with `masterKey` in the NEW `{iv, content}` envelope:
     * a fresh 96-bit IV, AES-256-GCM, tag appended to the ciphertext. Mirrors
     * the JS `sealData`.
     */
    fun sealEnvelope(masterKey: ByteArray, plaintext: String): String {
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(masterKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        // AES/GCM's doFinal already appends the tag to the ciphertext, which is
        // exactly what the new envelope expects under "content".
        val contentWithTag = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val json = JSONObject()
        json.put("iv", AndroidBase64.encodeToString(iv, AndroidBase64.NO_WRAP))
        json.put("content", AndroidBase64.encodeToString(contentWithTag, AndroidBase64.NO_WRAP))
        return json.toString()
    }

    /**
     * Opens a payload produced by [sealEnvelope] (new `{iv, content}`, tag
     * appended to the content) OR the legacy envelope (`{iv, tag, content}`,
     * tag in its own field). Mirrors the JS `openData`'s dual-read.
     */
    fun openEnvelope(masterKey: ByteArray, payload: String): String {
        val json = JSONObject(payload)
        val iv = AndroidBase64.decode(json.getString("iv"), AndroidBase64.DEFAULT)
        val content = AndroidBase64.decode(json.getString("content"), AndroidBase64.DEFAULT)
        val ciphertextWithTag = if (json.has("tag")) {
            // Legacy envelope: the tag is separate and must be re-appended for
            // the JCE GCM implementation, which expects it inline.
            content + AndroidBase64.decode(json.getString("tag"), AndroidBase64.DEFAULT)
        } else {
            content
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(masterKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(ciphertextWithTag), Charsets.UTF_8)
    }

    /**
     * Seals raw material `bytes` for storage at `m/<id>`: the sealed plaintext
     * is `base64(bytes)`, never a JSON document (this is what `DriverMaterial`
     * bytes are — e.g. an HD root's raw 96 bytes, not a `KeyData` object).
     */
    fun sealMaterial(masterKey: ByteArray, bytes: ByteArray): String =
        sealEnvelope(masterKey, AndroidBase64.encodeToString(bytes, AndroidBase64.NO_WRAP))

    /**
     * Opens an `m/<id>` payload (either envelope) back to the raw material
     * bytes it seals.
     */
    fun openMaterial(masterKey: ByteArray, payload: String): ByteArray =
        AndroidBase64.decode(openEnvelope(masterKey, payload), AndroidBase64.DEFAULT)

    /**
     * Whether a decoded record's `type` field identifies it as one of THIS
     * MODULE's own passkey credentials, as opposed to a record the wallet's
     * keystore owns (`seed`, `hd-root-key`, …). [CredentialRepository] uses
     * this both to select which records `getAllCredentials` surfaces and to
     * make sure `clearCredentials`/`deleteCredential` only ever touch
     * this module's own entries in the SHARED passkeys MMKV instance.
     */
    fun isPasskeyRecordType(type: String): Boolean = type == "hd-derived-p256" || type == "xhd-derived-p256"

    /**
     * Decides which keys of the SHARED passkeys MMKV instance a "clear
     * credentials" call may remove.
     *
     * The instance also holds the wallet's seeds, HD root keys and everything
     * else the keystore owns, so `clearAll()` is never an option: only entries
     * that decode as one of THIS MODULE's passkey types ([isPasskeyRecordType])
     * are returned, under either layout. An `m/` entry is only ever returned
     * together with its own `k/` metadata record — an orphan `m/` entry is not
     * ours to touch.
     *
     * @param allKeys every key currently present in the instance.
     * @param masterKey needed to open legacy flat records; when `null` those are
     *   left alone rather than guessed at.
     * @param payloadFor reads the raw stored payload for a key.
     */
    fun keysToRemoveForClear(
        allKeys: Array<String>,
        masterKey: ByteArray?,
        payloadFor: (String) -> String?,
    ): List<String> {
        val removable = mutableListOf<String>()
        for (key in allKeys) {
            // Handled alongside its `k/` metadata below, if owned by this module.
            if (key.startsWith(MATERIAL_PREFIX)) continue
            val payload = payloadFor(key) ?: continue
            val type = try {
                if (key.startsWith(METADATA_PREFIX)) {
                    JSONObject(payload).optString("type", "")
                } else {
                    decodeLegacyRecord(payload, masterKey).optString("type", "")
                }
            } catch (e: Exception) {
                continue
            }
            if (!isPasskeyRecordType(type)) continue

            removable.add(key)
            if (key.startsWith(METADATA_PREFIX)) {
                removable.add(materialKey(key.removePrefix(METADATA_PREFIX)))
            }
        }
        return removable
    }

    /**
     * Decodes a LEGACY flat record's payload (bare-id key, pre-`k/`+`m/`
     * split) into the `KeyData` JSON it seals.
     *
     * Two shapes are accepted, matching the old `commit()`/`decodeKeyData`:
     * - Sealed: `payload` is a JSON envelope (`{iv, tag, content}` or
     *   `{iv, content}`); once opened, the plaintext is
     *   `base64url(JSON.stringify(KeyData))`.
     * - Unsealed fallback (no master key available at write time): `payload`
     *   is directly `base64url(JSON.stringify(KeyData))`.
     *
     * Byte fields (`privateKey`, `publicKey`, `seed`, …) inside the returned
     * JSON are plain number arrays, per the legacy `KeyData` encoding — NOT
     * `{"$u8": …}` wrappers.
     */
    fun decodeLegacyRecord(payload: String, masterKey: ByteArray?): JSONObject {
        if (payload.startsWith("{")) {
            val envelope = JSONObject(payload)
            if (envelope.has("iv") && envelope.has("content")) {
                if (masterKey == null) {
                    throw IllegalStateException("Master key required for legacy decryption")
                }
                val base64urlJson = openEnvelope(masterKey, payload)
                val decodedJsonBytes = try {
                    AndroidBase64.decode(base64urlJson, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
                } catch (e: Exception) {
                    base64urlJson.toByteArray(Charsets.UTF_8)
                }
                return JSONObject(String(decodedJsonBytes, Charsets.UTF_8))
            }
            // Not a recognised envelope: treat as an already-decoded JSON object.
            return envelope
        }

        // Unsealed fallback: base64url(JSON) directly (no envelope at all).
        val decodedBytes = AndroidBase64.decode(payload, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
        return JSONObject(String(decodedBytes, Charsets.UTF_8))
    }

    /** A parent-secret candidate: which record, and which scheme it roots. */
    data class ParentKeyRecord(val keyId: String, val scheme: String)

    /**
     * The derivation scheme a decoded root record roots.
     *
     * `scheme` lives in the record's metadata (`k/<id>`'s `scheme`, or a legacy
     * flat record's `metadata.scheme`). Records written before the flag existed
     * have none, and every one of those is a BIP32-Ed25519 root — so an absent
     * scheme reads back as [SCHEME_BIP32_ED25519]. Getting this default wrong
     * would silently re-derive existing credentials against the wrong parent.
     */
    fun schemeOf(record: JSONObject): String {
        val metadata = record.optJSONObject("metadata")
        val scheme = metadata?.optString("scheme").takeUnless { it.isNullOrEmpty() }
            ?: record.optString("scheme").takeUnless { it.isEmpty() }
        return scheme ?: SCHEME_BIP32_ED25519
    }

    /**
     * Picks the parent record to derive from.
     *
     * @param candidates the known roots, in order of decreasing authority (what
     *   the wallet explicitly pointed us at first, discovered records last).
     * @param requestedScheme the scheme a credential is pinned to, or `null`
     *   when deriving a brand-new key.
     * @return the first candidate rooting `requestedScheme`; or, when no scheme
     *   is requested, the [SCHEME_PBKDF2_P256] main key if there is one and
     *   otherwise the most authoritative candidate. Preferring pbkdf2-p256 for
     *   new keys — rather than simply taking the first candidate — is what
     *   actually moves the hierarchy off the BIP32 root on a device where both
     *   roots exist.
     */
    fun selectParentKey(
        candidates: List<ParentKeyRecord>,
        requestedScheme: String?,
    ): ParentKeyRecord? {
        if (requestedScheme != null) {
            return candidates.firstOrNull { it.scheme == requestedScheme }
        }
        return candidates.firstOrNull { it.scheme == SCHEME_PBKDF2_P256 } ?: candidates.firstOrNull()
    }

    /**
     * Extracts the raw material a LEGACY flat record carries inline (its
     * `privateKey`, or the `seed` a seed record uses).
     *
     * The split layout keeps material in `m/<id>` instead, so this only ever
     * runs against a record that has not been re-sealed yet.
     *
     * Byte fields of a legacy `KeyData` are plain JSON number arrays, but older
     * writers also produced hex (optionally `0x`-prefixed) and base64url
     * strings; all three are accepted because the alternative is an unreadable
     * wallet.
     */
    fun materialFromLegacyRecord(record: JSONObject): ByteArray? {
        val array = record.optJSONArray("privateKey") ?: record.optJSONArray("seed")
        if (array != null) {
            val bytes = ByteArray(array.length())
            for (i in 0 until array.length()) {
                bytes[i] = array.getInt(i).toByte()
            }
            return bytes
        }

        val encoded = record.optString("privateKey").takeUnless { it.isEmpty() }
            ?: record.optString("seed").takeUnless { it.isEmpty() }
            ?: return null
        val hex = if (encoded.startsWith("0x")) encoded.substring(2) else encoded
        return try {
            require(hex.length % 2 == 0 && hex.all { Character.digit(it, 16) >= 0 })
            ByteArray(hex.length / 2) { i ->
                ((Character.digit(hex[i * 2], 16) shl 4) or Character.digit(hex[i * 2 + 1], 16)).toByte()
            }
        } catch (e: Exception) {
            try {
                AndroidBase64.decode(encoded, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
            } catch (e2: Exception) {
                null
            }
        }
    }
}
