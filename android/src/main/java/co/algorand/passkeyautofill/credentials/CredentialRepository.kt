package co.algorand.passkeyautofill.credentials

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import com.tencent.mmkv.MMKV
import foundation.algorand.deterministicP256.DeterministicP256
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject
import android.util.Base64 as AndroidBase64
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import co.algorand.passkeyautofill.auth.BiometricRequirement


/**
 * The parent secret a credential's deterministic keys hang off, together with
 * the record it came from and the scheme it roots ([KeystoreRecords.SCHEME_PBKDF2_P256]
 * or [KeystoreRecords.SCHEME_BIP32_ED25519]). Both are stamped onto a credential
 * at creation so a later assertion re-derives against the same parent.
 */
data class ParentSecret(val keyId: String, val scheme: String, val bytes: ByteArray)

/** A freshly derived domain (passkey) key pair and the parent it came from. */
data class DerivedDomainKeyPair(
    val keyPair: KeyPair,
    val parentKeyId: String,
    val derivationScheme: String,
)

/**
 * Why a parent secret could not be produced. The three failures are
 * indistinguishable from the outside — all three used to surface as "HD Root Key
 * not available" — but they need very different fixes: an unshared master key, a
 * wallet that never told us which record to derive from, and a record whose
 * material is missing or sealed with a different key.
 */
sealed class ParentSecretResult {
    data class Available(val secret: ParentSecret) : ParentSecretResult()

    /** The wallet has not shared its master key with this process yet. */
    object MasterKeyUnavailable : ParentSecretResult()

    /**
     * No record roots the requested scheme: either the wallet never called
     * `setMainKeyId`, or it has no key of that scheme (e.g. a credential pinned
     * to `bip32-ed25519` on a wallet that only has a dp256 main key).
     */
    data class NoParentKey(val requestedScheme: String?) : ParentSecretResult()

    /** The record exists but its sealed material is absent or undecodable. */
    data class MaterialUnavailable(val keyId: String, val scheme: String) : ParentSecretResult()

    /** A human-readable reason, safe to put in an exception message. */
    val reason: String
        get() = when (this) {
            is Available -> "available"
            is MasterKeyUnavailable -> "the wallet has not shared its master key with this process (setMasterKey)"
            is NoParentKey -> "no key store record roots " +
                (requestedScheme?.let { "the '$it' scheme" } ?: "a passkey hierarchy") +
                " (setMainKeyId)"
            is MaterialUnavailable -> "the material of parent key $keyId ($scheme) is missing or could not be opened"
        }
}

/**
 * Thrown when an operation that MUST encrypt has no master key to encrypt
 * with. Creation aborts on it: a passkey private key is never written to the
 * shared store in the clear (F-2026-18982).
 */
class MasterKeyUnavailableException(
    message: String = "Passkey master key unavailable: the wallet has not shared it with this process (setMasterKey)",
) : IllegalStateException(message)

interface CredentialRepository {
    val keyStore: KeyStore
    fun saveCredential(context: Context, credential: Credential, biometricCipher: Cipher? = null)
    fun generateCredentialId(keyPair: KeyPair): ByteArray
    fun getKeyPair(context: Context, credentialId: ByteArray, biometricCipher: Cipher? = null): KeyPair?

    /**
     * Derives the domain (passkey) key for `origin` and `identity`, reporting
     * which parent it used so the caller can stamp it onto the credential.
     *
     * @param identity the credential's derivation identity as returned by
     *   [PasskeyDerivation.identity] — the relying party's `user.id` for a
     *   canonical credential, the lowercased legacy label for an old one. It is
     *   passed to the derivation VERBATIM: it is already normalised and
     *   case-folded as its version requires, and `user.id` is opaque,
     *   case-significant RP-owned bytes, so nothing here may lowercase it.
     * @param requestedScheme the scheme an EXISTING credential is pinned to;
     *   `null` for a new credential, which then prefers the dp256 main key.
     */
    fun createDomainKeyPair(
        context: Context,
        origin: String,
        identity: String,
        requestedScheme: String? = null,
    ): DerivedDomainKeyPair
    fun getOrigin(info: CallingAppInfo): String
    fun appInfoToOrigin(info: CallingAppInfo): String

    /**
     * The credential stored under `credentialId` WITH its private material
     * (`privateKey`), opening the biometric wrapper with `biometricCipher` when
     * the record has one. This is the only read that materialises a private
     * key, so it must run after the user has selected the credential and
     * completed whatever verification the request demands — never during
     * candidate enumeration. Prefer [getCredentialMetadata] for anything that
     * does not sign.
     */
    fun getCredential(context: Context, credentialId: ByteArray, biometricCipher: Cipher? = null): Credential?

    /**
     * The credential stored under `credentialId` WITHOUT private material:
     * `privateKey` is always empty. Needs no cipher and cannot trip a
     * user-authentication requirement, so it is the right lookup for the
     * relying-party checks and response metadata that precede signing.
     */
    fun getCredentialMetadata(context: Context, credentialId: ByteArray): Credential?

    /** First stored credential for `origin`, metadata only (see [getAllCredentials]). */
    fun getCredentialByOrigin(context: Context, origin: String): Credential?

    /**
     * Every credential this module owns, METADATA ONLY: `privateKey` is empty
     * on each. Enumeration runs before the user has picked a credential or
     * verified anything (the Credential Provider service builds the chooser
     * from it), so no private scalar is copied into an immutable string for
     * records the user may never select. A legacy flat record still has to be
     * opened to read its metadata — that is the record format — but its
     * material is not decoded. Load exactly one credential's key afterwards
     * with [getCredential] / [getKeyPair].
     */
    fun getAllCredentials(context: Context): List<Credential>
    fun getPublicKeyFromKeyPair(keyPair: KeyPair?): ByteArray
    fun sign(keyPair: KeyPair, payload: ByteArray): ByteArray
    /**
     * `true` only when the master key can be read back AND proves it can seal
     * and open a payload. The Credential Provider service gates every
     * `CreateEntry` / `PublicKeyCredentialEntry` on this, so a device whose key
     * cannot encrypt is never offered a passkey to create.
     */
    fun isMasterKeyAvailable(context: Context): Boolean

    /**
     * Stores the wallet's master key. Fails closed: a wrong-length key, a
     * Keystore/Keychain failure, or a key that cannot round-trip a seal
     * throws instead of being logged and swallowed, so the caller (and the JS
     * side, as a rejected promise) knows the key is NOT in place.
     *
     * On success any of this module's own legacy records that an earlier build
     * wrote unsealed are re-sealed under the new key.
     */
    fun saveMasterKey(context: Context, secret: ByteArray)

    /**
     * Records which key store record the passkey hierarchy derives from — the
     * wallet's deterministic-P256 main key. The scheme is deliberately not part
     * of this call: it is read from the record's own metadata, so a wallet cannot
     * mislabel it.
     */
    fun saveMainKeyId(context: Context, id: String)
    fun getMainKeyId(context: Context): String?

    @Deprecated("The passkey parent is no longer the BIP32-Ed25519 root", ReplaceWith("saveMainKeyId(context, id)"))
    fun saveHdRootKeyId(context: Context, id: String)

    @Deprecated("The passkey parent is no longer the BIP32-Ed25519 root", ReplaceWith("getMainKeyId(context)"))
    fun getHdRootKeyId(context: Context): String?
    fun configureIntentActions(context: Context, getPasskeyAction: String, createPasskeyAction: String)
    fun getCreatePasskeyAction(context: Context): String?
    fun getGetPasskeyAction(context: Context): String?
    /**
     * Removes every credential THIS MODULE owns. The passkeys MMKV instance is
     * shared with the wallet's key store, so this is a record-by-record sweep
     * of positively identified passkey records ([KeystoreRecords.keysToRemoveForClear]),
     * never a `clearAll()` of the shared namespace.
     */
    fun clearCredentials(context: Context)

    /**
     * Removes the credential stored under `credentialId` (in any of its
     * historical encodings) — but only if the record reads back as one of this
     * module's passkey types ([KeystoreRecords.keysToRemoveForDelete]). An id
     * that addresses a wallet-owned record, or a sealed record that cannot be
     * opened to prove ownership, removes nothing.
     */
    fun deleteCredential(context: Context, credentialId: String)
    fun recordCredentialUsage(context: Context, credentialId: ByteArray)

    fun getBiometricCipherForEncryption(context: Context, requirement: BiometricRequirement): Cipher
    fun getBiometricCipherForDecryption(context: Context, iv: ByteArray, requirement: BiometricRequirement): Cipher

    /**
     * Resolves the parent secret that domain-specific signing keys and the PRF
     * extension's per-credential `credRandom` are derived from.
     *
     * @param requestedScheme the scheme a credential is pinned to, or `null` to
     *   let the preferred (dp256 main key) parent be chosen.
     */
    fun resolveParentSecret(context: Context, requestedScheme: String? = null): ParentSecretResult

    /**
     * The raw parent secret, or `null` when it cannot be resolved.
     *
     * Kept for callers that only need the bytes; prefer [resolveParentSecret],
     * whose failure says which of the three things went wrong.
     */
    fun getHdRootSecret(context: Context): ByteArray?

    companion object {
        const val TAG = "CredentialRepository"
        const val PASSKEYS_MMKV_ID = "keystore"
        const val CREDENTIALS_KEY = "credentials"
        const val GET_PASSKEY_ACTION_KEY = "get_passkey_action"
        const val CREATE_PASSKEY_ACTION_KEY = "create_passkey_action"
        const val MASTER_KEY_ALIAS = "co.algorand.passkeyautofill.masterkey"
        const val BIOMETRIC_KEY_ALIAS = "co.algorand.passkeyautofill.biometric.v2"
        const val KEYCHAIN_STORAGE_NAME = "PasskeyAutofillKeychain"
        const val PASSKEY_AUTOFILL_MMKV_ID = "passkey_autofill"

        /**
         * Points at the record whose material is the passkey parent secret. Its
         * predecessor [HD_ROOT_KEY_ID_KEY] named the wallet's BIP32-Ed25519
         * root; the slot was renamed rather than reused so a wallet that still
         * writes the old one is not mistaken for one that opted into the dp256
         * main key.
         */
        const val MAIN_KEY_ID_KEY = "main_key_id"

        @Deprecated("Superseded by MAIN_KEY_ID_KEY; still read so installed wallets keep working")
        const val HD_ROOT_KEY_ID_KEY = "hd_root_key_id"
        const val BIOMETRIC_KEY_LEVEL_KEY = "biometric_key_level"

        /**
         * JCE provider that exposes AndroidKeyStore-backed symmetric Cipher
         * transformations (including AES/GCM). Pinning to this provider avoids
         * BouncyCastle — which this module installs at position 1 — trying to
         * extract raw bytes from a hardware-bound SecretKey and crashing with
         * NullPointerException in `KeyParameter.<init>`.
         */
        const val ANDROID_KEYSTORE_CIPHER_PROVIDER = "AndroidKeyStoreBCWorkaround"
    }
}

fun CredentialRepository(): CredentialRepository = Repository()

class Repository() : CredentialRepository {
    override var keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    private var dP256: DeterministicP256 = DeterministicP256()

    init {
        keyStore.load(null)
    }

    private fun getPasskeysMMKV(context: Context): MMKV {
        MMKV.initialize(context)
        // Entry-level encryption (AES-256-GCM) is used for individual keys.
        return MMKV.mmkvWithID(CredentialRepository.PASSKEYS_MMKV_ID, MMKV.MULTI_PROCESS_MODE)
    }

    private fun getAutofillMMKV(context: Context): MMKV {
        MMKV.initialize(context)
        return MMKV.mmkvWithID(CredentialRepository.PASSKEY_AUTOFILL_MMKV_ID, MMKV.MULTI_PROCESS_MODE)
    }

    override fun saveCredential(context: Context, credential: Credential, biometricCipher: Cipher?) {
        Log.d(CredentialRepository.TAG, "saveCredential started for ${credential.origin}, userHandle: ${credential.userHandle}")
        val mmkv = getPasskeysMMKV(context)
        
        // 1. Create KeyData matching @algorandfoundation/keystore
        val keyData = JSONObject()
        keyData.put("id", credential.credentialId)
        keyData.put("type", "hd-derived-p256")
        keyData.put("algorithm", "P256")
        keyData.put("extractable", false)
        keyData.put("keyUsages", JSONArray(listOf("sign")))
        keyData.put("name", "Passkey: ${credential.origin}")
        
        val privateKeyBytes = AndroidBase64.decode(credential.privateKey, AndroidBase64.DEFAULT)
        if (biometricCipher != null) {
            Log.d(CredentialRepository.TAG, "Using biometricCipher for encryption")
            val encryptedBytes = biometricCipher.doFinal(privateKeyBytes)
            val encJson = JSONObject()
            encJson.put("iv", AndroidBase64.encodeToString(biometricCipher.iv, AndroidBase64.NO_WRAP))
            encJson.put("data", AndroidBase64.encodeToString(encryptedBytes, AndroidBase64.NO_WRAP))
            keyData.put("privateKeyEnc", encJson)
        } else {
            Log.d(CredentialRepository.TAG, "No biometricCipher, saving privateKey in plain (base64 in JSON)")
            keyData.put("privateKey", JSONArray(privateKeyBytes.map { it.toInt() and 0xFF }))
        }

        keyData.put("publicKey", JSONArray(AndroidBase64.decode(credential.publicKey, AndroidBase64.DEFAULT).map { it.toInt() and 0xFF }))
        
        // Custom fields for our use
        val metadata = JSONObject()
        metadata.put("origin", credential.origin)
        metadata.put("userHandle", credential.userHandle)
        metadata.put("userId", credential.userId)
        metadata.put("count", credential.count)
        // Pin the parent this key was derived from. Without it an assertion has
        // to guess, and a wallet that has since gained a dp256 main key would
        // re-derive an older credential against the wrong root.
        credential.parentKeyId?.let { metadata.put("parentKeyId", it) }
        credential.derivationScheme?.let { metadata.put("scheme", it) }
        metadata.put("derivationVersion", credential.derivationVersion)
        keyData.put("metadata", metadata)

        // 2. Encode matching react-native-keystore's encode()
        val jsonString = keyData.toString()
        val base64urlJson = AndroidBase64.encodeToString(jsonString.toByteArray(Charsets.UTF_8), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)

        // 3. Seal matching react-native-keystore's commit(). There is deliberately
        // no unsealed fallback: without the master key the record — which carries
        // the P-256 private key — is not written at all and creation aborts.
        val masterKey = getMasterKey(context) ?: throw MasterKeyUnavailableException()
        val sealed = KeystoreRecords.sealEnvelope(masterKey, base64urlJson)
        check(mmkv.encode(credential.credentialId, sealed)) {
            "Failed to write sealed credential record for ${credential.origin}"
        }
    }

    override fun getAllCredentials(context: Context): List<Credential> {
        val mmkv = getPasskeysMMKV(context)
        val allKeys = mmkv.allKeys() ?: return emptyList()
        val credentials = mutableListOf<Credential>()

        // Only the legacy layout needs the master key to be readable at all; in
        // the split layout the metadata half is plaintext, so the AutoFill list
        // can be built before the wallet has shared anything.
        val masterKey = getMasterKey(context)

        for (key in allKeys) {
            // Material is picked up through its own metadata record, never alone.
            if (key.startsWith(KeystoreRecords.MATERIAL_PREFIX)) continue

            if (key.startsWith(KeystoreRecords.METADATA_PREFIX)) {
                val plaintext = mmkv.decodeString(key) ?: continue
                try {
                    val json = JSONObject(plaintext)
                    if (!KeystoreRecords.isPasskeyRecordType(json.optString("type", ""))) continue
                    credentialFromMetadataRecord(json)?.let { credentials.add(it) }
                } catch (e: Exception) {
                    continue
                }
                continue
            }

            if (masterKey == null) continue
            val payload = mmkv.decodeString(key) ?: continue
            try {
                val json = KeystoreRecords.decodeLegacyRecord(payload, masterKey)
                // Only treat entries as passkey credentials that match p256
                if (!KeystoreRecords.isPasskeyRecordType(json.optString("type", ""))) {
                    continue
                }
                // Enumeration: metadata only, the material stays undecoded.
                credentialFromLegacyRecord(json, biometricCipher = null, includeMaterial = false)
                    ?.let { credentials.add(it) }
            } catch (e: Exception) {
                // Not a JSON or not a credential or decryption failed, skip
                continue
            }
        }
        return credentials
    }

    /**
     * Builds a [Credential] from a decoded legacy flat record (`KeyData` JSON).
     *
     * @param includeMaterial whether to materialise the private key. `false`
     *   for enumeration and pre-signing lookups; `true` only for the single
     *   credential the user selected and verified for.
     * @param biometricCipher opens a biometric-wrapped `privateKeyEnc` when
     *   material is requested and the record carries one.
     */
    private fun credentialFromLegacyRecord(
        json: JSONObject,
        biometricCipher: Cipher?,
        includeMaterial: Boolean,
    ): Credential? {
        if (!json.has("id") || !(json.has("origin") || json.has("metadata"))) return null
        val metadata = json.optJSONObject("metadata")
        val encJson = json.optJSONObject("privateKeyEnc")

        val privateKey = when {
            !includeMaterial -> ""
            encJson != null && biometricCipher != null -> {
                Log.d(CredentialRepository.TAG, "Decrypting privateKey with biometricCipher")
                val data = AndroidBase64.decode(encJson.getString("data"), AndroidBase64.DEFAULT)
                AndroidBase64.encodeToString(biometricCipher.doFinal(data), AndroidBase64.DEFAULT)
            }
            json.has("privateKey") ->
                AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("privateKey")), AndroidBase64.DEFAULT)
            else -> {
                Log.w(CredentialRepository.TAG, "No privateKey found in JSON")
                ""
            }
        }

        return Credential(
            credentialId = json.getString("id"),
            origin = metadata?.optString("origin") ?: json.optString("origin", ""),
            userHandle = metadata?.optString("userHandle") ?: json.optString("userHandle", ""),
            userId = metadata?.optString("userId") ?: json.optString("userId", ""),
            publicKey = AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("publicKey")), AndroidBase64.DEFAULT),
            privateKey = privateKey,
            count = metadata?.optInt("count") ?: json.optInt("count", 0),
            biometricIv = encJson?.optString("iv"),
            parentKeyId = metadata?.optString("parentKeyId").takeUnless { it.isNullOrEmpty() },
            derivationScheme = metadata?.optString("scheme").takeUnless { it.isNullOrEmpty() },
            derivationVersion = metadata?.optInt("derivationVersion", PasskeyDerivation.VERSION_LEGACY_LABEL)
                ?: PasskeyDerivation.VERSION_LEGACY_LABEL,
        )
    }

    /**
     * Builds a [Credential] from a split-layout `k/<id>` metadata record.
     *
     * These carry no material: a domain key is defined by its parent plus its
     * domain descriptor, so the private key is re-derived on demand (see
     * [getKeyPair]) rather than stored twice.
     */
    private fun credentialFromMetadataRecord(json: JSONObject): Credential? {
        val id = json.optString("id").takeUnless { it.isEmpty() } ?: return null
        val metadata = json.optJSONObject("metadata") ?: return null
        val origin = metadata.optString("origin").takeUnless { it.isEmpty() } ?: return null
        val publicKey = KeystoreRecords.unwrapBytes(json.opt("publicKey")) ?: return null
        return Credential(
            credentialId = id,
            origin = origin,
            userHandle = metadata.optString("userHandle"),
            userId = metadata.optString("userId"),
            publicKey = AndroidBase64.encodeToString(publicKey, AndroidBase64.DEFAULT),
            privateKey = "",
            count = metadata.optInt("count", 0),
            parentKeyId = metadata.optString("parentKeyId").takeUnless { it.isEmpty() },
            derivationScheme = metadata.optString("scheme").takeUnless { it.isEmpty() },
            derivationVersion = metadata.optInt("derivationVersion", PasskeyDerivation.VERSION_LEGACY_LABEL),
        )
    }

    private fun jsonArrayToByteArray(array: JSONArray): ByteArray {
        val bytes = ByteArray(array.length())
        for (i in 0 until array.length()) {
            bytes[i] = array.getInt(i).toByte()
        }
        return bytes
    }

    override fun generateCredentialId(keyPair: KeyPair): ByteArray {
        val publicKeyBytes = keyPair.public.encoded
        val messageDigest = MessageDigest.getInstance("SHA-256")
        return messageDigest.digest(publicKeyBytes)
    }

    override fun getCredential(context: Context, credentialId: ByteArray, biometricCipher: Cipher?): Credential? =
        readCredential(context, credentialId, biometricCipher, includeMaterial = true)

    override fun getCredentialMetadata(context: Context, credentialId: ByteArray): Credential? =
        readCredential(context, credentialId, biometricCipher = null, includeMaterial = false)

    private fun readCredential(
        context: Context,
        credentialId: ByteArray,
        biometricCipher: Cipher?,
        includeMaterial: Boolean,
    ): Credential? {
        val id = AndroidBase64.encodeToString(credentialId, AndroidBase64.DEFAULT).trim()
        Log.d(CredentialRepository.TAG, "getCredential started for id: $id")
        val mmkv = getPasskeysMMKV(context)

        // Split layout first: its metadata half is plaintext, so it reads without
        // the master key. The id is base64 and has historically been written in
        // several encodings, hence the candidates.
        for (candidate in credentialIdCandidates(id)) {
            val plaintext = mmkv.decodeString(KeystoreRecords.metadataKey(candidate)) ?: continue
            try {
                credentialFromMetadataRecord(JSONObject(plaintext))?.let { return it }
            } catch (e: Exception) {
                Log.w(CredentialRepository.TAG, "Unreadable metadata record for $candidate", e)
            }
        }

        val payload = mmkv.decodeString(id) ?: run {
            Log.w(CredentialRepository.TAG, "No payload found for id: $id")
            return null
        }
        val masterKey = getMasterKey(context) ?: run {
            Log.e(CredentialRepository.TAG, "Master key not found")
            return null
        }
        return try {
            val json = KeystoreRecords.decodeLegacyRecord(payload, masterKey)
            credentialFromLegacyRecord(json, biometricCipher, includeMaterial)
        } catch (e: Exception) {
            null
        }
    }

    override fun getCredentialByOrigin(context: Context, origin: String): Credential? {
        return getAllCredentials(context).find { it.origin == origin }
    }

    fun getKeyPairFromCredential(credential: Credential): KeyPair? {
        if (credential.privateKey.isEmpty()) return null
        val publicKeyBytes = AndroidBase64.decode(credential.publicKey, AndroidBase64.DEFAULT)
        val privateKeyBytes = AndroidBase64.decode(credential.privateKey, AndroidBase64.DEFAULT)

        return try {
            // First try DER-encoded format (X509/PKCS8)
            val factory = KeyFactory.getInstance("EC")
            val publicKey = factory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
            val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
            KeyPair(publicKey, privateKey)
        } catch (e: Exception) {
            // Fall back to raw EC bytes
            try {
                // Get the P-256 curve parameters
                val ecGenSpec = ECGenParameterSpec("secp256r1")
                val keyPairGen = KeyPairGenerator.getInstance("EC")
                keyPairGen.initialize(ecGenSpec)
                val paramSpec = (keyPairGen.generateKeyPair().public as java.security.interfaces.ECPublicKey).params
                val factory = KeyFactory.getInstance("EC")

                val publicKeyFromX509 = try {
                    factory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
                } catch (_: Exception) {
                    null
                }

                if (publicKeyFromX509 != null && privateKeyBytes.size == 32) {
                    val s = java.math.BigInteger(1, privateKeyBytes)
                    val privSpec = ECPrivateKeySpec(s, paramSpec)
                    val privateKey = factory.generatePrivate(privSpec)
                    return KeyPair(publicKeyFromX509, privateKey)
                }

                // privateKey is 32-byte scalar
                val rawXY: Pair<ByteArray, ByteArray>? = when {
                    // 65-byte uncompressed point: 04 || x(32) || y(32)
                    publicKeyBytes.size == 65 && publicKeyBytes[0] == 0x04.toByte() ->
                        Pair(publicKeyBytes.copyOfRange(1, 33), publicKeyBytes.copyOfRange(33, 65))
                    // 64-byte raw x || y (no prefix)
                    publicKeyBytes.size == 64 ->
                        Pair(publicKeyBytes.copyOfRange(0, 32), publicKeyBytes.copyOfRange(32, 64))
                    else -> null
                }

                if (rawXY != null) {
                    val x = java.math.BigInteger(1, rawXY.first)
                    val y = java.math.BigInteger(1, rawXY.second)
                    val pubSpec = ECPublicKeySpec(ECPoint(x, y), paramSpec)
                    val publicKey = factory.generatePublic(pubSpec)

                    val s = java.math.BigInteger(1, privateKeyBytes)
                    val privSpec = ECPrivateKeySpec(s, paramSpec)
                    val privateKey = factory.generatePrivate(privSpec)

                    KeyPair(publicKey, privateKey)
                } else {
                    Log.e(CredentialRepository.TAG, "Unrecognized key format: publicKey size=${publicKeyBytes.size}", e)
                    null
                }
            } catch (e2: Exception) {
                Log.e(CredentialRepository.TAG, "Failed to restore key from raw bytes", e2)
                null
            }
        }
    }

    override fun getKeyPair(context: Context, credentialId: ByteArray, biometricCipher: Cipher?): KeyPair? {
        val credential = getCredential(context, credentialId, biometricCipher) ?: return null
        getKeyPairFromCredential(credential)?.let { return it }

        // A credential the wallet derived itself carries no material at all (a
        // domain key is metadata plus a public key: it is re-derivable by
        // definition), and neither does one whose biometric-wrapped material we
        // could not open. Re-derive from the parent AND the identity it is
        // pinned to — its stored derivationVersion decides whether that is the
        // relying party's user.id or the legacy label.
        val identity = PasskeyDerivation.identity(credential)
        if (credential.origin.isEmpty() || identity.isEmpty()) return null
        return try {
            createDomainKeyPair(
                context,
                credential.origin,
                identity,
                credential.derivationScheme ?: KeystoreRecords.SCHEME_BIP32_ED25519,
            ).keyPair
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to re-derive key pair for ${credential.credentialId}", e)
            null
        }
    }

    override fun createDomainKeyPair(
        context: Context,
        origin: String,
        identity: String,
        requestedScheme: String?,
    ): DerivedDomainKeyPair {
        Log.d(CredentialRepository.TAG, "createDomainKeyPair for origin: $origin, scheme: ${requestedScheme ?: "preferred"}")
        val resolved = resolveParentSecret(context, requestedScheme)
        if (resolved is ParentSecretResult.MasterKeyUnavailable) {
            // Typed so the create flow can report a definite failure to the
            // relying party: without the master key nothing can be derived OR
            // stored, and no amount of retrying from the UI changes that.
            throw MasterKeyUnavailableException("Cannot derive a passkey: ${resolved.reason}")
        }
        if (resolved !is ParentSecretResult.Available) {
            throw IllegalStateException("Cannot derive a passkey: ${resolved.reason}")
        }
        val parent = resolved.secret
        Log.d(CredentialRepository.TAG, "deriving from parent ${parent.keyId} (${parent.scheme}, ${parent.bytes.size} bytes)")
        return DerivedDomainKeyPair(
            // `identity` verbatim: see the interface contract.
            keyPair = dP256.genDomainSpecificKeypair(parent.bytes, origin, identity),
            parentKeyId = parent.keyId,
            derivationScheme = parent.scheme,
        )
    }

    override fun resolveParentSecret(context: Context, requestedScheme: String?): ParentSecretResult {
        val masterKey = getMasterKey(context) ?: return ParentSecretResult.MasterKeyUnavailable
        val selected = KeystoreRecords.selectParentKey(parentKeyCandidates(context, masterKey), requestedScheme)
            ?: return ParentSecretResult.NoParentKey(requestedScheme)
        val bytes = readMaterial(context, selected.keyId, masterKey)
            ?: return ParentSecretResult.MaterialUnavailable(selected.keyId, selected.scheme)
        return ParentSecretResult.Available(ParentSecret(selected.keyId, selected.scheme, bytes))
    }

    /**
     * The roots this device could derive from, most authoritative first: what the
     * wallet pointed us at through `setMainKeyId`, then the record its
     * predecessor named, then any root record found in the shared store.
     *
     * The scan matters for a credential pinned to a scheme the wallet is no
     * longer pointing at: an already-issued passkey must keep re-deriving from
     * the BIP32-Ed25519 root even once the wallet has moved new keys onto its
     * dp256 main key.
     */
    private fun parentKeyCandidates(context: Context, masterKey: ByteArray): List<KeystoreRecords.ParentKeyRecord> {
        val mmkvAutofill = getAutofillMMKV(context)
        val pointed = listOfNotNull(
            mmkvAutofill.decodeString(CredentialRepository.MAIN_KEY_ID_KEY),
            @Suppress("DEPRECATION")
            mmkvAutofill.decodeString(CredentialRepository.HD_ROOT_KEY_ID_KEY),
        )

        val mmkvKeystore = getPasskeysMMKV(context)
        val discovered = (mmkvKeystore.allKeys() ?: emptyArray())
            .filter { it.startsWith(KeystoreRecords.METADATA_PREFIX) }
            .map { it.removePrefix(KeystoreRecords.METADATA_PREFIX) }

        val candidates = mutableListOf<KeystoreRecords.ParentKeyRecord>()
        for (id in (pointed + discovered).distinct()) {
            val record = readMetadata(context, id, masterKey) ?: continue
            // A discovered record is only a candidate if it is a root; a record the
            // wallet explicitly pointed at is trusted even if its type predates
            // the current naming (e.g. `xhd-root-key`, or a bare seed record).
            if (id !in pointed && record.optString("type") != KeystoreRecords.TYPE_HD_ROOT_KEY) continue
            candidates.add(KeystoreRecords.ParentKeyRecord(id, KeystoreRecords.schemeOf(record)))
        }
        return candidates
    }

    /**
     * A record's metadata, from `k/<id>` (split layout, stored in plaintext) or
     * from the sealed legacy flat record keyed by the bare id.
     */
    private fun readMetadata(context: Context, id: String, masterKey: ByteArray?): JSONObject? {
        val mmkv = getPasskeysMMKV(context)
        mmkv.decodeString(KeystoreRecords.metadataKey(id))?.let { plaintext ->
            return try {
                JSONObject(plaintext)
            } catch (e: Exception) {
                Log.w(CredentialRepository.TAG, "Unreadable metadata record for $id", e)
                null
            }
        }
        val legacy = mmkv.decodeString(id) ?: return null
        return try {
            KeystoreRecords.decodeLegacyRecord(legacy, masterKey)
        } catch (e: Exception) {
            Log.w(CredentialRepository.TAG, "Unreadable legacy record for $id", e)
            null
        }
    }

    /**
     * A record's raw secret bytes, from `m/<id>` (split layout) or, failing that,
     * from the inline material of the legacy flat record.
     */
    private fun readMaterial(context: Context, id: String, masterKey: ByteArray): ByteArray? {
        val mmkv = getPasskeysMMKV(context)
        mmkv.decodeString(KeystoreRecords.materialKey(id))?.let { sealed ->
            return try {
                KeystoreRecords.openMaterial(masterKey, sealed)
            } catch (e: Exception) {
                Log.w(CredentialRepository.TAG, "Failed to open material for $id", e)
                null
            }
        }
        val legacy = mmkv.decodeString(id) ?: return null
        return try {
            KeystoreRecords.materialFromLegacyRecord(KeystoreRecords.decodeLegacyRecord(legacy, masterKey))
        } catch (e: Exception) {
            Log.w(CredentialRepository.TAG, "Failed to read legacy material for $id", e)
            null
        }
    }

    override fun getHdRootSecret(context: Context): ByteArray? =
        (resolveParentSecret(context) as? ParentSecretResult.Available)?.secret?.bytes


    private fun decodeKeyData(payload: String, masterKey: ByteArray?): JSONObject {
        try {
            // Check if it's the old encrypted format (starts with { and has iv, tag, content)
            if (payload.startsWith("{")) {
                val json = JSONObject(payload)
                if (json.has("iv") && json.has("tag") && json.has("content")) {
                    if (masterKey == null) throw IllegalStateException("Master key required for legacy decryption")

                    val iv = AndroidBase64.decode(json.getString("iv"), AndroidBase64.DEFAULT)
                    val tag = AndroidBase64.decode(json.getString("tag"), AndroidBase64.DEFAULT)
                    val content = AndroidBase64.decode(json.getString("content"), AndroidBase64.DEFAULT)

                    val keySpec = javax.crypto.spec.SecretKeySpec(masterKey, "AES")
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val gcmSpec = GCMParameterSpec(128, iv)
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

                    val combined = content + tag
                    val decryptedBytes = cipher.doFinal(combined)
                    val decryptedString = String(decryptedBytes, Charsets.UTF_8)

                    // The decrypted bytes are base64url encoded JSON
                    val decodedJsonBytes = try {
                        AndroidBase64.decode(decryptedString, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
                    } catch (e: Exception) {
                        decryptedString.toByteArray(Charsets.UTF_8)
                    }
                    return JSONObject(String(decodedJsonBytes, Charsets.UTF_8))
                }
                return json
            }

            // New format: base64url encoded JSON (MMKV handles the encryption/decryption of this string)
            val decodedBytes = AndroidBase64.decode(payload, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
            return JSONObject(String(decodedBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to decode payload", e)
            throw e
        }
    }

    override fun saveMasterKey(context: Context, secret: ByteArray) {
        // Reject a key that could never seal anything BEFORE touching storage, so
        // a bad key does not replace a working one.
        KeystoreRecords.verifySealRoundTrip(secret)

        // The master key arrives as raw bytes (the bridge no longer takes a hex
        // String), so encrypt it straight into the Keychain. Nothing here is
        // caught: a Keystore failure must reach the caller.
        encryptToKeychain(context, secret)

        // Prove the stored key reads back as what was given before reporting
        // success — a silent readback failure would leave the wallet believing
        // the key is in place while every later write fails.
        val readBack = decryptFromKeychain(context)
        check(readBack != null && readBack.contentEquals(secret)) {
            "Master key did not read back from the Keychain after saving"
        }

        resealUnsealedRecords(context, secret)
    }

    /**
     * Re-seals any of this module's own legacy flat records that an earlier
     * build wrote without the AES-GCM envelope (see
     * [KeystoreRecords.unsealedPasskeyRecordKeys]). It runs here, when the master
     * key arrives, because that is the point at which the wallet has authenticated
     * its user and unlocked. A record that cannot be re-sealed is left in place
     * and logged rather than dropped: the credential id is what the relying
     * party knows, and deleting it would orphan the account.
     */
    private fun resealUnsealedRecords(context: Context, masterKey: ByteArray) {
        try {
            val mmkv = getPasskeysMMKV(context)
            val keys = KeystoreRecords.unsealedPasskeyRecordKeys(mmkv.allKeys() ?: emptyArray()) {
                mmkv.decodeString(it)
            }
            if (keys.isEmpty()) return
            Log.w(CredentialRepository.TAG, "Re-sealing ${keys.size} passkey record(s) stored without encryption")
            for (key in keys) {
                val payload = mmkv.decodeString(key) ?: continue
                // The envelope's plaintext is base64url(JSON); a record stored as
                // bare JSON is normalised to that shape first.
                val plaintext = if (payload.startsWith("{")) {
                    AndroidBase64.encodeToString(payload.toByteArray(Charsets.UTF_8), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
                } else {
                    payload
                }
                if (!mmkv.encode(key, KeystoreRecords.sealEnvelope(masterKey, plaintext))) {
                    Log.e(CredentialRepository.TAG, "Failed to re-seal passkey record $key")
                }
            }
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to re-seal unsealed passkey records", e)
        }
    }

    private fun getMasterKey(context: Context): ByteArray? {
        // Try our separate Keychain storage
        return try {
            val decrypted = decryptFromKeychain(context)
            if (decrypted != null) {
                // Return the raw bytes directly as they were already processed during save
                decrypted
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to get master key from Keychain", e)
            null
        }
    }

    private fun getSecretKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (!ks.containsAlias(CredentialRepository.MASTER_KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder(CredentialRepository.MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            keyGenerator.generateKey()
        }
        return ks.getKey(CredentialRepository.MASTER_KEY_ALIAS, null) as SecretKey
    }

    private fun encryptToKeychain(context: Context, data: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(data)
        
        val prefs = context.getSharedPreferences(CredentialRepository.KEYCHAIN_STORAGE_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString("iv", AndroidBase64.encodeToString(iv, AndroidBase64.NO_WRAP))
            .putString("content", AndroidBase64.encodeToString(encryptedData, AndroidBase64.NO_WRAP))
            .apply()
    }

    private fun decryptFromKeychain(context: Context): ByteArray? {
        val prefs = context.getSharedPreferences(CredentialRepository.KEYCHAIN_STORAGE_NAME, Context.MODE_PRIVATE)
        val ivStr = prefs.getString("iv", null) ?: return null
        val contentStr = prefs.getString("content", null) ?: return null
        
        val iv = AndroidBase64.decode(ivStr, AndroidBase64.NO_WRAP)
        val content = AndroidBase64.decode(contentStr, AndroidBase64.NO_WRAP)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), gcmSpec)
        
        return cipher.doFinal(content)
    }

    override fun isMasterKeyAvailable(context: Context): Boolean {
        val masterKey = getMasterKey(context) ?: return false
        return try {
            KeystoreRecords.verifySealRoundTrip(masterKey)
            true
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Master key present but cannot seal/open a payload", e)
            false
        }
    }

    override fun saveMainKeyId(context: Context, id: String) {
        val mmkv = getAutofillMMKV(context)
        mmkv.encode(CredentialRepository.MAIN_KEY_ID_KEY, id)
    }

    override fun getMainKeyId(context: Context): String? {
        val mmkv = getAutofillMMKV(context)
        @Suppress("DEPRECATION")
        return mmkv.decodeString(CredentialRepository.MAIN_KEY_ID_KEY)
            ?: mmkv.decodeString(CredentialRepository.HD_ROOT_KEY_ID_KEY)
    }

    @Deprecated("The passkey parent is no longer the BIP32-Ed25519 root", ReplaceWith("saveMainKeyId(context, id)"))
    override fun saveHdRootKeyId(context: Context, id: String) {
        // Writes the same slot: which setter a wallet happens to call says nothing
        // about the record, and the scheme is read from the record itself.
        saveMainKeyId(context, id)
    }

    @Deprecated("The passkey parent is no longer the BIP32-Ed25519 root", ReplaceWith("getMainKeyId(context)"))
    override fun getHdRootKeyId(context: Context): String? = getMainKeyId(context)

    override fun configureIntentActions(context: Context, getPasskeyAction: String, createPasskeyAction: String) {
        val mmkv = getAutofillMMKV(context)
        mmkv.encode(CredentialRepository.GET_PASSKEY_ACTION_KEY, getPasskeyAction)
        mmkv.encode(CredentialRepository.CREATE_PASSKEY_ACTION_KEY, createPasskeyAction)
    }

    override fun getCreatePasskeyAction(context: Context): String? {
        val mmkv = getAutofillMMKV(context)
        return mmkv.decodeString(CredentialRepository.CREATE_PASSKEY_ACTION_KEY)
    }

    override fun getGetPasskeyAction(context: Context): String? {
        val mmkv = getAutofillMMKV(context)
        return mmkv.decodeString(CredentialRepository.GET_PASSKEY_ACTION_KEY)
    }

    override fun clearCredentials(context: Context) {
        try {
            val mmkvAutofill = getAutofillMMKV(context)
            mmkvAutofill.clearAll()

            // The passkeys instance is the WALLET's key store: it also holds the
            // seed, the roots and every account key, so clearing it wholesale
            // would destroy the wallet. Only this module's own credentials go.
            val mmkvPasskeys = getPasskeysMMKV(context)
            val masterKey = getMasterKey(context)
            val removable = KeystoreRecords.keysToRemoveForClear(
                allKeys = mmkvPasskeys.allKeys() ?: emptyArray(),
                masterKey = masterKey,
            ) { mmkvPasskeys.decodeString(it) }
            removable.forEach { mmkvPasskeys.removeValueForKey(it) }
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Error clearing credentials and secrets", e)
        }
    }

    override fun deleteCredential(context: Context, credentialId: String) {
        try {
            // The passkeys instance is the WALLET's key store. Whatever id the
            // caller hands us, only a record that reads back as one of this
            // module's own passkeys is removed — never a seed, root or account
            // key that happens to live under that id.
            val mmkvPasskeys = getPasskeysMMKV(context)
            val removable = KeystoreRecords.keysToRemoveForDelete(
                candidateIds = credentialIdCandidates(credentialId),
                masterKey = getMasterKey(context),
            ) { mmkvPasskeys.decodeString(it) }
            if (removable.isEmpty()) {
                Log.w(CredentialRepository.TAG, "deleteCredential: no passkey record owned by this module matches; nothing removed")
                return
            }
            removable.forEach { mmkvPasskeys.removeValueForKey(it) }
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Error deleting credential", e)
        }
    }

    override fun recordCredentialUsage(context: Context, credentialId: ByteArray) {
        val id = AndroidBase64.encodeToString(credentialId, AndroidBase64.DEFAULT).trim()
        try {
            val mmkv = getPasskeysMMKV(context)
            val payload = mmkv.decodeString(id) ?: return
            val masterKey = getMasterKey(context) ?: return

            val json = KeystoreRecords.decodeLegacyRecord(payload, masterKey)
            val metadata = json.optJSONObject("metadata") ?: JSONObject()
            metadata.put("lastUsedAt", System.currentTimeMillis())
            metadata.put("count", metadata.optInt("count", 0) + 1)
            json.put("metadata", metadata)

            val base64urlJson = AndroidBase64.encodeToString(
                json.toString().toByteArray(Charsets.UTF_8),
                AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP,
            )
            mmkv.encode(id, KeystoreRecords.sealEnvelope(masterKey, base64urlJson))
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to record credential usage", e)
        }
    }

    private fun credentialIdCandidates(id: String): Set<String> {
        val candidates = mutableSetOf(id)
        val decoded = try {
            AndroidBase64.decode(id, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
        } catch (_: Exception) {
            try {
                AndroidBase64.decode(id, AndroidBase64.DEFAULT)
            } catch (_: Exception) {
                null
            }
        }

        if (decoded != null) {
            candidates.add(AndroidBase64.encodeToString(decoded, AndroidBase64.DEFAULT).trim())
            candidates.add(AndroidBase64.encodeToString(decoded, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING))
        }
        return candidates
    }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in 0 until hex.length step 2) {
            val firstIndex = Character.digit(hex[i], 16)
            val secondIndex = Character.digit(hex[i + 1], 16)
            val octet = firstIndex shl 4 or secondIndex
            result[i / 2] = octet.toByte()
        }
        return result
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun getBiometricSecretKey(context: Context, requirement: BiometricRequirement): SecretKey {
        // The key's auth binding is fixed at creation. If a new build changed the configured
        // level, regenerate the key so the prompt's allowed authenticators stay compatible.
        // Passkey private keys are deterministically re-derivable, so this is recoverable.
        val mmkv = getAutofillMMKV(context)
        val storedLevel = mmkv.decodeString(CredentialRepository.BIOMETRIC_KEY_LEVEL_KEY)
        if (keyStore.containsAlias(CredentialRepository.BIOMETRIC_KEY_ALIAS) &&
            storedLevel != requirement.name
        ) {
            Log.i(CredentialRepository.TAG, "Biometric requirement changed ($storedLevel -> ${requirement.name}); regenerating key")
            keyStore.deleteEntry(CredentialRepository.BIOMETRIC_KEY_ALIAS)
        }

        if (!keyStore.containsAlias(CredentialRepository.BIOMETRIC_KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                CredentialRepository.BIOMETRIC_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(requirement.isCryptoBound)

            // Biometric-enrollment invalidation and auth params only apply to user-auth-bound keys.
            if (requirement.isCryptoBound) {
                builder.setInvalidatedByBiometricEnrollment(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(60, requirement.keystoreAuthType)
                } else {
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(60)
                }
            }

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
            mmkv.encode(CredentialRepository.BIOMETRIC_KEY_LEVEL_KEY, requirement.name)
        }
        return keyStore.getKey(CredentialRepository.BIOMETRIC_KEY_ALIAS, null) as SecretKey
    }

    /**
     * Build an AES/GCM Cipher tied to the AndroidKeyStore-backed biometric key.
     *
     * We request the provider explicitly because this module installs
     * BouncyCastle at position 1 (see [co.algorand.passkeyautofill.ReactNativePasskeyAutofillModule]).
     * Without a pinned provider, [Cipher.getInstance] resolves to BouncyCastle, which
     * then tries to extract raw key material from an AndroidKeyStore SecretKey
     * (whose `getEncoded()` is null for hardware-bound keys) and crashes with:
     *
     *   java.lang.NullPointerException: Attempt to get length of null array
     *       at org.bouncycastle.crypto.params.KeyParameter.<init>(...)
     *
     * AndroidKeyStore AES keys are served by the "AndroidKeyStoreBCWorkaround"
     * JCE provider on all supported Android versions.
     */
    private fun newAndroidKeyStoreAesGcmCipher(): Cipher {
        return try {
            Cipher.getInstance("AES/GCM/NoPadding", CredentialRepository.ANDROID_KEYSTORE_CIPHER_PROVIDER)
        } catch (e: NoSuchProviderException) {
            // Extremely unlikely on stock Android, but fall back to provider discovery
            // by key rather than by name so we never hand the key to BouncyCastle.
            Log.w(CredentialRepository.TAG, "${CredentialRepository.ANDROID_KEYSTORE_CIPHER_PROVIDER} unavailable, falling back to default provider resolution", e)
            Cipher.getInstance("AES/GCM/NoPadding")
        }
    }

    override fun getBiometricCipherForEncryption(context: Context, requirement: BiometricRequirement): Cipher {
        val cipher = newAndroidKeyStoreAesGcmCipher()
        cipher.init(Cipher.ENCRYPT_MODE, getBiometricSecretKey(context, requirement))
        return cipher
    }

    override fun getBiometricCipherForDecryption(context: Context, iv: ByteArray, requirement: BiometricRequirement): Cipher {
        val cipher = newAndroidKeyStoreAesGcmCipher()
        cipher.init(Cipher.DECRYPT_MODE, getBiometricSecretKey(context, requirement), GCMParameterSpec(128, iv))
        return cipher
    }

    override fun sign(keyPair: KeyPair, payload: ByteArray): ByteArray {
        return dP256.signWithDomainSpecificKeyPair(keyPair, payload)
    }

    override fun getPublicKeyFromKeyPair(keyPair: KeyPair?): ByteArray {
        if (keyPair == null) return ByteArray(0)
        if (keyPair.public !is java.security.interfaces.ECPublicKey) return ByteArray(0)

        val ecPubKey = keyPair.public as java.security.interfaces.ECPublicKey
        val ecPoint: java.security.spec.ECPoint = ecPubKey.w

        // for now, only covers ES256
        if (ecPoint.affineX.bitLength() > 256 || ecPoint.affineY.bitLength() > 256) return ByteArray(0)

        val byteX = bigIntToByteArray32(ecPoint.affineX)
        val byteY = bigIntToByteArray32(ecPoint.affineY)

        // refer to RFC9052 Section 7 for details
        return "A5010203262001215820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() + byteX + "225820".chunked(2).map { it.toInt(16).toByte() }.toByteArray() + byteY
    }

    private fun bigIntToByteArray32(bigInteger: java.math.BigInteger): ByteArray {
        var ba = bigInteger.toByteArray()
        if (ba.size < 32) {
            ba = ByteArray(32 - ba.size) + ba
        }
        return ba.copyOfRange(ba.size - 32, ba.size)
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun getOrigin(info: CallingAppInfo): String {
        return appInfoToOrigin(info)
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun appInfoToOrigin(info: CallingAppInfo): String {
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val certHash = md.digest(cert)
        return "android:apk-key-hash:${AndroidBase64.encodeToString(certHash, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)}"
    }
}
