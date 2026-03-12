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


interface CredentialRepository {
    val keyStore: KeyStore
    fun saveCredential(context: Context, credential: Credential)
    fun generateCredentialId(keyPair: KeyPair): ByteArray
    fun getKeyPair(context: Context, credentialId: ByteArray): KeyPair?
    fun createDeterministicKeyPair(context: Context, origin: String, userHandle: String): KeyPair
    fun getOrigin(info: CallingAppInfo): String
    fun appInfoToOrigin(info: CallingAppInfo): String
    fun getCredential(context: Context, credentialId: ByteArray): Credential?
    fun getCredentialByOrigin(context: Context, origin: String): Credential?
    fun getAllCredentials(context: Context): List<Credential>
    fun getPublicKeyFromKeyPair(keyPair: KeyPair?): ByteArray
    fun sign(keyPair: KeyPair, payload: ByteArray): ByteArray
    fun isMasterKeyAvailable(context: Context): Boolean
    fun saveMasterKey(context: Context, secret: String)
    fun saveHdRootKeyId(context: Context, id: String)
    fun getHdRootKeyId(context: Context): String?
    fun configureIntentActions(context: Context, getPasskeyAction: String, createPasskeyAction: String)
    fun getCreatePasskeyAction(context: Context): String?
    fun getGetPasskeyAction(context: Context): String?
    fun clearCredentials(context: Context)

    companion object {
        const val TAG = "CredentialRepository"
        const val PASSKEYS_MMKV_ID = "keystore"
        const val CREDENTIALS_KEY = "credentials"
        const val GET_PASSKEY_ACTION_KEY = "get_passkey_action"
        const val CREATE_PASSKEY_ACTION_KEY = "create_passkey_action"
        const val MASTER_KEY_ALIAS = "co.algorand.passkeyautofill.masterkey"
        const val KEYCHAIN_STORAGE_NAME = "PasskeyAutofillKeychain"
        const val PASSKEY_AUTOFILL_MMKV_ID = "passkey_autofill"
        const val HD_ROOT_KEY_ID_KEY = "hd_root_key_id"
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

    override fun saveCredential(context: Context, credential: Credential) {
        val mmkv = getPasskeysMMKV(context)
        
        // 1. Create KeyData matching @algorandfoundation/keystore
        val keyData = JSONObject()
        keyData.put("id", credential.credentialId)
        keyData.put("type", "hd-derived-p256")
        keyData.put("algorithm", "P256")
        keyData.put("extractable", false)
        keyData.put("keyUsages", JSONArray(listOf("sign")))
        keyData.put("name", "Passkey: ${credential.origin}")
        keyData.put("privateKey", JSONArray(AndroidBase64.decode(credential.privateKey, AndroidBase64.DEFAULT).map { it.toInt() and 0xFF }))
        keyData.put("publicKey", JSONArray(AndroidBase64.decode(credential.publicKey, AndroidBase64.DEFAULT).map { it.toInt() and 0xFF }))
        
        // Custom fields for our use
        val metadata = JSONObject()
        metadata.put("origin", credential.origin)
        metadata.put("userHandle", credential.userHandle)
        metadata.put("userId", credential.userId)
        metadata.put("count", credential.count)
        keyData.put("metadata", metadata)

        // 2. Encode matching react-native-keystore's encode()
        val jsonString = keyData.toString()
        val base64urlJson = AndroidBase64.encodeToString(jsonString.toByteArray(Charsets.UTF_8), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)

        // 3. Encrypt matching react-native-keystore's commit()
        val masterKey = getMasterKey(context)
        if (masterKey != null) {
            val encryptedPayload = encryptData(masterKey, base64urlJson)
            mmkv.encode(credential.credentialId, encryptedPayload)
        } else {
            Log.w(CredentialRepository.TAG, "Master key not available for encrypting credential, saving encoded only")
            mmkv.encode(credential.credentialId, base64urlJson)
        }
    }

    override fun getAllCredentials(context: Context): List<Credential> {
        val mmkv = getPasskeysMMKV(context)
        val allKeys = mmkv.allKeys() ?: return emptyList()
        val credentials = mutableListOf<Credential>()
        
        val masterKey = getMasterKey(context) ?: return emptyList()

        for (key in allKeys) {
            val payload = mmkv.decodeString(key) ?: continue
            try {
                val json = decodeKeyData(payload, masterKey)
                // Basic validation to ensure it's a credential
                if (json.has("id") && (json.has("origin") || json.has("metadata"))) {
                    val metadata = json.optJSONObject("metadata")
                    credentials.add(Credential(
                        credentialId = json.getString("id"),
                        origin = metadata?.optString("origin") ?: json.optString("origin", ""),
                        userHandle = metadata?.optString("userHandle") ?: json.optString("userHandle", ""),
                        userId = metadata?.optString("userId") ?: json.optString("userId", ""),
                        publicKey = AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("publicKey")), AndroidBase64.DEFAULT),
                        privateKey = AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("privateKey")), AndroidBase64.DEFAULT),
                        count = metadata?.optInt("count") ?: json.optInt("count", 0)
                    ))
                }
            } catch (e: Exception) {
                // Not a JSON or not a credential or decryption failed, skip
                continue
            }
        }
        return credentials
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

    override fun getCredential(context: Context, credentialId: ByteArray): Credential? {
        val id = AndroidBase64.encodeToString(credentialId, AndroidBase64.DEFAULT).trim()
        val mmkv = getPasskeysMMKV(context)
        val payload = mmkv.decodeString(id) ?: return null
        val masterKey = getMasterKey(context) ?: return null
        return try {
            val json = decodeKeyData(payload, masterKey)
            val metadata = json.optJSONObject("metadata")
            Credential(
                credentialId = json.getString("id"),
                origin = metadata?.optString("origin") ?: json.optString("origin", ""),
                userHandle = metadata?.optString("userHandle") ?: json.optString("userHandle", ""),
                userId = metadata?.optString("userId") ?: json.optString("userId", ""),
                publicKey = AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("publicKey")), AndroidBase64.DEFAULT),
                privateKey = AndroidBase64.encodeToString(jsonArrayToByteArray(json.getJSONArray("privateKey")), AndroidBase64.DEFAULT),
                count = metadata?.optInt("count") ?: json.optInt("count", 0)
            )
        } catch (e: Exception) {
            null
        }
    }

    override fun getCredentialByOrigin(context: Context, origin: String): Credential? {
        return getAllCredentials(context).find { it.origin == origin }
    }

    fun getKeyPairFromCredential(credential: Credential): KeyPair? {
        val publicKeyBytes = AndroidBase64.decode(credential.publicKey, AndroidBase64.DEFAULT)
        val privateKeyBytes = AndroidBase64.decode(credential.privateKey, AndroidBase64.DEFAULT)
        val factory = KeyFactory.getInstance("EC")
        val publicKey = factory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
        val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
        return KeyPair(publicKey, privateKey)
    }

    override fun getKeyPair(context: Context, credentialId: ByteArray): KeyPair? {
        val credential = getCredential(context, credentialId)
        return credential?.let { getKeyPairFromCredential(it) }
    }

    override fun createDeterministicKeyPair(
        context: Context,
        origin: String,
        userHandle: String
    ): KeyPair {
        val masterKey = getMasterKey(context) ?: throw IllegalStateException("Master key not found in Keystore. Ensure you have called setMasterKey(key) from JavaScript.")
        
        val mmkvAutofill = getAutofillMMKV(context)
        val hdRootKeyId = mmkvAutofill.decodeString(CredentialRepository.HD_ROOT_KEY_ID_KEY) ?: throw IllegalStateException("HD Root Key ID not found. Ensure you have called setHdRootKeyId(id) from JavaScript.")
        
        val mmkvKeystore = getPasskeysMMKV(context)
        val hdRootKeyPayload = mmkvKeystore.decodeString(hdRootKeyId) ?: throw IllegalStateException("HD Root Key not found in keystore for ID: $hdRootKeyId")
        
        val hdRootKeyData = decodeKeyData(hdRootKeyPayload, masterKey)
        
        // In react-native-keystore, the private key/seed are stored as arrays of numbers in JSON
        // due to how JSON.stringify handles Uint8Array.
        // Our decode method in decryptHdRootKey might have already handled it if it matched react-native-keystore's decode.
        
        val seedArray = hdRootKeyData.optJSONArray("seed") ?: hdRootKeyData.optJSONArray("privateKey")
        val derivedParentSecret = if (seedArray != null) {
            val bytes = ByteArray(seedArray.length())
            for (i in 0 until seedArray.length()) {
                bytes[i] = seedArray.getInt(i).toByte()
            }
            bytes
        } else {
            val seed = (if (hdRootKeyData.has("seed")) hdRootKeyData.getString("seed") else null)
                ?: (if (hdRootKeyData.has("privateKey")) hdRootKeyData.getString("privateKey") else null)
                ?: throw IllegalStateException("HD Root Key does not contain a seed or privateKey")
            
            if (seed.startsWith("0x")) {
                hexToBytes(seed.substring(2))
            } else {
                // It might be base64url encoded or just hex
                try {
                    hexToBytes(seed)
                } catch (e: Exception) {
                    AndroidBase64.decode(seed, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP)
                }
            }
        }

        return dP256.genDomainSpecificKeypair(derivedParentSecret, origin, userHandle.lowercase())
    }

    private fun encryptData(key: ByteArray, data: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        
        val keySpec = javax.crypto.spec.SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        
        val encryptedWithTag = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        
        // In GCM mode, the tag is at the end of the ciphertext returned by doFinal
        val tagSize = 16
        val contentSize = encryptedWithTag.size - tagSize
        val content = encryptedWithTag.sliceArray(0 until contentSize)
        val tag = encryptedWithTag.sliceArray(contentSize until encryptedWithTag.size)
        
        val json = JSONObject()
        // Use NO_WRAP consistently to avoid newlines, but ensure standard base64 for compatibility
        json.put("iv", AndroidBase64.encodeToString(iv, AndroidBase64.NO_WRAP))
        json.put("tag", AndroidBase64.encodeToString(tag, AndroidBase64.NO_WRAP))
        json.put("content", AndroidBase64.encodeToString(content, AndroidBase64.NO_WRAP))
        
        return json.toString()
    }

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

    override fun saveMasterKey(context: Context, secret: String) {
        
        // Convert hex string to bytes if it's a valid hex string of appropriate length
        val keyBytes = try {
            if ((secret.length == 64 || secret.length == 32) && secret.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                hexToBytes(secret.trim())
            } else {
                secret.toByteArray(Charsets.UTF_8)
            }
        } catch (e: Exception) {
            secret.toByteArray(Charsets.UTF_8)
        }

        // Store in our separate Keychain for persistence
        try {
            encryptToKeychain(context, keyBytes)
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Failed to save master key to Keychain", e)
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
        return getMasterKey(context) != null
    }

    override fun saveHdRootKeyId(context: Context, id: String) {
        val mmkv = getAutofillMMKV(context)
        mmkv.encode(CredentialRepository.HD_ROOT_KEY_ID_KEY, id)
    }

    override fun getHdRootKeyId(context: Context): String? {
        val mmkv = getAutofillMMKV(context)
        return mmkv.decodeString(CredentialRepository.HD_ROOT_KEY_ID_KEY)
    }

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
            
            val mmkvPasskeys = getPasskeysMMKV(context)
            mmkvPasskeys.clearAll()

        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Error clearing credentials and secrets", e)
        }
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
        return try {
            info.origin ?: appInfoToOrigin(info)
        } catch (e: NoSuchMethodError) {
            appInfoToOrigin(info)
        } catch (e: Exception) {
            appInfoToOrigin(info)
        }
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun appInfoToOrigin(info: CallingAppInfo): String {
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val certHash = md.digest(cert)
        return "android:apk-key-hash:${AndroidBase64.encodeToString(certHash, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)}"
    }
}