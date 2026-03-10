package co.algorand.passkeyautofill.credentials

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.tencent.mmkv.MMKV
import foundation.algorand.deterministicP256.DeterministicP256
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import android.util.Base64 as AndroidBase64

private val Context.keychainDataStore by preferencesDataStore(name = "RN_KEYCHAIN")

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

    companion object {
        const val TAG = "CredentialRepository"
        const val MMKV_ID = "keystore"
        const val CREDENTIALS_KEY = "credentials"
        const val PARENT_SECRET_KEY = "parent_secret"
        const val GET_PASSKEY_ACTION_KEY = "get_passkey_action"
        const val CREATE_PASSKEY_ACTION_KEY = "create_passkey_action"
        const val MASTER_KEY_SERVICE = "app-secret"
        const val KEYCHAIN_STORAGE_NAME = "RN_KEYCHAIN"
    }
}

fun CredentialRepository(): CredentialRepository = Repository()

class Repository() : CredentialRepository {
    override var keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    private var dP256: DeterministicP256 = DeterministicP256()

    init {
        keyStore.load(null)
    }

    private fun getMMKV(context: Context): MMKV {
        MMKV.initialize(context)
        return MMKV.mmkvWithID(CredentialRepository.MMKV_ID)
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun saveCredential(context: Context, credential: Credential) {
        Log.d(CredentialRepository.TAG, "saveCredential($credential)")
        val mmkv = getMMKV(context)
        val credentials = getAllCredentials(context).toMutableList()
        credentials.removeAll { it.credentialId == credential.credentialId }
        credentials.add(credential)
        
        val jsonArray = JSONArray()
        credentials.forEach {
            val json = JSONObject()
            json.put("credentialId", it.credentialId)
            json.put("origin", it.origin)
            json.put("userHandle", it.userHandle)
            json.put("userId", it.userId)
            json.put("publicKey", it.publicKey)
            json.put("privateKey", it.privateKey)
            json.put("count", it.count)
            jsonArray.put(json)
        }
        mmkv.encode(CredentialRepository.CREDENTIALS_KEY, jsonArray.toString())
    }

    override fun getAllCredentials(context: Context): List<Credential> {
        val mmkv = getMMKV(context)
        val jsonString = mmkv.decodeString(CredentialRepository.CREDENTIALS_KEY) ?: return emptyList()
        val jsonArray = JSONArray(jsonString)
        val credentials = mutableListOf<Credential>()
        for (i in 0 until jsonArray.length()) {
            val json = jsonArray.getJSONObject(i)
            credentials.add(Credential(
                credentialId = json.getString("credentialId"),
                origin = json.getString("origin"),
                userHandle = json.getString("userHandle"),
                userId = json.getString("userId"),
                publicKey = json.getString("publicKey"),
                privateKey = json.getString("privateKey"),
                count = json.getInt("count")
            ))
        }
        return credentials
    }

    override fun generateCredentialId(keyPair: KeyPair): ByteArray {
        Log.d(CredentialRepository.TAG, "generateCredentialId()")
        val publicKeyBytes = keyPair.public.encoded
        val messageDigest = MessageDigest.getInstance("SHA-256")
        return messageDigest.digest(publicKeyBytes)
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun getCredential(context: Context, credentialId: ByteArray): Credential? {
        val id = Base64.encode(credentialId)
        return getAllCredentials(context).find { it.credentialId == id }
    }

    override fun getCredentialByOrigin(context: Context, origin: String): Credential? {
        return getAllCredentials(context).find { it.origin == origin }
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun getKeyPairFromCredential(credential: Credential): KeyPair? {
        val publicKeyBytes = Base64.decode(credential.publicKey)
        val privateKeyBytes = Base64.decode(credential.privateKey)
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
        Log.d(CredentialRepository.TAG, "createDeterministicKeyPair($context, $origin, ${userHandle.lowercase()})")

        val mmkv = getMMKV(context)
        val parentSecretHex = mmkv.decodeString(CredentialRepository.PARENT_SECRET_KEY)
        Log.d(CredentialRepository.TAG, "createDeterministicKeyPair: parentSecretHex=${parentSecretHex != null}")
        val derivedParentSecret = if (parentSecretHex != null) {
            hexToBytes(parentSecretHex)
        } else {
            val fromKeychain = getMasterKeyFromKeychain(context)
            if (fromKeychain != null) {
                // Persist to MMKV for future use by the service
                mmkv.encode(CredentialRepository.PARENT_SECRET_KEY, bytesToHex(fromKeychain))
                Log.d(CredentialRepository.TAG, "Persisted master key from Keychain to MMKV")
            }
            fromKeychain ?: throw IllegalStateException("Parent secret not found in MMKV or Keychain. Ensure you have called setParentSecret(key) from JavaScript or that react-native-keychain is correctly configured.")
        }

        return dP256.genDomainSpecificKeypair(derivedParentSecret, origin, userHandle.lowercase())
    }

    override fun isMasterKeyAvailable(context: Context): Boolean {
        val mmkv = getMMKV(context)
        if (mmkv.decodeString(CredentialRepository.PARENT_SECRET_KEY) != null) return true
        val fromKeychain = getMasterKeyFromKeychain(context)
        if (fromKeychain != null) {
            // Persist to MMKV for future use by the service
            mmkv.encode(CredentialRepository.PARENT_SECRET_KEY, bytesToHex(fromKeychain))
            Log.d(CredentialRepository.TAG, "Persisted master key from Keychain to MMKV during availability check")
            return true
        }
        return false
    }

    private fun getMasterKeyFromKeychain(context: Context): ByteArray? {
        val service = CredentialRepository.MASTER_KEY_SERVICE
        val keychainData = CredentialRepository.KEYCHAIN_STORAGE_NAME
        
        Log.d(CredentialRepository.TAG, "Attempting to retrieve master key from Keychain (service: $service, storage: $keychainData)")

        // 1. Try reading from SharedPreferences (Legacy/Fallback)
        val prefs = context.getSharedPreferences(keychainData, Context.MODE_PRIVATE)
        var encryptedPasswordBase64 = prefs.getString("$service:p", null)
        var cipherName = prefs.getString("$service:c", null)
        
        Log.d(CredentialRepository.TAG, "SharedPreferences: encryptedPasswordBase64=${encryptedPasswordBase64 != null}, cipherName=$cipherName")

        // 2. Try reading from DataStore if not found in SharedPreferences
        if (encryptedPasswordBase64 == null) {
            try {
                Log.d(CredentialRepository.TAG, "Checking DataStore for $service")
                // DataStore is async, use runBlocking to fetch it synchronously
                val preferences = runBlocking { 
                    context.keychainDataStore.data.first() 
                }
                encryptedPasswordBase64 = preferences[stringPreferencesKey("$service:p")]
                cipherName = preferences[stringPreferencesKey("$service:c")]
                Log.d(CredentialRepository.TAG, "DataStore: encryptedPasswordBase64=${encryptedPasswordBase64 != null}, cipherName=$cipherName")
            } catch (e: Exception) {
                Log.e(CredentialRepository.TAG, "Error reading from DataStore", e)
            }
        }
        
        if (encryptedPasswordBase64 == null || cipherName == null) {
            Log.d(CredentialRepository.TAG, "Master key not found in Keychain storage")
            return null
        }
        
        // 3. Decrypt using Android KeyStore
        try {
            if (cipherName == "KeystoreAESGCM_NoAuth" || cipherName == "KeystoreAESGCM") {
                Log.d(CredentialRepository.TAG, "Cipher $cipherName is supported, decrypting...")
                val encryptedBytes = AndroidBase64.decode(encryptedPasswordBase64, AndroidBase64.DEFAULT)
                Log.d(CredentialRepository.TAG, "Encrypted bytes length: ${encryptedBytes.size}")
                if (encryptedBytes.size < 12) {
                    Log.e(CredentialRepository.TAG, "Encrypted bytes too short (min 12 for IV)")
                    return null
                }
                
                val iv = encryptedBytes.sliceArray(0 until 12)
                val data = encryptedBytes.sliceArray(12 until encryptedBytes.size)
                
                val ks = KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                
                // Alias is the service name "app-secret"
                val key = ks.getKey(service, null)
                if (key == null) {
                    Log.e(CredentialRepository.TAG, "Key not found in Keystore for alias: $service")
                    return null
                }
                
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(128, iv)
                cipher.init(Cipher.DECRYPT_MODE, key, spec)
                
                val decryptedBytes = cipher.doFinal(data)
                val hexKey = String(decryptedBytes, Charsets.UTF_8)
                Log.d(CredentialRepository.TAG, "Successfully decrypted master key from Keychain")
                return hexToBytes(hexKey)
            } else {
                Log.w(CredentialRepository.TAG, "Unsupported cipher: $cipherName")
            }
        } catch (e: Exception) {
            Log.e(CredentialRepository.TAG, "Error decrypting master key from Keychain", e)
        }
        
        return null
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

    @OptIn(ExperimentalEncodingApi::class)
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun appInfoToOrigin(info: CallingAppInfo): String {
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val certHash = md.digest(cert)
        return "android:apk-key-hash:${Base64.UrlSafe.encode(certHash).replace("=", "")}"
    }
}