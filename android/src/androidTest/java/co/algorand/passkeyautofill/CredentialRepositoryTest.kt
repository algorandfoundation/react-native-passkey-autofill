package co.algorand.passkeyautofill

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.KeystoreRecords
import co.algorand.passkeyautofill.credentials.MasterKeyUnavailableException
import com.tencent.mmkv.MMKV
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CredentialRepositoryTest {

    private lateinit var repository: CredentialRepository
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() {
        repository = CredentialRepository()
        repository.clearCredentials(context)
        forgetMasterKey()
    }

    /** Removes the stored master key so the process is in its "wallet has not called setMasterKey" state. */
    private fun forgetMasterKey() {
        context.getSharedPreferences(CredentialRepository.KEYCHAIN_STORAGE_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    private fun passkeysMMKV(): MMKV {
        MMKV.initialize(context)
        return MMKV.mmkvWithID(CredentialRepository.PASSKEYS_MMKV_ID, MMKV.MULTI_PROCESS_MODE)
    }

    // --- Fail-closed master key (F-2026-18982) ------------------------------

    /**
     * `getCredential` takes the RAW credential id and base64-encodes it before
     * the MMKV lookup, while `saveCredential` stores under the base64 id the
     * create flow hands it. Tests therefore plant/save under [base64Id] and
     * read back with the raw bytes, exactly like the activity does.
     */
    private fun base64Id(rawId: ByteArray): String =
        android.util.Base64.encodeToString(rawId, android.util.Base64.NO_WRAP)

    @Test
    fun saveCredentialWithoutAMasterKeyThrowsAndWritesNothing() {
        assertFalse(repository.isMasterKeyAvailable(context))
        val rawId = "no-master-key".toByteArray()
        val credential = Credential(
            credentialId = base64Id(rawId),
            origin = "https://example.com",
            userHandle = "user-handle",
            userId = "user-id",
            publicKey = "YTM0",
            privateKey = "c2VjcmV0", // "secret"
            count = 0
        )

        try {
            repository.saveCredential(context, credential)
            fail("saveCredential must refuse to write without a master key")
        } catch (e: MasterKeyUnavailableException) {
            // expected
        }

        assertFalse(passkeysMMKV().containsKey(base64Id(rawId)))
        assertNull(repository.getCredential(context, rawId))
    }

    @Test
    fun saveMasterKeyRejectsAWrongLengthKeyAndKeepsTheOldOne() {
        val good = ByteArray(KeystoreRecords.MASTER_KEY_LENGTH) { it.toByte() }
        repository.saveMasterKey(context, good)
        assertTrue(repository.isMasterKeyAvailable(context))

        try {
            repository.saveMasterKey(context, ByteArray(16) { 1 })
            fail("a 16-byte master key must be rejected")
        } catch (e: IllegalArgumentException) {
            // expected
        }

        // The previous, valid key is untouched.
        assertTrue(repository.isMasterKeyAvailable(context))
    }

    @Test
    fun aSavedCredentialIsSealedInTheStore() {
        repository.saveMasterKey(context, ByteArray(32) { it.toByte() })
        val credential = Credential(
            credentialId = "sealed-credential",
            origin = "https://example.com",
            userHandle = "user-handle",
            userId = "user-id",
            publicKey = "YTM0",
            privateKey = "c2VjcmV0",
            count = 0
        )
        repository.saveCredential(context, credential)

        val stored = passkeysMMKV().decodeString("sealed-credential")
        assertNotNull(stored)
        assertTrue(KeystoreRecords.isSealedEnvelope(stored!!))
        assertFalse(stored.contains("privateKey"))
    }

    @Test
    fun saveMasterKeyResealsRecordsAnOlderBuildLeftUnsealed() {
        // Plant exactly what the pre-fix fallback wrote: bare base64url(JSON)
        // carrying the private key, keyed by the (base64) credential id.
        val rawId = "left-unsealed".toByteArray()
        val id = base64Id(rawId)
        val keyData = JSONObject()
            .put("id", id)
            .put("type", "hd-derived-p256")
            .put("privateKey", JSONArray(listOf(1, 2, 3)))
            .put("publicKey", JSONArray(listOf(4, 5, 6)))
            .put("metadata", JSONObject().put("origin", "https://legacy.example").put("userHandle", "u").put("userId", "id"))
        val unsealed = android.util.Base64.encodeToString(
            keyData.toString().toByteArray(Charsets.UTF_8),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP,
        )
        passkeysMMKV().encode(id, unsealed)

        val masterKey = ByteArray(32) { (it * 3).toByte() }
        repository.saveMasterKey(context, masterKey)

        val stored = passkeysMMKV().decodeString(id)!!
        assertTrue(KeystoreRecords.isSealedEnvelope(stored))
        assertFalse(stored.contains("privateKey"))
        // And the record is still readable through the normal path.
        val reopened = KeystoreRecords.decodeLegacyRecord(stored, masterKey)
        assertEquals(id, reopened.getString("id"))
        assertEquals("https://legacy.example", repository.getCredential(context, rawId)?.origin)
    }

    // --- Metadata-only enumeration (F-2026-19098) -----------------------------

    @Test
    fun enumerationAndMetadataLookupsNeverMaterialiseThePrivateKey() {
        repository.saveMasterKey(context, ByteArray(32) { it.toByte() })
        val rawId = "metadata-only".toByteArray()
        val privateKey = android.util.Base64.encodeToString(ByteArray(32) { (it + 1).toByte() }, android.util.Base64.NO_WRAP)
        repository.saveCredential(
            context,
            Credential(
                credentialId = base64Id(rawId),
                origin = "https://example.com",
                userHandle = "user-handle",
                userId = "dXNlci1pZA",
                publicKey = "YTM0",
                privateKey = privateKey,
                count = 0
            ),
        )

        val listed = repository.getAllCredentials(context).single { it.credentialId == base64Id(rawId) }
        assertEquals("", listed.privateKey)
        assertEquals("https://example.com", listed.origin)
        assertEquals("dXNlci1pZA", listed.userId)

        val metadata = repository.getCredentialMetadata(context, rawId)!!
        assertEquals("", metadata.privateKey)
        assertEquals(listed, metadata)

        // Only the post-selection read carries the material.
        assertEquals(privateKey, repository.getCredential(context, rawId)!!.privateKey)
    }

    @Test
    fun testSaveAndGetCredential() {
        val rawId = "test-credential-id".toByteArray()
        val base64Id = android.util.Base64.encodeToString(rawId, android.util.Base64.DEFAULT).trim()
        val credential = Credential(
            credentialId = base64Id,
            origin = "https://example.com",
            userHandle = "user-handle",
            userId = "user-id",
            publicKey = "YTM0", // valid base64
            privateKey = "YTM0", // valid base64
            count = 0
        )

        // We need a master key to save credentials in the current implementation
        repository.saveMasterKey(context, ByteArray(32) { it.toByte() })
        
        repository.saveCredential(context, credential)

        val retrieved = repository.getCredential(context, rawId)
        assertNotNull(retrieved)
        assertEquals(credential.origin, retrieved?.origin)
        assertEquals(credential.userHandle, retrieved?.userHandle)
    }

    @Test
    fun testGetAllCredentials() {
        repository.saveMasterKey(context, ByteArray(32) { it.toByte() })
        
        val credential1 = Credential(
            credentialId = "id1",
            origin = "origin1",
            userHandle = "handle1",
            userId = "user1",
            publicKey = "YTM0",
            privateKey = "YTM0",
            count = 0
        )
        val credential2 = Credential(
            credentialId = "id2",
            origin = "origin2",
            userHandle = "handle2",
            userId = "user2",
            publicKey = "YTM0",
            privateKey = "YTM0",
            count = 0
        )

        repository.saveCredential(context, credential1)
        repository.saveCredential(context, credential2)

        val all = repository.getAllCredentials(context)
        assertEquals(2, all.size)
    }
}
