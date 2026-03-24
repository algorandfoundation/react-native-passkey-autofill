package co.algorand.passkeyautofill

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import co.algorand.passkeyautofill.credentials.Credential
import co.algorand.passkeyautofill.credentials.CredentialRepository
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
        repository.saveMasterKey(context, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        
        repository.saveCredential(context, credential)

        val retrieved = repository.getCredential(context, rawId)
        assertNotNull(retrieved)
        assertEquals(credential.origin, retrieved?.origin)
        assertEquals(credential.userHandle, retrieved?.userHandle)
    }

    @Test
    fun testGetAllCredentials() {
        repository.saveMasterKey(context, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        
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
