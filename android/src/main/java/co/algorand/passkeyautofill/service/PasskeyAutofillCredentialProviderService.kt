package co.algorand.passkeyautofill.service

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.Bundle
import android.os.OutcomeReceiver
import android.os.CancellationSignal
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.Credential
import com.tencent.mmkv.MMKV
import kotlinx.coroutines.*
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyAutofillCredentialProviderService: CredentialProviderService() {
    private val credentialRepository = CredentialRepository()
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)

    companion object {
        const val TAG = "PasskeyAutofillCredentialProviderService"
        //TODO: App Lock Intents
        const val GET_PASSKEY_INTENT = 1
        const val CREATE_PASSKEY_INTENT = 2
        const val DEFAULT_GET_PASSKEY_ACTION = "co.algorand.passkeyautofill.GET_PASSKEY"
        const val DEFAULT_CREATE_PASSKEY_ACTION = "co.algorand.passkeyautofill.CREATE_PASSKEY"
    }
    /**
     * Handle Create Credential Requests
     */
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        val response: BeginCreateCredentialResponse? = processCreateCredentialRequest(request)
        if (response != null) {
            callback.onResult(response)
        } else {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    /**
     * Process incoming Create Credential Requests
     */
    private fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse? {
        when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                return handleCreatePasskeyQuery(request)
            }
        }
        return null
    }

    /**
     * Create a new PassKey Entry
     *
     * This returns an Entry list for the user to interact with.
     * A PendingIntent must be configured to receive the data from the WebAuthn client
     */
    private fun handleCreatePasskeyQuery(
        request: BeginCreatePublicKeyCredentialRequest
    ): BeginCreateCredentialResponse {
        val createEntries: MutableList<CreateEntry> = mutableListOf()
        
        // Ensure we have a master key available before offering to create a passkey
        if (!credentialRepository.isMasterKeyAvailable(this)) {
            return BeginCreateCredentialResponse(createEntries)
        }

        val userJson = JSONObject(request.requestJson).optJSONObject("user")
        val name = userJson?.optString("name") ?: "New Passkey"

        val action = credentialRepository.getCreatePasskeyAction(this) ?: DEFAULT_CREATE_PASSKEY_ACTION

        val data = Bundle()
        data.putString("requestJson", request.requestJson)

        val createEntry = CreateEntry.Builder(
            name,
            createNewPendingIntent(action, CREATE_PASSKEY_INTENT, data)
        ).setIcon(Icon.createWithResource(this, android.R.drawable.ic_menu_add))
            .build()
        
        createEntries.add(createEntry)
        return BeginCreateCredentialResponse(createEntries)
    }
    /**
     * Handle Get Credential Requests
     */
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        try {
            val response = processGetCredentialRequest(request)
            callback.onResult(response)
        } catch (e: Exception) {
            Log.e(TAG, "Error in onBeginGetCredentialRequest", e)
            callback.onError(GetCredentialUnknownException())
        }
    }

    /**
     * Fake a list of available PublicKeyCredential Entries
     */
    private fun processGetCredentialRequest(request: BeginGetCredentialRequest): BeginGetCredentialResponse{
        // Ensure we have a master key available. If not, we can't sign anything, so don't show entries.
        if (!credentialRepository.isMasterKeyAvailable(this)) {
            return BeginGetCredentialResponse(emptyList())
        }

        val credentials = runBlocking {
            credentialRepository.getAllCredentials(this@PasskeyAutofillCredentialProviderService)
        }

        val action = credentialRepository.getGetPasskeyAction(this) ?: DEFAULT_GET_PASSKEY_ACTION

        val entries = credentials.mapNotNull { credential ->
            try {
                // Find suitable option for this entry
                val option = request.beginGetCredentialOptions.find { opt -> 
                    if (opt !is BeginGetPublicKeyCredentialOption) return@find false
                    
                    // In a real app, we'd check if this credential's origin matches the request's origin
                    // For now, we return all credentials that match the requested type.
                    true
                } as? BeginGetPublicKeyCredentialOption

                if (option == null) {
                    return@mapNotNull null
                }

                val data = Bundle()
                data.putString("credentialId", credential.credentialId)
                data.putString("userHandle", credential.userHandle)
                data.putString("requestJson", option.requestJson)

                PublicKeyCredentialEntry.Builder(
                    this@PasskeyAutofillCredentialProviderService,
                    credential.userHandle,
                    createNewPendingIntent(action, GET_PASSKEY_INTENT, data),
                    option
                )
                    .setIcon(Icon.createWithResource(this@PasskeyAutofillCredentialProviderService, android.R.drawable.ic_lock_lock))
                    .build()
            } catch (e: Exception) {
                Log.e(TAG, "Error building PublicKeyCredentialEntry", e)
                null
            }
        }
        return BeginGetCredentialResponse(entries)
    }
    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // TODO: Implement clear credential state if needed
        callback.onResult(null)
    }

    private fun createNewPendingIntent(action: String, requestCode: Int, extra: Bundle?): PendingIntent{
        MMKV.initialize(this)
        val intent = Intent(action)
        // Set component to be explicit to this library's activities
        val componentName = when(requestCode) {
            GET_PASSKEY_INTENT -> android.content.ComponentName(packageName, "co.algorand.passkeyautofill.GetPasskeyActivity")
            CREATE_PASSKEY_INTENT -> android.content.ComponentName(packageName, "co.algorand.passkeyautofill.CreatePasskeyActivity")
            else -> null
        }
        if (componentName != null) {
            intent.component = componentName
        } else {
            intent.setPackage(packageName)
        }

        if (extra != null) {
            intent.putExtra("CREDENTIAL_DATA", extra)
        }
        
        // Add categories that might be required
        intent.addCategory(android.content.Intent.CATEGORY_DEFAULT)
        
        return PendingIntent.getActivity(
            applicationContext, requestCode,
            intent, (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }
    override fun onDestroy() {
        super.onDestroy()
        job.cancel()
    }
}