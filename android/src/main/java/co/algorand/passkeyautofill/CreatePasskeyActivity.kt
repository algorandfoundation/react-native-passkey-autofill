package co.algorand.passkeyautofill

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.Credential
import java.security.KeyPair
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CreatePasskeyActivity : AppCompatActivity() {
    private val credentialRepository = CredentialRepository()

    companion object {
        const val TAG = "CreatePasskeyActivity"
    }

    private var origin: String = "unknown-origin"
    private var userHandle: String = "unknown-user"
    private var userName: String = "User"
    private var userId: String = "unknown-id"
    private var request: ProviderCreateCredentialRequest? = null

    @OptIn(ExperimentalEncodingApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        if (request != null) {
            try {
                val publicKeyRequest = request!!.callingRequest as CreatePublicKeyCredentialRequest
                val requestJson = JSONObject(publicKeyRequest.requestJson)
                origin = credentialRepository.getOrigin(request!!.callingAppInfo)
                val userJson = requestJson.optJSONObject("user")
                userHandle = userJson?.optString("name") ?: "unknown-user"
                userName = userJson?.optString("displayName") ?: userHandle
                userId = userJson?.optString("id") ?: "unknown-id"
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing request", e)
            }
        }

        // Simple UI for demonstration
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
        }
        
        val title = TextView(this).apply {
            text = "Create New Passkey"
            textSize = 24f
            setPadding(0, 0, 0, 50)
        }
        layout.addView(title)

        val info = TextView(this).apply {
            text = "For: $userName\nAt: $origin"
            setPadding(0, 0, 0, 50)
        }
        layout.addView(info)
        
        val confirmButton = Button(this).apply {
            text = "Create Passkey"
            setOnClickListener {
                handleCreation()
            }
        }
        layout.addView(confirmButton)

        setContentView(layout)
    }

    @SuppressLint("RestrictedApi")
    @OptIn(ExperimentalEncodingApi::class)
    private fun handleCreation() {
        try {
            val req = request ?: throw IllegalStateException("No request found")
            val publicKeyRequest = req.callingRequest as CreatePublicKeyCredentialRequest
            val requestOptions = PublicKeyCredentialCreationOptions(publicKeyRequest.requestJson)

            val keyPair: KeyPair = credentialRepository.createDeterministicKeyPair(this, origin, userHandle)
            val credentialId = credentialRepository.generateCredentialId(keyPair)
            val credentialIdBase64 = Base64.encode(credentialId)

            val credential = Credential(
                credentialId = credentialIdBase64,
                origin = origin,
                userHandle = userHandle,
                userId = userId,
                publicKey = Base64.encode(keyPair.public.encoded),
                privateKey = Base64.encode(keyPair.private.encoded),
                count = 0
            )
            
            credentialRepository.saveCredential(this, credential)

            val response = AuthenticatorAttestationResponse(
                requestOptions = requestOptions,
                credentialId = credentialId,
                credentialPublicKey = credentialRepository.getPublicKeyFromKeyPair(keyPair),
                origin = credentialRepository.getOrigin(req.callingAppInfo),
                up = true,
                uv = true,
                be = true,
                bs = true,
                packageName = req.callingAppInfo.packageName
            )

            val fidoCredential = FidoPublicKeyCredential(
                rawId = credentialId,
                response = response,
                authenticatorAttachment = "platform"
            )

            val resultIntent = Intent()
            val createResponse = CreatePublicKeyCredentialResponse(fidoCredential.json())
            
            PendingIntentHandler.setCreateCredentialResponse(
                resultIntent,
                createResponse
            )
            
            setResult(Activity.RESULT_OK, resultIntent)
        } catch (e: Exception) {
            Log.e(TAG, "Error during passkey creation", e)
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }
}
