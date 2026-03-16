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
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.credentials.Credential
import java.security.KeyPair
import java.security.MessageDigest
import android.util.Base64 as AndroidBase64
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GetPasskeyActivity : AppCompatActivity() {
    private val credentialRepository = CredentialRepository()

    companion object {
        const val TAG = "GetPasskeyActivity"
    }

    private var origin: String = "unknown-origin"
    private var userHandle: String = "unknown-user"
    private var credentialIdEnc: String? = null
    private var request: ProviderGetCredentialRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")

        if (request != null && credentialData != null) {
            origin = credentialRepository.getOrigin(request!!.callingAppInfo)
            credentialIdEnc = credentialData.getString("credentialId")
            userHandle = credentialData.getString("userHandle") ?: "unknown-user"
        }

        // Simple UI
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
        }

        val title = TextView(this).apply {
            text = "Use Passkey"
            textSize = 24f
            setPadding(0, 0, 0, 50)
        }
        layout.addView(title)

        val info = TextView(this).apply {
            text = "User: $userHandle\nAt: $origin"
            setPadding(0, 0, 0, 50)
        }
        layout.addView(info)

        val confirmButton = Button(this).apply {
            text = "Sign In"
            setOnClickListener {
                handleAssertion()
            }
        }
        layout.addView(confirmButton)

        setContentView(layout)
    }

    @SuppressLint("RestrictedApi")
    private fun handleAssertion() {
        try {
            val req = request ?: throw IllegalStateException("No request found")
            val option = req.credentialOptions[0] as GetPublicKeyCredentialOption
            val requestOptions = PublicKeyCredentialRequestOptions(option.requestJson)

            val credId = AndroidBase64.decode(credentialIdEnc!!, AndroidBase64.DEFAULT)

            val requestJson = JSONObject(option.requestJson)
            val challenge = requestJson.getString("challenge")
            val sanitizedOrigin = origin.replace(Regex("/$"), "")

            val clientDataHash = option.requestData.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
                ?: MessageDigest.getInstance("SHA-256").digest(
                    "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$sanitizedOrigin\",\"crossOrigin\":false}".toByteArray(Charsets.UTF_8)
                )

            val dbCred = credentialRepository.getCredential(this, credId)
                ?: throw IllegalStateException("Credential not found")

            val response = AuthenticatorAssertionResponse(
                requestOptions = requestOptions,
                credentialId = credId,
                origin = credentialRepository.getOrigin(req.callingAppInfo),
                up = true,
                uv = true,
                be = true,
                bs = true,
                userHandle = AndroidBase64.decode(dbCred.userId, AndroidBase64.URL_SAFE),
                packageName = req.callingAppInfo.packageName,
                clientDataHash = clientDataHash
            )

            val keyPair = credentialRepository.getKeyPair(this, credId)
                ?: throw IllegalStateException("No keypair found")

            response.signature = credentialRepository.sign(keyPair, response.dataToSign())

            val fidoCredential = FidoPublicKeyCredential(
                rawId = credId,
                response = response,
                authenticatorAttachment = "platform"
            )

            // Manual addition of clientDataJSON if needed by some RPs, following reference
            val clientDataJSONb64 = getClientDataJSONb64(origin, challenge)

            val delimiter = "response\":{"
            val credentialJson = fidoCredential.json().substringBeforeLast(delimiter) + delimiter +
                    "\"clientDataJSON\":\"$clientDataJSONb64\"," +
                    fidoCredential.json().substringAfterLast(delimiter)

            val resultIntent = Intent()
            val passkeyCredential = PublicKeyCredential(credentialJson)

            PendingIntentHandler.setGetCredentialResponse(
                resultIntent,
                GetCredentialResponse(passkeyCredential)
            )

            setResult(Activity.RESULT_OK, resultIntent)
        } catch (e: Exception) {
            Log.e(TAG, "Error during passkey assertion", e)
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }

    private fun getClientDataJSONb64(origin: String, challenge: String): String {
        val sanitizedOrigin = origin.replace(Regex("/$"), "")
        val jsonString = "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$sanitizedOrigin\",\"crossOrigin\":false}"
        return AndroidBase64.encodeToString(jsonString.toByteArray(), AndroidBase64.NO_WRAP)
    }
}
