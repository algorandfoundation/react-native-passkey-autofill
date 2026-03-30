package co.algorand.passkeyautofill

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
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
import android.util.Base64 as AndroidBase64
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CreatePasskeyActivity : AppCompatActivity() {
    private val credentialRepository = CredentialRepository()

    companion object {
        const val TAG = "CreatePasskeyActivity"
    }

    private var origin: String = "unknown-origin" // Derivation origin (rpId or hash)
    private var displayOrigin: String = "unknown-origin"
    private var userHandle: String = "unknown-user"
    private var userName: String = "User"
    private var userId: String = "unknown-id"
    private var bundleRequestJson: String? = null
    private var request: ProviderCreateCredentialRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")
        
        if (credentialData != null) {
            bundleRequestJson = credentialData.getString("requestJson")
        }

        if (request != null) {
            try {
                val systemOrigin = credentialRepository.getOrigin(request!!.callingAppInfo)
                origin = systemOrigin
                displayOrigin = systemOrigin

                val publicKeyRequest = request!!.callingRequest as CreatePublicKeyCredentialRequest
                val rawJson = bundleRequestJson ?: publicKeyRequest.requestJson
                val requestJson = JSONObject(rawJson)
                val pkJson = if (requestJson.has("publicKey")) requestJson.getJSONObject("publicKey") else requestJson
                
                // Use RP ID as origin for derivation if available, otherwise fallback to app signature
                val rpId = pkJson.optJSONObject("rp")?.optString("id")
                if (rpId != null && rpId.isNotEmpty()) {
                    origin = rpId
                    displayOrigin = rpId
                }
                
                userHandle = pkJson.optJSONObject("user")?.optString("name") ?: "unknown-user"
                userName = pkJson.optJSONObject("user")?.optString("displayName") ?: userHandle
                userId = pkJson.optJSONObject("user")?.optString("id") ?: "unknown-id"
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing request", e)
            }
        }

        // Improved UI
        val layout = LinearLayout(this).apply {
            val padding = (32 * resources.displayMetrics.density).toInt()
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(Color.WHITE)
        }
        
        // Header with App Icon and Provider Label
        try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            val appIcon = packageManager.getApplicationIcon(appInfo)
            val appLabel = packageManager.getApplicationLabel(appInfo)

            val density = resources.displayMetrics.density
            val iconSize = (48 * density).toInt()
            val iconMargin = (12 * density).toInt()
            val headerPadding = (40 * density).toInt()

            val header = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, headerPadding)
            }

            val iconView = ImageView(this).apply {
                setImageDrawable(appIcon)
                layoutParams = LinearLayout.LayoutParams(iconSize, iconSize).apply {
                    marginEnd = iconMargin
                }
            }
            header.addView(iconView)

            val providerLabel = TextView(this).apply {
                text = appLabel
                textSize = 16f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.DKGRAY)
            }
            header.addView(providerLabel)
            layout.addView(header)
        } catch (e: Exception) {
            // Fallback if app info cannot be loaded
        }

        val title = TextView(this).apply {
            text = "Create Passkey"
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            setTextColor(Color.BLACK)
        }
        layout.addView(title)

        val description = TextView(this).apply {
            text = "Create a new passkey for $displayOrigin"
            textSize = 16f
            setPadding(0, 0, 0, (40 * resources.displayMetrics.density).toInt())
            gravity = Gravity.CENTER_HORIZONTAL
            setTextColor(Color.GRAY)
        }
        layout.addView(description)

        val userInfoContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, (50 * resources.displayMetrics.density).toInt())
            gravity = Gravity.CENTER_HORIZONTAL
        }

        val userLabel = TextView(this).apply {
            text = "ACCOUNT"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.GRAY)
            setPadding(0, 0, 0, (4 * resources.displayMetrics.density).toInt())
        }
        userInfoContainer.addView(userLabel)

        val userValue = TextView(this).apply {
            text = userName
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
        }
        userInfoContainer.addView(userValue)
        
        if (userHandle != userName) {
            val handleValue = TextView(this).apply {
                text = userHandle
                textSize = 14f
                setTextColor(Color.GRAY)
            }
            userInfoContainer.addView(handleValue)
        }
        layout.addView(userInfoContainer)
        
        val confirmButton = Button(this).apply {
            text = "Create Passkey"
            setOnClickListener {
                handleCreation()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            }
        }
        layout.addView(confirmButton)

        val cancelButton = Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = "Cancel"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        layout.addView(cancelButton)

        setContentView(layout)
        
        // Ensure the activity is focusable and can receive touches
        layout.isFocusable = true
        layout.isFocusableInTouchMode = true
        layout.requestFocus()
    }

    @SuppressLint("RestrictedApi")
    private fun handleCreation() {
        try {
            val req = request ?: throw IllegalStateException("No request found")
            
            // Prefer using the request JSON from the bundle if available
            val rawRequestJson = bundleRequestJson ?: run {
                val publicKeyRequest = req.callingRequest as CreatePublicKeyCredentialRequest
                publicKeyRequest.requestJson
            }

            val requestJson = JSONObject(rawRequestJson)
            val passkeyReqJson = if (requestJson.has("publicKey")) {
                requestJson.getJSONObject("publicKey").toString()
            } else {
                rawRequestJson
            }
            val requestOptions = try {
                PublicKeyCredentialCreationOptions(passkeyReqJson)
            } catch (e: org.json.JSONException) {
                Log.e(TAG, "Invalid passkey creation request JSON: $passkeyReqJson")
                throw e
            }

            val keyPair: KeyPair = credentialRepository.createDeterministicKeyPair(this, origin, userHandle)
            val credentialId = credentialRepository.generateCredentialId(keyPair)
            val credentialIdBase64 = AndroidBase64.encodeToString(credentialId, AndroidBase64.NO_WRAP)

            val credential = Credential(
                credentialId = credentialIdBase64,
                origin = origin,
                userHandle = userHandle,
                userId = userId,
                publicKey = AndroidBase64.encodeToString(keyPair.public.encoded, AndroidBase64.NO_WRAP),
                privateKey = AndroidBase64.encodeToString(keyPair.private.encoded, AndroidBase64.NO_WRAP),
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
            val fullJson = JSONObject(fidoCredential.json())
            val respJson = fullJson.getJSONObject("response")

            // Ensure compact clientDataJSON for registration too
            val sanitizedOrigin = credentialRepository.getOrigin(req.callingAppInfo).replace(Regex("/$"), "")
            val challenge = if (requestJson.has("publicKey")) {
                requestJson.getJSONObject("publicKey").getString("challenge")
            } else {
                requestJson.getString("challenge")
            }

            val clientDataJSONString = if (sanitizedOrigin.startsWith("https://") || sanitizedOrigin.startsWith("http://")) {
                "{\"type\":\"webauthn.create\",\"challenge\":\"$challenge\",\"origin\":\"$sanitizedOrigin\",\"crossOrigin\":false}"
            } else {
                val json = JSONObject()
                json.put("type", "webauthn.create")
                json.put("challenge", challenge)
                json.put("origin", sanitizedOrigin)
                json.put("crossOrigin", false)
                if (sanitizedOrigin.startsWith("android:apk-key-hash:")) {
                    json.put("androidPackageName", req.callingAppInfo.packageName)
                }
                json.toString()
            }
            val clientDataJSONb64 = AndroidBase64.encodeToString(clientDataJSONString.toByteArray(), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)
            respJson.put("clientDataJSON", clientDataJSONb64)

            val createResponse = CreatePublicKeyCredentialResponse(fullJson.toString())
            
            PendingIntentHandler.setCreateCredentialResponse(
                resultIntent,
                createResponse
            )
            
            setResult(Activity.RESULT_OK, resultIntent)
            ReactNativePasskeyAutofillModule.instance?.sendEvent("onPasskeyAdded", Bundle().apply {
                putBoolean("success", true)
            })
        } catch (e: Exception) {
            Log.e(TAG, "Error during passkey creation", e)
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }
}
