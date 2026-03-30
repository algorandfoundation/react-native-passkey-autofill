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
    private var displayOrigin: String = "unknown-origin"
    private var userHandle: String = "unknown-user"
    private var credentialIdEnc: String? = null
    private var bundleRequestJson: String? = null
    private var request: ProviderGetCredentialRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")

        if (credentialData != null) {
            credentialIdEnc = credentialData.getString("credentialId")
            userHandle = credentialData.getString("userHandle") ?: "unknown-user"
            bundleRequestJson = credentialData.getString("requestJson")
        }

        if (request != null) {
            origin = credentialRepository.getOrigin(request!!.callingAppInfo)
            displayOrigin = origin
            
            // Try to extract rpId for better display
            val rawJson = bundleRequestJson ?: (request?.credentialOptions?.get(0) as? GetPublicKeyCredentialOption)?.requestJson
            if (rawJson != null) {
                try {
                    val jsonObj = JSONObject(rawJson)
                    val pkJson = if (jsonObj.has("publicKey")) jsonObj.getJSONObject("publicKey") else jsonObj
                    val rpId = pkJson.optString("rpId")
                    if (rpId.isNotEmpty()) {
                        displayOrigin = rpId
                    }
                } catch (e: Exception) {
                    // ignore
                }
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
            text = "Use Passkey"
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, (8 * resources.displayMetrics.density).toInt())
            setTextColor(Color.BLACK)
        }
        layout.addView(title)

        val description = TextView(this).apply {
            text = "Sign in to $displayOrigin"
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
            text = userHandle
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
        }
        userInfoContainer.addView(userValue)
        layout.addView(userInfoContainer)

        val confirmButton = Button(this).apply {
            text = "Sign In"
            setOnClickListener {
                handleAssertion()
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
    private fun handleAssertion() {
        try {
            val req = request ?: throw IllegalStateException("No request found")
            
            // Prefer using the request JSON from the bundle if available, as it's specifically for this entry
            val rawRequestJson = bundleRequestJson ?: run {
                val option = req.credentialOptions[0] as GetPublicKeyCredentialOption
                option.requestJson
            }
            
            val requestJson = JSONObject(rawRequestJson)
            val passkeyReqJson = if (requestJson.has("publicKey")) {
                requestJson.getJSONObject("publicKey").toString()
            } else {
                rawRequestJson
            }
            val requestOptions = try {
                PublicKeyCredentialRequestOptions(passkeyReqJson)
            } catch (e: org.json.JSONException) {
                Log.e(TAG, "Invalid passkey request JSON: $passkeyReqJson")
                throw e
            }

            val credId = AndroidBase64.decode(credentialIdEnc!!, AndroidBase64.DEFAULT)

            val passkeyRequestJsonObj = JSONObject(passkeyReqJson)
            val challenge = if (passkeyRequestJsonObj.has("challenge")) {
                passkeyRequestJsonObj.getString("challenge")
            } else {
                throw org.json.JSONException("No value for challenge in requestJson: $passkeyReqJson")
            }
            val sanitizedOrigin = origin.replace(Regex("/$"), "")

            // Look for system-provided clientDataHash (e.g. from Chrome)
            val systemClientDataHash = run {
                val option = req.credentialOptions.find { opt ->
                    opt is GetPublicKeyCredentialOption && (opt.requestJson == rawRequestJson || 
                        try { JSONObject(opt.requestJson).toString() == JSONObject(rawRequestJson!!).toString() } catch(e: Exception) { false })
                } as? GetPublicKeyCredentialOption
                option?.requestData?.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
            }

            val clientDataJSONString = if (sanitizedOrigin.startsWith("https://") || sanitizedOrigin.startsWith("http://")) {
                // Compact JSON for web origins to match browser hashing (no spaces, specific order)
                "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$sanitizedOrigin\",\"crossOrigin\":false}"
            } else {
                val json = JSONObject()
                json.put("type", "webauthn.get")
                json.put("challenge", challenge)
                json.put("origin", sanitizedOrigin)
                json.put("crossOrigin", false)
                if (sanitizedOrigin.startsWith("android:apk-key-hash:")) {
                    json.put("androidPackageName", req.callingAppInfo.packageName)
                }
                json.toString()
            }

            val clientDataHash = systemClientDataHash ?: MessageDigest.getInstance("SHA-256").digest(clientDataJSONString.toByteArray(Charsets.UTF_8))

            val dbCred = credentialRepository.getCredential(this, credId)
                ?: throw IllegalStateException("Credential not found")

            val response = AuthenticatorAssertionResponse(
                requestOptions = requestOptions,
                credentialId = credId,
                origin = sanitizedOrigin,
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

            // Manual addition of clientDataJSON and signature to the response JSON
            val clientDataJSONb64 = AndroidBase64.encodeToString(clientDataJSONString.toByteArray(), AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)
            val signatureb64 = AndroidBase64.encodeToString(response.signature, AndroidBase64.URL_SAFE or AndroidBase64.NO_WRAP or AndroidBase64.NO_PADDING)

            val fullJson = JSONObject(fidoCredential.json())
            val respJson = fullJson.getJSONObject("response")
            respJson.put("clientDataJSON", clientDataJSONb64)
            respJson.put("signature", signatureb64)

            // Add clientExtensionResults as seen in the example
            val clientExtensionResults = JSONObject()
            val credProps = JSONObject()
            credProps.put("rk", true)
            clientExtensionResults.put("credProps", credProps)
            fullJson.put("clientExtensionResults", clientExtensionResults)

            val credentialJson = fullJson.toString()

            val resultIntent = Intent()
            val passkeyCredential = PublicKeyCredential(credentialJson)

            PendingIntentHandler.setGetCredentialResponse(
                resultIntent,
                GetCredentialResponse(passkeyCredential)
            )

            setResult(Activity.RESULT_OK, resultIntent)
            ReactNativePasskeyAutofillModule.instance?.sendEvent("onPasskeyAuthenticated", Bundle().apply {
                putBoolean("success", true)
            })
        } catch (e: Exception) {
            Log.e(TAG, "Error during passkey assertion", e)
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }

}
