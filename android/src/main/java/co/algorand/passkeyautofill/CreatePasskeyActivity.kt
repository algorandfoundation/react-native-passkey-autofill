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
import co.algorand.passkeyautofill.utils.PasskeyUtils
import java.security.KeyPair
import android.util.Base64 as AndroidBase64
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.launch
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
    private var userVerification: String = "preferred"
    private var bundleRequestJson: String? = null
    private var request: ProviderCreateCredentialRequest? = null
    private var biometricPromptResult: Any? = null
    private var systemUnlockedCipher: javax.crypto.Cipher? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "onCreate started")
        
        request = try {
            PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving request from intent", e)
            null
        }
        Log.i(TAG, "Retrieved request: $request")
        
        // Check for system-provided biometric result (Single Tap flow)
        try {
            val biometricResult = request?.biometricPromptResult
            Log.i(TAG, "biometricResult from system: $biometricResult")
            if (biometricResult != null) {
                this.biometricPromptResult = biometricResult
                val authResult = biometricResult.authenticationResult
                Log.i(TAG, "authResult from system: $authResult (${authResult?.javaClass?.name})")
                
                // Also try to find it in the biometricResult object itself
                systemUnlockedCipher = if (authResult != null) {
                    PasskeyUtils.extractCipher(authResult)
                } else {
                    PasskeyUtils.extractCipher(biometricResult)
                }
                Log.i(TAG, "systemUnlockedCipher from system: $systemUnlockedCipher")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing biometricPromptResult", e)
        }

        val credentialData = intent.getBundleExtra("CREDENTIAL_DATA")
        
        if (credentialData != null) {
            bundleRequestJson = credentialData.getString("requestJson")
            userVerification = credentialData.getString("userVerification") ?: "preferred"
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

        // If the system already showed a biometric prompt (Single Tap), proceed automatically
        if (biometricPromptResult != null) {
            Log.d(TAG, "System already showed biometric prompt (Single Tap), proceeding automatically")
            handleCreation()
            return
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
        Log.d(TAG, "handleCreation started, userVerification=$userVerification")
        lifecycleScope.launch {
            val cipherToUse = systemUnlockedCipher ?: run {
                if (biometricPromptResult != null) {
                    try {
                        val fallback = credentialRepository.getBiometricCipherForEncryption()
                        Log.i(TAG, "Successfully obtained fallback cipher from repository (Single Tap timeout)")
                        fallback
                    } catch (e: Exception) {
                        Log.d(TAG, "Fallback cipher failed: ${e.message}")
                        null
                    }
                } else {
                    null
                }
            } ?: run {
                // Only prompt for biometrics if userVerification is "required"
                // For "preferred" and "discouraged", we can proceed without a manual biometric prompt
                if (userVerification == "required") {
                    Log.i(TAG, "userVerification is required, running manual biometrics")
                    val result = biometrics(true)
                    Log.d(TAG, "Manual biometrics result: $result")
                    if (result == null) {
                        Log.w(TAG, "Biometrics failed or was canceled")
                        finish()
                        return@launch
                    }
                    result.cryptoObject?.cipher
                } else {
                    Log.d(TAG, "userVerification is $userVerification, skipping manual biometrics")
                    null
                }
            }
            
            Log.d(TAG, "cipherToUse: $cipherToUse")
            
            var finalCipher = cipherToUse

            try {
                val req = request ?: throw IllegalStateException("No request found")
                Log.d(TAG, "Request found, origin: $origin")
            
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
            Log.d(TAG, "Passkey request JSON: $passkeyReqJson")
            val requestOptions = try {
                PublicKeyCredentialCreationOptions(passkeyReqJson)
            } catch (e: org.json.JSONException) {
                Log.e(TAG, "Invalid passkey creation request JSON: $passkeyReqJson")
                throw e
            }

            Log.d(TAG, "Creating deterministic key pair")
            val keyPair: KeyPair = credentialRepository.createDeterministicKeyPair(this@CreatePasskeyActivity, origin, userHandle)
            Log.d(TAG, "Generating credential ID")
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
            
            Log.d(TAG, "Saving credential to repository")
            try {
                credentialRepository.saveCredential(this@CreatePasskeyActivity, credential, finalCipher)
            } catch (e: Exception) {
                if (e.message?.contains("user not authenticated", ignoreCase = true) == true || 
                    e.cause?.message?.contains("user not authenticated", ignoreCase = true) == true) {
                    Log.i(TAG, "Key is locked, triggering manual biometric prompt")
                    val result = biometrics(true)
                    if (result != null) {
                        finalCipher = result.cryptoObject?.cipher
                        Log.i(TAG, "Retrying save with manual biometric cipher")
                        credentialRepository.saveCredential(this@CreatePasskeyActivity, credential, finalCipher)
                    } else {
                        throw e
                    }
                } else {
                    throw e
                }
            }

            Log.d(TAG, "Building AuthenticatorAttestationResponse")
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

            Log.d(TAG, "Building clientDataJSON, challenge: $challenge, origin: $sanitizedOrigin")
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
            Log.d(TAG, "CreatePublicKeyCredentialResponse: ${fullJson.toString()}")
            
            PendingIntentHandler.setCreateCredentialResponse(
                resultIntent,
                createResponse
            )
            
            setResult(Activity.RESULT_OK, resultIntent)
            Log.d(TAG, "Result set to OK")
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


    private suspend fun biometrics(needsCipher: Boolean): BiometricPrompt.AuthenticationResult? {
        return suspendCoroutine { continuation ->
            val biometricPrompt = BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        continuation.resume(result)
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        continuation.resume(null)
                    }
                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                    }
                }
            )
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Create Passkey")
                .setSubtitle("Authenticate to save your passkey")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            
            if (needsCipher) {
                try {
                    val cipher = credentialRepository.getBiometricCipherForEncryption()
                    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to initialize biometric prompt with cipher", e)
                    biometricPrompt.authenticate(promptInfo)
                }
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }
}
