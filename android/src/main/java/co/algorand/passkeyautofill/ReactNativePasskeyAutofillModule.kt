package co.algorand.passkeyautofill

import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import co.algorand.passkeyautofill.utils.PasskeyLog
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Rejects the `setMasterKey` promise with code `ERR_MASTER_KEY` when the key
 * could not be stored and verified. The wallet must treat this as "no passkey
 * can be created or asserted on this device" rather than continue.
 */
class MasterKeyException(message: String, cause: Throwable? = null) : CodedException(message, cause)

class ReactNativePasskeyAutofillModule : Module() {
  private val credentialRepository = CredentialRepository()

  companion object {
    var instance: ReactNativePasskeyAutofillModule? = null
  }

  init {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.insertProviderAt(BouncyCastleProvider(), 1)
  }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeLiquidAuth')` in JavaScript.
    Name("ReactNativePasskeyAutofill")

    OnCreate {
      instance = this@ReactNativePasskeyAutofillModule
      ((appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context)?.let { PasskeyLog.init(it) }
    }

    OnDestroy {
      instance = null
    }

    Events("onPasskeyAdded", "onPasskeyAuthenticated")

    // Fails closed: every failure to store and verify the key rejects the
    // promise. Logging and resolving would let the wallet believe the key is in
    // place while credential creation is impossible.
    AsyncFunction("setMasterKey") { secret: ByteArray ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: throw MasterKeyException("Could not get context to save master key")
      try {
        credentialRepository.saveMasterKey(context, secret)
      } catch (e: Exception) {
        PasskeyLog.e(CredentialRepository.TAG, "Failed to save master key", e)
        throw MasterKeyException(e.message ?: "Failed to save master key", e)
      }
    }

    // Points the passkey hierarchy at the wallet's deterministic-P256 main key.
    // The scheme is not a parameter: it is read from the record's own metadata,
    // so a wallet cannot mislabel which hierarchy it handed us.
    AsyncFunction("setMainKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMainKeyId(context, id)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to save main key ID")
      }
    }

    AsyncFunction("getMainKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getMainKeyId(context)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to get main key ID")
        null
      }
    }

    // Deprecated aliases of the two above, kept because installed wallets still
    // call them. They address the same slot — see `saveMainKeyId`.
    AsyncFunction("setHdRootKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMainKeyId(context, id)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to save HD root key ID")
      }
    }

    AsyncFunction("getHdRootKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getMainKeyId(context)
      } else {
        PasskeyLog.e(CredentialRepository.TAG, "Could not get context to get HD root key ID")
        null
      }
    }

    AsyncFunction("clearCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.clearCredentials(context)
    }

    AsyncFunction("deleteCredential") { credentialId: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.deleteCredential(context, credentialId)
    }

    AsyncFunction("configureIntentActions") { getPasskeyAction: String, createPasskeyAction: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.configureIntentActions(context, getPasskeyAction, createPasskeyAction)
      }
    }

    // NoOp on Android. iOS uses ASCredentialIdentityStore to advertise
    // credentials to the system AutoFill UI; Android's Credential Manager
    // queries the provider service on demand instead, so there is no
    // equivalent identity store to populate.
    AsyncFunction("replaceCredentialIdentities") { _: List<Map<String, Any?>> ->
      // No-op: see comment above.
    }

    // NoOp on Android. See `replaceCredentialIdentities` above.
    AsyncFunction("refreshCredentialIdentities") {
      // No-op: see comment above.
    }

    // NoOp on Android. The iOS implementation returns credentials stored in
    // the shared App Group keychain used by the AutoFill extension. On
    // Android, credentials are managed by the CredentialProviderService and
    // are not exposed back to JS through this module.
    AsyncFunction("getStoredCredentials") {
      emptyList<Map<String, Any?>>()
    }

    // NoOp on Android. iOS exposes diagnostics from the shared App Group
    // store; there is no equivalent on Android yet.
    AsyncFunction("getDiagnostics") {
      emptyList<String>()
    }

    AsyncFunction("isProviderActive") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction false
      isProviderEnabled(context)
    }

    AsyncFunction("openProviderSettings") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction false
      openCredentialProviderSettings(context)
    }

    AsyncFunction("getStoredCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction emptyList<Map<String, Any>>()
      credentialRepository.getAllCredentials(context).map { credential ->
        mapOf(
          "credentialId" to credential.credentialId,
          "relyingPartyIdentifier" to credential.origin,
          "userName" to credential.userHandle,
          "userHandle" to credential.userHandle,
          "publicKey" to credential.publicKey,
          "derivationScheme" to credential.derivationScheme,
        )
      }
    }

    // The iOS AutoFill identity store (ASCredentialIdentityStore) has no
    // Android analogue: our CredentialProviderService answers each
    // BeginGetCredentialRequest from MMKV on demand, so there is no store to
    // pre-populate. This is a no-op purely to satisfy the shared JS API.
    AsyncFunction("refreshCredentialIdentities") {
      // no-op on Android
    }
  }

  /**
   * Returns `true` when this app's [PasskeyAutofillCredentialProviderService]
   * is registered as an active credential provider for the current user.
   *
   * On API 34+ (UpsideDownCake) we use the official
   * [android.credentials.CredentialManager.isEnabledCredentialProviderService]
   * API, which reflects the user's current toggle in Settings in real time.
   *
   * On older devices we fall back to a best-effort read of the `@hide`
   * `credential_service` / `credential_service_primary` Secure settings. These
   * typically throw `SecurityException` for non-system apps on Android 12+,
   * in which case we conservatively return `false` rather than guess.
   */
  private fun isProviderEnabled(context: Context): Boolean {
    val component = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    )
    val expected = component.flattenToString()

    // Preferred path (API 34+, UpsideDownCake): ask the platform
    // `CredentialManager` system service whether our component is enabled.
    // This is the official, real-time-accurate signal and is trusted
    // exclusively on supported OS versions.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      return try {
        val cm = context.getSystemService(android.credentials.CredentialManager::class.java)
        cm != null && cm.isEnabledCredentialProviderService(component)
      } catch (e: Throwable) {
        PasskeyLog.d("ReactNativePasskeyAutofill", "CredentialManager.isEnabledCredentialProviderService failed: ${e.message}")
        false
      }
    }

    // Pre-API-34 best-effort: try the (often `@hide`) Secure settings keys.
    val resolver = context.contentResolver
    val keys = arrayOf("credential_service", "credential_service_primary")
    for (key in keys) {
      val value = try {
        Settings.Secure.getString(resolver, key)
      } catch (e: SecurityException) {
        PasskeyLog.d("ReactNativePasskeyAutofill", "Secure key $key not readable: ${e.message}")
        null
      } ?: continue
      if (value.isEmpty()) continue
      val enabled = value.split(':').any { it.equals(expected, ignoreCase = true) } ||
        value.contains(expected, ignoreCase = true)
      if (enabled) return true
    }
    return false
  }

  /**
   * Best-effort deep link into the user's credential-provider preferences so
   * they can toggle our service on. Falls back to the app-details page when
   * the credential provider screen is not available on the device.
   */
  private fun openCredentialProviderSettings(context: Context): Boolean {
    // The system action for the Credential Manager provider picker is
    // `android.settings.CREDENTIAL_PROVIDER` (`Settings.ACTION_CREDENTIAL_PROVIDER`,
    // API 34+). Some OEM Settings builds additionally accept a
    // `:settings:fragment_args_key` extra so the screen scrolls directly to
    // our app's row instead of the generic list. We also include a legacy
    // autofill-service picker fallback for devices where the Credential
    // Manager screen isn't a directly launchable activity.
    val component = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    ).flattenToString()
    val intents = listOf(
      // Preferred: Credential Manager provider settings, deep-linked to our row.
      Intent("android.settings.CREDENTIAL_PROVIDER").apply {
        putExtra(":settings:fragment_args_key", component)
        putExtra(
          ":settings:show_fragment_args",
          android.os.Bundle().apply { putString(":settings:fragment_args_key", component) },
        )
      },
      // Same screen without the deep-link extras (some OEMs ignore them).
      Intent("android.settings.CREDENTIAL_PROVIDER"),
      // Legacy / fallback: the system autofill provider picker, which on
      // pre-14 devices is the closest "pick a passkey provider" screen.
      Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
        data = Uri.parse("package:${context.packageName}")
      },
      // Last-resort fallback: this app's details page.
      Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", context.packageName, null)
      },
    )
    for (intent in intents) {
      intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      try {
        context.startActivity(intent)
        return true
      } catch (e: Exception) {
        PasskeyLog.w("ReactNativePasskeyAutofill", "Failed to open ${intent.action}: ${e.message}")
      }
    }
    return false
  }
}
