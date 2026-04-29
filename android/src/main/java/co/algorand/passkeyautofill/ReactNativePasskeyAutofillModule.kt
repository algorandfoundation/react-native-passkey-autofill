package co.algorand.passkeyautofill

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import co.algorand.passkeyautofill.credentials.CredentialRepository
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService
import co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService.Companion.KEY_LAST_INVOKED_AT_MS
import com.tencent.mmkv.MMKV
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

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
    }

    OnDestroy {
      instance = null
    }

    Events("onPasskeyAdded", "onPasskeyAuthenticated")

    AsyncFunction("setMasterKey") { secret: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveMasterKey(context, secret)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to save master key")
      }
    }

    AsyncFunction("setHdRootKeyId") { id: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.saveHdRootKeyId(context, id)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to save HD root key ID")
      }
    }

    AsyncFunction("getHdRootKeyId") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.getHdRootKeyId(context)
      } else {
        Log.e(CredentialRepository.TAG, "Could not get context to get HD root key ID")
        null
      }
    }

    AsyncFunction("clearCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      credentialRepository.clearCredentials(context)
    }

    AsyncFunction("configureIntentActions") { getPasskeyAction: String, createPasskeyAction: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        credentialRepository.configureIntentActions(context, getPasskeyAction, createPasskeyAction)
      }
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
  }

  /**
   * Returns `true` when this app's [PasskeyAutofillCredentialProviderService]
   * is registered as an active credential provider for the current user.
   *
   * Android stores the enabled credential providers as a colon-separated list
   * of flattened [ComponentName]s in the `credential_service` and
   * `credential_service_primary` Secure settings (API 34+). However those
   * keys are `@hide` on Android 12+, so reading them from a regular app
   * throws `SecurityException`. We therefore combine two signals:
   *
   *  1. Best-effort: try [Settings.Secure.getString]; if it returns the
   *     expected component we know for sure we're the provider.
   *  2. Fallback: inspect the MMKV timestamp written by the service itself
   *     whenever the system routes a `BeginCreate/BeginGetCredentialRequest`
   *     to it ([PasskeyAutofillCredentialProviderService.KEY_LAST_INVOKED_AT_MS]).
   *     The Credential Manager only routes requests to *enabled* providers,
   *     so a non-zero stamp is proof that we were selected at least once.
   */
  private fun isProviderEnabled(context: Context): Boolean {
    val expected = ComponentName(
      context.packageName,
      PasskeyAutofillCredentialProviderService::class.java.name,
    ).flattenToString()
    val resolver = context.contentResolver
    val keys = arrayOf("credential_service", "credential_service_primary")
    for (key in keys) {
      val value = try {
        Settings.Secure.getString(resolver, key)
      } catch (e: SecurityException) {
        // `credential_service[_primary]` are @hide on Android 12+; fall
        // through to the MMKV stamp check below.
        Log.d("ReactNativePasskeyAutofill", "Secure key $key not readable: ${e.message}")
        null
      } ?: continue
      if (value.isEmpty()) continue
      val enabled = value.split(':').any { it.equals(expected, ignoreCase = true) } ||
        value.contains(expected, ignoreCase = true)
      if (enabled) return true
    }
    // Fallback: look for a timestamp written by our CredentialProviderService.
    return try {
      MMKV.initialize(context)
      (MMKV.defaultMMKV()?.decodeLong(KEY_LAST_INVOKED_AT_MS, 0L) ?: 0L) > 0L
    } catch (e: Exception) {
      Log.w("ReactNativePasskeyAutofill", "Failed to read provider stamp: ${e.message}")
      false
    }
  }

  /**
   * Best-effort deep link into the user's credential-provider preferences so
   * they can toggle our service on. Falls back to the app-details page when
   * the credential provider screen is not available on the device.
   */
  private fun openCredentialProviderSettings(context: Context): Boolean {
    val intents = listOf(
      Intent("android.settings.CREDENTIAL_PROVIDER"),
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
        Log.w("ReactNativePasskeyAutofill", "Failed to open ${intent.action}: ${e.message}")
      }
    }
    return false
  }
}
