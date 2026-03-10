package co.algorand.passkeyautofill

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import co.algorand.passkeyautofill.credentials.CredentialRepository
import com.tencent.mmkv.MMKV
import android.content.Context
import android.util.Log
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class ReactNativePasskeyAutofillModule : Module() {
  private val credentialRepository = CredentialRepository()

  init {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.addProvider(BouncyCastleProvider())
  }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativeLiquidAuth')` in JavaScript.
    Name("ReactNativePasskeyAutofill")

    // Defines constant property on the module.
    Constant("PI") {
      Math.PI
    }

    // Defines event names that the module can send to JavaScript.
    Events("onChange")

    // Defines a JavaScript synchronous function that runs the native code on the JavaScript thread.
    Function("hello") {
      "Hello world! 👋"
    }

    AsyncFunction("setParentSecret") { secret: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        MMKV.initialize(context)
      }
      val mmkv = MMKV.mmkvWithID(CredentialRepository.MMKV_ID)
      mmkv.encode(CredentialRepository.PARENT_SECRET_KEY, secret)
      Log.d(CredentialRepository.TAG, "Parent secret synced to MMKV (length: ${secret.length})")
    }

    AsyncFunction("clearCredentials") {
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
        ?: return@AsyncFunction Unit
      MMKV.initialize(context)
      val mmkv = MMKV.mmkvWithID(CredentialRepository.MMKV_ID)
      mmkv.clearAll()
    }

    AsyncFunction("configureIntentActions") { getPasskeyAction: String, createPasskeyAction: String ->
      val context = (appContext.reactContext ?: appContext.hostingRuntimeContext) as? Context
      if (context != null) {
        MMKV.initialize(context)
      }
      val mmkv = MMKV.mmkvWithID(CredentialRepository.MMKV_ID)
      mmkv.encode(CredentialRepository.GET_PASSKEY_ACTION_KEY, getPasskeyAction)
      mmkv.encode(CredentialRepository.CREATE_PASSKEY_ACTION_KEY, createPasskeyAction)
    }

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.
    AsyncFunction("setValueAsync") { value: String ->
      // Send an event to JavaScript.
      sendEvent("onChange", mapOf(
        "value" to value
      ))
    }
  }
}
