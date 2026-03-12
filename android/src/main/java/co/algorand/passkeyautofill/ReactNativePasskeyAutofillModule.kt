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
  }
}
