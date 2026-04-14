import ExpoModulesCore

public class ReactNativePasskeyAutofillModule: Module {
  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  public func definition() -> ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('ReactNativePasskeyAutofill')` in JavaScript.
    Name("ReactNativePasskeyAutofill")

    Events("onPasskeyAdded", "onPasskeyAuthenticated")
    
    OnCreate {
      let appGroupId = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String
      CredentialRepository.shared.initialize(appGroupId: appGroupId)
      
      let center = CFNotificationCenterGetDarwinNotifyCenter()
      let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
      
      CFNotificationCenterAddObserver(center, observer, { (_, observer, name, _, _) in
        guard let observer = observer, let name = name else { return }
        let module = Unmanaged<ReactNativePasskeyAutofillModule>.fromOpaque(observer).takeUnretainedValue()
        let nameString = (name.rawValue as String)
        
        if nameString == "co.algorand.passkeyautofill.onPasskeyAdded" {
          module.sendEvent("onPasskeyAdded", ["success": true])
        } else if nameString == "co.algorand.passkeyautofill.onPasskeyAuthenticated" {
          module.sendEvent("onPasskeyAuthenticated", ["success": true])
        }
      }, "co.algorand.passkeyautofill.onPasskeyAdded" as CFString, nil, .deliverImmediately)
      
      CFNotificationCenterAddObserver(center, observer, { (_, observer, name, _, _) in
        guard let observer = observer, let name = name else { return }
        let module = Unmanaged<ReactNativePasskeyAutofillModule>.fromOpaque(observer).takeUnretainedValue()
        let nameString = (name.rawValue as String)
        
        if nameString == "co.algorand.passkeyautofill.onPasskeyAdded" {
          module.sendEvent("onPasskeyAdded", ["success": true])
        } else if nameString == "co.algorand.passkeyautofill.onPasskeyAuthenticated" {
          module.sendEvent("onPasskeyAuthenticated", ["success": true])
        }
      }, "co.algorand.passkeyautofill.onPasskeyAuthenticated" as CFString, nil, .deliverImmediately)
    }
    
    OnDestroy {
      let center = CFNotificationCenterGetDarwinNotifyCenter()
      let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
      CFNotificationCenterRemoveEveryObserver(center, observer)
    }

    AsyncFunction("setMasterKey") { (secret: String) in
      CredentialRepository.shared.saveMasterKey(secret: secret)
    }

    AsyncFunction("setHdRootKeyId") { (id: String) in
      CredentialRepository.shared.saveHdRootKeyId(id: id)
    }

    AsyncFunction("getHdRootKeyId") { () -> String? in
      return CredentialRepository.shared.getHdRootKeyId()
    }

    AsyncFunction("clearCredentials") {
      CredentialRepository.shared.clearCredentials()
    }

    AsyncFunction("configureIntentActions") { (getPasskeyAction: String, createPasskeyAction: String) in
      CredentialRepository.shared.configureIntentActions(getPasskeyAction: getPasskeyAction, createPasskeyAction: createPasskeyAction)
    }

    // Enables the module to be used as a native view. Definition components that are accepted as part of the
    // view definition: Prop, Events.
    View(ReactNativePasskeyAutofillView.self) {
      // Defines a setter for the `url` prop.
      Prop("url") { (view: ReactNativePasskeyAutofillView, url: URL) in
        if view.webView.url != url {
          view.webView.load(URLRequest(url: url))
        }
      }

      Events("onLoad")
    }
  }
}
