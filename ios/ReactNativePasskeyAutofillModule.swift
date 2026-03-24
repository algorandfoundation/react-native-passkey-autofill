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

    AsyncFunction("setMasterKey") { (secret: String) in
      // TODO: Implement for iOS
    }

    AsyncFunction("setHdRootKeyId") { (id: String) in
      // TODO: Implement for iOS
    }

    AsyncFunction("getHdRootKeyId") { () -> String? in
      // TODO: Implement for iOS
      return nil
    }

    AsyncFunction("clearCredentials") {
      // TODO: Implement for iOS
    }

    AsyncFunction("configureIntentActions") { (getPasskeyAction: String, createPasskeyAction: String) in
      // TODO: Implement for iOS
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
