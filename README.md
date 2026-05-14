# @algorandfoundation/react-native-passkey-autofill

<p align="center">
  <img src="https://raw.githubusercontent.com/algorandfoundation/react-native-passkey-autofill/refs/heads/main/assets/banner.png" width="100%" />
</p>

<p align="center">
  Passkey AutoFill for React Native using DP256.
</p>

# 🚀 Get Started

For bare React Native projects, you must ensure that you have [installed and configured the `expo` package](https://docs.expo.dev/bare/installing-expo-modules/) before continuing.

### Add the package to your dependencies

```bash
pnpm add @algorandfoundation/react-native-passkey-autofill
```

### Configure for Android

To use this module on Android, you need to configure the AutoFill service in your `AndroidManifest.xml` or via the Expo plugin.

#### Expo Plugin Configuration

If you are using Expo, you can configure the plugin in your `app.json` or `app.config.js`:

```json
{
  "expo": {
    "plugins": [
      [
        "@algorandfoundation/react-native-passkey-autofill",
        {
          "site": "https://your-fido-server.com",
          "label": "My Custom Credential Provider"
        }
      ]
    ]
  }
}
```

- `site`: The URL of your FIDO server (default: `https://debug.liquidauth.com`).
- `label`: The name of the credential provider as it appears in Android settings (default: `My Credential Provider`).

### Configure for iOS

iOS passkey AutoFill requires a Credential Provider extension, an App Group shared between the app and extension, and an associated domain for Web Credentials. The Expo config plugin can create and wire the extension during prebuild:

```json
{
  "expo": {
    "ios": {
      "bundleIdentifier": "com.example.wallet",
      "associatedDomains": ["webcredentials:your-fido-server.com"],
      "entitlements": {
        "com.apple.developer.authentication-services.autofill-credential-provider": true
      }
    },
    "plugins": [
      [
        "@algorandfoundation/react-native-passkey-autofill",
        {
          "site": "https://your-fido-server.com",
          "label": "My Custom Credential Provider",
          "appGroup": "group.com.example.wallet.passkey-autofill",
          "appleTeamId": "YOUR_TEAM_ID"
        }
      ]
    ]
  }
}
```

For iOS integration, make sure that:

- The app and Credential Provider extension both have the AutoFill Credential Provider capability.
- The app and extension both have the same App Group entitlement.
- The app has a `webcredentials:<domain>` associated domain, and that domain serves a valid `apple-app-site-association` file for the app identifier.
- The deployment target is iOS 17 or newer for passkey credential provider support.
- The generated extension target can link `AuthenticationServices.framework`, `CryptoKit.framework`, `MMKVCore`, and the deterministic P-256 Swift package.
- `NSFaceIDUsageDescription` is present when biometric authentication is used.

At runtime, the app must provide the native side with key material and keep the iOS identity store in sync:

```typescript
await ReactNativePasskeyAutofill.setDerivedMainKey(derivedMainKeyHex);
await ReactNativePasskeyAutofill.setHdRootKeyId(hdRootKeyId);
await ReactNativePasskeyAutofill.refreshCredentialIdentities();
```

Call `refreshCredentialIdentities()` after creating, importing, deleting, or restoring passkeys so iOS AutoFill sees the current credentials.

## Usage

```typescript
import ReactNativePasskeyAutofill from "@algorandfoundation/react-native-passkey-autofill";

// 1. Set the master key for encryption (hex string)
await ReactNativePasskeyAutofill.setMasterKey(masterKeyHex);

// 2. Set the HD root key ID if applicable
await ReactNativePasskeyAutofill.setHdRootKeyId(hdRootKeyId);

// 3. Configure intent actions for the Passkey flows
await ReactNativePasskeyAutofill.configureIntentActions(
  "your.package.name.GET_PASSKEY",
  "your.package.name.CREATE_PASSKEY",
);

// Optional: Clear credentials
await ReactNativePasskeyAutofill.clearCredentials();
```

## Events

You can listen for events emitted by the native module when a passkey is successfully added or authenticated.

```typescript
import ReactNativePasskeyAutofill from "@algorandfoundation/react-native-passkey-autofill";
import { useEffect } from "react";

// ... inside a component or hook
useEffect(() => {
  const addedSubscription = ReactNativePasskeyAutofill.addListener("onPasskeyAdded", (event) => {
    console.log("Passkey added successfully:", event.success);
  });

  const authSubscription = ReactNativePasskeyAutofill.addListener(
    "onPasskeyAuthenticated",
    (event) => {
      console.log("Passkey authenticated successfully:", event.success);
    },
  );

  return () => {
    addedSubscription.remove();
    authSubscription.remove();
  };
}, []);
```

## 🧪 Testing

The project is set up with a comprehensive testing approach covering both JavaScript and Native (Kotlin) sides.

### JavaScript Tests

Run unit tests for the TypeScript module using Jest:

```bash
pnpm test
```

### Native Android Tests

Run unit tests for the Kotlin code using JUnit and Robolectric. These tests are executed via the example app's Gradle wrapper:

```bash
pnpm run test:android
```

### All Tests

Run both JS and Native tests:

```bash
pnpm run test:all
```

### Continuous Integration (CI)

The project includes a GitHub Actions workflow that automatically runs linting, JS tests, and Native Android tests on every push and pull request to the `main` or `release` branches. You can find the configuration in `.github/workflows/ci.yml`.

### Integration Testing (E2E)

Full end-to-end tests driving the example app with Appium and WebdriverIO are available in the [`e2e/`](./e2e) directory. These tests exercise the entire passkey creation and usage flow on Android emulators and iOS simulators. See the [E2E README](./e2e/README.md) for more details.

## 📱 Example App

The [example](./example) app demonstrates how to integrate this module with a full wallet implementation.

# 🤝 Contributing

Contributions are very welcome! Please refer to guidelines described in the [contributing guide](./CONTRIBUTING.md).

# 💖 Acknowledgements

This has been the culmination of many different efforts and ideas. We would like to thank the following individuals and organizations for their contributions:

- [Bruno Martins](https://github.com/bmartins) the architect at [Algorand Foundation](https://github.com/algorandfoundation) for conceptualizing and guiding the project.
- [HashMapsData2Value](https://github.com/HashMapsData2Value) for his guidance and support in DP256 and XHD and his work on the native autofill libraries.
- [Will Beaumont](https://github.com/mjbeau) for working through integration within the Pera wallet
- [Michael T Chuang](https://github.com/michaeltchuang) for his work in KMP integrations and client libraries.

# 📄 License

This project is licensed under the Apache-2.0 License - see the [LICENSE](./LICENSE) file for details.
