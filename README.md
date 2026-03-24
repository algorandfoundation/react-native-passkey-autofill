# @algorandfoundation/react-native-passkey-autofill

<p align="center">
  <img src="./example/assets/banner.png" width="100%" />
</p>

<p align="center">
  Passkey AutoFill for React Native using DP256.
</p>

# 🚀 Get Started

For bare React Native projects, you must ensure that you have [installed and configured the `expo` package](https://docs.expo.dev/bare/installing-expo-modules/) before continuing.

### Add the package to your npm dependencies

```bash
npm install @algorandfoundation/react-native-passkey-autofill
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

- `site`: The URL of your FIDO server (default: `https://fido.shore-tech.net`).
- `label`: The name of the credential provider as it appears in Android settings (default: `My Credential Provider`).

## Usage

```typescript
import ReactNativePasskeyAutofill from '@algorandfoundation/react-native-passkey-autofill';

// 1. Set the master key for encryption (hex string)
await ReactNativePasskeyAutofill.setMasterKey(masterKeyHex);

// 2. Set the HD root key ID if applicable
await ReactNativePasskeyAutofill.setHdRootKeyId(hdRootKeyId);

// 3. Configure intent actions for the Passkey flows
await ReactNativePasskeyAutofill.configureIntentActions(
  'your.package.name.GET_PASSKEY',
  'your.package.name.CREATE_PASSKEY'
);

// Optional: Clear credentials
await ReactNativePasskeyAutofill.clearCredentials();
```

## 🧪 Testing

The project is set up with a comprehensive testing approach covering both JavaScript and Native (Kotlin) sides.

### JavaScript Tests
Run unit tests for the TypeScript module using Jest:
```bash
npm test
```

### Native Android Tests
Run unit tests for the Kotlin code using JUnit and Robolectric. These tests are executed via the example app's Gradle wrapper:
```bash
npm run test:android
```

### All Tests
Run both JS and Native tests:
```bash
npm run test:all
```

### Continuous Integration (CI)
The project includes a GitHub Actions workflow that automatically runs linting, JS tests, and Native Android tests on every push and pull request to the `main` or `release` branches. You can find the configuration in `.github/workflows/ci.yml`.

### Integration Testing (E2E)
For full end-to-end testing that covers the bridge between JavaScript and Native, we recommend using [Maestro](https://maestro.mobile.dev/). It provides a clean, YAML-based way to automate UI flows and verify the integration of the Passkey Autofill service with the system UI.

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
