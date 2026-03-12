# 🔑 react-native-passkey-autofill

Passkey AutoFill for React Native using DP256.

# 🚀 Get Started

For bare React Native projects, you must ensure that you have [installed and configured the `expo` package](https://docs.expo.dev/bare/installing-expo-modules/) before continuing.

### Add the package to your npm dependencies

```bash
npm install react-native-passkey-autofill
```

### Configure for Android

To use this module on Android, you need to configure the AutoFill service in your `AndroidManifest.xml` or via the Expo plugin.

## Usage

```typescript
import ReactNativePasskeyAutofill from 'react-native-passkey-autofill';

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

# 🤝 Contributing

Contributions are very welcome! Please refer to guidelines described in the [contributing guide](./CONTRIBUTING.md).

# 💖 Acknowledgements

This has been the commination of many different efforts and ideas. We would like to thank the following individuals and organizations for their contributions:

- [Bruno Martins](https://github.com/bmartins) the architect at [Algorand Foundation](https://github.com/algorandfoundation) for conceptualizing and guiding the project.
- [HashMapsData2Value](https://github.com/HashMapsData2Value) for his guidance and support in DP256 and XHD and his work on the native autofill libraries.
- [Will Beaumont](https://github.com/mjbeau) for working though integration within the Pera wallet
- [Michael T Chuang](https://github.com/michaeltchuang) for his work in KMP integrations and client libraries.

## ❤️ Community

[![stargazers](https://reporoster.com/stars/dark/algorandfoundation/liquid-auth-js)](https://github.com/algorandfoundation/liquid-auth-js/stargazers)
[![forks](https://reporoster.com/forks/dark/algorandfoundation/liquid-auth-js)](https://github.com/algorandfoundation/liquid-auth-js/network/members)

# 📄 License

This project is licensed under the Apache-2.0 License - see the [LICENSE](./LICENSE) file for details.
