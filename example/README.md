# 📱 Example Application

This example application demonstrates how to use the `react-native-passkey-autofill` module in a real-world scenario, integrating it with the `@algorandfoundation/wallet-provider` and `@algorandfoundation/react-native-keystore`.

## 🏗️ WalletProvider

The `WalletProvider` is a core component (found in `providers/ReactNativeProvider.tsx`) that acts as a central hub for managing different types of credentials and state within the application. It leverages the `@algorandfoundation/wallet-provider` library to provide a unified interface for various extensions:

- **`WithKeyStore`**: Manages traditional cryptographic keys (like Ed25519 for Algorand).
- **`WithPasskeyStore`**: Manages Passkey metadata and state.
- **`WithPasskeysKeystore`**: Provides integration between the keystore and passkey store, allowing for automatic population of passkey data based on stored keys.

By wrapping the application in a `WalletProvider`, all components can easily access keys and passkeys through a consistent API via the `useProvider` hook.

## 🔗 Integration with Passkey Manager

The example app shows how to bridge the gap between high-level wallet operations and the low-level native `ReactNativePasskeyAutofill` module.

### Shared MMKV Store

A critical part of this integration is the use of a shared [MMKV](https://github.com/mrousavy/react-native-mmkv) store. Both the JavaScript `@algorandfoundation/react-native-keystore` and the native `react-native-passkey-autofill` module operate on the same encrypted storage:

1.  **Shared Master Key**: During the [bootstrap](./bootstrap.ts) process, the application retrieves a master key from the secure `react-native-keystore`.
2.  **Native Synchronization**: This master key is then passed to the native module using `ReactNativePasskeyAutofill.setMasterKey()`.
3.  **Unified Data Access**: Because both layers use the same master key and point to the same underlying MMKV storage, the native AutoFill service can securely access the same passkey data that the React Native application manages.

### Bootstrap Process

The `bootstrap()` function in `bootstrap.ts` ensures that the native side is always in sync with the current state of the wallet:

- It sets the master key for the native module.
- It identifies the primary HD root key (or seed) and informs the native module of its ID.
- It configures the Android Intent actions (`GET_PASSKEY` and `CREATE_PASSKEY`) that the system will use to trigger the AutoFill flows.

## 🚀 Getting Started

To run the example app, please refer to the instructions in the main [CONTRIBUTING.md](../CONTRIBUTING.md) file.
