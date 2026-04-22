# 🏗️ Architecture

This document describes the internal structure of the `react-native-passkey-autofill` module and how it works.

## Project Structure

The project follows the standard layout for an Expo module:

- `src/`: TypeScript source files for the module's JavaScript API.
- `android/`: Native Android implementation using Kotlin.
- `ios/`: Native iOS implementation using Swift.
- `example/`: An example app demonstrating the use of the module.

## How it works

The module provides an interface to interact with native Passkey AutoFill capabilities. It uses Expo's native module system to bridge the JavaScript code with the platform-specific implementations.

### TypeScript Layer (`src/`)

- `index.ts`: The entry point for the module, re-exporting the native module.
- `ReactNativePasskeyAutofillModule.ts`: Defines the `ReactNativePasskeyAutofillModule` class and its methods (`setMasterKey`, `setHdRootKeyId`, `getHdRootKeyId`, etc.).
- `ReactNativePasskeyAutofill.types.ts`: Defines types and interfaces used by the module.

### Android Implementation (`android/`)

The Android part is implemented using Kotlin and follows the Android Autofill Framework.

- `ReactNativePasskeyAutofillModule.kt`: The main class that exposes methods to React Native.
- `service/PasskeyAutofillCredentialProviderService.kt`: Implements the `CredentialProviderService` to handle Passkey AutoFill requests from the Android system.
- `credentials/`: Contains logic for managing credentials and interacting with the local storage.
- `GetPasskeyActivity.kt` and `CreatePasskeyActivity.kt`: Activities used to handle the UI flow for getting and creating passkeys.

#### The `CredentialProvider` and Chain of Trust

The `PasskeyAutofillCredentialProviderService` is the core of the Android implementation. It extends the Android Jetpack `CredentialProviderService` to provide passkeys directly to the system's Credential Manager.

##### What is `CredentialProviderService`?

Introduced in Android 14 (API level 34) and backported to Android 9 via the Jetpack Credentials library, this service allows password managers and other credential providers to integrate with the system's unified sign-in flow. When a user interacts with a sign-in or sign-up field, the system queries registered services to provide available credentials.

##### Handling the Chain of Trust

The "Chain of Trust" ensures that passkeys are only used by the legitimate owners of a domain or application. This is handled through several layers of validation:

1.  **Digital Asset Links**: For a passkey to be used across a website and an Android app, the website must host a `/.well-known/assetlinks.json` file that explicitly authorizes the Android app (via its package name and certificate fingerprint). This establishes a cryptographically verified link between the web origin and the mobile application.
2.  **Relying Party ID (rpId) Validation**: When the service receives a `BeginGetCredentialRequest` or `BeginCreateCredentialRequest`, it includes information about the `rpId` (e.g., `example.com`). The system and the provider must ensure that the requesting app is authorized to use credentials for that `rpId`.
3.  **App Signature Verification**: The Android system verifies the signature of the app requesting the credential. It will only offer credentials to apps that can prove their identity through the Digital Asset Link chain.
4.  **User Consent**: The `CredentialProviderService` does not directly return the credential. Instead, it returns a list of "Entries" (like `PublicKeyCredentialEntry`). When a user selects an entry, a `PendingIntent` is triggered, which typically launches an activity (like `GetPasskeyActivity`) to perform user verification (e.g., biometric check) before the actual passkey is released to the requesting app.

### iOS Implementation (`ios/`) [WIP]

The iOS part is implemented using Swift.

- `ReactNativePasskeyAutofillModule.swift`: Defines the native module for iOS.
- `ReactNativePasskeyAutofillView.swift`: If any native views are required.

## Native Module API

The following methods are exposed to the JavaScript layer:

- `setMasterKey(secret: string)`: Sets the master key for credential encryption/decryption.
- `setHdRootKeyId(id: string)`: Sets the ID for the HD root key.
- `getHdRootKeyId()`: Retrieves the current HD root key ID.
- `configureIntentActions(getPasskeyAction: string, createPasskeyAction: string)`: Configures the intent actions used for Passkey flows.
- `clearCredentials()`: Clears all stored credentials.
- `isProviderActive()`: Returns `true` if this app is the user-selected system credential/autofill provider. Uses Android's `Settings.Secure("credential_service"[_primary])` (API 34+) and iOS's `ASCredentialIdentityStore.getState`. Useful both for gating passkey UI at runtime and for E2E tests, which need to confirm that an OS passkey prompt is served by _this_ provider rather than any other installed one.
- `openProviderSettings()`: Deep-links the user to the OS credential/autofill provider settings so they can enable this app as the active provider. Resolves to `true` if a settings screen could be launched.

## Security Considerations

As this module handles sensitive information (Passkeys), it is crucial to ensure that keys and secrets are handled securely in the native layers. Master keys should be stored in secure storage (like Android Keystore or iOS Keychain).

## End-to-End Tests

The `e2e/` workspace drives the `example/` app with Appium 2 + WebdriverIO, executed through Jest. The Android job uses the UiAutomator2 driver; the iOS job uses XCUITest. The happy-path spec mirrors the example and exercises passkey registration and assertion against `https://debug.liquidauth.com`. See [`e2e/README.md`](./e2e/README.md) for local usage and the [`E2E` workflow](./.github/workflows/e2e.yml) for CI.
