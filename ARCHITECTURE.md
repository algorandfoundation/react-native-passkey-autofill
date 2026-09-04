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
- `ReactNativePasskeyAutofillModule.ts`: Defines the `ReactNativePasskeyAutofillModule` class and its methods (`setMasterKey`, `setMainKeyId`, `getMainKeyId`, etc.).
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

- `setMasterKey(secret: Uint8Array)`: Sets the master key for credential encryption/decryption. Takes raw bytes (not a hex string) so the secret never becomes a non-zeroable JS string.
- `setMainKeyId(id: string)`: Sets the ID for the P-256 main key (the parent secret for passkey derivation). The legacy `setHdRootKeyId` remains as a deprecated alias.
- `getMainKeyId()`: Retrieves the current P-256 main key ID.
- `configureIntentActions(getPasskeyAction: string, createPasskeyAction: string)`: Configures the intent actions used for Passkey flows.
- `clearCredentials()`: Clears all stored credentials.
- `isProviderActive()`: Returns `true` if this app is the user-selected system credential/autofill provider. Uses Android's `Settings.Secure("credential_service"[_primary])` (API 34+) and iOS's `ASCredentialIdentityStore.getState`. Useful both for gating passkey UI at runtime and for E2E tests, which need to confirm that an OS passkey prompt is served by _this_ provider rather than any other installed one.
- `openProviderSettings()`: Deep-links the user to the OS credential/autofill provider settings so they can enable this app as the active provider. Resolves to `true` if a settings screen could be launched.

## Security Considerations

As this module handles sensitive information (Passkeys), keys and secrets are handled securely in the native layers. The master key is stored in platform secure storage — never in plaintext: on Android it is AES/GCM-encrypted under the AndroidKeyStore, and on iOS it is held in the Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) within a shared keychain access group so the app and the AutoFill extension can both read it. It is deliberately not biometric-gated, because the extension must read it to enumerate credentials before the user authenticates; biometric verification is applied at the assertion step instead. The master key crosses the JS↔native bridge as raw bytes (`Uint8Array`), never as a hex string.

Encryption is a precondition, not a best effort. On Android, `setMasterKey` rejects its promise (code `ERR_MASTER_KEY`) if the key is not 32 bytes, cannot be stored in the AndroidKeyStore-backed Keychain, does not read back, or fails a seal/open round trip; nothing is silently logged and swallowed. `saveCredential` refuses to write a record when no master key is available (it throws `MasterKeyUnavailableException` and the create flow returns a `CreateCredentialUnknownException` to the relying party), so a P-256 private key is never persisted without AES-256-GCM. The Credential Provider service only offers `CreateEntry` / credential entries once the master key both reads back and passes the round trip. When a master key is stored, any of this module's own legacy records that an older build wrote unsealed are re-sealed under it; the wallet's records in the shared MMKV instance are never touched.

## End-to-End Tests

The `e2e/` workspace drives the `example/` app with Appium 2 + WebdriverIO, executed through Jest. The Android job uses the UiAutomator2 driver; the iOS job uses XCUITest. The happy-path spec mirrors the example and exercises passkey registration and assertion against `https://debug.liquidauth.com`. See [`e2e/README.md`](./e2e/README.md) for local usage and the [`E2E` workflow](./.github/workflows/e2e.yml) for CI.
