# E2E — Appium + WebdriverIO

End-to-end tests driving the `example/` app with [Appium 2](https://appium.io)
through [WebdriverIO](https://webdriver.io). Tests are written in TypeScript
and executed with Jest (to stay consistent with the rest of the repo).

The happy-path test mirrors the example app: it mints a local XHD Ed25519
key, creates a passkey against `https://debug.liquidauth.com`, and then
re-uses it for an assertion round-trip.

## Layout

```
e2e/
├── driver/
│   ├── capabilities.ts   # Android (UiAutomator2) + iOS (XCUITest) caps
│   ├── selectors.ts      # testID + system-dialog helpers
│   └── session.ts        # createDriver() — wraps webdriverio.remote()
├── tests/
│   └── passkey.test.ts   # smoke + passkey create/use against debug.liquidauth.com
├── jest.config.ts
├── package.json
└── tsconfig.json
```

All app-level taps use React Native `testID`s (exposed as
`accessibility id` on both platforms) via `byTestId("...")`. System
WebAuthn/biometric dialogs are auto-confirmed by `confirmSystemPrompt()`.

## Provider-active precondition

The example app exposes a provider-status banner so the suite (and
human testers) can confirm that _this_ package is the user-selected
system credential/autofill provider before exercising passkey flows —
otherwise another installed password manager could silently serve the
system WebAuthn prompts. The example exposes:

- A `testID="provider-status"` label whose text reads `active`,
  `inactive`, or `unknown`.
- A `testID="open-provider-settings"` CTA that deep-links to the OS
  settings (Android: credential provider picker; iOS: AutoFill
  settings).

The first suite step (`surfaces the initial provider status`) is a
smoke read only. The authoritative assertion runs after the passkey
creation step: once Android has routed a
`BeginCreate/BeginGetCredentialRequest` to our
`PasskeyAutofillCredentialProviderService`, the service stamps an MMKV
key that `ReactNativePasskeyAutofill.isProviderActive()` picks up and
the banner flips to `active`. This two-signal design sidesteps the
fact that `Settings.Secure("credential_service")` is `@hide`-restricted
on Android 12+ and cannot be read by a regular app.

If the passkey flow never reaches the stamp, enable the app manually
on the device:

- **Android 14+**: Settings → Passwords, passkeys & accounts →
  Additional providers → _Passkey AutoFill Example_.
- **iOS 17+**: Settings → Passwords → Password Options → enable
  _Passkey AutoFill Example_.

## Biometric prompts

The passkey create/use flow ultimately routes through either the
system's Single-Tap bottom sheet (when the provider attaches
`BiometricPromptData` + `CryptoObject`) or the fallback
`CreatePasskeyActivity` / `GetPasskeyActivity` screens. Both require a
biometric confirmation from the user. On emulators the suite automates
this by synthesising finger touches via `adb` (Android) or the
`enrollBiometric` extension (iOS).

## Prerequisites

- Node.js 22+, pnpm 10+
- **Android**: Android SDK, an AVD (API 34 recommended). Biometrics
  are automatically enrolled by the suite on first run.
- **iOS** (macOS only): Xcode 16.1+, an iOS 17+ Simulator. Face ID is
  automatically enrolled by the suite.
- Appium drivers. The driver packages are declared as regular `devDependencies`
  and installed by `pnpm install`, so they are version-locked alongside the
  rest of the workspace. The `appium:setup*` scripts then register them with
  the Appium CLI from their local `node_modules` path (no `npm` shell-out,
  no global `~/.appium` mutation required beyond Appium's own manifest):

  ```bash
  pnpm install                   # installs appium-uiautomator2-driver & appium-xcuitest-driver
  pnpm run appium:setup          # register both drivers with Appium
  pnpm run appium:setup:android  # Android only
  pnpm run appium:setup:ios      # iOS only (macOS)
  ```

## Running locally

1. Install repo deps:

   ```bash
   pnpm install
   ```

2. Build the example app for the target platform:

   ```bash
   pnpm run e2e:build:android   # produces example/android/app/build/outputs/apk/release/app-release.apk
   pnpm run e2e:build:ios       # produces example/ios/build/Build/Products/Release-iphonesimulator/PasskeyAutofillExample.app
   ```

3. Boot an emulator/simulator, then run:

   ```bash
   pnpm run e2e:android
   # or
   pnpm run e2e:ios
   ```

   These scripts start Appium via `start-server-and-test`, wait for
   `http://127.0.0.1:4723/status`, execute the Jest suite, and shut
   Appium down afterwards.

### Overrides

| Env var                      | Purpose                                          |
| ---------------------------- | ------------------------------------------------ |
| `E2E_PLATFORM`               | `android` (default) or `ios`                     |
| `E2E_APP_PATH`               | Absolute path to a prebuilt `.apk` / `.app`      |
| `APPIUM_HOST`, `APPIUM_PORT` | Appium server (defaults `127.0.0.1:4723`)        |
| `ANDROID_PLATFORM_VERSION`   | e.g. `"14"`                                      |
| `ANDROID_DEVICE_NAME`        | e.g. `"Pixel_6_API_34"`                          |
| `IOS_PLATFORM_VERSION`       | e.g. `"17.5"`                                    |
| `IOS_DEVICE_NAME`            | e.g. `"iPhone 15"`                               |
| `WDIO_LOG_LEVEL`             | `error` \| `warn` (default) \| `info` \| `debug` |

## CI

The [`E2E` workflow](../.github/workflows/e2e.yml) runs on
`workflow_dispatch` or when a PR is labelled `e2e`:

- **Android** job builds the release APK, installs the UiAutomator2 driver,
  and runs the suite inside `reactivecircus/android-emulator-runner`.
- **iOS** job (currently disabled) builds the `.app` for the iPhone Simulator,
  installs the XCUITest driver, boots a simulator, and runs the suite.

Screenshots of the test run are uploaded as workflow artifacts for debugging.

## Authoring new tests

1. Add a stable `testID` to the target React Native component.
2. Import the helpers:

   ```ts
   import { createDriver } from "../driver/session";
   import { byTestId, tap, confirmSystemPrompt } from "../driver/selectors";
   ```

3. Drive the app with `tap(driver, byTestId("..."))`. Use
   `confirmSystemPrompt()` for OS-level WebAuthn/biometric dialogs.
