import path from "node:path";

/**
 * Platform target for the E2E run. Selected via the `E2E_PLATFORM`
 * environment variable (defaults to `android`).
 */
export type Platform = "android" | "ios";

export const PLATFORM: Platform = (process.env.E2E_PLATFORM as Platform | undefined) ?? "android";

/** Example app identifiers (must match `example/app.json`). */
export const ANDROID_PACKAGE = "co.algorand.auth.example";
export const IOS_BUNDLE_ID = "co.algorand.auth.example";

/**
 * Absolute paths to the built example app binaries. Override with
 * `E2E_APP_PATH` to point at a prebuilt artifact in CI. When omitted
 * the helpers below fall back to the default expo-built location.
 */
const repoRoot = path.resolve(__dirname, "..", "..");
const defaultAndroidApk = path.join(
  repoRoot,
  "example",
  "android",
  "app",
  "build",
  "outputs",
  "apk",
  "release",
  "app-release.apk",
);
const defaultIosApp = path.join(
  repoRoot,
  "example",
  "ios",
  "build",
  "Build",
  "Products",
  "Release-iphonesimulator",
  "PasskeyAutofillExample.app",
);

export const ANDROID_APP_PATH = process.env.E2E_APP_PATH ?? defaultAndroidApk;
export const IOS_APP_PATH = process.env.E2E_APP_PATH ?? defaultIosApp;

export const APPIUM_HOST = process.env.APPIUM_HOST ?? "127.0.0.1";
export const APPIUM_PORT = Number(process.env.APPIUM_PORT ?? 4723);

export interface Capabilities {
  [key: string]: unknown;
}

/**
 * Android (UiAutomator2) capabilities. `noReset: false` ensures a clean
 * keystore/passkey state between runs so tests are idempotent.
 */
export const androidCapabilities: Capabilities = {
  platformName: "Android",
  "appium:automationName": "UiAutomator2",
  // `platformVersion` is intentionally only set when explicitly provided:
  // when omitted, UiAutomator2 attaches to whichever device is currently
  // connected via `adb`, which is the common case on a developer laptop.
  ...(process.env.ANDROID_PLATFORM_VERSION
    ? { "appium:platformVersion": process.env.ANDROID_PLATFORM_VERSION }
    : {}),
  "appium:deviceName": process.env.ANDROID_DEVICE_NAME ?? "Android Emulator",
  "appium:app": ANDROID_APP_PATH,
  "appium:appPackage": ANDROID_PACKAGE,
  "appium:autoGrantPermissions": true,
  "appium:noReset": false,
  "appium:fullReset": false,
  "appium:newCommandTimeout": 240,
  // Bumped to absorb cold-AVD session-install flakes: on a fresh
  // `google_apis_playstore` AVD, the UiAutomator2 server APK + the
  // `io.appium.settings` helper app can occasionally take longer than
  // the 30s default to install and start, producing
  // `Appium Settings app is not running after 30000ms` at session
  // creation. These knobs are the documented escape hatches.
  "appium:uiautomator2ServerInstallTimeout": 120_000,
  "appium:uiautomator2ServerLaunchTimeout": 120_000,
  "appium:uiautomator2ServerReadTimeout": 240_000,
  "appium:adbExecTimeout": 60_000,
  "appium:appWaitActivity": "*",
  "appium:appWaitDuration": 60_000,
};

/**
 * iOS (XCUITest) capabilities. Targets the simulator.
 */
export const iosCapabilities: Capabilities = {
  platformName: "iOS",
  "appium:automationName": "XCUITest",
  "appium:platformVersion": process.env.IOS_PLATFORM_VERSION ?? "17.5",
  "appium:deviceName": process.env.IOS_DEVICE_NAME ?? "iPhone 15",
  "appium:app": IOS_APP_PATH,
  "appium:bundleId": IOS_BUNDLE_ID,
  "appium:noReset": false,
  "appium:newCommandTimeout": 240,
};

export function capabilitiesForPlatform(platform: Platform = PLATFORM): Capabilities {
  return platform === "ios" ? iosCapabilities : androidCapabilities;
}
