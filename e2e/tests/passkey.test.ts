import { createDriver, type Driver } from "../driver/session";
import {
  byTestId,
  confirmSystemPrompt,
  tap,
  takeScreenshot,
  systemDialogButton,
} from "../driver/selectors";
import { PLATFORM, ANDROID_PACKAGE } from "../driver/capabilities";
import {
  ensureBiometricEnrolled,
  pumpFingerprintUntil,
  restoreAppFocus,
  currentPackage,
  currentActivity,
} from "../driver/fingerprint";
import { ensureAndroidCredentialProviderEnabled } from "../driver/credentialProvider";

/**
 * End-to-end coverage for the Passkey AutoFill example app.
 *
 * The flow mirrors what the example does at runtime:
 *   1. Mint a local XHD Ed25519 key (prerequisite for `handleCreatePasskey`).
 *   2. Create a passkey via `https://debug.liquidauth.com/attestation/*`.
 *   3. Re-use the passkey via `https://debug.liquidauth.com/assertion/*`.
 *
 * System-level WebAuthn prompts (e.g. "Continue", Face ID/Touch ID) are
 * auto-confirmed where possible; on the Android emulator the
 * `autoGrantPermissions` capability handles runtime permissions.
 */
describe("Passkey AutoFill example", () => {
  let driver: Driver;

  beforeAll(async () => {
    // eslint-disable-next-line no-console
    console.log("[e2e] beforeAll: creating driver...");
    driver = await createDriver();
    // eslint-disable-next-line no-console
    console.log("[e2e] beforeAll: driver created");

    if (PLATFORM === "android") {
      // eslint-disable-next-line no-console
      console.log("[e2e] beforeAll: ensuring credential provider enabled...");
      // Register our passkey service as the system's Credential Manager
      // provider. A fresh AVD has no providers enabled, so Credential
      // Manager would never route BeginCreate*/BeginGet* to our service
      // and `provider-status` would stay `inactive` (observed in CI).
      const providerRegistered = await ensureAndroidCredentialProviderEnabled();
      // eslint-disable-next-line no-console
      console.log("[e2e] beforeAll: android credential provider registered:", providerRegistered);
      if (!providerRegistered) {
        throw new Error(
          "[e2e] Android Credential Provider registration failed — cannot exercise passkey flow",
        );
      }
    }

    // eslint-disable-next-line no-console
    console.log("[e2e] beforeAll: ensuring biometrics enrolled...");
    // Enroll biometrics so the system prompts can be satisfied
    // (Touch ID/Face ID on iOS simulator, Fingerprint on Android emulator).
    const enrolled = await ensureBiometricEnrolled(driver);
    // eslint-disable-next-line no-console
    console.log(`[e2e] beforeAll: ${PLATFORM} biometric enrolled:`, enrolled);
    if (!enrolled) {
      throw new Error(
        `[e2e] ${PLATFORM} biometric enrollment failed — cannot exercise passkey flow. ` +
          (PLATFORM === "android"
            ? "See [e2e:fingerprint] logs for the Settings wizard labels observed on the AVD."
            : ""),
      );
    }
    // eslint-disable-next-line no-console
    console.log("[e2e] beforeAll: finished");
  }, 180_000);

  afterAll(async () => {
    if (driver) {
      await driver.deleteSession().catch(() => undefined);
    }
  });

  it("launches the example app and shows the header", async () => {
    const header = await driver.$(
      PLATFORM === "ios"
        ? `-ios predicate string:name == 'Passkey AutoFill Example'`
        : `android=new UiSelector().text("Passkey AutoFill Example")`,
    );
    await header.waitForDisplayed({ timeout: 30_000 });
    expect(await header.isDisplayed()).toBe(true);
    await driver.pause(200);
    await takeScreenshot(driver, "app-start");
  });

  /**
   * Smoke-read the provider status banner before the passkey flow runs.
   *
   * The native check is best-effort: on Android 12+ the underlying
   * `credential_service` Secure key is `@hide`-restricted and throws
   * `SecurityException` when read from a regular app, so the status can
   * legitimately report `unknown` or `inactive` *before* the system has
   * routed the first `BeginCreateCredentialRequest` to our service (which
   * stamps MMKV and flips the status to `active`). That authoritative
   * post-stamp assertion lives in the passkey creation test below; this
   * one only surfaces the initial reading for log context.
   */
  it("surfaces the initial provider status", async () => {
    const status = await driver.$(byTestId("provider-status"));
    await status.waitForDisplayed({ timeout: 15_000 });
    const text = (await status.getText()).toLowerCase();
    // eslint-disable-next-line no-console
    console.log("[e2e] initial provider status:", text);
    expect(["active", "inactive", "unknown"].some((s) => text.includes(s))).toBe(true);
  });

  it("creates an XHD Ed25519 key", async () => {
    await tap(driver, byTestId("create-ed25519-key-button"));
    // Wait for the alert with the mnemonic to show.
    await driver.$(systemDialogButton("XHD Ed25519 Key created")).waitForExist({ timeout: 10_000 });
    await driver.pause(200);
    await takeScreenshot(driver, "xhd-key-created-alert");
    await confirmSystemPrompt(driver, ["OK", "Okay", "Dismiss"]);
  });

  /**
   * Predicate: is the example app currently in the foreground? Used as
   * the termination signal when we spam `adb emu finger touch` — as
   * soon as Credential Manager closes its bottom-sheet and control
   * returns to the app, we stop touching.
   */
  const appInForeground = async (): Promise<boolean> => {
    const pkg = await currentPackage();
    const act = await currentActivity();
    if (pkg === ANDROID_PACKAGE) {
      // Only return true if we are in the main activity. If a library activity
      // like CreatePasskeyActivity is on top, we want to keep pumping.
      return act.includes("MainActivity");
    }
    const el = await driver.$(byTestId("passkey-action-button"));
    return el.isDisplayed().catch(() => false);
  };

  it("creates and then uses a passkey against debug.liquidauth.com", async () => {
    // `beforeAll` has already thrown on Android if the Credential
    // Provider wasn't registered or no fingerprint could be enrolled,
    // so reaching this point means the biometric sheet can be satisfied
    // deterministically via `adb emu finger touch`.
    // Create passkey. The system first shows a consent screen ("Continue"
    // / "Create"), then the biometric sheet. We dismiss the consent via
    // `confirmSystemPrompt`, then feed simulated finger touches via
    // `adb emu finger touch` until the sheet closes and the app returns
    // to the foreground.
    await tap(driver, byTestId("passkey-action-button"));
    // pumpFingerprintUntil now handles both system prompts (Continue/Create)
    // and our own intermediate activities (CreatePasskeyActivity) by
    // repeatedly clicking affirmative buttons until back in the main app.
    await pumpFingerprintUntil(driver, appInForeground, { timeoutMs: 45_000 });
    // Wait for the app-level success alert to appear.
    await driver.$(systemDialogButton("Passkey created")).waitForExist({ timeout: 10_000 });
    await confirmSystemPrompt(driver, ["OK", "Okay", "Dismiss", "Got it"]);
    // Allow time for the alert to clear before the final screenshot.
    await driver.pause(500);
    await takeScreenshot(driver, "passkey-create-success");

    // After the first create, the provider stamp must flip the status to
    // "active" — this is the authoritative assertion that *this* app
    // served the system prompt (not a different installed provider).
    const status = await driver.$(byTestId("provider-status"));
    await status.waitForDisplayed({ timeout: 15_000 });
    const deadline = Date.now() + 10_000;
    let text = "";
    while (Date.now() < deadline) {
      text = (await status.getText()).toLowerCase();
      if (text.includes("active") && !text.includes("inactive")) break;
      await driver.pause(500);
    }
    expect(text).toMatch(/active/);
    expect(text).not.toMatch(/inactive/);

    // The button title flips to "Use Passkey" once one exists; re-tap it
    // to exercise the assertion flow.
    await tap(driver, byTestId("passkey-action-button"));
    await pumpFingerprintUntil(driver, appInForeground, { timeoutMs: 45_000 });
    await confirmSystemPrompt(driver, ["OK", "Okay", "Dismiss", "Got it"]);
  });

  it("clears all passkeys and keys", async () => {
    await tap(driver, byTestId("clear-passkeys-button"));
    await confirmSystemPrompt(driver, ["OK", "Okay", "Dismiss"]);
  });
});
