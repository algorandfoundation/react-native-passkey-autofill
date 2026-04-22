import { execFile, execFileSync } from "node:child_process";
import path from "node:path";
import { PLATFORM, ANDROID_PACKAGE } from "./capabilities";
import type { Driver } from "./session";
import { confirmSystemPrompt, byTestId } from "./selectors";
import { adb, adbAsync, adbSilent, getAdbSerial } from "./adb";

/**
 * Fingerprint enrollment + trigger helpers for the Android emulator.
 *
 * Why this file exists
 * --------------------
 * The Android Credential Manager / passkey flow presents a biometric
 * bottom-sheet that Appium can't dismiss by tapping a button (the sheet
 * is served by the system, and on a device with no enrolled finger the
 * ceremony never completes). On an emulator we *can* synthesise touches
 * via the host emulator console — but only once a finger is actually
 * enrolled in Settings, and the emulator image boots without one.
 *
 * So this helper:
 *   1. Drives `android.settings.BIOMETRIC_ENROLL` (preferred on API 30+)
 *      / `FINGERPRINT_ENROLL` (legacy) via UiAutomator2,
 *   2. Feeds "finger touch" events through Appium's
 *      `mobile: sendFingerprint` extension (a.k.a. WebdriverIO's
 *      `driver.fingerPrint(id)`). This is the Sauce-Labs-compatible
 *      path: on a local emulator Appium routes it to the host emulator
 *      console, on Sauce Labs' device cloud the same command is served
 *      by their sensor API. We keep a host-side `adb emu finger touch`
 *      fallback for the pre-session enrollment wizard, since the driver
 *      isn't available until after the Appium session is created.
 *   3. Exposes `triggerFingerprintTouch()` / `pumpFingerprintUntil()`
 *      for tests to call while a biometric prompt is on screen.
 *
 * Everything is focused on emulators: on non-Android runs
 * the helpers are a no-op.
 */

const DEFAULT_PIN = process.env.E2E_DEVICE_PIN ?? "1111";
const FINGER_ID = Number(process.env.E2E_FINGER_ID ?? 1);
const DEBUG = process.env.E2E_DEBUG_FINGERPRINT === "1" || process.env.CI === "true";

const PLACE_FINGER_MARKERS = [
  /Touch the (fingerprint )?sensor/i,
  /Place (your )?finger/i,
  /Lift,? then touch/i,
  /Keep lifting your finger/i,
  /Add more fingerprint/i,
  /Lift your finger/i,
  /Setup is complete/i,
  /Fingerprint added/i,
];

function log(...parts: unknown[]): void {
  if (!DEBUG) return;
  // eslint-disable-next-line no-console
  console.log("[e2e:fingerprint]", ...parts);
}

function isAndroidEmulator(): boolean {
  if (PLATFORM !== "android") return false;
  // `adb emu` commands only exist against an `emulator-XXXX` serial.
  return getAdbSerial().startsWith("emulator-");
}

/**
 * Sends a single synthesised fingerprint touch via Appium's
 * `mobile: sendFingerprint` extension when a driver is available
 * (portable to Sauce Labs and other device farms), falling back to
 * host-side `adb emu finger touch` for the pre-session enrollment
 * wizard where no driver exists yet.
 */
export async function triggerFingerprintTouch(driver?: Driver): Promise<void> {
  if (PLATFORM !== "android") return;
  if (driver) {
    // Preferred path: portable to Sauce Labs & other clouds.
    try {
      const anyDriver = driver as unknown as {
        execute: (script: string, args: unknown) => Promise<unknown>;
        fingerPrint?: (id: number) => Promise<void>;
      };
      if (typeof anyDriver.fingerPrint === "function") {
        await anyDriver.fingerPrint(FINGER_ID);
        return;
      }
      await anyDriver.execute("mobile: sendFingerprint", {
        fingerprintId: FINGER_ID,
      });
      return;
    } catch {
      // Fall through to adb fallback for local emulator runs where
      // the extension isn't wired up.
    }
  }
  if (isAndroidEmulator()) {
    adbAsync(["emu", "finger", "touch", String(FINGER_ID)]);
  }
}

/**
 * Spam touches at ~200ms cadence while `predicate()` is false. Designed
 * for the brief window when the biometric sheet is on screen — stops as
 * soon as the prompt closes (predicate returns true) or the deadline
 * elapses.
 */
export async function pumpFingerprintUntil(
  driver: Driver,
  predicate: () => Promise<boolean> | boolean,
  {
    timeoutMs = 45_000,
    intervalMs = 1200,
    waitFirst = true,
  }: { timeoutMs?: number; intervalMs?: number; waitFirst?: boolean } = {},
): Promise<boolean> {
  if (PLATFORM !== "android") return false;
  const deadline = Date.now() + timeoutMs;
  log(`pump: starting (timeout=${timeoutMs}ms, waitFirst=${waitFirst})`);

  const confirmIds = ["create-passkey-confirm", "get-passkey-confirm"];
  const systemLabels = [
    "Continue",
    "Create",
    "Save",
    "Allow",
    "Use",
    "Got it",
    "Select",
    "OK",
    "Sign In",
  ];

  if (waitFirst) {
    log("pump: waiting for app to lose focus...");
    while (Date.now() < deadline) {
      if (!(await predicate())) {
        log("pump: focus lost, starting pump");
        break;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  let lastTriggerTime = 0;

  while (Date.now() < deadline) {
    if (await predicate()) {
      log("pump: predicate true, stopping");
      return true;
    }

    const src = await getPageSource(driver);

    // 1. Try to click our own app's confirmation buttons if visible.
    for (const id of confirmIds) {
      const el = await driver.$(byTestId(id));
      if (await el.isExisting().catch(() => false)) {
        log(`pump: clicking app button ${id}`);
        await el.click().catch(() => undefined);
      }
    }

    // 2. Try to dismiss any system prompt that might be blocking us.
    await confirmSystemPrompt(driver, systemLabels, 200).catch(() => undefined);

    // 3. Trigger fingerprint sensor if the prompt is visible.
    const isPromptVisible = PLACE_FINGER_MARKERS.some((re) => re.test(src));
    const timeSinceLastTrigger = Date.now() - lastTriggerTime;

    if (isPromptVisible) {
      if (timeSinceLastTrigger > 2000) {
        log("pump: fingerprint prompt visible, triggering touch");
        await triggerFingerprintTouch(driver);
        lastTriggerTime = Date.now();
      }
    } else if (src.length < 500) {
      // If screen is "empty", it might be a secure window containing the prompt.
      // In this case we still pump but slower.
      if (timeSinceLastTrigger > 3000) {
        log("pump: screen empty (secure window?), triggering fallback touch");
        await triggerFingerprintTouch(driver);
        lastTriggerTime = Date.now();
      }
    }

    await new Promise((r) => setTimeout(r, intervalMs));
  }
  log("pump: timed out");
  return false;
}

async function getPageSource(driver: Driver): Promise<string> {
  const start = Date.now();
  try {
    let src = await driver.getPageSource().catch(() => "");
    if ((!src || src.length < 200) && PLATFORM === "android") {
      // Fallback to adb uiautomator dump for secure/system screens.
      adbSilent(["shell", "uiautomator", "dump", "/sdcard/view.xml"]);
      const dumped = adbSilent(["shell", "cat", "/sdcard/view.xml"]);
      if (dumped && dumped.length > 200) src = dumped;
    }
    const elapsed = Date.now() - start;
    if (elapsed > 3000) log(`getPageSource took ${elapsed}ms`);
    return src;
  } catch {
    return "";
  }
}

async function pageSourceContains(driver: Driver, patterns: RegExp[]): Promise<RegExp | null> {
  const src = await getPageSource(driver);
  for (const p of patterns) if (p.test(src)) return p;
  return null;
}

export async function currentActivity(): Promise<string> {
  // `dumpsys window` is the most reliable source for the focused
  // window's package/activity across API 28..34.
  const out = adbSilent(["shell", "dumpsys", "window"]);
  // Match mCurrentFocus=Window{... u0 pkg/activity} or mCurrentFocus=null
  const focusMatch = out.match(/mCurrentFocus=Window\{.*?\s([a-zA-Z0-9_.]+)\/([a-zA-Z0-9_.$]+)\}/);
  if (focusMatch) return `${focusMatch[1]}/${focusMatch[2]}`;

  const windowMatch = out.match(
    /mFocusedWindow=Window\{.*?\s([a-zA-Z0-9_.]+)\/([a-zA-Z0-9_.$]+)\}/,
  );
  if (windowMatch) return `${windowMatch[1]}/${windowMatch[2]}`;

  // Fallback 1: mFocusedApp (sometimes focus is in transition)
  const appMatch = out.match(/mFocusedApp=.*?\b([a-zA-Z0-9_.]+)\/([a-zA-Z0-9_.$]+)/);
  if (appMatch) return `${appMatch[1]}/${appMatch[2]}`;

  // Fallback 2: mResumedActivity
  const resumedMatch = out.match(/mResumedActivity:.*?\b([a-zA-Z0-9_.]+)\/([a-zA-Z0-9_.$]+)/);
  if (resumedMatch) return `${resumedMatch[1]}/${resumedMatch[2]}`;

  return "";
}

export async function currentPackage(): Promise<string> {
  const act = await currentActivity();
  return act.split("/")[0] || "";
}

/** True if `dumpsys fingerprint` reports at least one enrolled finger. */
function fingerprintEnrolledOnDevice(): boolean {
  const out = adbSilent(["shell", "dumpsys", "fingerprint"]);
  // Match both legacy and API-34 formats:
  //   "enrolledFingerprints (1): [Fingerprint: ...]"
  //   "hasEnrolledFingerprints=true"
  //   "Enrollments: 1"
  if (/hasEnrolledFingerprints\s*=\s*true/i.test(out)) return true;
  if (/enrolledFingerprints\s*\(\s*[1-9]\d*\s*\)/i.test(out)) return true;
  if (/Enrollments?:\s*[1-9]\d*\b/i.test(out)) return true;
  if (/"count"\s*:\s*[1-9]\d*/i.test(out)) return true;
  // `dumpsys biometric` fallback (API 34).
  const bio = adbSilent(["shell", "dumpsys", "biometric"]);
  if (/authenticatorIds=\{[^}]*[1-9]/i.test(bio)) return true;
  return false;
}

/**
 * Extract visible button-like text/content-desc nodes from a UiAutomator
 * page source for diagnostic logging + label-driven wizard navigation.
 */
function extractClickableLabels(src: string): string[] {
  const labels = new Set<string>();
  // Match any text="..." or content-desc="..." attribute in the XML.
  // We use a broad regex because Appium's getPageSource output varies by
  // driver version and we want maximum visibility in logs.
  const rx = /(?:text|content-desc)="([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(src))) {
    const label = m[1].trim();
    if (label && label.length > 0 && label.length < 80) {
      labels.add(label);
    }
  }
  return [...labels];
}

/**
 * Perform a vertical swipe to scroll down (moving content up).
 * Uses adb for robustness on system/secure screens.
 */
async function swipeUp(): Promise<void> {
  log("wizard: swiping up...");
  // Swipe from middle-bottom to middle-top.
  adbSilent(["shell", "input", "swipe", "500", "1500", "500", "500", "300"]);
  await new Promise((r) => setTimeout(r, 800));
}

async function tapAnyButton(
  driver: Driver,
  labels: RegExp[],
  shouldSwipe = false,
): Promise<string | null> {
  const tryTap = async () => {
    // 1. Try text and content-desc with clickable(true)
    for (const re of labels) {
      const flags = re.flags.includes("i") ? "(?i)" : "";
      const pattern = `${flags}${re.source}`;

      // Try text
      let sel = `android=new UiSelector().textMatches("${pattern}").clickable(true)`;
      let el = await driver.$(sel);
      if (await el.isExisting().catch(() => false)) {
        if (
          await el
            .click()
            .then(() => true)
            .catch(() => false)
        )
          return re.source;
      }

      // Try content-desc
      sel = `android=new UiSelector().descriptionMatches("${pattern}").clickable(true)`;
      el = await driver.$(sel);
      if (await el.isExisting().catch(() => false)) {
        if (
          await el
            .click()
            .then(() => true)
            .catch(() => false)
        )
          return `(desc) ${re.source}`;
      }
    }

    // 2. Resource-ids (very common for "Next" buttons)
    const commonIds = [
      "button1",
      "next_button",
      "continue_button",
      "suw_navbar_next",
      "sud_navbar_next",
    ];
    for (const id of commonIds) {
      const sel = `android=new UiSelector().resourceIdMatches(".*:id/${id}").clickable(true)`;
      const el = await driver.$(sel);
      if (await el.isExisting().catch(() => false)) {
        if (
          await el
            .click()
            .then(() => true)
            .catch(() => false)
        )
          return `(id) ${id}`;
      }
    }

    // 3. Ultimate fallback: try clicking by text even if NOT marked clickable="true"
    for (const re of labels) {
      const flags = re.flags.includes("i") ? "(?i)" : "";
      const sel = `android=new UiSelector().textMatches("${flags}${re.source}")`;
      const el = await driver.$(sel);
      if (await el.isExisting().catch(() => false)) {
        if (
          await el
            .click()
            .then(() => true)
            .catch(() => false)
        )
          return `(unclickable) ${re.source}`;
      }
    }
    return null;
  };

  let hit = await tryTap();
  if (hit) return hit;

  if (shouldSwipe) {
    // If not found, maybe it's off-screen. Try one swipe and look again.
    // This is helpful for "Pixel Imprint" / "I agree" screens.
    await swipeUp();
    hit = await tryTap();
    return hit;
  }
  return null;
}

async function enterPinIfPrompted(driver: Driver, pin = DEFAULT_PIN): Promise<boolean> {
  const hit = await pageSourceContains(driver, [
    /Enter your PIN/i,
    /Confirm your PIN/i,
    /Re-enter your PIN/i,
    /Enter PIN/i,
    /PIN area/i,
  ]);

  // Also check activity if screen is "empty" (potential FLAG_SECURE).
  const activity = await currentActivity();
  const isPinScreen = /ConfirmDeviceCredential|ConfirmLockPassword/i.test(activity);

  if (!hit && !isPinScreen) return false;

  if (isPinScreen && !hit) {
    log(`wizard: possible secure PIN screen (activity=${activity}), attempting blind entry...`);
  } else {
    log("wizard: entering PIN...");
  }

  const typeAndEnter = async () => {
    // 1. Try input text (fastest, works on most AOSP images).
    log("wizard: attempting 'input text' for PIN...");
    adbSilent(["shell", "input", "text", pin]);
    adbSilent(["shell", "input", "keyevent", "66"]); // KEYCODE_ENTER
    await new Promise((r) => setTimeout(r, 800));

    // 2. If still on PIN screen, try individual keyevents (works on custom/secure PIN pads).
    const src = await getPageSource(driver);
    const stillThere = [/PIN area/i, /Enter.*PIN/i, /Confirm.*PIN/i, /Re-enter/i].some((re) =>
      re.test(src),
    );
    if (stillThere) {
      log("wizard: PIN screen still visible after 'input text', trying keyevents...");
      // Backspace a bunch to clear the previous attempt.
      for (let i = 0; i < 12; i++) adbSilent(["shell", "input", "keyevent", "67"]);

      for (const char of pin) {
        const code = 7 + Number(char); // KEYCODE_0 is 7, KEYCODE_1 is 8...
        adbSilent(["shell", "input", "keyevent", String(code)]);
        await new Promise((r) => setTimeout(r, 150));
      }
      adbSilent(["shell", "input", "keyevent", "66"]); // KEYCODE_ENTER
      await new Promise((r) => setTimeout(r, 1000));

      // 3. Try clicking the "Enter" button if it exists in the source we just got.
      if (src.includes('text="Enter"') || src.includes('content-desc="Enter"')) {
        log("wizard: found 'Enter' button, tapping...");
        await tapAnyButton(driver, [/Enter/i]);
      }
    }
  };

  await typeAndEnter();

  // If we are still on the PIN screen after a moment, try clicking buttons.
  // We poll activity for a faster transition.
  let isStillPin = true;
  for (let i = 0; i < 6; i++) {
    const activity = await currentActivity();
    if (!/ConfirmDeviceCredential|ConfirmLockPassword/i.test(activity)) {
      isStillPin = false;
      break;
    }
    await new Promise((r) => setTimeout(r, 400));
  }

  if (
    isStillPin &&
    (await pageSourceContains(driver, [/PIN area/i, /Enter.*PIN/i, /Confirm.*PIN/i, /Re-enter/i]))
  ) {
    log("wizard: PIN screen still visible, trying button clicks...");
    // Click "PIN area" first to focus it.
    await tapAnyButton(driver, [/PIN area/i]);

    for (const char of pin) {
      // Tap the digit button.
      await tapAnyButton(driver, [new RegExp(`^${char}$`)]);
    }
    // Try clicking any "Next" or "Enter" button that appeared or was already there.
    await tapAnyButton(driver, [/Next/i, /Enter/i, /Confirm/i, /Done/i, /OK/i, /Continue/i]);
    // And another Enter keyevent.
    adbSilent(["shell", "input", "keyevent", "66"]);
  }

  return true;
}

let enrollmentAttempted = false;
let enrollmentSucceeded = false;

/**
 * Unified entry point to ensure biometrics (Face ID / Fingerprint) are
 * enrolled on the current platform's virtual device. Throws if
 * enrollment fails on a platform that supports it.
 */
export async function ensureBiometricEnrolled(driver: Driver): Promise<boolean> {
  if (PLATFORM === "ios") {
    return ensureIosBiometricEnrolled(driver);
  }
  if (PLATFORM === "android") {
    return ensureAndroidFingerprintEnrolled(driver);
  }
  return true;
}

/**
 * Enable Face ID enrollment on the iOS simulator via Appium's
 * `mobile: enrollBiometric` extension.
 */
export async function ensureIosBiometricEnrolled(driver: Driver): Promise<boolean> {
  if (PLATFORM !== "ios") return true;
  try {
    const anyDriver = driver as unknown as {
      execute: (script: string, args: unknown) => Promise<unknown>;
    };
    await anyDriver.execute("mobile: enrollBiometric", { isEnabled: true });
    log("ios: biometric enrollment enabled");
    return true;
  } catch (e) {
    log("ios: biometric enrollment failed:", e);
    return false;
  }
}

/**
 * Reset the device state by clearing all fingerprints and PINs.
 * This ensures the AVD is "fresh" for the test run.
 */
async function resetDeviceState(): Promise<void> {
  log("resetting device state...");
  // Clear any existing PIN. This also clears fingerprints.
  // The magic number 1234 is a common default or previously set PIN.
  // Try with common PINs just in case.
  for (const p of [DEFAULT_PIN, "1234", "0000", "1111"]) {
    adbSilent(["shell", "locksettings", "clear", "--old", p]);
  }
  // Force a clean state.
  adbSilent(["shell", "locksettings", "clear"]);
  // Clear settings app data to reset wizard states.
  adbSilent(["shell", "pm", "clear", "com.android.settings"]);
  log("device state reset complete");
}

/**
 * Drive `android.settings.BIOMETRIC_ENROLL` / `FINGERPRINT_ENROLL` to
 * completion on the emulator so subsequent passkey / biometric prompts
 * can be satisfied with `adb emu finger touch`.
 *
 * Idempotent: if the fingerprint is already enrolled (detected via
 * `dumpsys fingerprint`) the wizard is skipped. Returns `true` if the
 * emulator has at least one finger enrolled when the call returns.
 */
export async function ensureAndroidFingerprintEnrolled(driver: Driver): Promise<boolean> {
  if (!isAndroidEmulator()) return false;
  if (enrollmentSucceeded) return true;
  if (enrollmentAttempted && !enrollmentSucceeded) return false;
  enrollmentAttempted = true;

  await resetDeviceState();

  // Pre-flight diagnostics (always printed; cheap and invaluable when
  // CI flakes on a new image revision).
  log(
    "preflight:",
    "fingerprint-feature=" +
      (adbSilent(["shell", "pm", "list", "features"]).includes("fingerprint") ? "yes" : "no"),
  );
  log(
    "preflight: BIOMETRIC_ENROLL resolves to:",
    adbSilent([
      "shell",
      "cmd",
      "package",
      "resolve-activity",
      "-a",
      "android.settings.BIOMETRIC_ENROLL",
    ])
      .replace(/\s+/g, " ")
      .slice(0, 200),
  );

  // Quick exit if a finger is already enrolled (e.g. AVD cache warm).
  if (fingerprintEnrolledOnDevice()) {
    log("preflight: finger already enrolled, skipping wizard");
    enrollmentSucceeded = true;
    return true;
  }

  // Make sure a device credential exists — the enrollment wizard will
  // hand off to the "Confirm your PIN" screen otherwise and stall.
  adbSilent(["shell", "locksettings", "set-pin", DEFAULT_PIN]);

  // After `locksettings set-pin` the keyguard can be up (on top of
  // `com.android.systemui`), which prevents any `am start` activity
  // from becoming the focused window. Wake the device, dismiss the
  // keyguard (requires PIN since API 28, so feed it), and only then
  // launch the enrollment intent.
  const unlockDevice = async (): Promise<void> => {
    log("unlocking device...");
    adbSilent(["shell", "input", "keyevent", "KEYCODE_WAKEUP"]);
    adbSilent(["shell", "wm", "dismiss-keyguard"]);
    // Keyevent 82 is "Menu", which on many emulator images bypasses
    // the "Swipe up to unlock" screen.
    adbSilent(["shell", "input", "keyevent", "82"]);
    adbSilent(["shell", "input", "keyevent", "KEYCODE_ESCAPE"]);
    await new Promise((r) => setTimeout(r, 500));

    // If the PIN entry is showing (post-dismiss), feed it.
    for (let i = 0; i < 3; i++) {
      const policy = adbSilent(["shell", "dumpsys", "window", "policy"]);
      const isLocked = /mKeyguardShowing=true|isKeyguardShowing=true|mShowingLockscreen=true/i.test(
        policy,
      );
      const pkg = await currentPackage();

      if (isLocked || /systemui|keyguard/i.test(pkg)) {
        log(`unlock: device is locked (pkg=${pkg}), entering PIN (attempt ${i + 1})`);
        // Swipe up as a fallback for newer images
        adbSilent(["shell", "input", "swipe", "500", "1500", "500", "500"]);
        await new Promise((r) => setTimeout(r, 500));
        adbSilent(["shell", "input", "text", DEFAULT_PIN]);
        adbSilent(["shell", "input", "keyevent", "KEYCODE_ENTER"]);
        await new Promise((r) => setTimeout(r, 1000));
      } else {
        break;
      }
    }
  };

  // Launch the enrollment activity. Prioritize FINGERPRINT_ENROLL on
  // Play Store images as it's often more direct.
  const tryLaunch = async (action: string, extras: string[] = []): Promise<boolean> => {
    adbSilent(["shell", "am", "force-stop", "com.android.settings"]);
    await unlockDevice();
    log(`wizard: launching ${action}...`);
    // `am start -W` blocks until the target Activity reports launched
    const startOut = adbSilent(["shell", "am", "start", "-W", "-a", action, ...extras]);
    if (startOut.includes("Error") || startOut.includes("Exception")) {
      log(`wizard: launch failed: ${startOut.replace(/\s+/g, " ").slice(0, 100)}`);
    }

    for (let i = 0; i < 40; i++) {
      const act = await currentActivity();
      if (/settings/i.test(act)) {
        log(`wizard: Settings foreground (act=${act}) after ${i * 400}ms`);
        return true;
      }
      // If we landed back on keyguard (e.g. PIN entry required before
      // Settings opens biometric enroll), dismiss + enter PIN again.
      if (/systemui|keyguard/i.test(act)) {
        adbSilent(["shell", "wm", "dismiss-keyguard"]);
        adbSilent(["shell", "input", "text", DEFAULT_PIN]);
        adbSilent(["shell", "input", "keyevent", "66"]);
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  };

  const settingsLaunched =
    (await tryLaunch("android.settings.FINGERPRINT_ENROLL")) ||
    (await tryLaunch("android.settings.BIOMETRIC_ENROLL", [
      "--ei",
      "android.provider.extra.BIOMETRIC_AUTHENTICATORS_ALLOWED",
      "15",
    ])) ||
    (await tryLaunch("android.settings.FINGERPRINT_SETTINGS"));
  if (!settingsLaunched) {
    const act = await currentActivity();
    const keyguard =
      adbSilent(["shell", "dumpsys", "window", "policy"]).match(/mKeyguardShowing=(\w+)/)?.[1] ??
      "unknown";
    log(
      `wizard: Settings never came to foreground; bailing. focused-act=${act || "(none)"} keyguard=${keyguard}`,
    );
    log(
      "wizard: dumpsys power (partial) =",
      adbSilent(["shell", "dumpsys", "power"])
        .match(/mWakefulness=\w+|mScreenOn=\w+|mInteractive=\w+/g)
        ?.join(", ") || "unknown",
    );
    log("wizard: dumpsys window (tail) =", adbSilent(["shell", "dumpsys", "window"]).slice(-1000));
    await restoreAppFocus(driver);
    return false;
  }

  // Wait a moment for the initial wizard screen to render.
  await new Promise((r) => setTimeout(r, 200));

  const overallDeadline = Date.now() + 120_000;
  const doneMarkers = [/^Done$/i, /^Finish$/i, /^Got it$/i, /^I'm done$/i];
  const stepForwardMarkers = [
    /^Next$/i,
    /^Continue$/i,
    /^Start$/i,
    /^I agree$/i,
    /^Agree$/i,
    /^Agree & continue$/i,
    /^Accept$/i,
    /^OK$/i,
    /^Okay$/i,
    /^Got it$/i,
    /^Done$/i,
    /^Finish$/i,
    /^Set up$/i,
    /^Use fingerprint$/i,
    /^Yes, I'm in$/i,
    /^I'm in$/i,
    /^Turn on$/i,
    /^Confirm$/i,
    /^Enter$/i,
    // Catch-all for varied labels
    /^Fingerprint unlock$/i,
    /^Add fingerprint$/i,
  ];

  let lastScreenSignature = "";
  let sameScreenCount = 0;

  while (Date.now() < overallDeadline) {
    if (fingerprintEnrolledOnDevice()) {
      log("wizard: dumpsys reports enrolled, finishing");
      enrollmentSucceeded = true;
      // Tap Done if the summary screen is up; harmless if not.
      await tapAnyButton(driver, doneMarkers);
      break;
    }

    const src = await getPageSource(driver);
    const sig = src.slice(0, 4096);
    if (sig === lastScreenSignature) {
      sameScreenCount++;
      if (sameScreenCount === 4) {
        log("wizard: screen unchanged, swiping up to reveal more...");
        await swipeUp();
      }
    } else {
      sameScreenCount = 0;
      lastScreenSignature = sig;
      const act = await currentActivity();
      const pkg = await currentPackage();
      const labels = extractClickableLabels(src);
      log(`wizard: screen change (act=${act}), clickable labels:`, labels.slice(0, 30));

      // If focus lost unexpectedly, try to bring Settings back.
      if (
        !/settings|systemui|keyguard|confirm|enroll/i.test(pkg) &&
        pkg !== "" &&
        Date.now() < overallDeadline - 5000
      ) {
        log(`wizard: focus lost to ${pkg} (act=${act}), attempting to re-launch Settings...`);
        const ok = await tryLaunch("android.settings.FINGERPRINT_ENROLL");
        if (ok) {
          log("wizard: successfully re-launched Settings");
          sameScreenCount = 0;
          continue;
        } else {
          log("wizard: failed to re-launch Settings; continuing anyway");
        }
      }

      if (labels.length === 0 && src.length < 500) {
        log("wizard: screen source is very short/empty, possible secure window or loading state.");
      }
    }

    // 1. Are we on the "place your finger" screen? Pump touches hard.
    if (PLACE_FINGER_MARKERS.some((re) => re.test(src))) {
      log("wizard: place-finger screen; pumping touches");
      for (let i = 0; i < 8; i++) {
        await triggerFingerprintTouch(driver);
        await new Promise((r) => setTimeout(r, 400));
        if (fingerprintEnrolledOnDevice()) break;
      }
      // After the sensor screen usually a "Done" / "Next" follows.
      continue;
    }

    // 2. PIN confirmation.
    if (await enterPinIfPrompted(driver)) {
      sameScreenCount = 0; // Reset count as we just interacted
      await new Promise((r) => setTimeout(r, 200));
      continue;
    }

    // 3. Terminal "Done".
    const doneHit = await tapAnyButton(driver, doneMarkers);
    if (doneHit && fingerprintEnrolledOnDevice()) {
      log("wizard: Done clicked:", doneHit);
      enrollmentSucceeded = true;
      break;
    }

    // 4. "More" button (common on Pixel Imprint/Agree screens).
    // Prioritize this to navigate to Agree without a blind swipe.
    const moreHit = await tapAnyButton(driver, [/^More$/i]);
    if (moreHit) {
      log("wizard: 'More' clicked, scrolling down");
      await new Promise((r) => setTimeout(r, 500));
      continue;
    }

    // 5. Step-forward button.
    const stepHit = await tapAnyButton(driver, stepForwardMarkers);
    if (stepHit) {
      log("wizard: stepped forward via:", stepHit);
      await new Promise((r) => setTimeout(r, 400));
      continue;
    }

    // 6. Scroll if we seem stuck or on a long page (like Pixel Imprint)
    if (sameScreenCount > 3) {
      await swipeUp();
      sameScreenCount = 0;
      continue;
    }

    // 7. Unrecognised screen — feed a touch (harmless if not on sensor
    // screen) and wait. If nothing changes for too long, bail.
    await triggerFingerprintTouch(driver);
    await new Promise((r) => setTimeout(r, 500));

    if (sameScreenCount > 20) {
      log(
        "wizard: screen unchanged for ~10s, giving up. Last labels:",
        extractClickableLabels(src),
      );
      break;
    }
  }

  // Double-check by querying the service directly.
  if (!enrollmentSucceeded && fingerprintEnrolledOnDevice()) {
    enrollmentSucceeded = true;
  }

  if (!enrollmentSucceeded) {
    log("wizard: enrollment FAILED; final dumpsys fingerprint =");
    log(adbSilent(["shell", "dumpsys", "fingerprint"]).slice(0, 800));
  } else {
    log("wizard: enrollment SUCCEEDED");
  }

  // Return focus to the example app regardless of outcome so the first
  // test can still run its non-biometric assertions.
  await restoreAppFocus(driver);

  return enrollmentSucceeded;
}

/**
 * Bring the RN example app back to the foreground after we navigated
 * into Settings for fingerprint enrollment. Uses Appium's
 * `mobile: activateApp` first (correct native API, survives Settings
 * task being on top), falling back to `am start` / `monkey` if the
 * Appium command is unavailable on the current driver build.
 */
export async function restoreAppFocus(driver: Driver): Promise<void> {
  // 0. If we're already in the app, do nothing.
  const pkg = await currentPackage();
  if (pkg === ANDROID_PACKAGE) {
    log("restoreAppFocus: already in app, skipping");
    return;
  }

  log(`restoreAppFocus: in ${pkg}, returning to ${ANDROID_PACKAGE}`);

  // 1. Close any Settings-owned activity cluttering the back stack.
  adbSilent(["shell", "input", "keyevent", "KEYCODE_HOME"]);
  await new Promise((r) => setTimeout(r, 300));

  // 2. Ask Appium to bring the RN app forward (preferred path).
  try {
    // `activateApp` is exposed on UiAutomator2 sessions.
    const anyDriver = driver as unknown as {
      activateApp?: (pkg: string) => Promise<void>;
      execute?: (script: string, args: unknown) => Promise<unknown>;
    };
    if (typeof anyDriver.activateApp === "function") {
      await anyDriver.activateApp(ANDROID_PACKAGE);
    } else if (typeof anyDriver.execute === "function") {
      await anyDriver.execute("mobile: activateApp", { appId: ANDROID_PACKAGE });
    }
  } catch {
    // Fall through to adb fallbacks below.
  }

  // 3. Best-effort adb fallbacks.
  adbSilent([
    "shell",
    "monkey",
    "-p",
    ANDROID_PACKAGE,
    "-c",
    "android.intent.category.LAUNCHER",
    "1",
  ]);

  // 4. Verify focus returned; poll briefly.
  for (let i = 0; i < 15; i++) {
    if ((await currentPackage()) === ANDROID_PACKAGE) return;
    await new Promise((r) => setTimeout(r, 400));
  }
}
