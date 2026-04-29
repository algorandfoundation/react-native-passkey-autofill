import * as fs from "fs";
import * as path from "path";
import type { Driver } from "./session";
import { PLATFORM } from "./capabilities";

/**
 * Returns a locator string matching an element by its React Native
 * `testID`. On iOS (XCUITest) `testID` is surfaced as the accessibility
 * id, so the `~testID` tilde-selector works directly. On Android
 * (UiAutomator2) RN maps `testID` to the view's `resource-id` instead,
 * so we build a UiSelector querying `resourceId(...)`.
 */
export const byTestId = (testID: string): string => {
  if (PLATFORM === "ios") return `~${testID}`;
  // Android: check both resource-id (used by RN) and content-desc (used by
  // native activities). We also match the short :id/name suffix.
  return `//*[@resource-id='${testID}' or @content-desc='${testID}' or contains(@resource-id, ':id/${testID}') or @text='${testID}']`;
};

/**
 * Platform-neutral selector for native system dialogs triggered by
 * WebAuthn (passkey prompts, biometrics, save-password sheets).
 */
export const systemDialogButton = (label: string): string => {
  if (PLATFORM === "ios") {
    // iOS system alerts: CONTAINS match survives suffixes like "Create Passkey".
    return `-ios predicate string:type == 'XCUIElementTypeButton' AND name CONTAINS[c] '${label}'`;
  }
  // Android: case-insensitive substring match — intentionally *contains*,
  // not exact. We check both text and content-desc using XPath.
  const l = label.toLowerCase();
  const u = label.toUpperCase();
  return `//*[contains(@text, '${label}') or contains(@text, '${l}') or contains(@text, '${u}') or contains(@content-desc, '${label}') or contains(@content-desc, '${l}') or contains(@content-desc, '${u}')]`;
};

/**
 * Waits for an element to exist and be displayed, then taps it.
 */
export async function tap(driver: Driver, selector: string, timeoutMs = 15_000): Promise<void> {
  const el = await driver.$(selector);
  await el.waitForDisplayed({ timeout: timeoutMs });
  await el.click();
}

/**
 * Attempts to dismiss any OS-level passkey/biometric dialog by pressing
 * the affirmative button. No-op if the dialog is not present.
 */
export async function confirmSystemPrompt(
  driver: Driver,
  labels: string[] = ["Continue", "Allow", "Save", "Use Passkey", "Sign In"],
  timeoutMs = 10_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const label of labels) {
      const el = await driver.$(systemDialogButton(label));
      if (await el.isExisting().catch(() => false)) {
        await el.click().catch(() => undefined);
        return true;
      }
    }
    await driver.pause(500);
  }
  // eslint-disable-next-line no-console
  console.log(
    `[e2e] confirmSystemPrompt: timed out waiting for labels [${labels.join(", ")}]. Visible labels: ${await getVisibleLabels(driver)}`,
  );
  return false;
}

async function getVisibleLabels(driver: Driver): Promise<string[]> {
  try {
    const src = await driver.getPageSource();
    const rx = /(?:text|content-desc)="([^"]+)"/g;
    const labels = new Set<string>();
    let m;
    while ((m = rx.exec(src))) {
      const l = m[1].trim();
      if (l && l.length < 50) labels.add(l);
    }
    return [...labels];
  } catch {
    return [];
  }
}

/**
 * Capture a screenshot for review.
 */
export async function takeScreenshot(driver: Driver, name: string): Promise<void> {
  try {
    const b64 = await driver.takeScreenshot();
    const filename = `screenshot-${Date.now()}-${name.replace(/[^a-z0-9]/gi, "-").toLowerCase()}.png`;
    const fullPath = path.join(process.cwd(), filename);
    fs.writeFileSync(fullPath, Buffer.from(b64, "base64"));
    // eslint-disable-next-line no-console
    console.log(`[e2e] screenshot saved to ${filename}`);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[e2e] failed to take screenshot: ${e}`);
  }
}
