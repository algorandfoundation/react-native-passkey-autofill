import { PLATFORM, ANDROID_PACKAGE } from "./capabilities";
import { adb, adbSilent } from "./adb";

/**
 * Credential Manager provider registration helper (Android only).
 *
 * Why this file exists
 * --------------------
 * On Android 14 the Credential Manager only routes `BeginCreate*` /
 * `BeginGet*` requests to credential-provider services that the user has
 * explicitly enabled in Settings → Passwords, passkeys & accounts →
 * Additional providers. A freshly booted AVD has **no** providers
 * enabled, so:
 *
 *   - `handleCreatePasskey` opens a Credential Manager sheet that lists
 *     zero providers, the consent screen is dismissed by the system, and
 *     our service never receives a `BeginCreateCredentialRequest` — so
 *     `provider-status` stays `inactive` forever.
 *   - Every test after "creates an XHD Ed25519 key" then fails because
 *     the passkey flow deadlocks on an empty system UI.
 *
 * Settings → Additional providers writes the enabled component names to
 * the secure setting `credential_service` (comma-separated) and the
 * primary provider to `credential_service_primary`. We can do the same
 * thing via `adb shell settings put secure ...` — the `adb shell` user
 * already holds `WRITE_SECURE_SETTINGS`, so no root / magisk required.
 *
 * This helper is idempotent and a no-op on iOS / when the
 * target APK isn't installed.
 */

function isAndroidTarget(): boolean {
  return PLATFORM === "android";
}

let registered = false;

/**
 * Enable our passkey provider service as the system's credential
 * provider so Credential Manager actually routes requests to it.
 *
 * Returns `true` if the `credential_service` secure setting ends up
 * containing our component. Safe to call repeatedly; no-ops on iOS.
 */
// Must stay in sync with `android/src/main/AndroidManifest.xml` and
// `android/build.gradle` (`namespace`). The component name is:
//   <applicationId>/<library-namespace>.service.PasskeyAutofillCredentialProviderService
// i.e. the host app id + the FQCN of the service declared by the
// library whose manifest is merged into the example app.
const SERVICE_FQCN = "co.algorand.passkeyautofill.service.PasskeyAutofillCredentialProviderService";

export async function ensureAndroidCredentialProviderEnabled(): Promise<boolean> {
  if (!isAndroidTarget()) return false;
  if (registered) return true;

  const component = `${ANDROID_PACKAGE}/${SERVICE_FQCN}`;

  // Guard: the service must actually be installed — otherwise the
  // Credential Manager silently drops the component on first use and
  // our `settings put` is effectively a no-op.
  const pmCheck = adbSilent(["shell", "pm", "list", "packages", ANDROID_PACKAGE]);
  if (!pmCheck.includes(ANDROID_PACKAGE)) {
    // eslint-disable-next-line no-console
    console.warn(
      `[e2e] credential-provider: ${ANDROID_PACKAGE} not installed yet; ` +
        "skipping provider registration.",
    );
    return false;
  }

  // Write both the primary slot and the list slot. Different AOSP
  // builds read one or the other (Android 14 stock uses
  // `credential_service_primary` for the default, `credential_service`
  // for additional providers); setting both makes us the only
  // configured provider either way.
  adbSilent(["shell", "settings", "put", "secure", "credential_service", component]);
  adbSilent(["shell", "settings", "put", "secure", "credential_service_primary", component]);

  // Some OEM Settings UIs also persist the enabled providers into
  // `autofill_service` when Autofill & Credential Manager share the
  // provider. Best-effort mirror; failure is fine.
  adbSilent(["shell", "settings", "put", "secure", "autofill_service", component]);

  // Verify what the system actually stored. `settings get` returns the
  // literal value or "null" if unset.
  const got = adbSilent(["shell", "settings", "get", "secure", "credential_service"]);
  const gotPrimary = adbSilent([
    "shell",
    "settings",
    "get",
    "secure",
    "credential_service_primary",
  ]);

  const ok = got.includes(component) || gotPrimary.includes(component);
  // eslint-disable-next-line no-console
  console.log(
    `[e2e] credential-provider: component=${component} registered=${ok} ` +
      `(credential_service=${got || "null"}, primary=${gotPrimary || "null"})`,
  );

  registered = ok;
  return ok;
}
