import { execFile, execFileSync } from "node:child_process";

/**
 * Common ADB helpers to ensure consistent device targeting across the E2E suite.
 */

export function getAdbSerial(): string {
  if (process.env.ANDROID_UDID) return process.env.ANDROID_UDID;

  // Try to find the first connected emulator or device.
  try {
    const devices = execFileSync("adb", ["devices"], {
      encoding: "utf8",
      timeout: 5000,
    })
      .split("\n")
      .slice(1)
      .filter((l) => l.includes("\tdevice"))
      .map((l) => l.split("\t")[0].trim());

    if (devices.length === 1) return devices[0];
    if (devices.length > 1) {
      const emulators = devices.filter((d) => d.startsWith("emulator-"));
      if (emulators.length > 0) return emulators[0];
      return devices[0];
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn("[e2e:adb] failed to list devices via adb:", (err as Error).message);
  }

  return "emulator-5554";
}

/**
 * Wrap adb so we can swap serials / run headless without inheriting
 * stdin from the caller (Jest runners hate dangling fds).
 */
export function adb(args: string[], opts: { timeout?: number } = {}): string {
  const serial = getAdbSerial();
  try {
    return execFileSync("adb", ["-s", serial, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: opts.timeout ?? 15_000,
    }).trim();
  } catch (err) {
    const error = err as Error & { stderr?: string };
    const msg = error.stderr ? `${error.message}\n${error.stderr}` : error.message;
    throw new Error(`adb command failed: adb -s ${serial} ${args.join(" ")}\n${msg}`);
  }
}

export function adbSilent(args: string[]): string {
  try {
    const serial = getAdbSerial();
    return execFileSync("adb", ["-s", serial, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 15_000,
    }).trim();
  } catch {
    return "";
  }
}

export function adbAsync(args: string[]): void {
  // Fire-and-forget, used for the finger-touch spam where we don't
  // want to block the test thread on adb's per-call latency (~50ms).
  const serial = getAdbSerial();
  const child = execFile("adb", ["-s", serial, ...args], () => undefined);
  child.stdin?.end();
}
