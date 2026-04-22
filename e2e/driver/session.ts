import { remote, type Browser } from "webdriverio";

import {
  APPIUM_HOST,
  APPIUM_PORT,
  PLATFORM,
  capabilitiesForPlatform,
  type Platform,
} from "./capabilities";

export type Driver = Browser;

/**
 * Creates a WebdriverIO session against a locally running Appium server.
 * The caller is responsible for tearing the session down with `driver.deleteSession()`.
 */
export async function createDriver(platform: Platform = PLATFORM): Promise<Driver> {
  return remote({
    hostname: APPIUM_HOST,
    port: APPIUM_PORT,
    path: "/",
    logLevel: (process.env.WDIO_LOG_LEVEL as "error" | "warn" | "info" | "debug") ?? "warn",
    capabilities: capabilitiesForPlatform(platform),
  });
}
