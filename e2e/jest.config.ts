import type { Config } from "jest";

/**
 * Jest configuration for Appium / WebdriverIO end-to-end tests.
 *
 * Each test file bootstraps its own WebdriverIO `remote()` session via
 * `driver/session.ts`, so we run a single worker and give each spec a
 * generous timeout to account for native app cold starts + WebAuthn UI.
 */
const config: Config = {
  preset: "ts-jest",
  testEnvironment: "node",
  rootDir: ".",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  testTimeout: 5 * 60 * 1000,
  maxWorkers: 1,
  verbose: true,
};

export default config;
