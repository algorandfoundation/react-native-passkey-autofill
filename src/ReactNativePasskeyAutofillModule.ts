import { NativeModule, requireNativeModule } from "expo";

import {
  PasskeyAutofillCredentialIdentity,
  ReactNativePasskeyAutofillModuleEvents,
} from "./ReactNativePasskeyAutofill.types";

declare class ReactNativePasskeyAutofillModule extends NativeModule<ReactNativePasskeyAutofillModuleEvents> {
  setMasterKey(secret: string): Promise<void>;
  setHdRootKeyId(id: string): Promise<void>;
  getHdRootKeyId(): Promise<string | null>;
  configureIntentActions(getPasskeyAction: string, createPasskeyAction: string): Promise<void>;
  clearCredentials(): Promise<void>;
  deleteCredential(credentialId: string): Promise<void>;
  getStoredCredentials(): Promise<PasskeyAutofillCredentialIdentity[]>;
  getDiagnostics(): Promise<string[]>;
  /**
   * Replaces the iOS AutoFill passkey identity store with credentials
   * available to the native Credential Provider extension. Each item must
   * include a credential id, relying party (`relyingPartyIdentifier`,
   * `rpId`, or `origin`), user handle, and P-256 private key material.
   * Android ignores this method because the provider reads MMKV directly.
   */
  replaceCredentialIdentities(credentials: PasskeyAutofillCredentialIdentity[]): Promise<void>;
  refreshCredentialIdentities(): Promise<void>;
  /**
   * Resolves to `true` when this app is registered as the active
   * credential/autofill provider on the current device (Android 14+
   * credential provider or iOS AutoFill). Useful for gating passkey UI
   * and for E2E tests that need to confirm the prompt that appears
   * belongs to this provider and not a third party.
   */
  isProviderActive(): Promise<boolean>;
  /**
   * Opens the OS credential/autofill provider settings screen so the
   * user can enable this app as the active provider. Resolves to `true`
   * if a settings screen could be launched, `false` otherwise.
   */
  openProviderSettings(): Promise<boolean>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativePasskeyAutofillModule>("ReactNativePasskeyAutofill");
