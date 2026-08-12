import { NativeModule, requireNativeModule } from "expo";
import { Platform } from "react-native";

import {
  PasskeyAutofillCredentialIdentity,
  ReactNativePasskeyAutofillModuleEvents,
} from "./ReactNativePasskeyAutofill.types";

declare class ReactNativePasskeyAutofillModule extends NativeModule<ReactNativePasskeyAutofillModuleEvents> {
  /**
   * Persists the keystore master key as **raw bytes**, so a non-zeroable hex
   * string is never materialized in the JS heap (immutable JS strings can't be
   * wiped and linger until GC). The caller should zero the `Uint8Array` after
   * the promise resolves.
   */
  setMasterKey(secret: Uint8Array): Promise<void>;
  /**
   * Sets the ID of the keystore record to use as the parent secret for passkey
   * derivation. The record must be a deterministic-P256 main key (64 bytes).
   */
  setMainKeyId(id: string): Promise<void>;
  /**
   * Returns the ID of the keystore record currently used as the parent secret
   * for passkey derivation.
   */
  getMainKeyId(): Promise<string | null>;
  /** @deprecated use {@link setMainKeyId} */
  setHdRootKeyId(id: string): Promise<void>;
  /** @deprecated use {@link getMainKeyId} */
  getHdRootKeyId(): Promise<string | null>;
  configureIntentActions(getPasskeyAction: string, createPasskeyAction: string): Promise<void>;
  clearCredentials(): Promise<void>;
  deleteCredential(credentialId: string): Promise<void>;
  /**
   * iOS: returns the identities currently published to the AutoFill
   * `ASCredentialIdentityStore`. Android: no-op returning `[]` because the
   * native Credential Provider service reads credentials directly from MMKV
   * and there is no separate identity store to query.
   */
  getStoredCredentials(): Promise<PasskeyAutofillCredentialIdentity[]>;
  /**
   * iOS: returns diagnostic strings from the AutoFill extension.
   * Android: no-op returning `[]`.
   */
  getDiagnostics(): Promise<string[]>;
  /**
   * Replaces the iOS AutoFill passkey identity store with credentials
   * available to the native Credential Provider extension. Each item must
   * include a credential id, relying party (`relyingPartyIdentifier`,
   * `rpId`, or `origin`), user handle, and P-256 private key material.
   * Android ignores this method (no-op) because the provider reads MMKV
   * directly.
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
const nativeModule = requireNativeModule<ReactNativePasskeyAutofillModule>(
  "ReactNativePasskeyAutofill",
);

// A handful of methods are only implemented in the iOS native module because
// they interact with `ASCredentialIdentityStore`, which has no Android
// equivalent (the Android Credential Provider service reads credentials
// directly from MMKV on each request).
if (Platform.OS === "android") {
  const noops: Record<string, (...args: unknown[]) => Promise<unknown>> = {
    replaceCredentialIdentities: () => Promise.resolve(),
    refreshCredentialIdentities: () => Promise.resolve(),
    getStoredCredentials: () => Promise.resolve([]),
    getDiagnostics: () => Promise.resolve([]),
  };
  for (const name of Object.keys(noops)) {
    if (typeof (nativeModule as unknown as Record<string, unknown>)[name] !== "function") {
      (nativeModule as unknown as Record<string, unknown>)[name] = noops[name];
    }
  }
}

export default nativeModule;
