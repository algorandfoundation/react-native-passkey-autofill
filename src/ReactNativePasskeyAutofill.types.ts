export type ReactNativePasskeyAutofillModuleEvents = {
  onPasskeyAdded: (event: { success: boolean }) => void;
  onPasskeyAuthenticated: (event: { success: boolean; credentialId?: string }) => void;
};

export type PasskeyAutofillCredentialIdentity = {
  credentialId: string;
  relyingPartyIdentifier?: string;
  rpId?: string;
  origin?: string;
  userName?: string;
  name?: string;
  userHandle: string;
  userId?: string;
  privateKey?: string;
  privateKeyBase64?: string;
  publicKey?: string;
  publicKeyBase64?: string;
  createdAt?: number;
  lastUsedAt?: number;
  parentKeyId?: string;
  /**
   * The version of the identity derivation logic used for this credential.
   * Pinned for the life of the credential.
   */
  derivationVersion?: number;
  /**
   * The scheme the passkey key was derived from. Absent means "bip32-ed25519".
   * Pinned for the life of the credential — changing it changes the secret
   * every relying party is bound to.
   */
  derivationScheme?: string;
};

/**
 * Capabilities advertised by this credential provider. Exposed so the
 * surrounding wallet UI / RP-side wallet can know which WebAuthn extensions
 * are wired up natively before issuing a passkey request.
 */
export type PasskeyAutofillCapabilities = {
  /**
   * Whether the WebAuthn `prf` extension (a.k.a. `hmac-secret`) is supported
   * by this credential provider. PRF outputs are derived deterministically
   * from the wallet's parent secret (the P-256 main key or legacy HD root)
   * so that restoring the wallet seed reproduces the same secrets on another
   * device.
   */
  prf: boolean;
};

export const PASSKEY_AUTOFILL_CAPABILITIES: PasskeyAutofillCapabilities = {
  prf: true,
};
