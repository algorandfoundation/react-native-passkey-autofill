export type ReactNativePasskeyAutofillModuleEvents = {
  onPasskeyAdded: (event: { success: boolean }) => void;
  onPasskeyAuthenticated: (event: { success: boolean }) => void;
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
};
