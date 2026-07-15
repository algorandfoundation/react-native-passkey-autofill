import { Store } from "@tanstack/store";
import ReactNativePasskeyAutofill from "@algorandfoundation/react-native-passkey-autofill";
import { initializeKeyStore, Key, KeyData, KeyStoreState } from "@algorandfoundation/keystore";
import { fetchSecret, getMasterKey, storage } from "@algorandfoundation/react-native-keystore";
import { keyStore } from "./stores/keystore";
import { passkeysStore } from "./stores/passkeys";

/**
 * This is required when a key is modified outside of our control
 * This eventually will just be a part of the passkey extension.
 */
export async function fullReload() {
  const secrets = await Promise.all(
    storage
      .getAllKeys()
      .map(async (keyId) =>
        fetchSecret<KeyData>({ keyId, options: { masterKey: await getMasterKey() } }),
      ),
  );
  const keys = secrets
    .filter((k) => k !== null)
    .map(({ privateKey: _privateKey, ...rest }: KeyData) => rest) as Key[];
  initializeKeyStore({
    store: keyStore as unknown as Store<KeyStoreState>,
    keys,
  });
}

export async function bootstrap() {
  // Configure Autofill
  const masterKey = await getMasterKey();

  // Set master key in native side BEFORE reloading. Pass the raw bytes (not a
  // hex string) so the secret never becomes a non-zeroable JS string.
  await ReactNativePasskeyAutofill.setMasterKey(Uint8Array.from(masterKey));

  // Reload keys into the JS store
  await fullReload();

  const secrets = await Promise.all(
    storage
      .getAllKeys()
      .map(async (keyId) =>
        fetchSecret<KeyData>({ keyId, options: { masterKey: await getMasterKey() } }),
      ),
  );

  const keys = secrets
    .filter((k) => k !== null)
    .map(({ privateKey: _privateKey, ...rest }: KeyData) => rest) as Key[];

  const hdRootKey = keys.find(
    (k) => k.type === "hd-root-key" || k.type === "xhd-root-key" || k.type === "hd-seed",
  );

  if (hdRootKey) {
    await ReactNativePasskeyAutofill.setHdRootKeyId(hdRootKey.id);
  }

  await ReactNativePasskeyAutofill.refreshCredentialIdentities();
  await syncNativePasskeys();

  ReactNativePasskeyAutofill.configureIntentActions(
    "co.algorand.passkeyautofill.GET_PASSKEY",
    "co.algorand.passkeyautofill.CREATE_PASSKEY",
  ).catch(console.error);
}

async function syncNativePasskeys() {
  const credentials = await ReactNativePasskeyAutofill.getStoredCredentials();
  passkeysStore.setState((state) => {
    // Index existing passkeys by id so updates collapse to a single entry.
    const existingById = new Map(state.passkeys.map((passkey) => [passkey.id, passkey]));

    for (const credential of credentials) {
      const id = credential.credentialId;
      const publicKey = credential.publicKey ?? credential.publicKeyBase64;
      if (!id || !publicKey) continue;

      const publicKeyBytes = base64ToBytes(publicKey);

      for (const [existingId, existing] of existingById) {
        if (existingId !== id && publicKeysEqual(existing.publicKey, publicKeyBytes)) {
          existingById.delete(existingId);
        }
      }

      existingById.set(id, {
        id,
        name: credential.userName ?? credential.relyingPartyIdentifier ?? "Unnamed Passkey",
        publicKey: publicKeyBytes,
        algorithm: "ES256",
        metadata: {
          origin: credential.relyingPartyIdentifier,
          userHandle: credential.userHandle,
          parentKeyId: credential.parentKeyId,
        },
      });
    }
    return {
      ...state,
      passkeys: Array.from(existingById.values()),
    };
  });
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

function publicKeysEqual(a: Uint8Array | undefined, b: Uint8Array): boolean {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
