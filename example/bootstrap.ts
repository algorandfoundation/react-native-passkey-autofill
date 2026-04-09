import { Store } from "@tanstack/store";
import ReactNativePasskeyAutofill from "@algorandfoundation/react-native-passkey-autofill";
import {
  clearKeyData,
  initializeKeyStore,
  Key,
  KeyData,
  KeyStoreState,
} from "@algorandfoundation/keystore";
import { fetchSecret, getMasterKey, storage } from "@algorandfoundation/react-native-keystore";
import { keyStore } from "./stores/keystore";

/**
 * This is required when a key is modified outside of our control
 * This eventually will just be a part of the passkey extension.
 */
export async function fullReload() {
  /*
        const _keys = storage.getAllKeys()
        _keys.forEach((keyId) => {
            const secret = storage.getString(keyId)
        })
    */

  const secrets = await Promise.all(
    storage
      .getAllKeys()
      .map(async (keyId) => fetchSecret<KeyData>({ keyId, masterKey: await getMasterKey() })),
  );
  const keys = secrets
    .filter((k) => k !== null)
    .map(({ privateKey, ...rest }: KeyData) => rest) as Key[];
  initializeKeyStore({
    store: keyStore as unknown as Store<KeyStoreState>,
    keys,
  });
}

export async function bootstrap() {
  // Configure Autofill
  const masterKey = await getMasterKey();

  // Set master key in native side BEFORE reloading
  await ReactNativePasskeyAutofill.setMasterKey(masterKey.toString("hex"));

  // Reload keys into the JS store
  await fullReload();

  const secrets = await Promise.all(
    storage
      .getAllKeys()
      .map(async (keyId) => fetchSecret<KeyData>({ keyId, masterKey: await getMasterKey() })),
  );

  const keys = secrets
    .filter((k) => k !== null)
    .map(({ privateKey, ...rest }: KeyData) => rest) as Key[];

  const hdRootKey = keys.find(
    (k) => k.type === "hd-root-key" || k.type === "xhd-root-key" || k.type === "hd-seed",
  );

  if (hdRootKey) {
    await ReactNativePasskeyAutofill.setHdRootKeyId(hdRootKey.id);
  }

  ReactNativePasskeyAutofill.configureIntentActions(
    "co.algorand.passkeyautofill.GET_PASSKEY",
    "co.algorand.passkeyautofill.CREATE_PASSKEY",
  ).catch(console.error);
}
