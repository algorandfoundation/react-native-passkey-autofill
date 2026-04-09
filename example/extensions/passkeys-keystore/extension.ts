import type {
  Key,
  KeyStoreExtension,
  KeyStoreState,
  XHDDomainP256KeyData,
} from "@algorandfoundation/keystore";
import type { Passkey, PasskeyStoreExtension } from "../passkeys";
import type { Extension } from "@algorandfoundation/wallet-provider";
import type { Store } from "@tanstack/store";
import type { PasskeysKeystoreExtension, PasskeysKeystoreExtensionOptions } from "./types";

export const WithPasskeysKeystore: Extension<PasskeysKeystoreExtension> = (
  provider: KeyStoreExtension & PasskeyStoreExtension,
  options: PasskeysKeystoreExtensionOptions,
) => {
  if (!provider.passkey) {
    throw new Error(
      "PasskeysKeystore extension requires WithPasskeyStore extension to be present on the provider.",
    );
  }
  if (!provider.key) {
    throw new Error(
      "PasskeysKeystore extension requires WithKeyStore extension to be present on the provider.",
    );
  }

  const keyStore: Store<KeyStoreState> = options.keystore.store;
  const { autoPopulate = true } = options.passkeys.keystore ?? {};

  const createPasskeyFromKey = (key: XHDDomainP256KeyData): Passkey => {
    if (!key.publicKey) {
      throw new Error(`Key ${key.id} is missing public key`);
    }
    return {
      id: key.id,
      name: key.metadata?.origin || "Unnamed Passkey",
      publicKey: key.publicKey,
      algorithm: key.algorithm || "ES256",
      metadata: {
        ...key.metadata,
        keyId: key.id,
      },
    };
  };

  if (autoPopulate) {
    const keys = [...((provider.keys as Key[]) ?? [])];

    const processUpdates = (newKeys: Key[]) => {
      const addedKeys = newKeys.filter(
        (newKey) => !keys.some((existingKey) => existingKey.id === newKey.id),
      );

      const removedKeys = keys.filter(
        (existingKey) => !newKeys.some((newKey) => newKey.id === existingKey.id),
      );

      if (addedKeys.length === 0 && removedKeys.length === 0) return;

      addedKeys.forEach((k) => {
        keys.push(k);
      });
      removedKeys.forEach((k) => {
        const index = keys.findIndex((existingKey) => existingKey.id === k.id);
        if (index !== -1) {
          keys.splice(index, 1);
        }
      });

      removedKeys.forEach((k) => {
        if (k.type === "hd-derived-p256" || k.type === "xhd-derived-p256") {
          provider.passkey.store.removePasskey(k.id);
        }
      });

      for (const k of addedKeys) {
        if (k.type === "hd-derived-p256" || k.type === "xhd-derived-p256") {
          provider.passkey.store.addPasskey(createPasskeyFromKey(k as XHDDomainP256KeyData));
        }
      }
    };

    keyStore.subscribe((state) => {
      if (state.status !== "ready" && state.status !== "idle") return;
      processUpdates(state.keys as unknown as Key[]);
    });
  }

  return provider as unknown as PasskeysKeystoreExtension;
};
