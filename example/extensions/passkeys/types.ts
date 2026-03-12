import type { ExtensionOptions } from "@algorandfoundation/wallet-provider";
import type { Store } from "@tanstack/store";
import type { HookCollection } from "before-after-hook";

export interface Passkey {
  id: string;
  name: string;
  publicKey: Uint8Array;
  algorithm: string;
  metadata?: Record<string, any>;
}

export interface PasskeyStoreState {
  passkeys: Passkey[];
}

export interface PasskeyStoreOptions extends ExtensionOptions {
  passkeys: {
    store: Store<PasskeyStoreState>;
    hooks: HookCollection<any>;
  };
}

export interface PasskeyStoreApi {
  addPasskey: (passkey: Passkey) => Promise<Passkey>;
  getPasskey: (id: string) => Promise<Passkey | undefined>;
  removePasskey: (id: string) => Promise<void>;
  clear: () => Promise<void>;
  hooks: HookCollection<any>;
}

export interface PasskeyStoreExtension extends PasskeyStoreState {
  passkey: {
    store: PasskeyStoreApi;
  };
}

export function removePasskey({
  store,
  id,
}: {
  store: Store<PasskeyStoreState>;
  id: string;
}): void {
  store.setState((state) => ({
    ...state,
    passkeys: state.passkeys.filter((p) => p.id !== id),
  }));
}
