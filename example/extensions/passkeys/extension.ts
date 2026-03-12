import type { Extension } from "@algorandfoundation/wallet-provider";
import { Store } from "@tanstack/store";
import Hook from "before-after-hook";
import { addPasskey, getPasskey, clearPasskeys } from "./store";
import { removePasskey } from "./types";
import type { PasskeyStoreExtension, PasskeyStoreState } from "./types";

export const WithPasskeyStore: Extension<PasskeyStoreExtension> = (_provider, options) => {
  const store = options?.passkeys?.store ?? new Store<PasskeyStoreState>({ passkeys: [] });
  const hooks = options?.passkeys?.hooks ?? new Hook.Collection();

  return {
    get passkeys() {
      return store.state.passkeys;
    },
    passkey: {
      store: {
        addPasskey: async (passkey) => {
          return hooks("add", addPasskey, { store, passkey });
        },
        getPasskey: async (id) => {
          return hooks("get", getPasskey, { store, id });
        },
        removePasskey: async (id) => {
          return hooks("remove", removePasskey, { store, id });
        },
        clear: async () => {
          return hooks("clear", clearPasskeys, { store });
        },
        hooks,
      },
    },
  } as PasskeyStoreExtension;
};
