import { useContext } from "react";
import { useStore } from "@tanstack/react-store";
import { WalletProviderContext } from "../providers/ReactNativeProvider";
import { keyStore } from "../stores/keystore";
import { passkeysStore } from "../stores/passkeys";

export function useProvider() {
  const provider = useContext(WalletProviderContext);
  if (provider === null) {
    throw new Error("No Provider Found");
  }

  const keys = useStore(keyStore, (state) => state.keys);
  const status = useStore(keyStore, (state) => state.status);
  const passkeys = useStore(passkeysStore, (state) => state.passkeys);

  return {
    ...provider,
    keys,
    status,
    passkeys,
  };
}
