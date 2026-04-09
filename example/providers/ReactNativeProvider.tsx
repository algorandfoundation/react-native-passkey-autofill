import React, { createContext, type ReactNode } from "react";
import { Provider } from "@algorandfoundation/wallet-provider";
import { WithKeyStore } from "@algorandfoundation/react-native-keystore";
import { WithPasskeyStore, type Passkey, type PasskeyStoreApi } from "../extensions/passkeys";
import { WithPasskeysKeystore } from "../extensions/passkeys-keystore";
import type { Key } from "@algorandfoundation/keystore";

export class ReactNativeProvider extends Provider<typeof ReactNativeProvider.EXTENSIONS> {
  static EXTENSIONS = [WithKeyStore, WithPasskeyStore, WithPasskeysKeystore] as const;

  keys!: Key[];
  passkeys!: Passkey[];
  status!: string;

  passkey!: {
    store: PasskeyStoreApi;
  };

  key!: {
    store: any; // Simplified for the example
  };
}

export const WalletProviderContext = createContext<null | ReactNativeProvider>(null);

export interface WalletProviderProps {
  children: ReactNode;
  provider: ReactNativeProvider;
}

export function WalletProvider({ children, provider }: WalletProviderProps) {
  return (
    <WalletProviderContext.Provider value={provider}>{children}</WalletProviderContext.Provider>
  );
}
