import type { KeyStoreExtension, KeyStoreOptions } from "@algorandfoundation/keystore";
import type { PasskeyStoreExtension, PasskeyStoreOptions } from "../passkeys";
import type { ExtensionOptions } from "@algorandfoundation/wallet-provider";

export interface PasskeysKeystoreExtensionOptions
  extends ExtensionOptions, PasskeyStoreOptions, KeyStoreOptions {
  passkeys: PasskeyStoreOptions["passkeys"] & {
    keystore: {
      autoPopulate?: boolean;
    };
  };
}

export interface PasskeysKeystoreExtension extends PasskeyStoreExtension, KeyStoreExtension {
  passkey: PasskeyStoreExtension["passkey"] & {
    keystore: {
      autoPopulate: boolean;
    };
  };
}
