import { NativeModule, requireNativeModule } from "expo";

import { ReactNativePasskeyAutofillModuleEvents } from "./ReactNativePasskeyAutofill.types";

declare class ReactNativePasskeyAutofillModule extends NativeModule<ReactNativePasskeyAutofillModuleEvents> {
  setMasterKey(secret: string): Promise<void>;
  setHdRootKeyId(id: string): Promise<void>;
  getHdRootKeyId(): Promise<string | null>;
  configureIntentActions(getPasskeyAction: string, createPasskeyAction: string): Promise<void>;
  clearCredentials(): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativePasskeyAutofillModule>("ReactNativePasskeyAutofill");
