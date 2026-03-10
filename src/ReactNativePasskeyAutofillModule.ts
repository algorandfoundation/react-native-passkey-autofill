import { NativeModule, requireNativeModule } from 'expo';

import { ReactNativePasskeyAutofillModuleEvents } from './ReactNativePasskeyAutofill.types';

declare class ReactNativePasskeyAutofillModule extends NativeModule<ReactNativePasskeyAutofillModuleEvents> {
  hello(): string;
  setParentSecret(secret: string): Promise<void>;
  configureIntentActions(getPasskeyAction: String, createPasskeyAction: String): Promise<void>;
  clearCredentials(): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ReactNativePasskeyAutofillModule>('ReactNativePasskeyAutofill');
