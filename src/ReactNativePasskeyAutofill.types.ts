export type ReactNativePasskeyAutofillModuleEvents = {
  onPasskeyAdded: (event: { success: boolean }) => void;
  onPasskeyAuthenticated: (event: { success: boolean }) => void;
};
