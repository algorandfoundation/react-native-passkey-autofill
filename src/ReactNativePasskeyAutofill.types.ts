export type ChangeEventPayload = {
  value: string;
};

export type ReactNativePasskeyAutofillModuleEvents = {
  onChange: (params: ChangeEventPayload) => void;
};
