import type { Store } from "@tanstack/store";
import type { Passkey, PasskeyStoreState } from "./types";

export function addPasskey({
  store,
  passkey,
}: {
  store: Store<PasskeyStoreState>;
  passkey: Passkey;
}): Passkey {
  store.setState((state) => ({
    ...state,
    passkeys: [passkey, ...state.passkeys],
  }));
  return passkey;
}

export function getPasskey({
  store,
  id,
}: {
  store: Store<PasskeyStoreState>;
  id: string;
}): Passkey | undefined {
  return store.state.passkeys.find((p) => p.id === id);
}

export function clearPasskeys({ store }: { store: Store<PasskeyStoreState> }): void {
  store.setState((state) => ({
    ...state,
    passkeys: [],
  }));
}
