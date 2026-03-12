import { Store } from "@tanstack/store";
import type { PasskeyStoreState } from "../extensions/passkeys/types";

export const passkeysStore = new Store<PasskeyStoreState>({
  passkeys: [],
});
