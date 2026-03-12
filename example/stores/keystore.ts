import { Store } from "@tanstack/store";
import type { Key } from "@algorandfoundation/keystore";

export const keyStore = new Store<{
  keys: Key[];
  status: string;
}>({
  keys: [],
  status: "idle",
});
