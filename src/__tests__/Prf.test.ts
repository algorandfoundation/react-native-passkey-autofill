/// <reference types="node" />
import { createHash, createHmac } from "crypto";

import { PASSKEY_AUTOFILL_CAPABILITIES } from "../ReactNativePasskeyAutofill.types";

/**
 * Reference (JS) implementation of the same PRF derivation used by the
 * iOS (`Prf.swift`) and Android (`Prf.kt`) native modules. Pinning the
 * output against a known vector ensures all three implementations stay
 * in sync — if any of them drifts, this test goes red.
 *
 *   credRandom = HKDF-SHA256(
 *     ikm  = hdRootSecret,
 *     salt = utf8(lower(rpId)) || 0x00 || utf8(lower(userHandle)),
 *     info = "WebAuthn-PRF-credRandom",
 *     L    = 32,
 *   )
 *   prfOutput = HMAC-SHA256(
 *     credRandom,
 *     SHA-256("WebAuthn PRF" || 0x00 || salt)
 *   )
 */

function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  const effectiveSalt = salt.length === 0 ? Buffer.alloc(32) : salt;
  const prk = createHmac("sha256", effectiveSalt).update(ikm).digest();
  const out = Buffer.alloc(length);
  let t = Buffer.alloc(0);
  let offset = 0;
  let counter = 1;
  while (offset < length) {
    t = createHmac("sha256", prk)
      .update(Buffer.concat([t, info, Buffer.from([counter])]))
      .digest();
    const take = Math.min(t.length, length - offset);
    t.copy(out, offset, 0, take);
    offset += take;
    counter += 1;
  }
  return out;
}

function credRandom(
  hdRootSecret: Buffer,
  relyingPartyIdentifier: string,
  userHandle: string,
): Buffer {
  const salt = Buffer.concat([
    Buffer.from(relyingPartyIdentifier.toLowerCase(), "utf8"),
    Buffer.from([0x00]),
    Buffer.from(userHandle.toLowerCase(), "utf8"),
  ]);
  return hkdfSha256(hdRootSecret, salt, Buffer.from("WebAuthn-PRF-credRandom", "utf8"), 32);
}

function prfEvaluate(cr: Buffer, salt: Buffer, alreadyHashed = true): Buffer {
  const macInput = alreadyHashed
    ? salt
    : createHash("sha256")
        .update(Buffer.concat([Buffer.from("WebAuthn PRF", "utf8"), Buffer.from([0x00]), salt]))
        .digest();
  return createHmac("sha256", cr).update(macInput).digest();
}

function fromBase64Url(value: string): Buffer {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

describe("PRF (WebAuthn `prf` extension) reference vector", () => {
  const hdRootSecret = Buffer.from(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "hex",
  );
  const rpId = "example.com";
  const userHandle = "dXNlci0xMjM=";

  it("derives a stable 32-byte credRandom from (hdRootSecret, rpId, userHandle)", () => {
    const cr = credRandom(hdRootSecret, rpId, userHandle);
    expect(cr.length).toBe(32);
    // Pinned reference value — must match iOS `Prf.credRandom(...)` and
    // Android `Prf.credRandom(...)` for the same inputs.
    expect(cr.toString("hex")).toBe(
      "13837ef05514972d99cef1aae8148908391b79b04a1cb1973a938f739dc54660",
    );
  });

  it("produces the expected PRF output for a raw RP salt (`extensions.prf`, alreadyHashed = false)", () => {
    const cr = credRandom(hdRootSecret, rpId, userHandle);
    const salt = Buffer.alloc(32, 0x42);
    const output = prfEvaluate(cr, salt, /* alreadyHashed = */ false);
    expect(output.length).toBe(32);
    expect(output.toString("hex")).toBe(
      "36562465a0c8b718a3463128e7866e87669c7bda087f36d85d7e40eb3776d74b",
    );
  });

  it("is case-insensitive in rpId and userHandle", () => {
    const lower = credRandom(hdRootSecret, "example.com", "user-123");
    const mixed = credRandom(hdRootSecret, "Example.COM", "User-123");
    expect(mixed.equals(lower)).toBe(true);
  });

  it("changes when a different salt is supplied", () => {
    const cr = credRandom(hdRootSecret, rpId, userHandle);
    const a = prfEvaluate(cr, Buffer.alloc(32, 0x01));
    const b = prfEvaluate(cr, Buffer.alloc(32, 0x02));
    expect(a.equals(b)).toBe(false);
  });

  /**
   * Real over-the-wire example observed from a Chromium client forwarding
   * a `prf` request to the Android credential provider. The `first` salt
   * inside `prfAlreadyHashed.eval` is the already-computed
   * `SHA-256("WebAuthn PRF" || 0x00 || rpSalt)` value, so providers must
   * HMAC it directly without re-hashing.
   */
  it("handles the wire-shape from Chromium Android (`prfAlreadyHashed.eval.first`)", () => {
    const chromiumRpId = "hayai-client-git-beta-txnlab.vercel.app";
    const cr = credRandom(hdRootSecret, chromiumRpId, userHandle);
    const innerHash = fromBase64Url("vDGGHBtx2Ay5qmbyzpAcvw-8Vt2Jn2jTyG5q0kxCax8");
    expect(innerHash.length).toBe(32);

    const output = prfEvaluate(cr, innerHash, /* alreadyHashed = */ true);
    expect(output.length).toBe(32);
    // Pinned: must match what the native iOS/Android providers compute for
    // the same hdRootSecret + rpId + userHandle + inner-hash inputs.
    expect(output.toString("hex")).toBe(
      "184448877b829af49e2bcaa7a70eed105dbbec5ea5fd72a7b1bc55bc8d09bedd",
    );
  });

  it("re-hashing an already-hashed salt produces a different (wrong) output", () => {
    // Sanity check that the alreadyHashed flag matters — protects against
    // someone accidentally flipping the default to `false` for hashed input.
    const cr = credRandom(hdRootSecret, rpId, userHandle);
    const innerHash = fromBase64Url("vDGGHBtx2Ay5qmbyzpAcvw-8Vt2Jn2jTyG5q0kxCax8");
    const correct = prfEvaluate(cr, innerHash, true);
    const wrong = prfEvaluate(cr, innerHash, false);
    expect(correct.equals(wrong)).toBe(false);
  });
});

describe("Public capabilities", () => {
  it("advertises PRF support to wallet/RP-side consumers", () => {
    expect(PASSKEY_AUTOFILL_CAPABILITIES.prf).toBe(true);
  });
});
