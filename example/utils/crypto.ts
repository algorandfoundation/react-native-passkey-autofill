import { sha512_256 } from "@noble/hashes/sha2.js";
import { base32 } from "@scure/base";
import { Buffer } from "buffer";

export function encodeAddress(publicKey: Uint8Array): string {
  const hash = sha512_256(publicKey);
  const checksum = hash.slice(-4);
  const addressBytes = new Uint8Array([...publicKey, ...checksum]);
  return base32.encode(addressBytes).replace(/=+$/, "").toUpperCase();
}

export function toBase64URL(arr: Uint8Array | ArrayBuffer): string {
  const buf = arr instanceof ArrayBuffer ? Buffer.from(arr) : Buffer.from(arr.buffer as ArrayBuffer, arr.byteOffset, arr.byteLength);
  const base64 = buf.toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function fromBase64Url(base64url: string): Uint8Array {
  // Use Buffer's built-in base64url support if possible, or manually pad it
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

export async function generateEd25519KeyPair() {
  const keyPair = await crypto.subtle.generateKey(
      { name: "Ed25519", namedCurve: "Ed25519" },
      true,
      ["sign", "verify"]
  );

  return {
    privateKey: keyPair.privateKey,
    publicKey: await crypto.subtle.exportKey("raw", keyPair.publicKey)
  };
}
