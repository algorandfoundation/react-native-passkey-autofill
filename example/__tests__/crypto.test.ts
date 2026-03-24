import { encodeAddress, toBase64URL, fromBase64Url } from '../utils/crypto';

describe('crypto utils', () => {
  it('toBase64URL and fromBase64Url should be reversible', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 255]);
    const base64url = toBase64URL(data);
    const decoded = fromBase64Url(base64url);
    expect(decoded).toEqual(data);
  });

  it('toBase64URL should use URL-safe characters', () => {
    // Data that would normally produce + and / in base64
    const data = new Uint8Array([251, 255, 191]);
    const base64url = toBase64URL(data);
    expect(base64url).not.toContain('+');
    expect(base64url).not.toContain('/');
    expect(base64url).not.toContain('=');
  });

  it('encodeAddress should produce a valid base32 string', () => {
    // Zeroed out 32-byte public key (like an empty Algorand address)
    const publicKey = new Uint8Array(32).fill(0);
    const address = encodeAddress(publicKey);
    expect(address).toMatch(/^[A-Z2-7]{58}$/);
  });
});
