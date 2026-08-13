/**
 * @module PasskeyDerivation
 *
 * The identity every deterministic secret of a passkey is derived from.
 *
 * Everything deterministic about a credential — the P-256 signing key
 * (`SHA-512(parentSecret ‖ origin ‖ identity ‖ counterBE)[0..32]`, the
 * canonical `@algorandfoundation/dp256` contract) and the WebAuthn PRF
 * `credRandom` (`HKDF-SHA256(parentSecret, salt = utf8(lower(rpId)) ‖ 0x00 ‖ utf8(identity))`)
 * — is keyed on an identity string. Which string that is has to be recorded
 * per credential: PRF is recomputed from the seed on EVERY assertion, so
 * silently changing the input would silently change every already-issued PRF
 * secret.
 *
 * This module is the JavaScript half of a contract implemented three times —
 * here, in `credentials/PasskeyDerivation.kt` (Android) and in
 * `ios/AutofillCredentialProvider/PasskeyDerivation.swift` (iOS). The three
 * must stay in lockstep; `src/__tests__/Prf.test.ts` pins the shared vectors
 * against the same values the Kotlin and Swift unit tests pin.
 *
 * @remarks
 * Wallets do not need this module to read or create credentials through the
 * native flows — the native side stamps and resolves the version itself. It is
 * exported for wallets that keep their own mirror of the credential store, that
 * derive PRF outputs or P-256 keys in JavaScript, or that need to decide which
 * version to write when they insert a keystore-derived credential directly
 * (see {@link versionForNewCredential}).
 */

import { PasskeyAutofillCredentialIdentity } from "./ReactNativePasskeyAutofill.types";

/**
 * The account label (`user.name` on Android, the stored handle on iOS),
 * lowercased.
 *
 * @remarks
 * What every build before the canonical identity existed derived from, and
 * therefore what a credential stored without a `derivationVersion` reads back
 * as. Relying parties rename users routinely — an email or username change
 * makes the credential non-re-derivable — and the label was platform-specific,
 * which is why Android and iOS derived different keys for the same account.
 * Never stamped on new credentials.
 */
export const DERIVATION_VERSION_LEGACY_LABEL = 1;

/**
 * The relying party's `user.id`, base64url and case preserved.
 *
 * @remarks
 * The one identifier the WebAuthn spec guarantees is stable for the lifetime of
 * the credential, and identical on both platforms — so the same seed + relying
 * party + account reproduces the same key and the same PRF outputs everywhere.
 */
export const DERIVATION_VERSION_CANONICAL_USER_ID = 2;

/** The version stamped on credentials created by this version of the module. */
export const DERIVATION_VERSION_CURRENT = DERIVATION_VERSION_CANONICAL_USER_ID;

/**
 * The deterministic-P256 main key scheme (PBKDF2-HMAC-SHA512, 64 bytes).
 * Preferred for new keys.
 */
export const PASSKEY_DERIVATION_SCHEME_PBKDF2_P256 = "pbkdf2-p256";

/**
 * The legacy BIP32-Ed25519 root scheme (96 bytes).
 */
export const PASSKEY_DERIVATION_SCHEME_BIP32_ED25519 = "bip32-ed25519";

/**
 * Placeholder written by the native creation flows when a request carries no
 * `user.id`. It must never become key material.
 */
const PLACEHOLDER_USER_ID = "unknown-id";

/**
 * Normalises a `user.id` to unpadded base64url so an encoding variant can never
 * change the derived key.
 *
 * @param userId - The raw `user.id` as stored or as received from the relying
 *   party; `null`/`undefined` normalise to the empty string.
 * @returns The trimmed, unpadded, base64url form of `userId`.
 *
 * @remarks
 * Case is deliberately preserved: `user.id` is opaque, RP-owned bytes and
 * base64url is case significant. Only the legacy identity is case-folded, and
 * only inside {@link derivationIdentity}.
 */
export function normalizeUserId(userId: string | undefined | null): string {
  return (userId ?? "").trim().replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/**
 * Whether a `user.id` is present and usable as a derivation input.
 *
 * @param userId - The raw `user.id`.
 * @returns `false` for a blank id and for the `unknown-id` placeholder the
 *   native flows write when the relying party supplied none.
 */
export function isDerivableUserId(userId: string | undefined | null): boolean {
  const normalized = normalizeUserId(userId);
  return normalized.length > 0 && normalized !== PLACEHOLDER_USER_ID;
}

/**
 * The version to stamp on a credential being created.
 *
 * @param userId - The `user.id` the creation request carried, if any.
 * @returns {@link DERIVATION_VERSION_CURRENT} when the relying party supplied a
 *   usable `user.id`, otherwise {@link DERIVATION_VERSION_LEGACY_LABEL}.
 *
 * @remarks
 * Mirrors `PasskeyDerivation.versionForNewCredential` on both native platforms.
 * A wallet inserting a keystore-derived credential of its own must call this
 * with the same `user.id` it stores, and must NOT re-stamp credentials that
 * already exist: their `derivationVersion` is pinned for the life of the
 * credential, and changing it changes the secret every relying party is already
 * bound to.
 */
export function versionForNewCredential(userId: string | undefined | null): number {
  return isDerivableUserId(userId) ? DERIVATION_VERSION_CURRENT : DERIVATION_VERSION_LEGACY_LABEL;
}

/**
 * The derivation identity for a credential.
 *
 * @param version - The credential's stored `derivationVersion`; an absent
 *   version is treated as {@link DERIVATION_VERSION_LEGACY_LABEL}, which is
 *   what every record written before the field existed reads back as.
 * @param userId - The credential's canonical `user.id`.
 * @param legacyLabel - The credential's legacy label (`userHandle`).
 * @returns The identity string, ready to be passed VERBATIM to the key or PRF
 *   derivation — it is already normalised and case-folded as its version
 *   requires, so callers must not lowercase it again.
 */
export function derivationIdentity(
  version: number | undefined | null,
  userId: string | undefined | null,
  legacyLabel: string,
): string {
  if (
    (version ?? DERIVATION_VERSION_LEGACY_LABEL) >= DERIVATION_VERSION_CANONICAL_USER_ID &&
    isDerivableUserId(userId)
  ) {
    return normalizeUserId(userId);
  }
  return legacyLabel.toLowerCase();
}

/**
 * The derivation identity of a stored credential, as returned by
 * `getStoredCredentials()`.
 *
 * @param credential - The credential, or any object carrying its
 *   `derivationVersion`, `userId` and `userHandle`.
 * @returns The identity string, as {@link derivationIdentity} would return for
 *   those three fields.
 *
 * @remarks
 * Mirrors `PasskeyDerivation.identity(credential)` on Android and
 * `PasskeyDerivation.identity(for:)` on iOS.
 */
export function credentialDerivationIdentity(
  credential: Pick<
    PasskeyAutofillCredentialIdentity,
    "derivationVersion" | "userId" | "userHandle"
  >,
): string {
  return derivationIdentity(credential.derivationVersion, credential.userId, credential.userHandle);
}
