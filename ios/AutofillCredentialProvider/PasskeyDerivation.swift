import Foundation

/// Which identity a credential's deterministic material is derived from.
///
/// Everything deterministic about a passkey — the P-256 signing key
/// (`SHA-512(mainKey ‖ origin ‖ identity ‖ counter)[0..32]`, the canonical
/// `@algorandfoundation/dp256` contract) and the PRF `credRandom` — is keyed on
/// an identity string. Which string that is has to be recorded per credential:
/// PRF is recomputed from the seed on EVERY assertion, so silently changing the
/// input would silently change every already-issued PRF secret.
///
/// - ``versionLegacyLabel`` is what earlier builds used, and it was not even
///   self-consistent: registration derived the key from the utf8 (or base64url)
///   rendering of `user.id`, lowercased, while every later assertion derived PRF
///   from the STORED `userHandle` — base64 of `user.id` for a natively created
///   credential, the wallet address for a keystore-derived one. Android used the
///   account label (`user.name`) for both, so the same account produced
///   different keys on the two platforms.
/// - ``versionCanonicalUserId`` is the RP-owned `user.id` (base64url, case
///   preserved), the one identifier the spec guarantees is stable for the
///   lifetime of the credential. It is identical on both platforms, so the same
///   seed + relying party + account now reproduces the same key and the same PRF
///   outputs on iOS and Android.
///
/// Records written before the field existed read back as
/// ``versionLegacyLabel``, so their derivation is unchanged. This includes the
/// wallet's own keystore-derived passkeys, whose keys the keystore derives from
/// the account address — they keep deriving from it until the wallet opts them in
/// by writing `metadata.derivationVersion`.
///
/// Mirrors `credentials/PasskeyDerivation.kt` on Android; the two must stay in
/// lockstep, and `src/__tests__/Prf.test.ts` pins the shared vectors.
enum PasskeyDerivation {
  /// The stored legacy handle, lowercased. Legacy; never stamped on new credentials.
  static let versionLegacyLabel = 1

  /// The relying party's `user.id`, base64url and case preserved.
  static let versionCanonicalUserId = 2

  /// Stamped on credentials created by this build.
  static let versionCurrent = versionCanonicalUserId

  /// Placeholder some clients send when a creation request carries no `user.id`.
  private static let placeholderUserId = "unknown-id"

  /// Normalise a `user.id` to unpadded base64url so an encoding variant can
  /// never change the derived key. The value is OPAQUE RP-owned bytes, so case
  /// is significant and must be preserved.
  static func normalizeUserId(_ userId: String?) -> String {
    guard let userId else { return "" }
    var normalized = userId.trimmingCharacters(in: .whitespacesAndNewlines)
    while normalized.hasSuffix("=") { normalized.removeLast() }
    return normalized.replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
  }

  /// Whether a `user.id` is present and usable as a derivation input.
  static func isDerivableUserId(_ userId: String?) -> Bool {
    let normalized = normalizeUserId(userId)
    return !normalized.isEmpty && normalized != placeholderUserId
  }

  /// The version to stamp on a credential being created: canonical when the
  /// relying party supplied a `user.id`, otherwise legacy — a placeholder must
  /// never become key material.
  static func versionForNewCredential(userId: String?) -> Int {
    isDerivableUserId(userId) ? versionCurrent : versionLegacyLabel
  }

  /// The derivation identity for a credential, ready to be passed verbatim to
  /// the key/PRF derivation (already normalised and case-folded as its version
  /// requires — callers must not lowercase it again).
  static func identity(version: Int?, userId: String?, legacyLabel: String) -> String {
    if (version ?? versionLegacyLabel) >= versionCanonicalUserId, isDerivableUserId(userId) {
      return normalizeUserId(userId)
    }
    return legacyLabel.lowercased()
  }

  /// The derivation identity of a stored credential.
  static func identity(for credential: StoredPasskeyCredential) -> String {
    identity(
      version: credential.derivationVersion,
      userId: credential.userId,
      legacyLabel: credential.userHandle
    )
  }
}
