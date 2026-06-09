import CryptoKit
import Foundation

/// WebAuthn PRF (`prf`) extension helpers, backed by the authenticator
/// `hmac-secret` mechanism (CTAP2.1).
///
/// Per the WebAuthn spec, for each input salt the authenticator computes:
///
///     output = HMAC-SHA256(credRandom, SHA256("WebAuthn PRF" || 0x00 || salt))
///
/// where `credRandom` is a 32-byte per-credential secret. To avoid a storage
/// migration we derive `credRandom` deterministically from the wallet's HD
/// root secret and the credential's (rpId, userHandle) — the same inputs that
/// already produce the deterministic P-256 signing key. As a result, restoring
/// the wallet seed on another device produces the same PRF outputs.
enum Prf {
  /// Domain separator used to derive `credRandom` from the HD root secret.
  /// Kept under a distinct label from the P-256 key derivation to ensure
  /// the credRandom value can never collide with private-key material.
  static let credRandomInfo = "WebAuthn-PRF-credRandom"

  /// WebAuthn-defined prefix for PRF salt hashing.
  /// See: https://www.w3.org/TR/webauthn-3/#prf-extension
  static let saltPrefix: [UInt8] = Array("WebAuthn PRF".utf8) + [0x00]

  /// Derive a 32-byte per-credential PRF secret (`credRandom`) from the wallet
  /// HD root secret. Deterministic over `(hdRootSecret, rpId, userHandle)`.
  static func credRandom(
    hdRootSecret: Data,
    relyingPartyIdentifier: String,
    userHandle: String
  ) -> Data {
    var salt = Data()
    salt.append(contentsOf: relyingPartyIdentifier.lowercased().utf8)
    salt.append(0x00)
    salt.append(contentsOf: userHandle.lowercased().utf8)

    let info = Data(credRandomInfo.utf8)
    let key = SymmetricKey(data: hdRootSecret)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      salt: salt,
      info: info,
      outputByteCount: 32
    )
    return derived.withUnsafeBytes { Data($0) }
  }

  /// Evaluate the PRF for a single salt. Returns 32 bytes of output material.
  ///
  /// Per the WebAuthn spec the PRF input the authenticator sees is the
  /// hash `SHA-256("WebAuthn PRF" || 0x00 || rpSalt)`. The platform layer
  /// (Apple AuthenticationServices on iOS, the system credential manager on
  /// Android with `prfAlreadyHashed`) performs this hashing before passing
  /// the salt down to credential providers. Pass `alreadyHashed = true` in
  /// that case so we don't hash twice.
  static func evaluate(credRandom: Data, salt: Data, alreadyHashed: Bool = true) -> Data {
    let macInput: Data
    if alreadyHashed {
      macInput = salt
    } else {
      var hashInput = Data(saltPrefix)
      hashInput.append(salt)
      macInput = Data(SHA256.hash(data: hashInput))
    }
    let mac = HMAC<SHA256>.authenticationCode(
      for: macInput,
      using: SymmetricKey(data: credRandom)
    )
    return Data(mac)
  }
}

/// Parsed PRF extension input as supplied by the relying party.
///
/// At the WebAuthn layer the RP can either supply a single global pair of
/// salts (`eval`) or a per-credential map (`evalByCredential`). We always
/// reduce that down to at most two salts for the credential we are about to
/// assert with, matching the platform behaviour on iOS 18 and Android.
struct PrfInput {
  let first: Data
  let second: Data?
}

/// Computed PRF outputs ready to attach to a WebAuthn response.
struct PrfOutput {
  let first: Data
  let second: Data?
}
