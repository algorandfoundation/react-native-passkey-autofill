import AuthenticationServices
import CryptoKit
import Foundation
import Security

enum PasskeyCredentialStoreError: Error {
  case appGroupUnavailable
  case credentialNotFound
  case credentialEncodingFailed
  case credentialStorageFailed
  /// The wallet has not shared its master key with this process yet.
  case masterKeyUnavailable
  /// No record roots the requested scheme (the wallet never called `setMainKeyId`,
  /// or it holds no key of that scheme).
  case parentKeyUnavailable(String?)
  /// The parent record exists but its material is missing or undecodable.
  case parentMaterialUnavailable(String)
  @available(*, deprecated, message: "Use the three specific parent-secret cases")
  case hdRootKeyUnavailable
  case invalidPrivateKey
  case signingFailed
}

/// The parent secret a credential's deterministic material hangs off, with the
/// record it came from and the scheme it roots.
struct PasskeyParentSecret {
  let keyId: String
  let scheme: String
  let bytes: Data
}

struct StoredPasskeyCredential: Codable {
  let credentialId: String
  let relyingPartyIdentifier: String
  let userName: String
  let userHandle: String
  let privateKey: String
  let publicKey: String?
  let createdAt: Double
  let lastUsedAt: Double?
  let parentKeyId: String?
  /// The derivation scheme this credential is pinned to for life
  /// (`PasskeyKeystoreRecords.schemePbkdf2P256` or `.schemeBip32Ed25519`).
  ///
  /// `nil` on every credential created before the wallet exposed its
  /// deterministic-P256 main key, and those all derive from the BIP32-Ed25519
  /// root — re-deriving one against a different parent produces a different key
  /// and silently breaks the passkey the relying party already trusts.
  var derivationScheme: String? = nil
}

/// The on-disk record format shared with the wallet's
/// `@algorandfoundation/react-native-keystore` MMKV instance.
///
/// The keystore splits every key into two entries: `k/<id>` holds PLAINTEXT
/// `Key` metadata (no material) and `m/<id>` holds the sealed raw material,
/// whose sealed plaintext is exactly `base64(bytes)` rather than a JSON
/// document. Records written before the split are a single entry keyed by the
/// bare id, sealing `base64url(JSON.stringify(KeyData))` — metadata and material
/// together. Both layouts must stay readable.
///
/// Kept byte-for-byte in step with `credentials/KeystoreRecords.kt` on Android.
enum PasskeyKeystoreRecords {
  /// Prefix for plaintext `Key` metadata records.
  static let metadataPrefix = "k/"

  /// Prefix for sealed raw-material records.
  static let materialPrefix = "m/"

  /// The type shared by both roots of the wallet's hierarchy; only the scheme
  /// tells them apart.
  static let typeHdRootKey = "hd-root-key"

  /// The deterministic-P256 main key (PBKDF2-HMAC-SHA512, 64 bytes): the root the
  /// passkey hierarchy is defined against, and the preferred parent for new keys.
  static let schemePbkdf2P256 = "pbkdf2-p256"

  /// The BIP32-Ed25519 account root (96 bytes). Passkeys used to derive from it
  /// because it was the only root a wallet exposed, so credentials created then
  /// stay pinned to it.
  static let schemeBip32Ed25519 = "bip32-ed25519"

  static func metadataKey(_ id: String) -> String { metadataPrefix + id }

  static func materialKey(_ id: String) -> String { materialPrefix + id }

  /// The scheme a decoded root record roots. Records written before the flag
  /// existed have none, and every one of those is a BIP32-Ed25519 root.
  static func scheme(of record: [String: Any]) -> String {
    let metadata = record["metadata"] as? [String: Any]
    if let scheme = metadata?["scheme"] as? String, !scheme.isEmpty { return scheme }
    if let scheme = record["scheme"] as? String, !scheme.isEmpty { return scheme }
    return schemeBip32Ed25519
  }

  /// Picks the parent record to derive from: the one rooting `requestedScheme`,
  /// or — for a new credential, which requests none — the main key if there is
  /// one, falling back to the most authoritative candidate.
  static func selectParentKey(
    candidates: [(keyId: String, scheme: String)],
    requestedScheme: String?
  ) -> (keyId: String, scheme: String)? {
    if let requestedScheme {
      return candidates.first { $0.scheme == requestedScheme }
    }
    return candidates.first { $0.scheme == schemePbkdf2P256 } ?? candidates.first
  }
}

final class PasskeyCredentialStore {
  static let defaultSuiteNameKey = "ReactNativePasskeyAutofillAppGroup"
  static let legacyCredentialKey = "ReactNativePasskeyAutofillCredentials"
  static let defaultCredentialKey = "ReactNativePasskeyAutofillCredentialsV2"
  static let defaultMasterKeyKey = "ReactNativePasskeyAutofillMasterKey"
  /// Points at the record whose material is the passkey parent secret. Its
  /// predecessor `defaultHdRootKeyIdKey` named the wallet's BIP32-Ed25519 root;
  /// the slot was renamed rather than reused so a wallet that still writes the
  /// old one is not mistaken for one that opted into the dp256 main key.
  static let defaultMainKeyIdKey = "ReactNativePasskeyAutofillMainKeyId"
  static let defaultHdRootKeyIdKey = "ReactNativePasskeyAutofillHdRootKeyId"
  static let defaultGetPasskeyActionKey = "ReactNativePasskeyAutofillGetPasskeyAction"
  static let defaultCreatePasskeyActionKey = "ReactNativePasskeyAutofillCreatePasskeyAction"
  static let defaultDiagnosticsKey = "ReactNativePasskeyAutofillDiagnostics"
  static let defaultDeletedCredentialIdsKey = "ReactNativePasskeyAutofillDeletedCredentialIds"
  /// Info.plist key holding the keychain access-group *base* (without the team
  /// prefix) shared by the app and the AutoFill extension. Injected by the
  /// config plugin so the module stays team-agnostic.
  static let keychainGroupInfoKey = "ReactNativePasskeyAutofillKeychainGroup"

  private let defaults: UserDefaults
  private let credentialKey: String

  init?(
    suiteName: String? = Bundle.main.object(
      forInfoDictionaryKey: PasskeyCredentialStore.defaultSuiteNameKey
    ) as? String,
    credentialKey: String = PasskeyCredentialStore.defaultCredentialKey
  ) {
    guard let suiteName, let defaults = UserDefaults(suiteName: suiteName) else {
      return nil
    }
    self.defaults = defaults
    self.credentialKey = credentialKey
  }

  func allCredentials() -> [StoredPasskeyCredential] {
    let keystoreCredentials = allKeystoreCredentials()
    let legacyCredentials = allLegacyCredentials()
    var credentialsById: [String: StoredPasskeyCredential] = [:]

    for credential in legacyCredentials {
      credentialsById[credential.credentialId] = credential
    }

    for credential in keystoreCredentials {
      credentialsById[credential.credentialId] = credential
    }

    return Array(credentialsById.values)
  }

  private func allLegacyCredentials() -> [StoredPasskeyCredential] {
    guard let data = defaults.data(forKey: credentialKey),
          let credentials = try? JSONDecoder().decode([StoredPasskeyCredential].self, from: data)
    else { return [] }
    return credentials
  }

  func credentials(relyingPartyIdentifier: String) -> [StoredPasskeyCredential] {
    allCredentials().filter { $0.relyingPartyIdentifier == relyingPartyIdentifier }
  }

  func credential(id: Data) -> StoredPasskeyCredential? {
    let encodedId = id.base64EncodedString()
    let urlEncodedId = id.base64URLEncodedString()
    return allCredentials().first { $0.credentialId == encodedId || $0.credentialId == urlEncodedId }
  }

  func save(_ credential: StoredPasskeyCredential) throws {
    unmarkCredentialDeleted(id: credential.credentialId)
    #if PASSKEY_AUTOFILL_EXTENSION
    try saveKeystoreCredential(credential)
    #else
    var credentials = allLegacyCredentials().filter { $0.credentialId != credential.credentialId }
    credentials.append(credential)
    try replace(credentials)
    #endif
  }

  func removeCredential(id: String) throws {
    let candidateIds = credentialIdCandidates(id)
    markCredentialsDeleted(ids: candidateIds)
    var credentials = allLegacyCredentials()
    let originalCount = credentials.count
    credentials.removeAll { candidateIds.contains($0.credentialId) }
    if credentials.count != originalCount {
      try replace(credentials)
    }

    guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String else {
      return
    }

    for candidateId in candidateIds {
      try? PasskeyKeystoreMMKV.removeValue(forKey: candidateId, appGroup: appGroup)
    }
  }

  func replace(_ credentials: [StoredPasskeyCredential]) throws {
    let data = try JSONEncoder().encode(credentials)
    defaults.set(data, forKey: credentialKey)
  }

  private func allKeystoreCredentials() -> [StoredPasskeyCredential] {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      appendDiagnostic("keystore credentials unavailable: missing master key or app group")
      return []
    }

    let keys: [String] = PasskeyKeystoreMMKV.allKeys(forAppGroup: appGroup, error: nil)
    appendDiagnostic("keystore allKeys count: \(keys.count)")
    return keys.compactMap { key -> StoredPasskeyCredential? in
      guard let payload = try? PasskeyKeystoreMMKV.string(forKey: key, appGroup: appGroup),
            let keyData = try? decodeKeystorePayload(payload, masterKey: masterKey),
            let id = keyData["id"] as? String,
            let publicKey = dataArray(keyData["publicKey"]),
            let privateKey = dataArray(keyData["privateKey"])
      else {
        appendDiagnostic("skipping keystore key: \(key)")
        return nil
      }

      let metadata = keyData["metadata"] as? [String: Any]
      let origin = metadata?["origin"] as? String ?? keyData["origin"] as? String ?? ""
      let userHandle = metadata?["userHandle"] as? String ?? keyData["userHandle"] as? String ?? ""
      let parentKeyId = metadata?["parentKeyId"] as? String ?? keyData["parentKeyId"] as? String
      guard !origin.isEmpty, !userHandle.isEmpty else {
        appendDiagnostic("skipping keystore credential missing metadata: \(id)")
        return nil
      }
      let rawUserName = metadata?["userName"] as? String ?? keyData["userName"] as? String ?? userHandle

      return StoredPasskeyCredential(
        credentialId: id,
        relyingPartyIdentifier: origin.relyingPartyIdentifier,
        userName: rawUserName.passkeyDisplayName,
        userHandle: userHandle,
        privateKey: privateKey.base64EncodedString(),
        publicKey: publicKey.base64EncodedString(),
        createdAt: metadata?["createdAt"] as? Double ?? Date().timeIntervalSince1970,
        lastUsedAt: metadata?["lastUsedAt"] as? Double,
        parentKeyId: parentKeyId,
        derivationScheme: metadata?["scheme"] as? String
      )
    }
  }

  #if PASSKEY_AUTOFILL_EXTENSION
  private func saveKeystoreCredential(_ credential: StoredPasskeyCredential) throws {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      throw PasskeyCredentialStoreError.appGroupUnavailable
    }
    guard let privateKey = Data(base64URLEncoded: credential.privateKey) ?? Data(base64Encoded: credential.privateKey),
          let publicKeyString = credential.publicKey,
          let publicKey = Data(base64URLEncoded: publicKeyString) ?? Data(base64Encoded: publicKeyString)
    else {
      throw PasskeyCredentialStoreError.invalidPrivateKey
    }

    var metadata: [String: Any] = [
      "origin": credential.relyingPartyIdentifier,
      "userName": credential.userName.passkeyDisplayName,
      "userHandle": credential.userHandle,
      "userId": credential.userHandle,
      "count": 0,
      "createdAt": credential.createdAt,
      "registered": true,
    ]
    if let lastUsedAt = credential.lastUsedAt {
      metadata["lastUsedAt"] = lastUsedAt
    }
    if let parentKeyId = credential.parentKeyId ?? mainKeyId() {
      metadata["parentKeyId"] = parentKeyId
    }
    // Pin the parent this key was derived from, so a later assertion re-derives
    // against the same root even once the wallet points us at a different one.
    if let derivationScheme = credential.derivationScheme {
      metadata["scheme"] = derivationScheme
    }

    let keyData: [String: Any] = [
      "id": credential.credentialId,
      "type": "hd-derived-p256",
      "algorithm": "P256",
      "extractable": false,
      "keyUsages": ["sign"],
      "name": "Passkey: \(credential.relyingPartyIdentifier)",
      "privateKey": privateKey.byteArray,
      "publicKey": publicKey.byteArray,
      "metadata": metadata,
    ]

    let encoded = try encodeKeyData(keyData)
    let encrypted = try encryptData(masterKey, encoded)
    do {
      try PasskeyKeystoreMMKV.setString(encrypted, forKey: credential.credentialId, appGroup: appGroup)
    } catch {
      throw PasskeyCredentialStoreError.credentialStorageFailed
    }
  }

  func recordCredentialUsage(id: String) {
    guard let masterKey = masterKey(),
          let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else { return }

    for candidate in credentialIdCandidates(id) {
      guard let payload = try? PasskeyKeystoreMMKV.string(forKey: candidate, appGroup: appGroup),
            var keyData = try? decodeKeystorePayload(payload, masterKey: masterKey)
      else { continue }

      var metadata = keyData["metadata"] as? [String: Any] ?? [:]
      metadata["lastUsedAt"] = Date().timeIntervalSince1970
      metadata["count"] = ((metadata["count"] as? Int) ?? 0) + 1
      keyData["metadata"] = metadata

      guard let encoded = try? encodeKeyData(keyData),
            let encrypted = try? encryptData(masterKey, encoded)
      else { return }
      try? PasskeyKeystoreMMKV.setString(encrypted, forKey: candidate, appGroup: appGroup)
      return
    }
  }
  #endif

  func clear() {
    defaults.removeObject(forKey: credentialKey)
    defaults.removeObject(forKey: Self.legacyCredentialKey)
    defaults.removeObject(forKey: Self.defaultDeletedCredentialIdsKey)
    defaults.removeObject(forKey: Self.defaultMasterKeyKey)
    defaults.removeObject(forKey: Self.defaultMainKeyIdKey)
    defaults.removeObject(forKey: Self.defaultHdRootKeyIdKey)
    defaults.removeObject(forKey: Self.defaultGetPasskeyActionKey)
    defaults.removeObject(forKey: Self.defaultCreatePasskeyActionKey)
    if let query = masterKeyQuery() {
      _ = SecItemDelete(query as CFDictionary)
    }
  }

  // MARK: - Master key (Keychain-backed)
  //
  // The master key is the KEK for the credential store and is read by *both*
  // the app and the AutoFill extension. It is stored in the Keychain (encrypted
  // at rest, hardware-backed) in a shared access group so both processes can
  // read it — never in plaintext UserDefaults. Accessibility is
  // `AfterFirstUnlockThisDeviceOnly`, NOT biometric: the extension must read the
  // key to *enumerate* credentials before the user authenticates, so a
  // biometric-gated item would break the AutoFill list. Biometric checks stay at
  // the assertion step (`LAContext` in `CredentialProviderViewController`).

  func saveMasterKey(_ secret: Data) {
    guard var query = masterKeyQuery() else { return }
    // Upsert: drop any existing value, then add the new one.
    _ = SecItemDelete(query as CFDictionary)
    query[kSecValueData as String] = secret
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    _ = SecItemAdd(query as CFDictionary, nil)
    // Scrub any legacy plaintext copy now that the Keychain holds the key.
    defaults.removeObject(forKey: Self.defaultMasterKeyKey)
  }

  func masterKey() -> Data? {
    if var query = masterKeyQuery() {
      query[kSecReturnData as String] = true
      query[kSecMatchLimit as String] = kSecMatchLimitOne
      var item: CFTypeRef?
      if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
         let data = item as? Data
      {
        return data
      }
    }
    // Migration: older builds stored the key as plaintext in the App Group
    // UserDefaults. Move it into the Keychain (and scrub the plaintext) once.
    if let legacy = defaults.string(forKey: Self.defaultMasterKeyKey),
       let data = Data(base64URLEncoded: legacy) ?? Data(base64Encoded: legacy)
    {
      saveMasterKey(data)
      return data
    }
    return nil
  }

  func isMasterKeyAvailable() -> Bool {
    masterKey() != nil
  }

  /// Base Keychain query identifying the shared master-key item. Returns `nil`
  /// when the access group can't be resolved (no Info.plist group or no team
  /// prefix), in which case the caller falls back / no-ops rather than writing
  /// to the wrong place.
  private func masterKeyQuery() -> [String: Any]? {
    guard let accessGroup = masterKeyAccessGroup() else { return nil }
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.defaultMasterKeyKey,
      kSecAttrAccount as String: Self.defaultMasterKeyKey,
      kSecAttrAccessGroup as String: accessGroup,
    ]
  }

  /// The full keychain access group (`<TeamID>.<base>`). The base is injected by
  /// the config plugin via Info.plist; the team prefix is resolved at runtime.
  private func masterKeyAccessGroup() -> String? {
    guard
      let base = Bundle.main.object(forInfoDictionaryKey: Self.keychainGroupInfoKey) as? String,
      let prefix = Self.keychainTeamPrefix()
    else {
      return nil
    }
    return prefix + base
  }

  private static var cachedTeamPrefix: String?

  /// Resolves the app's keychain access-group team prefix (`<TeamID>.`) at
  /// runtime by probing a throwaway Keychain item and reading back the group the
  /// system assigns. Avoids hardcoding a team ID in a module shared across teams.
  private static func keychainTeamPrefix() -> String? {
    if let cached = cachedTeamPrefix {
      return cached
    }
    let probeAccount = "ReactNativePasskeyAutofillTeamPrefixProbe"
    let cleanup: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: probeAccount,
    ]
    _ = SecItemDelete(cleanup as CFDictionary)

    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: probeAccount,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: Data(),
      kSecReturnAttributes as String: true,
    ]
    var result: CFTypeRef?
    let status = SecItemAdd(query as CFDictionary, &result)
    defer { _ = SecItemDelete(cleanup as CFDictionary) }

    guard
      status == errSecSuccess,
      let attributes = result as? [String: Any],
      let accessGroup = attributes[kSecAttrAccessGroup as String] as? String,
      let dotIndex = accessGroup.firstIndex(of: ".")
    else {
      return nil
    }
    // accessGroup is "<TeamID>.<something>"; keep through the first dot.
    let prefix = String(accessGroup[...dotIndex])
    cachedTeamPrefix = prefix
    return prefix
  }

  /// Records which key store record the passkey hierarchy derives from — the
  /// wallet's deterministic-P256 main key. The scheme is deliberately not part of
  /// this call: it is read from the record's own metadata, so a wallet cannot
  /// mislabel it.
  func saveMainKeyId(_ id: String) {
    defaults.set(id, forKey: Self.defaultMainKeyIdKey)
  }

  func mainKeyId() -> String? {
    defaults.string(forKey: Self.defaultMainKeyIdKey)
      ?? defaults.string(forKey: Self.defaultHdRootKeyIdKey)
  }

  /// Writes the same slot as `saveMainKeyId`: which setter a wallet happens to
  /// call says nothing about the record.
  @available(*, deprecated, message: "The passkey parent is no longer the BIP32-Ed25519 root")
  func saveHdRootKeyId(_ id: String) {
    saveMainKeyId(id)
  }

  @available(*, deprecated, message: "The passkey parent is no longer the BIP32-Ed25519 root")
  func hdRootKeyId() -> String? {
    mainKeyId()
  }

  /// Resolves the parent secret the deterministic P-256 key and the PRF
  /// `credRandom` are derived from.
  ///
  /// - Parameter scheme: the scheme a credential is pinned to, or `nil` for a new
  ///   credential, which then takes the preferred (dp256 main key) parent.
  func parentSecret(scheme: String? = nil) throws -> PasskeyParentSecret {
    guard let masterKey = masterKey() else {
      throw PasskeyCredentialStoreError.masterKeyUnavailable
    }
    guard let appGroup = Bundle.main.object(forInfoDictionaryKey: Self.defaultSuiteNameKey) as? String
    else {
      throw PasskeyCredentialStoreError.appGroupUnavailable
    }

    let candidates = parentKeyCandidates(masterKey: masterKey, appGroup: appGroup)
    guard let selected = PasskeyKeystoreRecords.selectParentKey(
      candidates: candidates,
      requestedScheme: scheme
    ) else {
      throw PasskeyCredentialStoreError.parentKeyUnavailable(scheme)
    }
    guard let bytes = material(of: selected.keyId, masterKey: masterKey, appGroup: appGroup) else {
      throw PasskeyCredentialStoreError.parentMaterialUnavailable(selected.keyId)
    }
    return PasskeyParentSecret(keyId: selected.keyId, scheme: selected.scheme, bytes: bytes)
  }

  /// The roots this device could derive from, most authoritative first: what the
  /// wallet pointed us at, then any root record present in the shared store.
  ///
  /// The scan matters for a credential pinned to a scheme the wallet is no longer
  /// pointing at: an already-issued passkey must keep re-deriving from the
  /// BIP32-Ed25519 root even once new keys use the dp256 main key.
  private func parentKeyCandidates(
    masterKey: Data,
    appGroup: String
  ) -> [(keyId: String, scheme: String)] {
    let pointed = [
      defaults.string(forKey: Self.defaultMainKeyIdKey),
      defaults.string(forKey: Self.defaultHdRootKeyIdKey),
    ].compactMap { $0 }

    let discovered = PasskeyKeystoreMMKV.allKeys(forAppGroup: appGroup, error: nil)
      .filter { $0.hasPrefix(PasskeyKeystoreRecords.metadataPrefix) }
      .map { String($0.dropFirst(PasskeyKeystoreRecords.metadataPrefix.count)) }

    var seen = Set<String>()
    var candidates: [(keyId: String, scheme: String)] = []
    for id in pointed + discovered where seen.insert(id).inserted {
      guard let record = metadata(of: id, masterKey: masterKey, appGroup: appGroup) else { continue }
      // A discovered record is only a candidate if it is a root; a record the
      // wallet explicitly pointed at is trusted even if its type predates the
      // current naming.
      if !pointed.contains(id),
         record["type"] as? String != PasskeyKeystoreRecords.typeHdRootKey
      {
        continue
      }
      candidates.append((keyId: id, scheme: PasskeyKeystoreRecords.scheme(of: record)))
    }
    return candidates
  }

  /// A record's metadata, from `k/<id>` (plaintext) or from the sealed legacy flat
  /// record keyed by the bare id.
  private func metadata(of id: String, masterKey: Data, appGroup: String) -> [String: Any]? {
    if let plaintext = try? PasskeyKeystoreMMKV.string(
      forKey: PasskeyKeystoreRecords.metadataKey(id),
      appGroup: appGroup
    ),
      let data = plaintext.data(using: .utf8),
      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    {
      return json
    }
    guard let payload = try? PasskeyKeystoreMMKV.string(forKey: id, appGroup: appGroup) else {
      return nil
    }
    return try? decodeKeystorePayload(payload, masterKey: masterKey)
  }

  /// A record's raw secret bytes, from `m/<id>` (whose sealed plaintext is
  /// `base64(bytes)`) or from the inline material of the legacy flat record.
  private func material(of id: String, masterKey: Data, appGroup: String) -> Data? {
    if let sealed = try? PasskeyKeystoreMMKV.string(
      forKey: PasskeyKeystoreRecords.materialKey(id),
      appGroup: appGroup
    ),
      let encoded = try? decryptData(masterKey, sealed),
      let bytes = Data(base64Encoded: encoded) ?? Data(base64URLEncoded: encoded)
    {
      return bytes
    }

    guard let payload = try? PasskeyKeystoreMMKV.string(forKey: id, appGroup: appGroup),
          let keyData = try? decodeKeystorePayload(payload, masterKey: masterKey)
    else {
      return nil
    }
    if let seed = dataArray(keyData["seed"]) ?? dataArray(keyData["privateKey"]) {
      return seed
    }
    if let seed = keyData["seed"] as? String ?? keyData["privateKey"] as? String {
      return Self.secretStringData(seed)
    }
    return nil
  }

  /// The raw parent secret for a new credential. Prefer ``parentSecret(scheme:)``,
  /// whose failure says which of the three things went wrong.
  func hdRootKeySecret() throws -> Data {
    try parentSecret().bytes
  }

  func configureIntentActions(getPasskeyAction: String, createPasskeyAction: String) {
    defaults.set(getPasskeyAction, forKey: Self.defaultGetPasskeyActionKey)
    defaults.set(createPasskeyAction, forKey: Self.defaultCreatePasskeyActionKey)
  }

  func appendDiagnostic(_ message: String) {
    var diagnostics = defaults.array(forKey: Self.defaultDiagnosticsKey) as? [String] ?? []
    let timestamp = ISO8601DateFormatter().string(from: Date())
    diagnostics.append("\(timestamp) \(message)")
    defaults.set(Array(diagnostics.suffix(50)), forKey: Self.defaultDiagnosticsKey)
  }

  func diagnostics() -> [String] {
    defaults.array(forKey: Self.defaultDiagnosticsKey) as? [String] ?? []
  }

  func isCredentialDeleted(id: Data) -> Bool {
    isCredentialDeleted(id: id.base64EncodedString()) || isCredentialDeleted(id: id.base64URLEncodedString())
  }

  func replaceIdentityStore() async throws {
    guard #available(iOS 17.0, *) else {
      return
    }

    let identities = allCredentials().map { credential in
      ASPasskeyCredentialIdentity(
        relyingPartyIdentifier: credential.relyingPartyIdentifier,
        userName: credential.userName,
        credentialID: Data(base64URLEncoded: credential.credentialId) ?? Data(),
        userHandle: Data(base64URLEncoded: credential.userHandle) ?? Data(credential.userHandle.utf8),
        recordIdentifier: credential.credentialId
      )
    }

    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { success, error in
        if let error {
          continuation.resume(throwing: error)
        } else if success {
          continuation.resume()
        } else {
          continuation.resume(throwing: PasskeyCredentialStoreError.credentialNotFound)
        }
      }
    }
  }

  func removeAllIdentities() async throws {
    guard #available(iOS 17.0, *) else {
      return
    }

    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      ASCredentialIdentityStore.shared.removeAllCredentialIdentities { success, error in
        if let error {
          continuation.resume(throwing: error)
        } else if success {
          continuation.resume()
        } else {
          continuation.resume(throwing: PasskeyCredentialStoreError.credentialNotFound)
        }
      }
    }
  }

  private func credentialIdCandidates(_ id: String) -> Set<String> {
    var candidates: Set<String> = [id]
    if let data = Data(base64URLEncoded: id) ?? Data(base64Encoded: id) {
      candidates.insert(data.base64EncodedString())
      candidates.insert(data.base64URLEncodedString())
    }
    return candidates
  }

  private func deletedCredentialIds() -> Set<String> {
    Set(defaults.stringArray(forKey: Self.defaultDeletedCredentialIdsKey) ?? [])
  }

  private func isCredentialDeleted(id: String) -> Bool {
    !deletedCredentialIds().isDisjoint(with: credentialIdCandidates(id))
  }

  private func markCredentialsDeleted(ids: Set<String>) {
    var deletedIds = deletedCredentialIds()
    deletedIds.formUnion(ids)
    defaults.set(Array(deletedIds), forKey: Self.defaultDeletedCredentialIdsKey)
  }

  private func unmarkCredentialDeleted(id: String) {
    var deletedIds = deletedCredentialIds()
    deletedIds.subtract(credentialIdCandidates(id))
    defaults.set(Array(deletedIds), forKey: Self.defaultDeletedCredentialIdsKey)
  }

  private func encodeKeyData(_ keyData: [String: Any]) throws -> String {
    let jsonData = try JSONSerialization.data(withJSONObject: keyData, options: [])
    return jsonData.base64URLEncodedString()
  }

  private func decodeKeystorePayload(_ payload: String, masterKey: Data) throws -> [String: Any] {
    let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
    // An envelope is `iv` + `content` (the tag either appended to the content or,
    // in the legacy shape, in its own `tag` field). Anything else that is JSON is
    // an already-decoded record.
    if trimmed.hasPrefix("{"),
       let payloadData = trimmed.data(using: .utf8),
       let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
       json["iv"] == nil || json["content"] == nil
    {
      return json
    }

    let encoded = trimmed.hasPrefix("{") ? try decryptData(masterKey, trimmed) : trimmed
    guard let jsonData = Data(base64URLEncoded: encoded) ?? encoded.data(using: .utf8),
          let json = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
    else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return json
  }

  private func encryptData(_ key: Data, _ plaintext: String) throws -> String {
    let symmetricKey = SymmetricKey(data: key)
    let nonceData = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
    let nonce = try AES.GCM.Nonce(data: nonceData)
    let sealedBox = try AES.GCM.seal(Data(plaintext.utf8), using: symmetricKey, nonce: nonce)

    let payload: [String: String] = [
      "iv": nonceData.base64EncodedString(),
      "tag": sealedBox.tag.base64EncodedString(),
      "content": sealedBox.ciphertext.base64EncodedString(),
    ]
    let data = try JSONSerialization.data(withJSONObject: payload, options: [])
    guard let string = String(data: data, encoding: .utf8) else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return string
  }

  private func decryptData(_ key: Data, _ payload: String) throws -> String {
    guard let payloadData = payload.data(using: .utf8),
          let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: String],
          let ivString = json["iv"], let iv = Data(base64Encoded: ivString),
          let contentString = json["content"], let content = Data(base64Encoded: contentString)
    else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }

    // The keystore's current `sealData` appends the 16-byte GCM tag to the
    // ciphertext (the WebCrypto convention); the legacy envelope carried it in its
    // own field. Both have to open, or existing records become unreadable.
    let ciphertext: Data
    let tag: Data
    if let tagString = json["tag"], let separateTag = Data(base64Encoded: tagString),
       !separateTag.isEmpty
    {
      ciphertext = content
      tag = separateTag
    } else {
      guard content.count > 16 else {
        throw PasskeyCredentialStoreError.credentialEncodingFailed
      }
      ciphertext = content.prefix(content.count - 16)
      tag = content.suffix(16)
    }

    let sealedBox = try AES.GCM.SealedBox(
      nonce: AES.GCM.Nonce(data: iv),
      ciphertext: ciphertext,
      tag: tag
    )
    let decrypted = try AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
    guard let string = String(data: decrypted, encoding: .utf8) else {
      throw PasskeyCredentialStoreError.credentialEncodingFailed
    }
    return string
  }

  private func dataArray(_ value: Any?) -> Data? {
    guard let array = value as? [Any] else {
      return nil
    }
    var data = Data(capacity: array.count)
    for item in array {
      if let int = item as? Int {
        data.append(UInt8(int & 0xff))
      } else if let number = item as? NSNumber {
        data.append(UInt8(truncating: number))
      } else {
        return nil
      }
    }
    return data
  }

  private static func secretStringData(_ secret: String) -> Data? {
    let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
      return Data(hex: String(trimmed.dropFirst(2)))
    }
    return Data(hex: trimmed) ?? Data(base64URLEncoded: trimmed) ?? Data(base64Encoded: trimmed)
  }
}

extension StoredPasskeyCredential {
  var credentialIdData: Data {
    Data(base64URLEncoded: credentialId) ?? Data()
  }

  var userHandleData: Data {
    Data(base64URLEncoded: userHandle) ?? Data(userHandle.utf8)
  }

  func privateSecKey() throws -> SecKey {
    guard let privateKeyData = Data(base64URLEncoded: privateKey) ?? Data(base64Encoded: privateKey)
    else {
      throw PasskeyCredentialStoreError.invalidPrivateKey
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 256,
    ]

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(privateKeyData as CFData, attributes as CFDictionary, &error)
    else {
      throw error?.takeRetainedValue() ?? PasskeyCredentialStoreError.invalidPrivateKey
    }
    return key
  }

  func sign(_ data: Data) throws -> Data {
    if let privateKeyData = Data(base64URLEncoded: privateKey) ?? Data(base64Encoded: privateKey) {
      if let key = try? P256.Signing.PrivateKey(rawRepresentation: privateKeyData) {
        return try key.signature(for: data).derRepresentation
      }

      if let key = try? P256.Signing.PrivateKey(derRepresentation: privateKeyData) {
        return try key.signature(for: data).derRepresentation
      }
    }

    let key = try privateSecKey()
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error)
      as Data?
    else {
      throw error?.takeRetainedValue() ?? PasskeyCredentialStoreError.signingFailed
    }
    return signature
  }
}

extension Data {
  var byteArray: [Int] {
    map { Int($0) }
  }

  init?(hex: String) {
    let normalized = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard normalized.count % 2 == 0 else {
      return nil
    }

    var bytes = Data(capacity: normalized.count / 2)
    var index = normalized.startIndex
    while index < normalized.endIndex {
      let nextIndex = normalized.index(index, offsetBy: 2)
      guard let byte = UInt8(normalized[index..<nextIndex], radix: 16) else {
        return nil
      }
      bytes.append(byte)
      index = nextIndex
    }
    self = bytes
  }

  init?(base64URLEncoded string: String) {
    var base64 = string.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 {
      base64.append(String(repeating: "=", count: 4 - remainder))
    }
    self.init(base64Encoded: base64)
  }

  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

extension String {
  var relyingPartyIdentifier: String {
    guard let url = URL(string: self), let host = url.host else {
      return self
    }
    return host
  }

  var passkeyDisplayName: String {
    let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          let decodedData = Data(base64URLEncoded: trimmed) ?? Data(base64Encoded: trimmed),
          let decoded = String(data: decodedData, encoding: .utf8)
    else {
      return self
    }

    let normalized = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty,
          normalized.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 })
    else {
      return self
    }

    return normalized
  }
}
