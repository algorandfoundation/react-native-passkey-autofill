import Foundation
import CryptoKit
import LocalAuthentication
import Security
import MMKV

public class CredentialRepository {
    public static let shared = CredentialRepository()
    
    private let PASSKEYS_MMKV_ID = "keystore"
    private let PASSKEY_AUTOFILL_MMKV_ID = "passkey_autofill"
    private let MASTER_KEY_TAG = "co.algorand.passkeyautofill.masterkey"
    private let HD_ROOT_KEY_ID_KEY = "hd_root_key_id"
    private let GET_PASSKEY_ACTION_KEY = "get_passkey_action"
    private let CREATE_PASSKEY_ACTION_KEY = "create_passkey_action"
    
    private var mmkv: MMKV?
    private var autofillMmkv: MMKV?
    
    private init() {}
    
    public func initialize(appGroupId: String?) {
        if let appGroupId = appGroupId {
            MMKV.initialize(rootDir: nil, groupDir: appGroupId, logLevel: .info)
            self.mmkv = MMKV(mmapID: PASSKEYS_MMKV_ID, mode: .multiProcess)
            self.autofillMmkv = MMKV(mmapID: PASSKEY_AUTOFILL_MMKV_ID, mode: .multiProcess)
        } else {
            MMKV.initialize(rootDir: nil)
            self.mmkv = MMKV(mmapID: PASSKEYS_MMKV_ID)
            self.autofillMmkv = MMKV(mmapID: PASSKEY_AUTOFILL_MMKV_ID)
        }
    }
    
    public func getMmkv() -> MMKV? {
        return mmkv
    }
    
    public func saveCredential(credential: Credential) {
        guard let mmkv = mmkv else { return }
        
        var keyData: [String: Any] = [
            "id": credential.credentialId,
            "type": "hd-derived-p256",
            "algorithm": "P256",
            "extractable": false,
            "keyUsages": ["sign"],
            "name": "Passkey: \(credential.origin)"
        ]
        
        if let publicKeyData = Data(base64Encoded: credential.publicKey) {
             keyData["publicKey"] = Array(publicKeyData)
        }
        
        if let privateKeyData = Data(base64Encoded: credential.privateKey) {
            keyData["privateKey"] = Array(privateKeyData)
        }
        
        let metadata: [String: Any] = [
            "origin": credential.origin,
            "userHandle": credential.userHandle,
            "userId": credential.userId,
            "count": credential.count
        ]
        keyData["metadata"] = metadata
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: keyData)
            let base64urlJson = jsonData.base64URLEncodedString()
            
            if let masterKey = getMasterKey() {
                if let encryptedPayload = encryptData(key: masterKey, data: base64urlJson) {
                    mmkv.set(encryptedPayload, forKey: credential.credentialId)
                } else {
                    mmkv.set(base64urlJson, forKey: credential.credentialId)
                }
            } else {
                mmkv.set(base64urlJson, forKey: credential.credentialId)
            }
        } catch {
            print("Failed to save credential: \(error)")
        }
        
        let notificationName = "co.algorand.passkeyautofill.onPasskeyAdded"
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(notificationName as CFString), nil, nil, true)
    }

    public func updateCredential(credential: Credential) {
        saveCredential(credential: credential)
        
        let notificationName = "co.algorand.passkeyautofill.onPasskeyAuthenticated"
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(notificationName as CFString), nil, nil, true)
    }
    
    public func getAllCredentials() -> [Credential] {
        guard let mmkv = mmkv else { return [] }
        let allKeys = mmkv.allKeys() as? [String] ?? []
        var credentials: [Credential] = []
        
        let masterKey = getMasterKey()
        
        for key in allKeys {
            if let payload = mmkv.string(forKey: key) {
                do {
                    let json = try decodeKeyData(payload: payload, masterKey: masterKey)
                    if let id = json["id"] as? String {
                        let metadata = json["metadata"] as? [String: Any]
                        
                        let publicKeyBytes = json["publicKey"] as? [UInt8] ?? []
                        let privateKeyBytes = json["privateKey"] as? [UInt8] ?? []
                        
                        credentials.append(Credential(
                            credentialId: id,
                            origin: (metadata?["origin"] as? String) ?? (json["origin"] as? String) ?? "",
                            userHandle: (metadata?["userHandle"] as? String) ?? (json["userHandle"] as? String) ?? "",
                            userId: (metadata?["userId"] as? String) ?? (json["userId"] as? String) ?? "",
                            publicKey: Data(publicKeyBytes).base64EncodedString(),
                            privateKey: Data(privateKeyBytes).base64EncodedString(),
                            count: (metadata?["count"] as? Int) ?? (json["count"] as? Int) ?? 0,
                            biometricIv: nil
                        ))
                    }
                } catch {
                    continue
                }
            }
        }
        return credentials
    }
    
    public func getCredential(credentialId: Data) -> Credential? {
        let id = credentialId.base64EncodedString()
        guard let mmkv = mmkv, let payload = mmkv.string(forKey: id) else { return nil }
        
        let masterKey = getMasterKey()
        do {
            let json = try decodeKeyData(payload: payload, masterKey: masterKey)
            if let id = json["id"] as? String {
                let metadata = json["metadata"] as? [String: Any]
                let publicKeyBytes = json["publicKey"] as? [UInt8] ?? []
                let privateKeyBytes = json["privateKey"] as? [UInt8] ?? []
                
                return Credential(
                    credentialId: id,
                    origin: (metadata?["origin"] as? String) ?? (json["origin"] as? String) ?? "",
                    userHandle: (metadata?["userHandle"] as? String) ?? (json["userHandle"] as? String) ?? "",
                    userId: (metadata?["userId"] as? String) ?? (json["userId"] as? String) ?? "",
                    publicKey: Data(publicKeyBytes).base64EncodedString(),
                    privateKey: Data(privateKeyBytes).base64EncodedString(),
                    count: (metadata?["count"] as? Int) ?? (json["count"] as? Int) ?? 0,
                    biometricIv: nil
                )
            }
        } catch {
            return nil
        }
        return nil
    }

    public func saveMasterKey(secret: String) {
        var keyBytes: Data
        if (secret.count == 64 || secret.count == 32) && secret.range(of: "^[0-9a-fA-F]*$", options: .regularExpression) != nil {
            keyBytes = Data(hexString: secret)
        } else {
            keyBytes = secret.data(using: .utf8) ?? Data()
        }
        
        saveToKeychain(data: keyBytes, tag: MASTER_KEY_TAG)
    }
    
    public func getMasterKey() -> Data? {
        return loadFromKeychain(tag: MASTER_KEY_TAG)
    }
    
    public func saveHdRootKeyId(id: String) {
        autofillMmkv?.set(id, forKey: HD_ROOT_KEY_ID_KEY)
    }
    
    public func getHdRootKeyId() -> String? {
        return autofillMmkv?.string(forKey: HD_ROOT_KEY_ID_KEY)
    }
    
    public func configureIntentActions(getPasskeyAction: String, createPasskeyAction: String) {
        autofillMmkv?.set(getPasskeyAction, forKey: GET_PASSKEY_ACTION_KEY)
        autofillMmkv?.set(createPasskeyAction, forKey: CREATE_PASSKEY_ACTION_KEY)
    }
    
    public func getGetPasskeyAction() -> String? {
        return autofillMmkv?.string(forKey: GET_PASSKEY_ACTION_KEY)
    }
    
    public func getCreatePasskeyAction() -> String? {
        return autofillMmkv?.string(forKey: CREATE_PASSKEY_ACTION_KEY)
    }
    
    public func clearCredentials() {
        mmkv?.clearAll()
        autofillMmkv?.clearAll()
    }
    
    public func getPublicKeyFromKeyPair(privateKey: P256.Signing.PrivateKey) -> Data {
        let x = privateKey.publicKey.rawRepresentation[0..<32]
        let y = privateKey.publicKey.rawRepresentation[32..<64]
        
        // COSE key encoding matching Android
        var data = Data(hexString: "A5010203262001215820")
        data.append(x)
        data.append(contentsOf: Data(hexString: "225820"))
        data.append(y)
        return data
    }
    
    public func sign(privateKey: P256.Signing.PrivateKey, payload: Data) throws -> Data {
        return try privateKey.signature(for: payload).rawRepresentation
    }

    // MARK: - Crypto Helpers
    
    private func encryptData(key: Data, data: String) -> String? {
        let nonce = AES.GCM.Nonce()
        guard let dataToEncrypt = data.data(using: .utf8) else { return nil }
        
        do {
            let sealedBox = try AES.GCM.seal(dataToEncrypt, using: SymmetricKey(data: key), nonce: nonce)
            
            let json: [String: String] = [
                "iv": Data(nonce).base64EncodedString(),
                "tag": sealedBox.tag.base64EncodedString(),
                "content": sealedBox.ciphertext.base64EncodedString()
            ]
            
            let jsonData = try JSONSerialization.data(withJSONObject: json)
            return String(data: jsonData, encoding: .utf8)
        } catch {
            return nil
        }
    }
    
    public func decodeKeyDataPublic(payload: String, masterKey: Data?) throws -> [String: Any] {
        return try decodeKeyData(payload: payload, masterKey: masterKey)
    }

    private func decodeKeyData(payload: String, masterKey: Data?) throws -> [String: Any] {
        if payload.hasPrefix("{") {
            guard let payloadData = payload.data(using: .utf8),
                  let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: String],
                  let ivBase64 = json["iv"],
                  let tagBase64 = json["tag"],
                  let contentBase64 = json["content"],
                  let ivData = Data(base64Encoded: ivBase64),
                  let tagData = Data(base64Encoded: tagBase64),
                  let contentData = Data(base64Encoded: contentBase64),
                  let masterKey = masterKey else {
                
                if let payloadData = payload.data(using: .utf8),
                   let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] {
                    return json
                }
                throw NSError(domain: "Invalid payload", code: -1)
            }
            
            let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: ivData), ciphertext: contentData, tag: tagData)
            let decryptedData = try AES.GCM.open(sealedBox, using: SymmetricKey(data: masterKey))
            
            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw NSError(domain: "Failed to decode decrypted data", code: -1)
            }
            
            if let decodedData = Data(base64URLEncoded: decryptedString),
               let finalJson = try JSONSerialization.jsonObject(with: decodedData) as? [String: Any] {
                return finalJson
            }
            
            if let finalJsonData = decryptedString.data(using: .utf8),
               let finalJson = try JSONSerialization.jsonObject(with: finalJsonData) as? [String: Any] {
                return finalJson
            }
        }
        
        if let decodedData = Data(base64URLEncoded: payload),
           let json = try JSONSerialization.jsonObject(with: decodedData) as? [String: Any] {
            return json
        }
        
        throw NSError(domain: "Unknown payload format", code: -1)
    }
    
    private func saveToKeychain(data: Data, tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
    
    private func loadFromKeychain(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            return dataTypeRef as? Data
        }
        return nil
    }
}

// MARK: - Extensions

public extension Data {
    init(hexString: String) {
        var hex = hexString
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        self = data
    }
    
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = 4 - base64.count % 4
        if padding < 4 {
            base64 += String(repeating: "=", count: padding)
        }
        self.init(base64Encoded: base64)
    }
}
