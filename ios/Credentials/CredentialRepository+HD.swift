import Foundation
import CryptoKit
import deterministicP256_swift
internal import ReactNativePasskeyAutofill

extension CredentialRepository {
    internal func createDeterministicKeyPair(origin: String, userHandle: String) throws -> P256.Signing.PrivateKey {
        guard let masterKey = getMasterKey() else {
            throw NSError(domain: "Master key not found", code: -1)
        }
        
        guard let hdRootKeyId = getHdRootKeyId() else {
            throw NSError(domain: "HD Root Key ID not found", code: -1)
        }
        
        guard let mmkv = getMmkv(), let hdRootKeyPayload = mmkv.string(forKey: hdRootKeyId) else {
            throw NSError(domain: "HD Root Key not found", code: -1)
        }
        
        let hdRootKeyData = try decodeKeyDataPublic(payload: hdRootKeyPayload, masterKey: masterKey)
        
        let seedBytes: [UInt8]
        if let seedArray = hdRootKeyData["seed"] as? [UInt8] {
            seedBytes = seedArray
        } else if let privateKeyArray = hdRootKeyData["privateKey"] as? [UInt8] {
            seedBytes = privateKeyArray
        } else if let seedString = (hdRootKeyData["seed"] as? String) ?? (hdRootKeyData["privateKey"] as? String) {
            if seedString.hasPrefix("0x") {
                seedBytes = Array(Data(hexString: String(seedString.dropFirst(2))))
            } else {
                seedBytes = Array(Data(base64URLEncoded: seedString) ?? Data())
            }
        } else {
            throw NSError(domain: "HD Root Key does not contain seed", code: -1)
        }
        
        let dp256 = DeterministicP256()
        let derivedMainKey = Data(seedBytes)
        return dp256.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userHandle: userHandle.lowercased())
    }
}
