import AuthenticationServices
import CryptoKit
import deterministicP256_swift
import LocalAuthentication
import UIKit
import Security
internal import ReactNativePasskeyAutofill

// Note: Ported from LiquidAuthSDK and ExampleShared to avoid heavy dependencies in the extension
// This should be adjusted based on the final project structure

class CredentialProviderViewController: ASCredentialProviderViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Initialize repository with App Group if available
        let appGroupId = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String
        CredentialRepository.shared.initialize(appGroupId: appGroupId)
    }

    // MARK: - Registration Flow
    
    override func prepareInterface(forPasskeyRegistration request: ASCredentialRequest) {
        guard #available(iOSApplicationExtension 17.0, *),
              let passkeyRequest = request as? ASPasskeyCredentialRequest,
              let credentialIdentity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.Code.userCanceled.rawValue))
            return
        }

        Task {
            let title = "Register Passkey"
            let message = "Do you want to register a new passkey for \(credentialIdentity.relyingPartyIdentifier)?"
            
            let consent = await presentUserConsentAlert(title: title, message: message)
            guard consent else {
                self.extensionContext.cancelRequest(withError: NSError(domain: "User cancelled", code: -1))
                return
            }

            do {
                let credential = try await createRegistrationCredential(for: passkeyRequest)
                await extensionContext.completeRegistrationRequest(using: credential)
            } catch {
                self.extensionContext.cancelRequest(withError: error)
            }
        }
    }

    // MARK: - Assertion Flow
    
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        let origin = requestParameters.relyingPartyIdentifier
        let credentials = CredentialRepository.shared.getAllCredentials().filter { it in
             // Simple origin matching, can be improved to match multiple origins/apps
             return it.origin == origin || origin.contains(it.origin)
        }
        
        var assertionCredentials: [ASPasskeyAssertionCredential] = []
        
        for cred in credentials {
            guard let privateKeyData = Data(base64Encoded: cred.privateKey) else { continue }
            do {
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
                let userHandleData = Data(cred.userHandle.utf8)
                let clientDataHash = requestParameters.clientDataHash
                
                let rpIdHash = Data(SHA256.hash(data: origin.data(using: .utf8)!))
                
                // Build AuthenticatorData (Assertion)
                let authenticatorData = buildAuthenticatorData(
                    rpIdHash: rpIdHash,
                    userPresent: true,
                    userVerified: true,
                    signCount: UInt32(cred.count)
                )
                
                let dataToSign = authenticatorData + clientDataHash
                let signature = try privateKey.signature(for: dataToSign).derRepresentation
                let credentialID = Data(base64Encoded: cred.credentialId) ?? Data()
                
                let assertionCredential = ASPasskeyAssertionCredential(
                    userHandle: userHandleData,
                    relyingParty: origin,
                    signature: signature,
                    clientDataHash: clientDataHash,
                    authenticatorData: authenticatorData,
                    credentialID: credentialID
                )
                assertionCredentials.append(assertionCredential)
            } catch {
                continue
            }
        }
        
        Task { [weak self] in
            if let credential = assertionCredentials.first {
                // If only one, or for simplicity in this integration, auto-select first
                let cred = credentials.first { $0.credentialId == credential.credentialID.base64EncodedString() }
                if let cred = cred {
                    let updatedCred = Credential(
                        credentialId: cred.credentialId,
                        origin: cred.origin,
                        userHandle: cred.userHandle,
                        userId: cred.userId,
                        publicKey: cred.publicKey,
                        privateKey: cred.privateKey,
                        count: cred.count + 1,
                        biometricIv: cred.biometricIv
                    )
                    CredentialRepository.shared.updateCredential(credential: updatedCred)
                }
                await self?.extensionContext.completeAssertionRequest(using: credential)
            } else {
                self?.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.Code.userCanceled.rawValue))
            }
        }
    }

    // MARK: - Helpers
    
    private func createRegistrationCredential(for request: ASPasskeyCredentialRequest) async throws -> ASPasskeyRegistrationCredential {
        guard let credentialIdentity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            throw NSError(domain: "Missing credential identity", code: -1)
        }

        let origin = credentialIdentity.relyingPartyIdentifier
        let clientDataHash = request.clientDataHash
        let userHandle = String(data: credentialIdentity.userHandle, encoding: .utf8) ?? "unknown"

        let privateKey = try CredentialRepository.shared.createDeterministicKeyPair(origin: origin, userHandle: userHandle)
        let pubkey = privateKey.publicKey.rawRepresentation
        let credentialID = Data(SHA256.hash(data: pubkey))

        // Check for excluded credentials
        if let excludedCredentials = request.excludedCredentials {
            for excluded in excludedCredentials {
                if excluded.credentialID == credentialID {
                    throw NSError(domain: "Credential already exists for this site", code: -2)
                }
            }
        }

        // Build attestation object
        // AAGUID can be random or fixed for the provider
        let aaguid = UUID(uuidString: "1F59713A-C021-4E63-9158-2CC5FDC14E52")!
        let attestedCredData = buildAttestedCredentialData(
            aaguid: aaguid,
            credentialId: credentialID,
            publicKey: pubkey
        )

        let rpIdHash = Data(SHA256.hash(data: origin.data(using: .utf8)!))
        let authData = buildAuthenticatorData(
            rpIdHash: rpIdHash,
            userPresent: true,
            userVerified: true,
            attestedCredentialData: attestedCredData
        )

        // Sanitize result as "none" attestation
        let attestationObject = try buildAttestationObject(authData: authData)
        
        // Save the credential
        let credential = Credential(
            credentialId: credentialID.base64EncodedString(),
            origin: origin,
            userHandle: userHandle,
            userId: userHandle,
            publicKey: pubkey.base64EncodedString(),
            privateKey: privateKey.rawRepresentation.base64EncodedString(),
            count: 0
        )
        CredentialRepository.shared.saveCredential(credential: credential)

        return ASPasskeyRegistrationCredential(
            relyingParty: origin,
            clientDataHash: clientDataHash,
            credentialID: credentialID,
            attestationObject: attestationObject
        )
    }

    private func presentUserConsentAlert(title: String, message: String) async -> Bool {
        await withCheckedContinuation { continuation in
            let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Continue", style: .default) { _ in
                continuation.resume(returning: true)
            })
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                continuation.resume(returning: false)
            })
            DispatchQueue.main.async {
                self.present(alert, animated: true, completion: nil)
            }
        }
    }

    // MARK: - WebAuthn Encoding Helpers
    
    private func buildAuthenticatorData(
        rpIdHash: Data,
        userPresent: Bool,
        userVerified: Bool,
        signCount: UInt32 = 0,
        attestedCredentialData: Data? = nil
    ) -> Data {
        var flags: UInt8 = 0
        if userPresent { flags |= 0x01 }
        if userVerified { flags |= 0x04 }
        if attestedCredentialData != nil { flags |= 0x40 }
        
        var data = rpIdHash
        data.append(flags)
        
        var count = signCount.bigEndian
        data.append(Data(bytes: &count, count: 4))
        
        if let attested = attestedCredentialData {
            data.append(attested)
        }
        
        return data
    }

    private func buildAttestedCredentialData(aaguid: UUID, credentialId: Data, publicKey: Data) -> Data {
        var data = Data()
        var uuid = aaguid.uuid
        data.append(Data(bytes: &uuid, count: 16))
        
        var idLength = UInt16(credentialId.count).bigEndian
        data.append(Data(bytes: &idLength, count: 2))
        data.append(credentialId)
        
        // COSE key encoding for P256
        let x = publicKey[0..<32]
        let y = publicKey[32..<64]
        
        // This is a simplified CBOR/COSE encoding for the public key
        // Map of 5 items: kty=2, alg=-7, crv=1, x=..., y=...
        // A5 01 02 03 26 20 01 21 58 20 [X] 22 58 20 [Y]
        var cose = Data([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        cose.append(x)
        cose.append(Data([0x22, 0x58, 0x20]))
        cose.append(y)
        
        data.append(cose)
        return data
    }

    private func buildAttestationObject(authData: Data) throws -> Data {
        // Build a minimal "none" attestation object: { "fmt": "none", "attStmt": {}, "authData": authData }
        // CBOR: A3 63 66 6D 74 64 6E 6F 6E 65 67 61 74 74 53 74 6D 74 A0 68 61 75 74 68 44 61 74 61 58 [len] [authData]
        var cbor = Data([0xA3])
        
        // "fmt": "none"
        cbor.append(Data([0x63, 0x66, 0x6D, 0x74, 0x64, 0x6E, 0x6F, 0x6E, 0x65]))
        
        // "attStmt": {}
        cbor.append(Data([0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6D, 0x74, 0xA0]))
        
        // "authData": authData
        cbor.append(Data([0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]))
        
        let len = authData.count
        if len < 24 {
            cbor.append(UInt8(0x40 + len))
        } else if len < 256 {
            cbor.append(0x58)
            cbor.append(UInt8(len))
        } else {
            cbor.append(0x59)
            var len16 = UInt16(len).bigEndian
            cbor.append(Data(bytes: &len16, count: 2))
        }
        cbor.append(authData)
        
        return cbor
    }
}
