import Foundation

public struct Credential: Codable {
    public let credentialId: String
    public let origin: String
    public let userHandle: String
    public let userId: String
    public let publicKey: String
    public let privateKey: String
    public let count: Int
    public let biometricIv: String?

    public init(
        credentialId: String,
        origin: String,
        userHandle: String,
        userId: String,
        publicKey: String,
        privateKey: String,
        count: Int,
        biometricIv: String? = nil
    ) {
        self.credentialId = credentialId
        self.origin = origin
        self.userHandle = userHandle
        self.userId = userId
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.count = count
        self.biometricIv = biometricIv
    }
}
