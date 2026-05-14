import CryptoKit
import Foundation

enum WebAuthnError: LocalizedError {
  case invalidP256PublicKeyLength(Int)

  var errorDescription: String? {
    switch self {
    case .invalidP256PublicKeyLength(let length):
      return "Invalid P-256 public key length: \(length)."
    }
  }
}

enum WebAuthn {
  static let aaguid = UUID(uuidString: "1F59713A-C021-4E63-9158-2CC5FDC14E52")!

  static func authenticatorDataForAssertion(relyingPartyIdentifier: String) -> Data {
    var data = Data(SHA256.hash(data: Data(relyingPartyIdentifier.utf8)))
    data.append(flags(attestedCredentialDataIncluded: false))
    data.append(signCount())
    return data
  }

  static func authenticatorDataForAttestation(
    relyingPartyIdentifier: String,
    credentialId: Data,
    publicKey: Data
  ) throws -> Data {
    var data = Data(SHA256.hash(data: Data(relyingPartyIdentifier.utf8)))
    data.append(flags(attestedCredentialDataIncluded: true))
    data.append(signCount())
    data.append(try attestedCredentialData(credentialId: credentialId, publicKey: publicKey))
    return data
  }

  static func attestationObject(authenticatorData: Data) -> Data {
    Cbor.encodeMap([
      (Cbor.encodeText("fmt"), Cbor.encodeText("none")),
      (Cbor.encodeText("attStmt"), Cbor.encodeMap([])),
      (Cbor.encodeText("authData"), Cbor.encodeBytes(authenticatorData)),
    ])
  }

  static func credentialId(publicKey: Data) -> Data {
    Data(SHA256.hash(data: publicKey))
  }

  private static func flags(attestedCredentialDataIncluded: Bool) -> Data {
    var flags: UInt8 = 0x01
    flags |= 0x04
    flags |= 0x08
    flags |= 0x10
    if attestedCredentialDataIncluded {
      flags |= 0x40
    }
    return Data([flags])
  }

  private static func signCount() -> Data {
    Data([0x00, 0x00, 0x00, 0x00])
  }

  private static func attestedCredentialData(credentialId: Data, publicKey: Data) throws -> Data {
    var data = aaguid.bytes
    data.append(UInt8((credentialId.count >> 8) & 0xff))
    data.append(UInt8(credentialId.count & 0xff))
    data.append(credentialId)
    data.append(try coseKey(publicKey: publicKey))
    return data
  }

  private static func coseKey(publicKey: Data) throws -> Data {
    let coordinates = try p256Coordinates(publicKey: publicKey)

    return Cbor.encodeMap([
      (Cbor.encodeInt(1), Cbor.encodeInt(2)),
      (Cbor.encodeInt(3), Cbor.encodeInt(-7)),
      (Cbor.encodeInt(-1), Cbor.encodeInt(1)),
      (Cbor.encodeInt(-2), Cbor.encodeBytes(coordinates.x)),
      (Cbor.encodeInt(-3), Cbor.encodeBytes(coordinates.y)),
    ])
  }

  private static func p256Coordinates(publicKey: Data) throws -> (x: Data, y: Data) {
    if let derPublicKey = try? P256.Signing.PublicKey(derRepresentation: publicKey) {
      return try p256Coordinates(publicKey: derPublicKey.x963Representation)
    }

    if publicKey.count == 65, publicKey.first == 0x04 {
      let coordinates = publicKey.dropFirst()
      return (
        Data(coordinates.prefix(32)),
        Data(coordinates.dropFirst(32).prefix(32))
      )
    }

    if publicKey.count == 64 {
      return (
        Data(publicKey.prefix(32)),
        Data(publicKey.dropFirst(32).prefix(32))
      )
    }

    throw WebAuthnError.invalidP256PublicKeyLength(publicKey.count)
  }
}

private enum Cbor {
  static func encodeInt(_ value: Int) -> Data {
    if value >= 0 {
      return encodeUnsigned(UInt64(value), majorType: 0)
    }
    return encodeUnsigned(UInt64(-1 - value), majorType: 1)
  }

  static func encodeBytes(_ bytes: Data) -> Data {
    encodeUnsigned(UInt64(bytes.count), majorType: 2) + bytes
  }

  static func encodeText(_ string: String) -> Data {
    let bytes = Data(string.utf8)
    return encodeUnsigned(UInt64(bytes.count), majorType: 3) + bytes
  }

  static func encodeMap(_ pairs: [(Data, Data)]) -> Data {
    var data = encodeUnsigned(UInt64(pairs.count), majorType: 5)
    for (key, value) in pairs {
      data.append(key)
      data.append(value)
    }
    return data
  }

  private static func encodeUnsigned(_ value: UInt64, majorType: UInt8) -> Data {
    let prefix = majorType << 5
    switch value {
    case 0..<24:
      return Data([prefix | UInt8(value)])
    case 24..<256:
      return Data([prefix | 24, UInt8(value)])
    case 256..<65_536:
      return Data([prefix | 25, UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
    case 65_536..<4_294_967_296:
      return Data([
        prefix | 26,
        UInt8((value >> 24) & 0xff),
        UInt8((value >> 16) & 0xff),
        UInt8((value >> 8) & 0xff),
        UInt8(value & 0xff),
      ])
    default:
      return Data([
        prefix | 27,
        UInt8((value >> 56) & 0xff),
        UInt8((value >> 48) & 0xff),
        UInt8((value >> 40) & 0xff),
        UInt8((value >> 32) & 0xff),
        UInt8((value >> 24) & 0xff),
        UInt8((value >> 16) & 0xff),
        UInt8((value >> 8) & 0xff),
        UInt8(value & 0xff),
      ])
    }
  }
}

private extension UUID {
  var bytes: Data {
    var uuid = uuid
    return withUnsafeBytes(of: &uuid) { Data($0) }
  }
}
