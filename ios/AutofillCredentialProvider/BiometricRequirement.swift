import Foundation
import LocalAuthentication

/// Authentication requirement for passkey operations, configured at build time via the
/// `biometricRequirement` config-plugin prop and read from the extension Info.plist.
/// iOS has no weak-biometric concept, so both relaxed levels allow the device passcode.
enum BiometricRequirement: String {
  case strong
  case strongOrCredential
  case weakOrCredential

  private static let infoDictionaryKey = "ReactNativePasskeyAutofillBiometricRequirement"

  static let current: BiometricRequirement = {
    guard
      let raw = Bundle.main.object(forInfoDictionaryKey: infoDictionaryKey) as? String,
      let parsed = BiometricRequirement(rawValue: raw)
    else {
      return .strongOrCredential
    }
    return parsed
  }()

  /// `.deviceOwnerAuthenticationWithBiometrics` rejects the passcode; `.deviceOwnerAuthentication`
  /// allows biometrics or passcode.
  var laPolicy: LAPolicy {
    switch self {
    case .strong:
      return .deviceOwnerAuthenticationWithBiometrics
    case .strongOrCredential, .weakOrCredential:
      return .deviceOwnerAuthentication
    }
  }
}
