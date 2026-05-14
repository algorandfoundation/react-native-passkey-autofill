import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
  private let store = PasskeyCredentialStore()
  private var pendingRegistrationRequest: ASPasskeyCredentialRequest?
  private var pendingRegistrationIdentity: ASPasskeyCredentialIdentity?
  private var isCompletingRegistration = false
  private var hasPresentedInterface = false
  private var authContext: LAContext?
  private let activityIndicator = UIActivityIndicatorView(style: .large)
  private let statusLabel = UILabel()

  override func viewDidLoad() {
    super.viewDidLoad()
    configureView()
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)
    hasPresentedInterface = true

    guard pendingRegistrationRequest != nil else {
      return
    }

    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
      self?.authenticateAndCompleteRegistration()
    }
  }

  override func prepareCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier],
    requestParameters: ASPasskeyCredentialRequestParameters
  ) {
    guard #available(iOSApplicationExtension 17.0, *) else {
      cancel(code: .failed, message: "Passkeys require iOS 17 or newer.")
      return
    }

    let relyingPartyIdentifier = requestParameters.relyingPartyIdentifier
    guard let credential = store?.credentials(
            relyingPartyIdentifier: relyingPartyIdentifier
          ).first
    else {
      cancel(code: .credentialIdentityNotFound, message: "No passkey is available.")
      return
    }

    completeAssertion(
      credential: credential,
      clientDataHash: requestParameters.clientDataHash,
      relyingPartyIdentifier: relyingPartyIdentifier
    )
  }

  override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
    guard #available(iOSApplicationExtension 17.0, *),
          let request = credentialRequest as? ASPasskeyCredentialRequest
    else {
      cancel(code: .failed, message: "Unsupported credential request.")
      return
    }

    guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
          let credential = store?.credential(id: identity.credentialID)
    else {
      cancel(code: .credentialIdentityNotFound, message: "Credential identity not found.")
      return
    }

    completeAssertion(
      credential: credential,
      clientDataHash: request.clientDataHash,
      relyingPartyIdentifier: identity.relyingPartyIdentifier
    )
  }

  override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
    provideCredentialWithoutUserInteraction(for: credentialRequest)
  }

  override func prepareInterface(forPasskeyRegistration request: ASCredentialRequest) {
    store?.appendDiagnostic("prepareInterface(forPasskeyRegistration)")
    guard #available(iOSApplicationExtension 17.0, *),
          let request = request as? ASPasskeyCredentialRequest,
          let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    else {
      cancel(code: .failed, message: "Unsupported passkey registration request.")
      return
    }

    pendingRegistrationRequest = request
    pendingRegistrationIdentity = identity
    showCheckingPasskeys()

    if hasPresentedInterface {
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
        self?.authenticateAndCompleteRegistration()
      }
    }
  }

  override func prepareInterfaceForExtensionConfiguration() {
    extensionContext.completeExtensionConfigurationRequest()
  }

  private func completePendingRegistration() {
    store?.appendDiagnostic("completePendingRegistration")
    showCheckingPasskeys()

    guard #available(iOSApplicationExtension 17.0, *),
          let request = pendingRegistrationRequest,
          let identity = pendingRegistrationIdentity
    else {
      cancel(code: .failed, message: "Unsupported passkey registration request.")
      return
    }

    do {
      guard let derivedMainKey = store?.derivedMainKey(),
            store?.isMasterKeyAvailable() == true,
            store?.hdRootKeyId() != nil
      else {
        store?.appendDiagnostic("missing wallet root-key state")
        showFailure("Wallet root key is not available. Open Rocca Wallet once, unlock it, then try again.")
        return
      }

      let userHandle = identity.userHandleString
      let privateKey = try Self.domainSpecificKeyPair(
        derivedMainKey: derivedMainKey,
        origin: identity.relyingPartyIdentifier,
        userHandle: userHandle.lowercased()
      )
      let publicKey = privateKey.publicKey.derRepresentation
      let credentialId = WebAuthn.credentialId(publicKey: publicKey)
      let storedCredential = StoredPasskeyCredential(
        credentialId: credentialId.base64EncodedString(),
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        userName: identity.userName.passkeyDisplayName,
        userHandle: identity.userHandle.base64EncodedString(),
        privateKey: privateKey.rawRepresentation.base64EncodedString(),
        publicKey: publicKey.base64EncodedString(),
        createdAt: Date().timeIntervalSince1970
      )

      if #available(iOSApplicationExtension 18.0, *) {
        if request.excludedCredentials?.contains(where: { $0.credentialID == credentialId }) == true {
          store?.appendDiagnostic("registration excluded credential matched generated credential id")
          if store?.isCredentialDeleted(id: credentialId) == true {
            store?.appendDiagnostic("excluded credential was deleted locally; not recovering")
            showFailure("This passkey was deleted from Rocca Wallet. Remove it from this website before creating it again.")
            return
          }
          try store?.save(storedCredential)
          store?.appendDiagnostic("stored existing excluded passkey credential")
          Task {
            do {
              try await store?.replaceIdentityStore()
              store?.appendDiagnostic("replaceIdentityStore after excluded registration succeeded")
            } catch {
              store?.appendDiagnostic("replaceIdentityStore after excluded registration failed: \(error.localizedDescription)")
            }
          }
          showFailure("A passkey already exists for this account.")
          return
        }
      }

      let authData = try WebAuthn.authenticatorDataForAttestation(
        relyingPartyIdentifier: identity.relyingPartyIdentifier,
        credentialId: credentialId,
        publicKey: publicKey
      )
      let registrationCredential = ASPasskeyRegistrationCredential(
        relyingParty: identity.relyingPartyIdentifier,
        clientDataHash: request.clientDataHash,
        credentialID: credentialId,
        attestationObject: WebAuthn.attestationObject(authenticatorData: authData)
      )

      try store?.save(storedCredential)
      store?.appendDiagnostic("stored passkey credential")

      Task {
        do {
          try await store?.replaceIdentityStore()
          store?.appendDiagnostic("replaceIdentityStore after registration succeeded")
        } catch {
          store?.appendDiagnostic("replaceIdentityStore after registration failed: \(error.localizedDescription)")
        }
      }

      store?.appendDiagnostic("completeRegistrationRequest")
      extensionContext.completeRegistrationRequest(using: registrationCredential) { [weak self] completed in
        self?.store?.appendDiagnostic("completeRegistrationRequest completion: \(completed)")
        self?.authContext = nil
      }
    } catch {
      store?.appendDiagnostic("registration error: \(error.localizedDescription)")
      showFailure(error.localizedDescription)
    }
  }

  private func completeAssertion(
    credential: StoredPasskeyCredential,
    clientDataHash: Data,
    relyingPartyIdentifier: String
  ) {
    do {
      let authenticatorData = WebAuthn.authenticatorDataForAssertion(
        relyingPartyIdentifier: relyingPartyIdentifier
      )
      let signature = try credential.sign(authenticatorData + clientDataHash)
      let assertionCredential = ASPasskeyAssertionCredential(
        userHandle: credential.userHandleData,
        relyingParty: relyingPartyIdentifier,
        signature: signature,
        clientDataHash: clientDataHash,
        authenticatorData: authenticatorData,
        credentialID: credential.credentialIdData
      )
      extensionContext.completeAssertionRequest(using: assertionCredential) { _ in }
    } catch {
      cancel(code: .failed, message: error.localizedDescription)
    }
  }
  private func cancel(code: ASExtensionError.Code, message: String) {
    store?.appendDiagnostic("cancel: \(message)")
    extensionContext.cancelRequest(
      withError: NSError(
        domain: ASExtensionErrorDomain,
        code: code.rawValue,
        userInfo: [NSLocalizedDescriptionKey: message]
      )
    )
  }

  private func configureView() {
    view.backgroundColor = .systemBackground

    activityIndicator.hidesWhenStopped = true
    activityIndicator.startAnimating()

    statusLabel.text = "checking passkeys..."
    statusLabel.font = .preferredFont(forTextStyle: .body)
    statusLabel.textColor = .secondaryLabel
    statusLabel.textAlignment = .center
    statusLabel.numberOfLines = 0
    statusLabel.adjustsFontForContentSizeCategory = true

    let stack = UIStackView(arrangedSubviews: [activityIndicator, statusLabel])
    stack.axis = .vertical
    stack.alignment = .center
    stack.spacing = 14
    stack.translatesAutoresizingMaskIntoConstraints = false

    view.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
      stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
      stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
    ])
  }

  private func showCheckingPasskeys() {
    activityIndicator.startAnimating()
    statusLabel.text = "checking passkeys..."
  }

  private func showFailure(_ message: String) {
    store?.appendDiagnostic("showFailure: \(message)")
    activityIndicator.stopAnimating()
    statusLabel.text = message
  }

  private func authenticateAndCompleteRegistration() {
    guard !isCompletingRegistration else {
      return
    }
    isCompletingRegistration = true

    let context = LAContext()
    authContext = context
    context.localizedCancelTitle = "Cancel"
    context.localizedFallbackTitle = ""

    let policy: LAPolicy = .deviceOwnerAuthentication

    var error: NSError?
    guard context.canEvaluatePolicy(policy, error: &error) else {
      authContext = nil
      showFailure(error?.localizedDescription ?? "Device authentication is not available.")
      return
    }

    store?.appendDiagnostic("evaluatePolicy start")
    context.evaluatePolicy(policy, localizedReason: "Create passkeys with Rocca Wallet") { [weak self] success, authenticationError in
      DispatchQueue.main.async {
        guard let self else {
          return
        }

        if success {
          self.store?.appendDiagnostic("evaluatePolicy success")
          self.completePendingRegistration()
        } else {
          self.authContext = nil
          self.store?.appendDiagnostic(
            "evaluatePolicy failed: \(authenticationError?.localizedDescription ?? "unknown")"
          )
          self.cancel(
            code: .userCanceled,
            message: authenticationError?.localizedDescription ?? "Biometric authentication was canceled."
          )
        }
      }
    }
  }

  private static func domainSpecificKeyPair(
    derivedMainKey: Data,
    origin: String,
    userHandle: String,
    counter: UInt32 = 0
  ) throws -> P256.Signing.PrivateKey {
    var input = Data()
    input.append(derivedMainKey)
    input.append(contentsOf: origin.utf8)
    input.append(contentsOf: userHandle.utf8)

    for attempt in counter..<(counter + 16) {
      var candidateInput = input
      var bigEndianAttempt = attempt.bigEndian
      withUnsafeBytes(of: &bigEndianAttempt) { candidateInput.append(contentsOf: $0) }

      let digest = SHA512.hash(data: candidateInput)
      if let key = try? P256.Signing.PrivateKey(rawRepresentation: Data(digest.prefix(32))) {
        return key
      }
    }

    throw PasskeyCredentialStoreError.invalidPrivateKey
  }
}

private extension ASPasskeyCredentialIdentity {
  var userHandleString: String {
    String(data: userHandle, encoding: .utf8) ?? userHandle.base64URLEncodedString()
  }
}
