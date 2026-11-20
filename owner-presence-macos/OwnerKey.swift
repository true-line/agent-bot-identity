import CryptoKit
import Foundation
import LocalAuthentication

// Library code only. Key lookup and provenance belong to the authorized owner
// provider. This module has no key creation, storage lookup or command interface.
func approveOwnerRequest(_ request: OwnerRequest, existingReference: Data) async throws -> [String: String] {
    let context = LAContext()
    defer { context.invalidate() }
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedReason = request.approvalReason
    try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    if case .harnessLaunch(let challenge) = request { try HarnessMachinePin.verify(challenge.machine_key) }
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: existingReference,
                                                          authenticationContext: context)
    if case .harnessLaunch(let challenge) = request {
        try challenge.checkOwnerKey(key.publicKey.x963Representation)
        try await HarnessNativeReview.confirm(challenge)
        try HarnessMachinePin.verify(challenge.machine_key)
        try challenge.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    }
    do {
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: request.approvalReason)
        else { throw PresenceFailure.incomplete }
    } catch let error as LAError where error.code == .userCancel {
        throw PresenceFailure.declined
    } catch let error as LAError where [.appCancel, .systemCancel, .authenticationFailed].contains(error.code) {
        throw PresenceFailure.incomplete
    }
    try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    if case .harnessLaunch(let challenge) = request { try HarnessMachinePin.verify(challenge.machine_key) }
    let signature = try key.signature(for: request.signedBytes)
    try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    if case .harnessLaunch(let challenge) = request { try HarnessMachinePin.verify(challenge.machine_key) }
    return ["public_key": key.publicKey.x963Representation.base64EncodedString(),
            "signature": signature.derRepresentation.base64EncodedString()]
}
