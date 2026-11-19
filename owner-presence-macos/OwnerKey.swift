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
    let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: existingReference,
                                                          authenticationContext: context)
    guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: request.approvalReason)
    else { throw PresenceFailure.declined }
    try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    let signature = try key.signature(for: request.signedBytes)
    try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
    return ["public_key": key.publicKey.x963Representation.base64EncodedString(),
            "signature": signature.derRepresentation.base64EncodedString()]
}
