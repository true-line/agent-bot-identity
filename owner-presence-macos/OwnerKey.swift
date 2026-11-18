import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let bundleID = "ai.true-line.agent-bot-owner-presence"

// Security.framework enforces the signed access-group entitlement on all
// Data Protection Keychain operations. Also require a valid Developer ID
// application before serving a command, including public-key enrollment.
func verifiedAccessGroup() throws -> String {
    guard let task = SecTaskCreateFromSelf(nil) else { throw PresenceFailure.unsigned }
    func entitlement(_ name: String) -> Any? {
        SecTaskCopyValueForEntitlement(task, name as CFString, nil)
    }
    func validPrefix(_ text: String) -> Bool {
        text.utf8.count == 10 && text.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) }
    }
    guard let team = entitlement("com.apple.developer.team-identifier") as? String, validPrefix(team),
          let app = entitlement("com.apple.application-identifier") as? String,
          app.hasSuffix("." + bundleID), validPrefix(String(app.dropLast(bundleID.count + 1))),
          let groups = entitlement("keychain-access-groups") as? [String], groups == [app],
          Bundle.main.bundleIdentifier == bundleID,
          FileManager.default.fileExists(atPath: Bundle.main.bundleURL
              .appendingPathComponent("Contents/embedded.provisionprofile").path)
    else { throw PresenceFailure.unsigned }

    var code: SecCode?
    var requirement: SecRequirement?
    let expression = "anchor apple generic and identifier \"\(bundleID)\" and certificate leaf[subject.OU] = \"\(team)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code,
          SecRequirementCreateWithString(expression as CFString, SecCSFlags(), &requirement) == errSecSuccess,
          let requirement, SecCodeCheckValidity(code, SecCSFlags(), requirement) == errSecSuccess
    else { throw PresenceFailure.unsigned }
    return app
}

struct OwnerKey {
    typealias Key = SecureEnclave.P256.Signing.PrivateKey
    let group: String
    private var item: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: bundleID,
         kSecAttrAccount: "owner-pairing-p256-v1", kSecAttrAccessGroup: group,
         kSecUseDataProtectionKeychain: true]
    }

    private func load(context: LAContext) throws -> Key? {
        var query = item
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw PresenceFailure.keychain(status) }
        guard let reference = result as? Data else { throw PresenceFailure.invalidKey }
        return try Key(dataRepresentation: reference, authenticationContext: context)
    }

    func publicKey() throws -> Data {
        let context = LAContext()
        context.interactionNotAllowed = true
        if let existing = try load(context: context) { return existing.publicKey.x963Representation }
        guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                   [.privateKeyUsage, .userPresence], nil) else { throw PresenceFailure.unavailable }
        let key = try Key(compactRepresentable: true, accessControl: acl, authenticationContext: context)
        var insert = item
        // CryptoKit exports only the opaque, device-bound key reference.
        insert[kSecValueData] = key.dataRepresentation
        insert[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(insert as CFDictionary, nil)
        if status == errSecDuplicateItem, let winner = try load(context: context) {
            return winner.publicKey.x963Representation
        }
        guard status == errSecSuccess else { throw PresenceFailure.keychain(status) }
        return key.publicKey.x963Representation
    }

    func approve(_ request: PairingChallenge) async throws -> [String: String] {
        // A new context per action prevents a prior request from granting this one.
        let context = LAContext()
        defer { context.invalidate() }
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = request.approvalReason
        guard let key = try load(context: context) else { throw PresenceFailure.missingKey }
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: request.approvalReason)
        else { throw PresenceFailure.declined }
        try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        let signature = try key.signature(for: request.signedBytes)
        try request.checkExpiry(now: Int64(Date().timeIntervalSince1970))
        return ["public_key": key.publicKey.x963Representation.base64EncodedString(),
                "signature": signature.derRepresentation.base64EncodedString()]
    }
}
