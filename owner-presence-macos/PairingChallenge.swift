import CryptoKit
import Foundation
import Security

enum PresenceFailure: Error, LocalizedError {
    case invalidChallenge, expired, unavailable, unsigned, missingKey, invalidKey, declined
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidChallenge: return "Invalid Machine pairing challenge."
        case .expired: return "Machine pairing challenge expired."
        case .unavailable: return "Secure Enclave owner approval is unavailable."
        case .unsigned: return "A provisioned Developer ID owner approval application is required."
        case .missingKey: return "Create the owner public key before approving pairing."
        case .invalidKey: return "The enrolled owner key could not be used."
        case .declined: return "Owner approval was declined."
        case .keychain(let status): return "Owner Keychain operation failed (\(status))."
        }
    }
}

struct PairingChallenge: Decodable {
    let action: String
    let machine_key: String
    let hq_key: String
    let nonce: String
    let expires_at: Int64

    static let maximumBytes = 2048

    static func parse(_ bytes: Data, now: Int64) throws -> Self {
        let fields: Set<String> = ["action", "machine_key", "hq_key", "nonce", "expires_at"]
        guard bytes.count <= maximumBytes,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(json.keys) == fields else { throw PresenceFailure.invalidChallenge }
        let challenge = try JSONDecoder().decode(Self.self, from: bytes)
        guard challenge.action == "machine-pair",
              [challenge.machine_key, challenge.hq_key, challenge.nonce].allSatisfy({ text in
                  text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
              }) else { throw PresenceFailure.invalidChallenge }
        try challenge.checkExpiry(now: now)
        return challenge
    }

    func checkExpiry(now: Int64) throws {
        guard now >= 0, expires_at > now, expires_at - now <= 120 else { throw PresenceFailure.expired }
    }

    var signedBytes: Data {
        Data("agent-bot-machine-owner/v1\n\(action)\n\(machine_key)\n\(hq_key)\n\(nonce)\n\(expires_at)\n".utf8)
    }

    private func fingerprint(_ hex: String) -> String {
        // The parser has already validated the 32 lowercase-hex octets.
        let octets = Array(hex.utf8)
        func value(_ c: UInt8) -> UInt8 { c <= 57 ? c - 48 : c - 87 }
        let bytes = stride(from: 0, to: octets.count, by: 2).map {
            (value(octets[$0]) << 4) | value(octets[$0 + 1])
        }
        return SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }

    var approvalReason: String {
        "Pair HQ with Machine?\nMachine SHA-256: \(fingerprint(machine_key))\nHQ SHA-256: \(fingerprint(hq_key))"
    }
}
